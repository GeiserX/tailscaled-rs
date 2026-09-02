//! `tnet` — the thin CLI client.
//!
//! Carries no node logic: every command marshals a [`Request`] to the daemon's LocalAPI socket and
//! renders the [`Response`]. This mirrors how Tailscale's `tailscale` CLI is a thin front-end over
//! `tailscaled`'s LocalAPI.

use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use secrecy::{ExposeSecret, SecretString};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use tailscaled_rs::goduration::parse_go_duration;
use tailscaled_rs::localapi::{Request, Response, RevertedPref};

/// Env var consulted for the auth key when neither `--authkey` nor `--authkey-file` is given.
const AUTHKEY_ENV: &str = "TS_AUTH_KEY";

#[derive(Parser)]
#[command(name = "tnet", about = "Control client for the tailnetd daemon")]
struct Cli {
    /// Path to the daemon's LocalAPI socket (defaults to the daemon's resolved path).
    #[arg(long, global = true)]
    socket: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

// NB: neither `Cli` nor `Command` derives `Debug`. That is deliberate — it keeps the parsed
// `authkey` off any accidental `{:?}` / debug-log path. Keep it that way (the secret is held in a
// `SecretString` once resolved; see `resolve_authkey`).
//
// `large_enum_variant` is allowed: `Up` carries the full `tailscale up` flag surface (~40 optional
// fields) so it dwarfs small variants like `Status`. This is a clap-`Subcommand` enum constructed
// exactly once per process at argv-parse time and immediately destructured, so the per-variant stack
// size is irrelevant here — boxing the variant would only fight clap's derive for no real benefit
// (same rationale as the `#[allow(clippy::too_many_arguments)]` on `run_up`, which mirrors this
// surface).
#[allow(clippy::large_enum_variant)]
#[derive(Subcommand)]
enum Command {
    /// Bring the node up and connect to the tailnet.
    Up {
        /// Pre-auth key for non-interactive registration, or `file:<path>` to read the key from a
        /// file. Exposes a bare key in argv/shell history; prefer `file:`, `--authkey-file` or the
        /// `TS_AUTH_KEY` env var. Precedence: `--authkey-file` > `--authkey` > `$TS_AUTH_KEY`.
        /// (INSECURE: visible in `ps`/shell history — prefer --authkey-file or $TS_AUTH_KEY.)
        //
        // `--auth-key` is Go's canonical spelling: `up.go` registers the flag under that name and
        // `cli.go`'s `CleanUpArgs` rewrites `--authkey` to it, so both spellings work upstream and
        // both must work here. The `file:` prefix comes with the flag (Go `resolveValueFromFile`,
        // reached through `upArgsT.getAuthKey`) and is resolved in `resolve_authkey`, so it is
        // honoured under either spelling exactly as it is upstream.
        #[arg(long, visible_alias = "auth-key", conflicts_with = "authkey_file")]
        authkey: Option<String>,
        /// Read the pre-auth key from a file (avoids argv/shell-history exposure). Takes precedence
        /// over `--authkey`; if neither is given, falls back to `$TS_AUTH_KEY`.
        #[arg(long, value_name = "PATH")]
        authkey_file: Option<PathBuf>,
        /// Requested hostname.
        #[arg(long)]
        hostname: Option<String>,
        /// Control server URL override (e.g. a self-hosted Headscale). Applied to the engine on
        /// `up`; a malformed URL fails loudly rather than silently using the default. Changing it on
        /// a node that is already running requires `--force-reauth` (switching control servers is a
        /// fresh registration, not an in-place tweak) — the daemon refuses the change otherwise.
        //
        // `--login-server` is Go's name for this flag (`up.go` `newUpFlagSet`, mapped to
        // `Prefs.ControlURL`) and the name `tnet login` already takes, so `up` was the odd one out.
        // A pure alias: same value, same pref, same "can't change --login-server without
        // --force-reauth" refusal, which this daemon already enforces on `--control-url`.
        #[arg(long, visible_alias = "login-server")]
        control_url: Option<String>,
        /// Enable kernel-TUN mode (`TransportMode::Tun`) instead of the userspace netstack. Requires
        /// a daemon built with the `tun` feature and run as root; the daemon fails loudly otherwise.
        /// Mutually exclusive with `--no-tun`; omitting both leaves the persisted setting unchanged.
        #[arg(long, conflicts_with = "no_tun")]
        tun: bool,
        /// Disable kernel-TUN mode, forcing the userspace netstack. Mutually exclusive with `--tun`;
        /// omitting both leaves the persisted setting unchanged.
        #[arg(long)]
        no_tun: bool,
        /// Desired TUN interface name (e.g. `tailscale0`); only meaningful with `--tun`.
        #[arg(long, value_name = "NAME")]
        tun_name: Option<String>,
        /// TUN interface MTU (Tailscale's overlay MTU is 1280); only meaningful with `--tun`.
        #[arg(long, value_name = "MTU")]
        tun_mtu: Option<u16>,
        /// Route this node's outbound traffic through a peer exit node, named by its tailnet IP or
        /// MagicDNS name (e.g. `100.64.0.9` or `exit-1`). Mutually exclusive with
        /// `--clear-exit-node`; omitting both leaves the persisted exit-node setting unchanged.
        /// (Automatic selection — Go's `--exit-node auto:any` — is not supported by this build; pass
        /// a concrete exit node.)
        #[arg(long, value_name = "IP|NAME", conflicts_with = "clear_exit_node")]
        exit_node: Option<String>,
        /// Stop routing through any exit node (clears the exit-node setting). Use this instead of an
        /// empty `--exit-node`, which clap can't tell apart from the flag being unset. Mutually
        /// exclusive with `--exit-node`.
        #[arg(long)]
        clear_exit_node: bool,
        /// Offer this node to the tailnet as an exit node (other nodes may route their traffic
        /// through it). Mutually exclusive with `--no-advertise-exit-node`; omitting both leaves the
        /// persisted setting unchanged.
        #[arg(long, conflicts_with = "no_advertise_exit_node")]
        advertise_exit_node: bool,
        /// Stop offering this node as an exit node. Mutually exclusive with
        /// `--advertise-exit-node`; omitting both leaves the persisted setting unchanged.
        #[arg(long)]
        no_advertise_exit_node: bool,
        /// Advertise these subnet routes (comma-separated CIDRs, e.g.
        /// `192.168.1.0/24,10.0.0.0/8`) so other tailnet nodes can reach those subnets through this
        /// node. Replaces the whole advertised set. Use `--clear-advertise-routes` to advertise
        /// none; passing neither leaves the persisted set unchanged.
        #[arg(long, value_name = "CIDR,...", value_delimiter = ',')]
        advertise_routes: Vec<String>,
        /// Stop advertising any subnet routes (clears the advertised set). Use this instead of an
        /// empty `--advertise-routes`, since clap can't distinguish "advertise none" from the flag
        /// being unset.
        // `--clear-advertise-routes` is the canonical spelling (consistent with `--clear-exit-node`);
        // `--advertise-routes-clear` is kept as an alias for backward-compatibility.
        #[arg(long = "clear-advertise-routes", alias = "advertise-routes-clear")]
        advertise_routes_clear: bool,
        /// Advertise these ACL tags (comma-separated `tag:<name>`, e.g. `tag:server,tag:ci`) at
        /// registration (Go `--advertise-tags`). Replaces the whole set. Use `--clear-advertise-tags`
        /// to request none; passing neither leaves the persisted set unchanged.
        #[arg(long, value_name = "tag:NAME,...", value_delimiter = ',')]
        advertise_tags: Vec<String>,
        /// Stop advertising any ACL tags (clears the set). Use this instead of an empty
        /// `--advertise-tags`, since clap can't distinguish "request none" from the flag being unset.
        #[arg(long = "clear-advertise-tags")]
        advertise_tags_clear: bool,
        /// Accept (and route to) subnet routes advertised by peers (Go `tailscale up
        /// --accept-routes`). Mutually exclusive with `--no-accept-routes`; omitting both leaves the
        /// persisted setting unchanged.
        #[arg(long, conflicts_with = "no_accept_routes")]
        accept_routes: bool,
        /// Stop accepting subnet routes advertised by peers. Mutually exclusive with
        /// `--accept-routes`; omitting both leaves the persisted setting unchanged.
        #[arg(long)]
        no_accept_routes: bool,
        /// Accept the tailnet's MagicDNS configuration (Go `tailscale up --accept-dns`; on by
        /// default). Mutually exclusive with `--no-accept-dns`; omitting both leaves the persisted
        /// setting unchanged.
        #[arg(long, conflicts_with = "no_accept_dns")]
        accept_dns: bool,
        /// Ignore the tailnet's MagicDNS configuration (keep the system resolver). Mutually exclusive
        /// with `--accept-dns`; omitting both leaves the persisted setting unchanged.
        #[arg(long)]
        no_accept_dns: bool,
        /// Block incoming connections from other nodes (Go `tailscale up --shields-up`). Mutually
        /// exclusive with `--no-shields-up`; omitting both leaves the persisted setting unchanged.
        #[arg(long, conflicts_with = "no_shields_up")]
        shields_up: bool,
        /// Allow incoming connections from other nodes (default). Mutually exclusive with
        /// `--shields-up`; omitting both leaves the persisted setting unchanged.
        #[arg(long)]
        no_shields_up: bool,
        /// Run the Tailscale SSH server on this node (accept tailnet SSH on port 22, authorized by
        /// the control SSH policy). Requires a daemon built with the `ssh` feature and run as root.
        /// Mutually exclusive with `--no-ssh`; omitting both leaves the setting unchanged.
        #[arg(long, conflicts_with = "no_ssh")]
        ssh: bool,
        /// Stop running the Tailscale SSH server on this node. Mutually exclusive with `--ssh`;
        /// omitting both leaves the setting unchanged.
        #[arg(long)]
        no_ssh: bool,
        /// Unix username allowed to operate this daemon without sudo (Go `tailscale up --operator`).
        /// Pass an EMPTY value (`--operator=`) to remove the operator, exactly as Go does; omitting
        /// the flag leaves the setting unchanged. NOTE: this daemon only RECORDS the operator today —
        /// LocalAPI writes are still gated purely on the peer UID (root or the daemon's owner;
        /// THREAT_MODEL §4.1), so naming an operator grants that user nothing yet.
        #[arg(long, value_name = "USER")]
        operator: Option<String>,
        /// Let peers using this node as their exit node also reach this node's local LAN (Go
        /// `tailscale up --exit-node-allow-lan-access`). Mutually exclusive with
        /// `--no-exit-node-allow-lan-access`; omitting both leaves the setting unchanged. NOTE: this
        /// is an OS-router route-shaping pref; it is recorded but has no effect in this build's
        /// userspace-netstack data path (Go documents the same no-op on router-less platforms).
        #[arg(long, conflicts_with = "no_exit_node_allow_lan_access")]
        exit_node_allow_lan_access: bool,
        /// Stop allowing exit-node clients to reach this node's local LAN. Mutually exclusive with
        /// `--exit-node-allow-lan-access`; omitting both leaves the setting unchanged.
        #[arg(long)]
        no_exit_node_allow_lan_access: bool,
        /// Advertise this node as an app connector (Go `tailscale up --advertise-connector`). This
        /// reaches the control plane (`Hostinfo.AppConnector`) at registration and on every map
        /// poll. It advertises the ROLE only — this build implements no app-connector data path, so
        /// the node serves no connector traffic. Mutually exclusive with `--no-advertise-connector`;
        /// omitting both leaves the setting unchanged.
        #[arg(long, conflicts_with = "no_advertise_connector")]
        advertise_connector: bool,
        /// Stop advertising this node as an app connector. Mutually exclusive with
        /// `--advertise-connector`; omitting both leaves the setting unchanged.
        #[arg(long)]
        no_advertise_connector: bool,
        /// Allow the management plane to gather device-posture information (Go `tailscale up
        /// --report-posture`). Recorded only: posture is a control-to-node pull this build does not
        /// answer, so control never collects anything. Mutually exclusive with
        /// `--no-report-posture`; omitting both leaves the setting unchanged.
        #[arg(long, conflicts_with = "no_report_posture")]
        report_posture: bool,
        /// Stop allowing device-posture collection. Mutually exclusive with `--report-posture`;
        /// omitting both leaves the setting unchanged.
        #[arg(long)]
        no_report_posture: bool,
        /// Reset every setting this command does not mention back to its default (Go `tailscale up
        /// --reset`). By default `tnet up` refuses to silently revert a non-default setting you did
        /// not re-mention (it tells you to re-state it or pass `--reset`); `--reset` is how you opt
        /// into "anything I didn't mention goes back to default". This is the only form of `up` that
        /// is a true wholesale replace rather than a patch of just the flags you passed.
        #[arg(long)]
        reset: bool,
        /// Force re-authentication: discard this node's key and register fresh, surfacing a new login
        /// URL (Go `tailscale up --force-reauth`). WARNING: this may bring the Tailscale connection
        /// down while it re-registers, so do NOT run it remotely over SSH/RDP — you may lock yourself
        /// out. It changes no settings (your prefs are kept); it only forces a new login.
        #[arg(long)]
        force_reauth: bool,
        /// Register as an ephemeral node: control garbage-collects it shortly after it disconnects
        /// (Go `tailscale up --ephemeral`). Useful for short-lived CI jobs / containers. WARNING: an
        /// ephemeral node will NOT rejoin after a reboot without a fresh auth key (control will have
        /// GC'd it). Mutually exclusive with `--no-ephemeral`; omitting both leaves the setting
        /// unchanged. The default for a fresh node is PERSISTENT (survives reboots).
        #[arg(long, conflicts_with = "no_ephemeral")]
        ephemeral: bool,
        /// Register as a persistent node (the default): keeps its registration across reboots and
        /// resumes from its key alone. Mutually exclusive with `--ephemeral`; omitting both leaves the
        /// setting unchanged.
        #[arg(long)]
        no_ephemeral: bool,
        /// Wait up to this many seconds for the node to reach the Running state after bringing it up,
        /// then exit (Go `tailscale up --timeout`). On timeout, exits non-zero. Omitted = don't wait
        /// (return as soon as the daemon accepts the up); `0` = wait forever. Handy in scripts as
        /// `tnet up --authkey <KEY> --timeout 30 && start-my-service`. For an interactive (no-authkey)
        /// up the login URL is printed first, then the wait runs — so a short timeout may elapse
        /// before a human authorizes. NOTE: this takes integer SECONDS (`--timeout 30`); Go's flag is
        /// a duration string (`30s`), so a duration suffix is not accepted here.
        #[arg(long, value_name = "SECONDS")]
        timeout: Option<u64>,
        /// Pre-accept a named risk and skip its safety refusal (Go `--accept-risk`). Currently the one
        /// enforced risk is `lose-ssh`: `--force-reauth` over a Tailscale SSH session can drop that
        /// very session (it re-registers the node), so it is refused unless you pass
        /// `--accept-risk=lose-ssh` (or `--accept-risk=all`). Unlike Go's interactive y/N prompt, this
        /// daemon CLI refuses non-interactively — pass the flag to override.
        #[arg(long, value_name = "RISK")]
        accept_risk: Option<String>,
        /// OAuth client ID for generating an auth key via workload-identity federation (Go
        /// `tailscale up --client-id`). Used with `--client-secret`, or with `--id-token`/`--audience`
        /// for the OIDC-exchange path. Registration-time only — NOT a stored pref. Requires a daemon
        /// built with the `identity-federation` feature.
        #[arg(long, value_name = "ID")]
        client_id: Option<String>,
        /// OAuth client secret for generating an auth key (Go `tailscale up --client-secret`). If the
        /// value begins with `file:`, the rest is a path to a file containing the secret (avoids
        /// argv/shell-history exposure — preferred for the bare value, which IS visible in `ps`).
        /// Registration-time only — NOT a stored pref. Requires the `identity-federation` daemon
        /// feature. Held in memory as a zeroizing secret and never logged.
        #[arg(long, value_name = "SECRET|file:PATH")]
        client_secret: Option<String>,
        /// IdP-issued OIDC ID token to exchange with control for an auth key via workload-identity
        /// federation (Go `tailscale up --id-token`). `file:PATH` reads it from a file. Used with
        /// `--client-id`; mutually exclusive with `--audience`. Registration-time only — NOT a stored
        /// pref. Requires the `identity-federation` daemon feature. Treated as a secret (bearer token).
        #[arg(long, value_name = "TOKEN|file:PATH")]
        id_token: Option<String>,
        /// Audience for requesting an OIDC ID token from the ambient workload identity (GitHub
        /// Actions / GCP / AWS), to exchange for an auth key (Go `tailscale up --audience`). Used with
        /// `--client-id`; mutually exclusive with `--id-token`. Registration-time only — NOT a stored
        /// pref. Requires the `identity-federation` daemon feature.
        #[arg(long, value_name = "AUDIENCE")]
        audience: Option<String>,
        /// Emit machine-readable JSON instead of the human-readable output (Go `tailscale up
        /// --json`). WARNING: the format is subject to change — Go labels it the same way, so do not
        /// treat the shape as a stable interface. With `--json`, every human line (the `ok:` line, the
        /// "To authenticate…" auth-URL block, the timeout/revert-guide text) is suppressed and the only
        /// thing written is one JSON object: `{AuthURL, BackendState, Error}`, with empty fields
        /// omitted (matching Go's `,omitempty`). NOTE: this fork emits NO `QR` field — Go gates QR
        /// behind a build tag (`HasQRCodes`) and a QR encoder, which this fork does not carry; the
        /// omission is the same honest reduced scope as a Go build without `HasQRCodes` (the field is
        /// simply absent), not a stub.
        #[arg(long)]
        json: bool,
        /// Install host routes to other Tailscale nodes (Go `up --host-routes`, hidden there too).
        /// Accepted and inert: Go has required this to be `true` since Tailscale 1.67, and this
        /// build's userspace netstack installs no host routes at all, so the only value Go allows is
        /// the state this daemon is always in. `--host-routes=false` is refused with Go's own
        /// message — see [`check_ported_up_flags`].
        //
        // Go types it as a `notFalseVar`, a bool flag whose `Set` accepts only "true". `num_args =
        // 0..=1` + `require_equals` reproduces that shape: bare `--host-routes` is the flag's
        // presence (Go's `IsBoolFlag`, which never consumes the next argument), and a value can only
        // arrive as `--host-routes=<v>`, which is the only form Go's flag package passes to `Set`.
        #[arg(
            long,
            hide = true,
            num_args = 0..=1,
            require_equals = true,
            default_missing_value = "true",
            value_name = "true"
        )]
        host_routes: Option<String>,
        /// NOT a `tnet up` flag, carried only so a ported command line reaches a refusal that names
        /// where profile naming lives (`tnet set --nickname`) instead of clap's "unexpected
        /// argument". Go does not register `--nickname` on `up` either — `up.go`'s shared flag set
        /// gates it on `cmd == "login"` — so `up` is not the place this fork is missing it.
        /// See [`check_ported_up_flags`].
        #[arg(long, hide = true, value_name = "NAME")]
        nickname: Option<String>,
    },
    /// Tweak individual prefs on an already-configured node, without an up/down cycle (the analogue
    /// of Go's `tailscale set`). This never (re)authenticates and never changes whether the node is
    /// up — it only patches the prefs you name and reconciles the running engine. The exit-node
    /// change applies live (no reconnect); the others take effect on a running device or persist for
    /// the next `up` if the node is down. Omitting a flag leaves that pref unchanged; pass no flags
    /// and the daemon reports "no preferences specified".
    Set {
        /// Requested hostname. Omit to leave the persisted hostname unchanged.
        #[arg(long)]
        hostname: Option<String>,
        /// Accept (and route to) subnet routes advertised by peers. Mutually exclusive with
        /// `--no-accept-routes`; omitting both leaves the persisted setting unchanged.
        #[arg(long, conflicts_with = "no_accept_routes")]
        accept_routes: bool,
        /// Stop accepting subnet routes advertised by peers. Mutually exclusive with
        /// `--accept-routes`; omitting both leaves the persisted setting unchanged.
        #[arg(long)]
        no_accept_routes: bool,
        /// Accept the tailnet's MagicDNS configuration (Go `tailscale set --accept-dns`). Mutually
        /// exclusive with `--no-accept-dns`; omitting both leaves the persisted setting unchanged.
        #[arg(long, conflicts_with = "no_accept_dns")]
        accept_dns: bool,
        /// Ignore the tailnet's MagicDNS configuration (keep the system resolver). Mutually exclusive
        /// with `--accept-dns`; omitting both leaves the persisted setting unchanged.
        #[arg(long)]
        no_accept_dns: bool,
        /// Block incoming connections from other nodes. Mutually exclusive with `--no-shields-up`;
        /// omitting both leaves the persisted setting unchanged.
        #[arg(long, conflicts_with = "no_shields_up")]
        shields_up: bool,
        /// Allow incoming connections from other nodes (default). Mutually exclusive with
        /// `--shields-up`; omitting both leaves the persisted setting unchanged.
        #[arg(long)]
        no_shields_up: bool,
        /// Route this node's outbound traffic through a peer exit node, named by its tailnet IP or
        /// MagicDNS name (e.g. `100.64.0.9` or `exit-1`). Applied live on a running node — no
        /// reconnect. Mutually exclusive with `--clear-exit-node`; omitting both leaves the persisted
        /// exit-node setting unchanged.
        #[arg(long, value_name = "IP|NAME", conflicts_with = "clear_exit_node")]
        exit_node: Option<String>,
        /// Stop routing through any exit node (clears the exit-node setting). Use this instead of an
        /// empty `--exit-node`, which clap can't tell apart from the flag being unset. Mutually
        /// exclusive with `--exit-node`.
        #[arg(long)]
        clear_exit_node: bool,
        /// Offer this node to the tailnet as an exit node (other nodes may route their traffic
        /// through it). Mutually exclusive with `--no-advertise-exit-node`; omitting both leaves the
        /// persisted setting unchanged.
        #[arg(long, conflicts_with = "no_advertise_exit_node")]
        advertise_exit_node: bool,
        /// Stop offering this node as an exit node. Mutually exclusive with
        /// `--advertise-exit-node`; omitting both leaves the persisted setting unchanged.
        #[arg(long)]
        no_advertise_exit_node: bool,
        /// Advertise these subnet routes (comma-separated CIDRs, e.g.
        /// `192.168.1.0/24,10.0.0.0/8`) so other tailnet nodes can reach those subnets through this
        /// node. Replaces the whole advertised set. Use `--clear-advertise-routes` to advertise
        /// none; passing neither leaves the persisted set unchanged.
        #[arg(long, value_name = "CIDR,...", value_delimiter = ',')]
        advertise_routes: Vec<String>,
        /// Stop advertising any subnet routes (clears the advertised set). Use this instead of an
        /// empty `--advertise-routes`, since clap can't distinguish "advertise none" from the flag
        /// being unset.
        // `--clear-advertise-routes` is the canonical spelling (consistent with `--clear-exit-node`);
        // `--advertise-routes-clear` is kept as an alias for backward-compatibility.
        #[arg(long = "clear-advertise-routes", alias = "advertise-routes-clear")]
        advertise_routes_clear: bool,
        /// Advertise these ACL tags (comma-separated `tag:<name>`, e.g. `tag:server,tag:ci`) at
        /// registration (Go `--advertise-tags`). Replaces the whole set. Use `--clear-advertise-tags`
        /// to request none; passing neither leaves the persisted set unchanged.
        #[arg(long, value_name = "tag:NAME,...", value_delimiter = ',')]
        advertise_tags: Vec<String>,
        /// Stop advertising any ACL tags (clears the set). Use this instead of an empty
        /// `--advertise-tags`, since clap can't distinguish "request none" from the flag being unset.
        #[arg(long = "clear-advertise-tags")]
        advertise_tags_clear: bool,
        /// Run the Tailscale SSH server on this node (accept tailnet SSH on port 22, authorized by
        /// the control SSH policy). Requires a daemon built with the `ssh` feature and run as root.
        /// Mutually exclusive with `--no-ssh`; omitting both leaves the setting unchanged.
        #[arg(long, conflicts_with = "no_ssh")]
        ssh: bool,
        /// Stop running the Tailscale SSH server on this node. Mutually exclusive with `--ssh`;
        /// omitting both leaves the setting unchanged.
        #[arg(long)]
        no_ssh: bool,
        /// Advertise this node as an app connector (Go `tailscale set --advertise-connector`). This
        /// reaches the control plane (`Hostinfo.AppConnector`), which is a construction-time engine
        /// setting — so on a RUNNING node this rebuilds the device (a brief reconnect). It advertises
        /// the ROLE only; this build implements no app-connector data path. Mutually exclusive with
        /// `--no-advertise-connector`; omitting both leaves the setting unchanged.
        #[arg(long, conflicts_with = "no_advertise_connector")]
        advertise_connector: bool,
        /// Stop advertising this node as an app connector. Mutually exclusive with
        /// `--advertise-connector`; omitting both leaves the setting unchanged.
        #[arg(long)]
        no_advertise_connector: bool,
        /// Tell the admin console this node accepts remote update triggers (Go `tailscale set
        /// --auto-update`). This reaches control (`Hostinfo.AllowsUpdate`), so on a RUNNING node it
        /// rebuilds the device (a brief reconnect). It advertises the opt-in ONLY: this daemon runs
        /// no background updater — `tnet update` is manual — so nothing here acts on a trigger.
        /// Mutually exclusive with `--no-auto-update`; omitting both leaves the setting unchanged.
        #[arg(long, conflicts_with = "no_auto_update")]
        auto_update: bool,
        /// Decline admin-console-triggered auto-updates. Distinct from never having stated a
        /// preference (Go's `opt.Bool` tri-state). Mutually exclusive with `--auto-update`; omitting
        /// both leaves the setting unchanged.
        #[arg(long)]
        no_auto_update: bool,
        /// Enable background checks for available updates (Go `tailscale set --update-check`; on by
        /// default). Recorded only: this daemon runs no background check loop — use `tnet update`.
        /// Mutually exclusive with `--no-update-check`; omitting both leaves the setting unchanged.
        #[arg(long, conflicts_with = "no_update_check")]
        update_check: bool,
        /// Disable background update checks. Mutually exclusive with `--update-check`; omitting both
        /// leaves the setting unchanged.
        #[arg(long)]
        no_update_check: bool,
        /// Unix username allowed to operate this daemon without sudo (Go `tailscale set
        /// --operator`). Pass an EMPTY value (`--operator=`) to remove the operator, as Go does;
        /// omitting the flag leaves the setting unchanged. NOTE: only RECORDED today — LocalAPI
        /// writes are still gated purely on the peer UID (root or the daemon's owner; THREAT_MODEL
        /// §4.1), so naming an operator grants that user nothing yet.
        #[arg(long, value_name = "USER")]
        operator: Option<String>,
        /// Nickname for this login profile (Go `tailscale set --nickname` / `Prefs.ProfileName`).
        /// Pass an EMPTY value (`--nickname=`) to clear it; omitting the flag leaves it unchanged.
        /// Client-local — never advertised to control — but not cosmetic: as in Go it RENAMES the
        /// current login profile, so this is the name `tnet switch --list` shows and the one
        /// `tnet switch <name>` resolves against. (Distinct from `--hostname`, which is the name
        /// this node REQUESTS from the tailnet.)
        #[arg(long, value_name = "NAME")]
        nickname: Option<String>,
        /// Allow the management plane to gather device-posture information (Go `tailscale set
        /// --report-posture`). Recorded only: posture is a control-to-node pull this build does not
        /// answer. Mutually exclusive with `--no-report-posture`; omitting both leaves it unchanged.
        #[arg(long, conflicts_with = "no_report_posture")]
        report_posture: bool,
        /// Stop allowing device-posture collection. Mutually exclusive with `--report-posture`;
        /// omitting both leaves the setting unchanged.
        #[arg(long)]
        no_report_posture: bool,
        /// Run the local web management client (Go `tailscale set --webclient`, served on port 5252).
        /// Recorded only: this build ships no web client, so nothing is served. Mutually exclusive
        /// with `--no-webclient`; omitting both leaves the setting unchanged.
        #[arg(long, conflicts_with = "no_webclient")]
        webclient: bool,
        /// Do not run the local web management client. Mutually exclusive with `--webclient`;
        /// omitting both leaves the setting unchanged.
        #[arg(long)]
        no_webclient: bool,
        /// Let peers using this node as their exit node also reach this node's local LAN (Go
        /// `tailscale set --exit-node-allow-lan-access`). Recorded only: an OS-router route-shaping
        /// pref with no effect on this build's userspace-netstack data path. Mutually exclusive with
        /// `--no-exit-node-allow-lan-access`; omitting both leaves the setting unchanged.
        #[arg(long, conflicts_with = "no_exit_node_allow_lan_access")]
        exit_node_allow_lan_access: bool,
        /// Stop allowing exit-node clients to reach this node's local LAN. Mutually exclusive with
        /// `--exit-node-allow-lan-access`; omitting both leaves the setting unchanged.
        #[arg(long)]
        no_exit_node_allow_lan_access: bool,
        /// PARTLY SUPPORTED (Go `--relay-server-port`): the UDP port a peer-relay server binds on
        /// all interfaces (`0` = pick a random unused port), or an EMPTY value
        /// (`--relay-server-port=`) to disable relay-server functionality. This build runs no peer
        /// relay, so only the empty (disable) value is honoured — it asks for the state this daemon
        /// is always in. A port is parsed exactly as Go parses it and then REFUSED by name: see
        /// [`check_unmodelled_set_flags`] and engine ask #34.
        #[arg(long, value_name = "PORT")]
        relay_server_port: Option<String>,
        /// PARTLY SUPPORTED (Go `--relay-server-static-endpoints`): static `IP:port` endpoints to
        /// advertise as candidates for relay connections (comma-separated, e.g.
        /// `[2001:db8::1]:40000,192.0.2.1:40000`), or an EMPTY value to advertise none. As with
        /// `--relay-server-port`, only the empty (advertise-none) value is honoured; a list is
        /// parsed as Go parses it and then REFUSED by name.
        #[arg(long, value_name = "IP:PORT,...")]
        relay_server_static_endpoints: Option<String>,
        /// NOT SUPPORTED by this build, by choice (Go `--remote-config`): delegate FULL remote
        /// control of this node's prefs and LocalAPI to the tailnet admin, bypassing Tailscale's
        /// per-feature double opt-in. Refused by name — this fork's authorization model is local
        /// (THREAT_MODEL §4.1) and the control plane is not trusted to rewrite prefs or drive the
        /// LocalAPI. `--no-remote-config` (Go's default) is what this build always does.
        //
        // `hide` mirrors Go, which registers both this and `--sync` with its `hidden` prefix — a
        // faithful port keeps them off `--help` and lets the refusal do the explaining.
        #[arg(long, hide = true, conflicts_with = "no_remote_config")]
        remote_config: bool,
        /// Do not delegate remote control of this node to the tailnet admin (Go
        /// `--remote-config=false`). Accepted: it is what this build always does.
        #[arg(long, hide = true)]
        no_remote_config: bool,
        /// Actively sync configuration from the control plane (Go `--sync`, default true). Accepted:
        /// it is what this build always does while up.
        #[arg(long, hide = true, conflicts_with = "no_sync")]
        sync: bool,
        /// NOT SUPPORTED by this build (Go `--sync=false`): stop syncing configuration from the
        /// control plane, Go's kill switch for exercising netmap caching and offline operation.
        /// Refused by name — the pinned engine offers no way to stop the map poll while staying up
        /// (engine ask #34).
        #[arg(long, hide = true)]
        no_sync: bool,
        /// Pre-accept a named risk and skip its safety refusal (Go `--accept-risk`), e.g. `lose-ssh`
        /// or `all`. On `set` the enforced risk is `lose-ssh`: toggling the Tailscale SSH server
        /// (`--ssh`/`--no-ssh`) over a Tailscale SSH session reroutes/drops that session, so it is
        /// refused unless you pass `--accept-risk=lose-ssh`.
        #[arg(long, value_name = "RISK")]
        accept_risk: Option<String>,
    },
    /// Disconnect the node without logging out.
    Down,
    /// Log out: deregister this node from the control plane and discard its node key, so the next
    /// `up` registers as a fresh login (requires a new auth key / interactive login). Unlike `down`,
    /// which keeps the registration for a seamless reconnect, `logout` ends it. Mirrors Go
    /// `tailscale logout`.
    Logout {
        /// Why this node is being logged out (Go `tailscale logout --reason`), for a fleet where a
        /// policy asks the operator to justify a disconnect. The text is sent to the daemon, which
        /// records it in its log alongside the logout.
        ///
        /// HONEST SCOPE: in Go the reason is what unlocks a logout on a node whose MDM policy
        /// requires a justification, and it lands in the node's audit log. This fork registers no
        /// policy store on Unix (`tnet syspolicy list` shows why) and the engine has no audit-log
        /// transport to control, so nothing *requires* a reason here and the reason is not forwarded
        /// to the control plane — it is recorded locally. The flag exists so the operator's habit and
        /// the tooling that types it keep working against this daemon.
        #[arg(long, value_name = "TEXT")]
        reason: Option<String>,
    },
    /// Re-read the daemon's `--config` file and adopt the changed settings into the running node. The
    /// operator-facing form of Go `tailscaled`'s internal `reload-config` (which Go also triggers on
    /// SIGHUP): edit the declarative config the daemon was started with, then run this to apply the
    /// changes WITHOUT restarting. The settings merge over the current prefs (an unset config field is
    /// left as-is); if the node is up, the engine is rebuilt from the updated settings (a brief
    /// reconnect). Requires the daemon to have been started with `--config` (errors otherwise), and a
    /// now-malformed config is rejected with the running node left untouched. A reloaded config's auth
    /// key is ignored (a reload is not a re-login).
    ReloadConfig,
    /// Authenticate this node with the control plane (Go `tailscale login`). With no `--authkey`, this
    /// is an **interactive login**: the node contacts control, reaches `NeedsLogin`, and the auth URL
    /// is printed for you to open in a browser; the node finishes connecting once you authorize it.
    /// With `--authkey`/`--authkey-file` (or `$TS_AUTH_KEY`) it registers non-interactively. Like Go's
    /// `login`, this re-authenticates **without changing any prefs** — it is `up`'s auth half on its
    /// own (use `tnet up <flags>` to also change settings). Brings the node up (sets want-running).
    Login {
        /// Pre-auth key for non-interactive login. Prefer `--authkey-file` or `$TS_AUTH_KEY` (a bare
        /// `--authkey` is visible in `ps`/shell history). Precedence: `--authkey-file` > `--authkey` >
        /// `$TS_AUTH_KEY`. With none of them, the login is interactive (an auth URL is printed).
        #[arg(long, conflicts_with = "authkey_file")]
        authkey: Option<String>,
        /// Read the pre-auth key from a file (avoids argv/shell-history exposure). Takes precedence
        /// over `--authkey`.
        #[arg(long, value_name = "PATH")]
        authkey_file: Option<PathBuf>,
        /// Control server URL to log in against (Go `--login-server`), e.g. a self-hosted Headscale.
        /// Changing the control server is itself a fresh registration, which is exactly what `login`
        /// does, so unlike `up` this needs no `--force-reauth`.
        #[arg(long, value_name = "URL")]
        login_server: Option<String>,
    },
    /// Switch between profiles (separate accounts/tailnets), or list/remove them. Mirrors Go
    /// `tailscale switch`. Each profile keeps its own prefs + node key; switching tears down the
    /// current connection and activates the target (run `tnet up` to connect it).
    Switch {
        /// List known profiles (with a `*` marking the current one) instead of switching.
        #[arg(long)]
        list: bool,
        /// With `--list`, emit the profiles as a JSON array (Go `tailscale switch --list --json`):
        /// one object per profile with `id`, `nickname`, and `selected`. (Go also carries `tailnet`
        /// and `account` per profile; this fork's engine does not surface those per-profile, so they
        /// are emitted as `null` — an honest reduction, not a fake value. See bead tsd-91w.)
        ///
        /// Only valid with `--list`: without it, this refuses like Go does — see
        /// [`switch_usage_refusal`]. The check is deliberately NOT a clap `requires = "list"`, so the
        /// message and the exit code are Go's rather than clap's.
        #[arg(long)]
        json: bool,
        /// The profile id to switch to (omit with `--list`). Ignored when `--list` is given.
        #[arg(value_name = "PROFILE")]
        target: Option<String>,
        #[command(subcommand)]
        cmd: Option<SwitchCmd>,
    },
    /// Print the version of this client (and, with `--daemon`, the running daemon). Mirrors Go
    /// `tailscale version`.
    Version {
        /// Also query and print the running daemon's version (Go `--daemon`). Without it, `version`
        /// answers purely locally and never contacts the daemon.
        #[arg(long)]
        daemon: bool,
        /// Output as JSON, in the shape of Go's `version.Meta`: `majorMinorPatch`/`short`/`long`/`cap`
        /// always, plus `unstableBranch` (when the minor is odd) and `daemonLong` (with `--daemon`).
        /// Git-stamp fields (`gitCommit`/`gitDirty`/…) are honestly omitted — the fork is not
        /// git-stamped. Mirrors Go `--json`.
        #[arg(long)]
        json: bool,
        /// Check for a newer upstream release (Go `--upstream`). This build does not fetch from any
        /// release server, so it returns "fetching latest version not supported in this build" and
        /// exits non-zero — faithful to Go's behavior when upstream-checking is unavailable.
        #[arg(long)]
        upstream: bool,
        /// Which release track `--upstream` should check: `stable`, `release-candidate` or
        /// `unstable` (Go `version --track`; empty means "same as the running version").
        ///
        /// Consulted ONLY by `--upstream`. Go reads it inside its upstream branch, after the
        /// "not supported in this build" check — so in a build without an upstream fetcher (Go's
        /// and this one alike) the flag is accepted and changes nothing. It is here so a script
        /// written against Go's `version` flags parses. For this fork's own working release check,
        /// which really does select a track, use `tnet update --check --track <stable|unstable>`.
        #[arg(long, value_name = "TRACK")]
        track: Option<String>,
    },
    /// Show current preference values (Go `tailscale get`). With no setting name, shows all prefs;
    /// with a name (e.g. `accept-routes`), shows just that one. Setting names match the `tnet set`
    /// flags.
    Get {
        /// A single setting to show (e.g. `accept-routes`, `exit-node`, `ssh`); omit (or `all`) to
        /// show every setting.
        #[arg(value_name = "SETTING")]
        setting: Option<String>,
        /// Output as JSON (a flattened `{ "setting-name": value }` map, matching Go `get --json`).
        #[arg(long, conflicts_with = "set_flags")]
        json: bool,
        /// Output every setting as a single re-appliable `tnet set …` flag-argument line (Go
        /// `get --set-flags`), e.g. `--accept-routes=true --hostname=node-a …`. Mutually exclusive
        /// with `--json`; a single-`SETTING` query is ignored for this mode (it emits all flags).
        #[arg(long)]
        set_flags: bool,
    },
    /// Show daemon and netmap status.
    Status {
        /// Stream status continuously, re-printing on every state transition, until interrupted
        /// (Ctrl-C). Like `tailscale status --watch`.
        #[arg(long)]
        watch: bool,
        /// Output as JSON, in the shape of Go's `ipnstate.Status` (a faithful subset). Mirrors
        /// `tailscale status --json`.
        #[arg(long)]
        json: bool,
        /// Show only active peers (Go `--active`). NOTE: Go's "active" means recent traffic; this
        /// fork has no per-peer traffic signal, so it approximates it with the peer's *online*
        /// (control-plane-connected) state — peers with unknown liveness are hidden.
        #[arg(long)]
        active: bool,
        /// Hide the peer list (Go `--peers=false`). Use `--no-peers`.
        #[arg(long = "no-peers")]
        no_peers: bool,
        /// Hide this node's own line/object (Go `--self=false`). Use `--no-self`.
        #[arg(long = "no-self")]
        no_self: bool,
        /// Serve an HTML status page from an embedded web server instead of printing (Go `tailscale
        /// status --web`). Runs until interrupted (Ctrl-C); each page load reflects the live status.
        /// Mutually exclusive with `--json`/`--watch`.
        #[arg(long, conflicts_with_all = ["json", "watch"])]
        web: bool,
        /// In `--web` mode, the address to listen on (Go `--listen`, default `127.0.0.1:8384`; use a
        /// `:0` port for an automatic free port). Ignored without `--web`.
        #[arg(long, value_name = "ADDR")]
        listen: Option<String>,
        /// In `--web` mode, do NOT open a browser at the served URL (Go's `--browser=false`; the
        /// browser opens by default). Ignored without `--web`.
        #[arg(long)]
        no_browser: bool,
        /// Go's spelling of the same switch: `--browser=false` suppresses the browser, `--browser`
        /// (or `--browser=true`) is the default. Accepted so a command line written for Go's
        /// `status` works here unchanged; mutually exclusive with `--no-browser`, which is this
        /// fork's spelling of `--browser=false`. Ignored without `--web`, like Go's.
        #[arg(
            long,
            value_name = "BOOL",
            num_args = 0..=1,
            default_missing_value = "true",
            conflicts_with = "no_browser"
        )]
        browser: Option<bool>,
    },
    /// Block until the node is connected (state `Running` with a tailnet IP), then exit 0. Mirrors
    /// Go `tailscale wait` — handy in scripts as `tnet wait && start-my-service`.
    Wait {
        /// How long to wait, in seconds, before giving up (omitted / `0` = wait forever). On
        /// timeout, exits non-zero.
        #[arg(long, value_name = "SECONDS")]
        timeout: Option<u64>,
    },
    /// Show the machine + user identity of THIS node (Go `tailscale whoami`): equivalent to
    /// `tnet whois` against the node's own tailnet IP.
    Whoami {
        /// Output as JSON (the whois record for this node).
        #[arg(long)]
        json: bool,
    },
    /// Show tailnet IP addresses — this node's by default, or a peer's (or a Tailscale Service's)
    /// if named. Mirrors Go `tailscale ip`.
    Ip {
        /// Show only the IPv4 address (Go `-4`). Mutually exclusive with `-6` and `-1`.
        #[arg(short = '4')]
        v4: bool,
        /// Show only the IPv6 address (Go `-6`). Mutually exclusive with `-4` and `-1`.
        #[arg(short = '6')]
        v6: bool,
        /// Show only the first/primary address (Go `-1`). Mutually exclusive with `-4` and `-6`:
        /// `-1` names the first address of the node's whole list, not the first of a family.
        /// All three are refused together by [`ip_usage_refusal`] rather than by clap, so one
        /// upstream check keeps one message.
        #[arg(short = '1')]
        first: bool,
        /// A peer (by MagicDNS name or IP) whose address to show instead of this node's. Resolved
        /// against the current netmap (the peer set `status` reports). An address that matches no
        /// peer is then matched against the VIPs of the Tailscale Services this node can reach, and
        /// that Service's addresses are printed instead (Go's Service fallback) — `tnet service
        /// list` shows them.
        #[arg(value_name = "PEER")]
        peer: Option<String>,
        /// Assert that one of the node's IPs matches this address (Go `tailscale ip --assert`).
        /// Prints nothing and exits 0 on a match; exits 1 if the node does not hold it. For scripts
        /// that want to verify the expected tailnet IP. Mutually exclusive with a peer argument.
        #[arg(long, value_name = "IP", conflicts_with = "peer")]
        assert: Option<String>,
    },
    /// Show which tailnet node owns an address (Go `tailscale whois [--json] ip[:port]`).
    Whois {
        /// The address to resolve to its owning node: a tailnet IP, or Go's `ip[:port]` flow form
        /// (`100.64.0.9:22`, `[fd7a::1]:22`). The port names a flow; see `--proto`.
        //
        // Collected as a list, not a single value, so the arity refusals are Go's own words rather
        // than clap's: `whois_target` turns zero or two-plus arguments into the upstream messages.
        // (A `//` comment, not a doc comment — this is why the type is a `Vec`, not something the
        // `--help` reader needs.)
        #[arg(value_name = "IP[:PORT]")]
        target: Vec<String>,
        /// Protocol of the flow to look up: `tcp` or `udp`; omitted means both (Go
        /// `tailscale whois --proto`).
        ///
        /// HONEST SCOPE: accepted and carried to the daemon, but it cannot change the answer on this
        /// build. Go consults `--proto` (and the port) only for flows tailscaled itself proxies —
        /// its `ProxyMapper` fallback, reached when the address matches no node in the netmap — and
        /// for a tailnet address, the only kind this fork resolves, Go answers by IP and ignores the
        /// protocol too. The pinned engine keeps no proxied-flow table (engine ask #35), so a
        /// proxied `127.0.0.1:port` flow that Go would attribute to a peer is reported here as
        /// owned by no node, with or without this flag.
        #[arg(long, value_name = "PROTO")]
        proto: Option<String>,
        /// Emit the result as JSON (Go `tailscale whois --json`) — the raw `WhoisReport` object, for
        /// scripting, instead of the human table.
        #[arg(long)]
        json: bool,
    },
    /// Fetch an OIDC id-token for this node, scoped to an audience (Go `tailscale id-token <aud>`).
    /// Control mints a signed JWT identifying this machine; prints the raw token. Requires the node
    /// to be up and a control server new enough to issue id-tokens.
    #[command(name = "id-token")]
    IdToken {
        /// The OIDC audience (the token's `aud` claim) — typically the URL/identifier of the service
        /// that will verify the token.
        #[arg(value_name = "AUDIENCE")]
        audience: String,
    },
    /// Ping a tailnet peer over the overlay and report the round-trip time (Go `tailscale ping`).
    ///
    /// By default this stops after 10 pings OR as soon as a **direct** (non-DERP) path is
    /// established, whichever comes first — matching Go. Each result line reports the path the pong
    /// took: `via <ip:port>` for a direct connection, `via DERP` when the overlay is still relayed.
    Ping {
        /// The tailnet IP of the peer to ping.
        #[arg(value_name = "IP")]
        ip: String,
        /// Per-attempt timeout in milliseconds (omit for a sensible default).
        #[arg(long, value_name = "MS")]
        timeout: Option<u64>,
        /// Max number of pings to send (Go `-c`). Default 10; `0` means infinity (ping until a direct
        /// path is established, or forever if `--no-until-direct`). Prints one result line per
        /// attempt, then a summary; a failed attempt is counted but does not abort the rest.
        #[arg(short = 'c', long, value_name = "N", default_value_t = 10)]
        count: u32,
        /// Stop once a direct (non-DERP) path is established (Go `--until-direct`, **on by default**).
        /// A new node usually starts out DERP-relayed and upgrades to a direct path within a few
        /// pings; with this on, `ping` returns as soon as that happens. Mutually exclusive with
        /// `--no-until-direct`.
        #[arg(long, conflicts_with = "no_until_direct")]
        until_direct: bool,
        /// Keep pinging for the full count even after a direct path is established (disables the
        /// default `--until-direct` early stop). Mutually exclusive with `--until-direct`.
        #[arg(long)]
        no_until_direct: bool,
    },
    /// Send and receive files over Taildrop (Go `tailscale file`).
    File {
        #[command(subcommand)]
        cmd: FileCmd,
    },
    /// Print this node's client metrics in Prometheus text format (Go `tailscale metrics`). With
    /// `write <path>`, writes them to a file instead of stdout.
    Metrics {
        #[command(subcommand)]
        cmd: Option<MetricsCmd>,
    },
    /// Print open-source license information (Go `tailscale licenses`). Local-only — contacts no
    /// daemon. This fork's own license + where to find the dependency licenses.
    Licenses,
    /// Serve a local web UI showing this node's status (Go `tailscale web`). Runs an HTTP server
    /// until interrupted (Ctrl-C); each page load reflects the live status. Bound to localhost by
    /// default (`--listen localhost:8088`, matching Go), so it is not reachable from the network.
    ///
    /// READ-ONLY: this serves the status view only. Go's `web` can switch to a *management* mode that
    /// edits prefs (a React SPA served over the tailnet behind an owner/session/control-approval auth
    /// stack); this fork does not yet ship that mutating UI (tracked separately) — to change settings,
    /// use `tnet up`/`tnet set`. (`tnet status --web` serves the same page; `web` is the Go-named
    /// command with Go's flags.)
    Web {
        /// Listen address (Go `web --listen`; default `localhost:8088`). Use `:0` for an OS-assigned
        /// port. Binding beyond localhost exposes this node's status (name, tailnet IPs, peers) with
        /// NO authentication — a warning is printed if you do.
        #[arg(long, value_name = "ADDR")]
        listen: Option<String>,
        /// Run the UI in read-only mode (Go `web --readonly`). This build's web UI is ALWAYS read-only
        /// (no mutating manage mode yet), so this flag is accepted for Go compatibility and is a no-op.
        #[arg(long)]
        readonly: bool,
        /// URL path prefix the UI is served under (Go `web --prefix`), for use behind a reverse proxy
        /// (e.g. `/tailscale`). Default: served at `/`.
        #[arg(long, value_name = "PREFIX")]
        prefix: Option<String>,
        /// Do not open a browser window after starting (the server still runs). Without this, a
        /// browser is opened to the served URL (best-effort). Ignored with `--cgi`, which never
        /// opens a browser (there is no long-lived server to browse to).
        #[arg(long)]
        no_browser: bool,
        /// Run as a CGI script (Go `web --cgi`) instead of binding a listener: serve exactly ONE
        /// request from the CGI/1.1 environment (`REQUEST_METHOD`, `REQUEST_URI` or
        /// `SCRIPT_NAME`+`PATH_INFO`), write the response to stdout, and exit. This is the mode a
        /// web server invokes the binary in per request, so nothing else may be written to stdout —
        /// the startup line and the browser launch are both suppressed. `--listen` is meaningless
        /// here (no listener is bound) and is refused alongside it.
        #[arg(long)]
        cgi: bool,
        /// Absolute URL the UI is actually reached at (Go `web --origin`), when that is not the
        /// address it bound — behind a reverse proxy, or under `--cgi`, where nothing is bound at
        /// all. `--prefix` fixes the path the server answers on; only this fixes the scheme and
        /// host. Must be an absolute `http`/`https` URL with a host and no query/fragment/userinfo
        /// (e.g. `https://ts.example.com/tailscale`). Used for link generation only: the URL this
        /// command reports and opens, and the `<link rel="canonical">` the served page states for
        /// itself. This build's UI is read-only, so the origin gates nothing else.
        #[arg(long, value_name = "URL")]
        origin: Option<String>,
    },
    /// Check for (and optionally install) a newer release of this client (Go `tailscale update`).
    /// Queries the project's GitHub Releases for the latest version and compares it to the running
    /// version. By DEFAULT (or with `--check`/`--dry-run`) it only REPORTS current-vs-latest and does
    /// nothing else — the same as Go's `--dry-run`. Pass `--yes` to actually download the matching
    /// release tarball, verify its published SHA-256 sidecar, and replace this binary in place.
    ///
    /// SECURITY: the SHA-256 sidecar is an INTEGRITY check (detects a corrupted/truncated download),
    /// NOT an authenticity check — this fork publishes no cryptographic signatures yet, so a
    /// `--yes` self-install trusts GitHub Releases as the source of truth. `update` says so before
    /// installing.
    ///
    /// A binary a package manager owns is never replaced in place: on a Homebrew install (the
    /// `packaging/homebrew` formula), `--yes` refuses and names `brew upgrade` instead, the way Go
    /// refuses a binary update for a `pkg`-installed client.
    Update {
        /// Only report whether a newer version is available (current vs latest); never install.
        /// Equivalent to Go `tailscale update --dry-run`. This is also the default when neither
        /// `--check` nor `--yes` is given.
        #[arg(long)]
        check: bool,
        /// Alias for `--check` (Go's flag name): report only, do not install.
        #[arg(long)]
        dry_run: bool,
        /// Actually download + verify + install the update (Go `--yes`: no interactive prompt). This
        /// fork never prompts, so an install requires `--yes` explicitly.
        #[arg(long)]
        yes: bool,
        /// Update/downgrade to an explicit version (e.g. `0.42.0` or `v0.42.0`) instead of the latest
        /// (Go `--version`). Mutually exclusive with `--track`.
        #[arg(long, value_name = "VERSION", conflicts_with = "track")]
        version: Option<String>,
        /// Which release track to consider: `stable` (default — only non-prerelease releases) or
        /// `unstable` (include prereleases). Go `--track`.
        #[arg(long, value_name = "TRACK")]
        track: Option<String>,
    },
    /// Tailnet Lock (TKA) commands. The read-only pair mirrors Go `tailscale lock status` (whether
    /// lock is in use, the authority head, any pending disablement) and Go `tailscale lock log` (the
    /// update-chain history, newest first); `init`/`sign`/`disable` mutate the lock and
    /// `disablement-kdf` is a pure-local derivation.
    Lock {
        #[command(subcommand)]
        cmd: LockCmd,
    },
    /// DNS commands. Currently `status` (read-only): the control-pushed MagicDNS configuration —
    /// MagicDNS on/off, resolvers in preference order, split-DNS routes, search/cert domains, extra
    /// records, and exit-node-filtered suffixes. Mirrors Go `tailscale dns status`.
    Dns {
        #[command(subcommand)]
        cmd: DnsCmd,
    },
    /// Show this node's network-conditions report (Go `tailscale netcheck`): the nearest (preferred)
    /// DERP region and the per-region DERP latency, lowest first. NOTE: this build's net-report
    /// measures DERP-region latency ONLY — Go's UDP/IPv4/IPv6/MappingVariesByDestIP/PortMapping flags
    /// are not measured, and DERP regions are shown by id (the engine carries no region name).
    Netcheck {
        /// Output as JSON (back-compat alias for `--format json`). Prefer `--format`.
        #[arg(long, conflicts_with = "format")]
        json: bool,
        /// Output format (Go `tailscale netcheck --format`): empty = human-readable, `json` =
        /// pretty/tab-indented JSON, `json-line` = a single compact JSON line (one report per line,
        /// handy with `--every`). NOTE: the JSON shape is a reduced fork shape (DERP-region latency
        /// only — see the report doc) and is not a stable interface, matching Go's own caveat.
        #[arg(long, value_name = "FMT", value_parser = ["json", "json-line"])]
        format: Option<String>,
        /// If set, repeat the report every N SECONDS (Go `tailscale netcheck --every <dur>`; this fork
        /// takes whole seconds rather than a Go-duration string, to avoid a duration-parser dep). Each
        /// report is separated by a blank line (human) or printed one-per-line (`--format json-line`).
        /// Runs until interrupted (Ctrl-C). Omit for a single report.
        #[arg(long, value_name = "SECONDS")]
        every: Option<u64>,
        /// Log how long each report took, to stderr (Go `tailscale netcheck --verbose`).
        ///
        /// PARTIAL: Go's `--verbose` turns on logging in TWO places — the CLI's own
        /// `GetReport took <d>; err=<e>` line, and the probe-by-probe chatter of the netcheck client
        /// it runs in-process. Here the measurement happens in the daemon's engine, not in this
        /// process, so only the timing line is available; the probe log is engine-side (it would need
        /// the engine to stream its net-report log over the LocalAPI).
        #[arg(long)]
        verbose: bool,
    },
    /// Exit-node commands. `list` shows tailnet peers offering to be exit nodes. Mirrors Go
    /// `tailscale exit-node`.
    #[command(name = "exit-node")]
    ExitNode {
        #[command(subcommand)]
        cmd: ExitNodeCmd,
    },
    /// Diagnose the system policy / MDM configuration (Go `tailscale syspolicy`). `list` prints the
    /// effective policy; `reload` forces a re-read first. On Linux/Unix no policy store is registered
    /// (Tailscale reads MDM policy only on Windows), so both normally print "No policy settings" —
    /// this is the faithful, accurate result, not a stub.
    Syspolicy {
        #[command(subcommand)]
        cmd: SyspolicyCmd,
    },
    /// Print a shareable diagnostic marker for bug reports (Go `tailscale bugreport`). NOTE: this
    /// fork uploads no logs — the marker is a LOCAL identifier (id + daemon version + state) to quote
    /// when reporting an issue, not a server-retrievable log id.
    Bugreport {
        /// An optional note (Go `bugreport [note]`) appended to the marker — e.g. a short description
        /// of what went wrong. Control characters are stripped so the marker stays one clean token.
        #[arg(value_name = "NOTE")]
        note: Option<String>,
    },
    /// Provision a TLS certificate + key for a tailnet domain via ACME (Go `tailscale cert`). The
    /// domain must be one of your tailnet's cert domains (`tnet dns status` lists them). Requires a
    /// daemon built with the `acme` feature; without it the command fails with a clear error rather
    /// than emitting a self-signed cert. By default writes `DOMAIN.crt` + `DOMAIN.key` in the current
    /// directory; override the paths with `--cert-file`/`--key-file`, or pass `-` for either to write
    /// that PEM to stdout instead.
    Cert {
        /// The DNS name to certify (one of the tailnet's cert domains).
        #[arg(value_name = "DOMAIN")]
        domain: String,
        /// Output path for the cert (leaf + chain) PEM, or `-` for stdout. Defaults to `DOMAIN.crt`
        /// when neither `--cert-file` nor `--key-file` is given.
        #[arg(long, value_name = "PATH")]
        cert_file: Option<String>,
        /// Output path for the private-key PEM, or `-` for stdout. Defaults to `DOMAIN.key` when
        /// neither `--cert-file` nor `--key-file` is given. Written with `0600` permissions.
        #[arg(long, value_name = "PATH")]
        key_file: Option<String>,
        /// The least remaining lifetime the returned certificate must have, as a Go duration
        /// (`720h`, `30m`, `1h30m`) — Go `tailscale cert --min-validity`. Unset (or `0`) means no
        /// minimum, Go's default.
        ///
        /// HONEST SCOPE: in Go this renews a *cached* certificate that has less than this much life
        /// left. This fork's engine keeps no cert cache — every `cert` issues fresh — so a
        /// full-lifetime certificate always satisfies the minimum and the flag changes nothing
        /// today. It is carried all the way to the engine (not swallowed by the CLI) so an
        /// engine-side cache would honor it without a CLI change. Go additionally accepts a NEGATIVE
        /// duration, where it has no effect; this refuses one rather than pretending to carry it.
        #[arg(long, value_name = "DURATION", value_parser = parse_min_validity)]
        min_validity: Option<std::time::Duration>,
        /// Instead of writing the cert to disk, serve HTTPS with it until interrupted (Ctrl-C), as a
        /// demo that the certificate works (Go `tailscale cert --serve-demo`). Every request gets a
        /// short "it works" page. `--cert-file`/`--key-file` are ignored in this mode — nothing is
        /// written — exactly as in Go.
        ///
        /// GRAMMAR NOTE: Go's `--serve-demo` needs no domain (its daemon hands it a certificate per
        /// SNI name as connections arrive) and takes the listen address as the positional argument.
        /// This fork's LocalAPI has no per-SNI certificate hook, so the domain positional is still
        /// required — it names the one certificate this server presents — and the listen address is
        /// `--listen`.
        #[arg(long)]
        serve_demo: bool,
        /// Address for `--serve-demo` to listen on (Go's positional argument, same default `:443`,
        /// which needs root). A bare `:PORT` binds every IPv4 interface; write `[::]:PORT` for IPv6
        /// or `127.0.0.1:PORT` to keep the demo on this host. Only valid with `--serve-demo`.
        #[arg(long, value_name = "ADDR")]
        listen: Option<String>,
    },
    /// Connect to a TCP port on a tailnet host and pipe stdin/stdout over the overlay (Go `tailscale
    /// nc`). Like netcat: bytes from stdin go to the peer, the peer's bytes go to stdout, until EOF.
    Nc {
        /// Destination host: a tailnet IP or MagicDNS name.
        #[arg(value_name = "HOST")]
        host: String,
        /// Destination TCP port.
        #[arg(value_name = "PORT")]
        port: u16,
    },
    /// SSH to a tailnet machine (Go `tailscale ssh [user@]<host> [args...]`). Resolves the peer
    /// against the current netmap, writes a `ssh_known_hosts` file pinned from the peer's advertised
    /// SSH host keys, and execs the system `ssh` with `StrictHostKeyChecking=yes` + a `ProxyCommand`
    /// that tunnels the connection over the tailnet via `tnet nc` — so `ssh` verifies the host key
    /// from the netmap (no TOFU prompt, no MITM window) and reaches the peer without a TUN/route.
    /// Requires the system `ssh` binary on `PATH`. Any trailing args are passed through to `ssh`.
    Ssh {
        /// Target as `[user@]host`. `host` is a peer's MagicDNS name (or bare hostname) or tailnet IP;
        /// omitting `user@` passes the bare host to `ssh`, so your own `ssh_config` `User` directive
        /// decides the login name (Go's behavior).
        #[arg(value_name = "[USER@]HOST")]
        target: String,
        /// Extra arguments passed verbatim to the system `ssh` after the destination (e.g. a remote
        /// command, or `ssh` flags). Everything here goes to `ssh`, not to `tnet`.
        #[arg(
            value_name = "SSH_ARGS",
            trailing_var_arg = true,
            allow_hyphen_values = true
        )]
        args: Vec<String>,
    },
    /// Expose a local service on the tailnet (Go `tailscale serve`), in either of two grammars.
    ///
    /// The Go v1.100.0 FLAG grammar (`cmd/tailscale/cli/serve_v2.go`) — `tnet serve [flags]
    /// <target> [off]`, where the listener is named by exactly one of `--https=PORT` /
    /// `--http=PORT` / `--tcp=PORT` / `--tls-terminated-tcp=PORT` (none given = `--https=443`,
    /// Go's default). A scripted `tailscale serve` invocation ports over unchanged.
    ///
    /// The fork's positional SUB-VERBS (`serve tcp|https|http|redirect <port> <target>`) — kept as
    /// a documented superset. `redirect` exists only here: Go's CLI has no redirect verb at
    /// v1.100.0, though the engine serves one.
    ///
    /// `serve status`/`serve reset` work under both. Like Go, a flag-grammar serve runs in the
    /// FOREGROUND by default and undoes itself on Ctrl-C; pass `--bg` to persist it and exit.
    ///
    /// DEVIATIONS from Go, each of which fails loudly rather than silently doing nothing:
    /// `--service`, `--tun`, `--accept-app-caps` and `--proxy-protocol` are parsed (so the error
    /// names the gap instead of clap rejecting an "unexpected argument") but refused — see the
    /// per-flag help. Go's foreground serve is torn down by the DAEMON when the CLI's IPN-bus
    /// session drops; this build restores the previous config from the CLI's own signal handler, so
    /// a `SIGKILL`ed foreground `tnet serve` leaves its config behind (use `serve reset`).
    #[command(args_conflicts_with_subcommands = true)]
    Serve {
        /// `status`/`reset`, or one of the fork's positional sub-verbs.
        #[command(subcommand)]
        cmd: Option<ServeCmd>,
        #[command(flatten)]
        flags: ServeFlags,
    },
    /// Expose a tailnet port to the PUBLIC internet via Tailscale Funnel (Go `tailscale funnel`).
    /// Takes the same flag grammar as `serve` (`tnet funnel [flags] <target> [off]`), plus
    /// `funnel status`/`funnel reset` and the legacy `funnel <port> on|off` toggle this fork
    /// shipped first. A funnel needs a serve to expose: the flag grammar configures both in one
    /// call, while `funnel <port> on` only flips the switch and warns when the port has no proxy
    /// backend yet.
    ///
    /// The node must have Funnel enabled for the tailnet (the `https` + `funnel` node attributes)
    /// and the port must be Funnel-allowed; the public ingress path needs a real Tailscale SaaS
    /// tailnet (a self-hosted control plane has no ingress relay). Turning a funnel off leaves the
    /// underlying serve in place — use `serve --https=PORT off` (or `serve reset`) to remove that.
    #[command(args_conflicts_with_subcommands = true)]
    Funnel {
        /// `status` or `reset` (both are Go aliases for their `serve` counterparts).
        #[command(subcommand)]
        cmd: Option<FunnelCmd>,
        #[command(flatten)]
        flags: ServeFlags,
    },
    /// Interact with Tailscale Services (Go `tailscale service`).
    ///
    /// A Tailscale Service is a virtual service with its own IP addresses; which Services this node
    /// can reach is decided by the tailnet's ACLs. `list` shows the ones currently available here.
    ///
    /// This is the READ half of Services. Hosting one (`serve --service=svc:<name>`) still needs a
    /// `Services` map in the LocalAPI `ServeConfig` this build does not carry, and is refused by
    /// name rather than silently ignored — see `tnet serve --help`.
    Service {
        #[command(subcommand)]
        cmd: ServiceCmd,
    },
    /// Debugging tools (Go `tailscale debug`).
    Debug {
        #[command(subcommand)]
        cmd: DebugCmd,
    },
    /// Host-specific setup glue (Go `tailscale configure`). Three sub-targets: `kubeconfig`, which
    /// writes a kubectl config pointed at a Kubernetes API server fronted by a Tailscale auth-proxy
    /// peer, plus the two macOS ones — `sysext` and `mac-vpn` — which refuse, exactly as Go's
    /// open-source CLI does, because the system extension and the VPN profile belong to the GUI
    /// client this fork does not ship.
    ///
    /// Go's other `configure` sub-targets are host-integration commands for products this fork does
    /// not build, and are OUT OF SCOPE rather than unfinished: `synology`, `synology-cert` and the
    /// hidden `configure-host` alias (DSM package plumbing — Go registers all three only on a
    /// Synology), `jetkvm` (a JetKVM boot script that starts Go's `tailscaled`), and
    /// `flash-appliance` / `pve-appliance` (they download and flash Tailscale's signed appliance
    /// image). The ruling, command by command, is in `docs/CONFIGURE_SCOPE.md`.
    Configure {
        #[command(subcommand)]
        cmd: ConfigureCmd,
    },
    /// Install tailnetd as a system service (systemd/launchd) that starts at boot. Requires root.
    Install,
    /// Remove the tailnetd system service. Requires root; leaves node state.
    Uninstall,
}

/// `tnet configure` subcommands (Go `tailscale configure`). `kubeconfig` is ported; `sysext` and
/// `mac-vpn` are Go's macOS-only pair, ported as the refusals Go's own CLI-only build serves. Go's
/// remaining sub-targets (`synology`, `synology-cert`, `configure-host`, `jetkvm`,
/// `flash-appliance`, `pve-appliance`) are ruled out of scope in `docs/CONFIGURE_SCOPE.md` — they
/// configure hosts around software this fork does not ship, so they are absent by decision, not by
/// omission.
#[derive(Subcommand)]
enum ConfigureCmd {
    /// [ALPHA] Generate a kubeconfig that reaches a Kubernetes cluster through a Tailscale auth-proxy
    /// peer (Go `tailscale configure kubeconfig <hostname-or-fqdn>`). The argument names the tailnet
    /// peer running the auth proxy in front of the cluster's API server — a bare hostname, its full
    /// MagicDNS name, or one of its tailnet IPs, optionally prefixed with `http://`/`https://`; it is
    /// resolved against the current netmap, and the resolved MagicDNS name becomes the cluster
    /// `server` URL and the context. The user entry is the shared `tailscale-auth` one Go writes,
    /// carrying the placeholder token Go uses: the proxy authenticates the caller by its tailnet
    /// identity, and the token only stops kubectl prompting for a username and password.
    ///
    /// Like Go, this MERGES into the kubeconfig kubectl already reads — `$KUBECONFIG` (first entry
    /// that exists), else `~/.kube/config` — adding or replacing just this peer's triple and leaving
    /// every other cluster, context and user in the file untouched, then making the new context
    /// current. The file is created (`0600`) if it does not exist, and a document that is not an
    /// `apiVersion: v1` / `kind: Config` kubeconfig is refused rather than overwritten.
    ///
    /// `--output` opts out of that: it writes a standalone kubeconfig and reads nothing. Point
    /// kubectl at the result (`--kubeconfig`), or stack it: `KUBECONFIG=~/.kube/config:<path>`.
    Kubeconfig {
        /// The auth-proxy peer: a bare hostname, a full MagicDNS name, or a tailnet IP.
        #[arg(value_name = "HOSTNAME_OR_FQDN")]
        host: String,
        /// Use HTTP instead of HTTPS to connect to the auth proxy. Ignored if you include a scheme
        /// in the hostname argument (Go `tailscale configure kubeconfig --http`).
        #[arg(long)]
        http: bool,
        /// Write a STANDALONE kubeconfig to PATH (mode `0600`) instead of merging into the
        /// kubeconfig kubectl reads. `-` means stdout. Refuses to overwrite an existing file unless
        /// `--force` is given — nothing is merged on this path, so a blind overwrite would silently
        /// drop every other cluster in that file.
        #[arg(long, short = 'o', value_name = "PATH")]
        output: Option<String>,
        /// Overwrite `--output PATH` if it already exists. DESTRUCTIVE: the file is replaced, not
        /// merged, so any other clusters/contexts it held are lost. Ignored without `--output`, where
        /// the existing kubeconfig is merged into and never replaced.
        #[arg(long)]
        force: bool,
    },
    /// Manage the macOS system extension (Go `tailscale configure sysext`, with the verbs
    /// `activate`/`deactivate`/`status`). Present so a command line copied from a macOS Tailscale
    /// install is answered rather than rejected at argument parsing — but every verb REFUSES, as a
    /// system extension is something only the signed GUI client can register. Go's open-source CLI
    /// refuses these the same way (`requiresStandalone`); only the Swift GUI build handles them.
    /// This fork ships no macOS app, no system extension, and runs its data plane in userspace
    /// networking, so there is nothing to activate, deactivate or report on — `tnet install` is the
    /// analogue.
    Sysext {
        /// `activate`, `deactivate` or `status`. Optional: the bare `configure sysext` refuses with
        /// the same message, as it does in Go.
        #[command(subcommand)]
        cmd: Option<SysextCmd>,
    },
    /// Manage the macOS VPN configuration — the entry in System Settings > VPN (Go `tailscale
    /// configure mac-vpn [install|uninstall]`). Refuses for the same reason as `sysext`: the profile
    /// is written by the macOS GUI client, which this fork is not, and Go's open-source CLI refuses
    /// it identically (`requiresGUI`). This fork installs no VPN profile on any platform; use
    /// `tnet install` to register the daemon as a system service.
    MacVpn {
        /// `install` or `uninstall`. Optional: the bare `configure mac-vpn` refuses with the same
        /// message, as it does in Go.
        #[command(subcommand)]
        cmd: Option<MacVpnCmd>,
    },
}

/// `tnet configure sysext` verbs (Go `tailscale configure sysext`). All three refuse; the verb is
/// carried only so the refusal can name the command the user actually typed.
#[derive(Subcommand, Debug, Clone, Copy, PartialEq, Eq)]
enum SysextCmd {
    /// Register the system extension with macOS (Go `configure sysext activate`).
    Activate,
    /// Deactivate the system extension (Go `configure sysext deactivate`).
    Deactivate,
    /// Print the extension's enablement status (Go `configure sysext status`).
    Status,
}

/// `tnet configure mac-vpn` verbs (Go `tailscale configure mac-vpn`). Both refuse; the verb is
/// carried only so the refusal can name the command the user actually typed.
#[derive(Subcommand, Debug, Clone, Copy, PartialEq, Eq)]
enum MacVpnCmd {
    /// Write the VPN configuration to the macOS settings (Go `configure mac-vpn install`).
    Install,
    /// Delete the VPN configuration from the macOS settings (Go `configure mac-vpn uninstall`).
    Uninstall,
}

/// `tnet debug` subcommands (Go `tailscale debug`).
#[derive(Subcommand)]
enum DebugCmd {
    /// Capture the dataplane's plaintext packets to a pcap file (Go `tailscale debug capture`). The
    /// file is a classic pcap (link-type USER0 + Tailscale's per-packet path preamble) — open it in
    /// Wireshark, with Tailscale's `ts-dissector.lua` for per-packet direction. Captures for
    /// `--seconds`, then stops.
    Capture {
        /// Local path to write the pcap to (a fresh path, or an existing regular file to overwrite).
        #[arg(value_name = "PATH")]
        path: PathBuf,
        /// How long to capture before stopping, in seconds.
        #[arg(long, default_value_t = 10)]
        seconds: u64,
    },
    /// Dump the node's current preferences as JSON (Go `tailscale debug prefs`). A read-only view of
    /// the persisted prefs — the same data `tnet get` renders, but as the raw pretty-printed object
    /// for scripting/debugging rather than the human/flag view.
    Prefs,
    /// Print this CLI process's Tailscale-relevant environment (Go `tailscale debug env`): the `TS_*`
    /// / `TAILNETD_*` env vars that influence the daemon + client (control URL, socket, state dir,
    /// log filter, the experiment gate) plus the build version. Purely local — reads the process
    /// environment, no daemon round-trip (matching Go, whose `debug env` dumps `os.Environ`-derived
    /// Tailscale settings). Values are printed verbatim; nothing is mutated.
    Env,
    /// Dump the node's client metrics in Prometheus text format (Go `tailscale debug metrics`). The
    /// same data as `tnet metrics`, exposed under `debug` for parity with Go's `debug metrics`
    /// alias. Requires the node to be up. Write-gated like `tnet metrics` (the metrics may carry
    /// operational detail — Go gates `serveMetrics` on PermitWrite).
    Metrics,
    /// Convert between a 4via6 IPv6 route and its `(site-id, IPv4-CIDR)` components (Go `tailscale
    /// debug via`). 4via6 lets several subnet routers advertise the *same* private IPv4 CIDR without
    /// collision by mapping each into a distinct IPv6 `via` route under `fd7a:115c:a1e0:b1a::/64`,
    /// keyed by a site id. Purely local bit-math — no daemon round-trip (matches Go).
    ///
    /// Two forms, exactly like Go:
    /// - `debug via <site-id> <ipv4-cidr>` → prints the encoded IPv6 `via` route, e.g.
    ///   `debug via 7 10.1.2.0/24` → `fd7a:115c:a1e0:b1a:0:7:a01:200/120`.
    /// - `debug via <ipv6-via-route>` → decodes it back to the site id and the IPv4 CIDR.
    Via {
        /// Either a decimal site id (then `cidr` is required) or, alone, an IPv6 `via` route to decode.
        #[arg(value_name = "SITE-ID|IPv6-ROUTE")]
        site_or_route: String,
        /// The IPv4 CIDR to encode (only with the two-argument site-id form).
        #[arg(value_name = "IPv4-CIDR")]
        cidr: Option<String>,
    },
    /// Force the daemon's engine to rebind its UDP sockets (Go `tailscale debug rebind`). A
    /// connectivity-recovery knob: re-creates magicsock's underlying sockets to clear a wedged NAT
    /// binding or recover after a network change, without restarting the node. Requires the node to
    /// be up. Write-gated (root/same-uid) — it mutates live datapath state.
    Rebind,
    /// Force the daemon's engine to re-run STUN now (Go `tailscale debug restun`), re-deriving this
    /// node's public/reflexive endpoint WITHOUT rebinding the socket. Strictly lighter than `rebind`
    /// (no socket churn, the NAT mapping is kept) — reach for it first when the public endpoint may
    /// have changed (e.g. a NAT rebinding) but the socket is otherwise fine, instead of waiting out
    /// the periodic prober. Requires the node to be up. Write-gated (root/same-uid).
    Restun,
    /// Check whether the OS forwards IP traffic — a subnet-router / exit-node readiness diagnostic (Go
    /// `check-ip-forwarding`, normally run internally by `up`/`set`). Prints a warning if forwarding
    /// is disabled, or nothing if it is fine. In netstack mode (the default) and on macOS this is a
    /// no-op (the kernel does not forward our traffic); on Linux with a kernel TUN it reads the
    /// forwarding sysctls.
    CheckIpForwarding,
    /// Validate a prospective prefs change WITHOUT applying it (Go `check-prefs`, normally the
    /// fail-fast pre-flight for `up`/`set`). Composes the named overrides over the current prefs and
    /// reports the first conflict (exit-node-vs-advertise, an unmasked advertised route, SSH without
    /// the build feature) — or confirms the prefs are valid. Mutates nothing.
    CheckPrefs {
        /// Prospective exit-node selector (IP / MagicDNS name / stable id). Omit to keep the current.
        #[arg(long, value_name = "NODE")]
        exit_node: Option<String>,
        /// Prospective advertise-exit-node intent.
        #[arg(long)]
        advertise_exit_node: Option<bool>,
        /// Prospective advertised subnet routes (CIDRs), comma-separated. Omit to keep the current.
        #[arg(long, value_name = "CIDR,CIDR", value_delimiter = ',')]
        advertise_routes: Option<Vec<String>>,
        /// Prospective SSH-server enable intent.
        #[arg(long)]
        ssh: Option<bool>,
    },
    /// Stream the daemon's IPN notification bus as JSON, one object per line (Go `tailscale debug
    /// watch-ipn-bus`). Subscribes to the **masked** `watch` path with both initial snapshots
    /// requested, so the first line is the current state + peer set and each subsequent line carries
    /// only what changed (state transitions, the full peer set on a netmap change, interactive-login /
    /// consent URLs). Read-only and long-lived — it runs until interrupted (Ctrl-C) or the daemon
    /// closes the stream (node torn down / shutdown). Distinct from `tnet status --watch`, which stays
    /// on the bare status-stream path.
    WatchIpn,
    /// Print how to reach the daemon's LocalAPI by hand (Go `tailscale debug local-creds`). Purely
    /// local — emits a ready-to-run `curl` command for the resolved LocalAPI socket; no daemon
    /// round-trip and nothing is mutated. On this fork the LocalAPI is a Unix-domain socket, so the
    /// output is the `curl --unix-socket <path> …` form (Go prints this same form for its Unix socket;
    /// its TCP-port+token form is Windows-only and does not apply here). Useful for poking the LocalAPI
    /// with raw HTTP while debugging.
    LocalCreds,
    /// Stat one or more files and print their mode + size, listing directory entries (Go `tailscale
    /// debug stat`). Purely local — a plain `lstat` of each path (symlinks are NOT followed, matching
    /// Go's `os.Lstat`), no daemon round-trip. For a directory, its entries are listed (capped at 25,
    /// like Go, then `...`). A path that cannot be stat-ed is reported inline and the rest continue.
    Stat {
        /// The files (or directories) to stat. Each is `lstat`-ed independently.
        #[arg(value_name = "FILE", required = true)]
        files: Vec<String>,
    },
    /// Print the state directory this CLI resolved, WHY it resolved there, and the socket derived
    /// from it (Go `tailscale debug statedir`). Purely local — it reports the paths the CLI would
    /// use; nothing is read from the daemon, created, or mutated.
    ///
    /// The state dir is chosen by a cascade (`$TAILNETD_STATE_DIR`, else the packaged system dir
    /// when running as root, else `$XDG_STATE_HOME`/`$HOME`), and the winning rule is invisible in
    /// the resulting path. That is exactly the shape of this fork's most common confusion: a root
    /// `tailnetd` and an unprivileged `tnet` resolve *different* dirs, hence different sockets, and
    /// the CLI just reports a missing socket. This prints the rule that won, so the split is one
    /// line to spot instead of a guess.
    Statedir,
    /// Resolve a hostname to its IP addresses, one per line (Go `tailscale debug resolve`). Purely
    /// local — a **host-resolver** lookup inside this CLI process (Go's `net.DefaultResolver`, i.e.
    /// `getaddrinfo` here), NOT a MagicDNS query through the daemon: no LocalAPI round-trip and no
    /// daemon state, so it answers with the node down. The lookup is bounded to 5 seconds (Go's
    /// `context.WithTimeout`), and a resolver failure is reported rather than swallowed into an
    /// empty result.
    Resolve {
        /// Which address family to resolve: `ip` (both, the default), `ip4` (IPv4 only) or `ip6`
        /// (IPv6 only). Deliberately a free-form string rather than a clap value-enum: Go passes
        /// this flag straight to `LookupIP`, so a bad value is refused by the *command* with
        /// `unknown network <net>` on stderr and exit 1 — not by the flag parser with a usage block
        /// and exit 2.
        #[arg(long, value_name = "ip|ip4|ip6", default_value = "ip")]
        net: String,
        /// The hostname (or IP literal) to resolve. Exactly one, and for the same reason it is
        /// collected as a list rather than a required single value: Go refuses any other count from
        /// inside the command, with `usage: tnet debug resolve <hostname>`.
        #[arg(value_name = "HOSTNAME")]
        hostname: Vec<String>,
    },
    /// Print this binary's build metadata as JSON (Go `tailscale debug go-buildinfo`, which dumps
    /// Go's `runtime/debug.BuildInfo`). Purely local — no daemon round-trip. Rust has no runtime
    /// build-info reflection, so the same facts are stamped in at compile time by `build.rs`: the
    /// package + version, the target triple and cargo profile, the `rustc` that built it, the git
    /// revision (and whether the tree was dirty), and the cargo features this build was compiled
    /// with. The intended use is Go's: paste it into a bug report so the exact binary is identified.
    ///
    /// Fields that could not be determined at build time (e.g. building from a release tarball with
    /// no `.git`, or with no `rustc` on PATH) are emitted as JSON `null` rather than a placeholder
    /// string — an honest "unknown", never a fabricated value.
    #[command(alias = "go-buildinfo")]
    BuildInfo,
}

/// `tnet serve` subcommands. Mirrors the TCP-forward subset of Go `tailscale serve`.
#[derive(Subcommand)]
enum ServeCmd {
    /// Forward a tailnet TCP port to a local address (Go `serve --tcp <port> <target>`). Inbound
    /// connections on tailnet `<PORT>` are spliced to `<TARGET>` (`host:port`, or a bare port meaning
    /// `127.0.0.1:<port>`).
    Tcp {
        /// The tailnet port to listen on.
        #[arg(value_name = "PORT")]
        port: u16,
        /// Local forward target: `host:port`, or a bare port for `127.0.0.1:<port>`.
        #[arg(value_name = "TARGET")]
        target: String,
    },
    /// Serve HTTPS on a tailnet port, reverse-proxying to a local backend (Go `serve --https`). The
    /// engine terminates TLS for this node's MagicDNS name and proxies each request to `<TARGET>`.
    /// Requires the daemon's `acme` feature + a Funnel/HTTPS-enabled SaaS tailnet to issue the cert;
    /// otherwise the engine fails closed (no plaintext) and `serve status` shows it as not yet active.
    Https {
        /// The tailnet port to terminate TLS on.
        #[arg(value_name = "PORT")]
        port: u16,
        /// What to serve: a proxy backend (`host:port`, or a bare port for `127.0.0.1:<port>`), or
        /// `text:<body>` to serve a fixed plaintext body (Go `serve` `text:` target).
        #[arg(value_name = "TARGET")]
        target: String,
        /// Mount the handler at this URL path prefix instead of `/` (Go `serve --set-path`). With
        /// multiple mounts on one port the longest-matching prefix wins (unmatched = 404).
        #[arg(long = "set-path", value_name = "MOUNT")]
        set_path: Option<String>,
    },
    /// Serve HTTP on a tailnet port, reverse-proxying to a local backend (Go `serve --http`). Like
    /// [`Https`](ServeCmd::Https) but records HTTP intent; the engine reverse-proxies via the same
    /// native serve path.
    Http {
        /// The tailnet port to serve on.
        #[arg(value_name = "PORT")]
        port: u16,
        /// What to serve: a proxy backend (`host:port`, or a bare port for `127.0.0.1:<port>`), or
        /// `text:<body>` to serve a fixed plaintext body.
        #[arg(value_name = "TARGET")]
        target: String,
        /// Mount the handler at this URL path prefix instead of `/` (Go `serve --set-path`).
        #[arg(long = "set-path", value_name = "MOUNT")]
        set_path: Option<String>,
    },
    /// Serve an HTTP redirect on a tailnet port (engine-backed extension — Go's CLI has no redirect
    /// path at v1.100.0, but the engine serves it). TLS-terminated like `https`.
    Redirect {
        /// The tailnet port to terminate TLS on and redirect from.
        #[arg(value_name = "PORT")]
        port: u16,
        /// The `Location:` target to redirect to. Sent verbatim — no variable expansion.
        ///
        /// The engine writes one fixed `Location:` header for every request on the port, so a
        /// `${HOST}` / `${REQUEST_URI}` placeholder would be sent to the client as those literal
        /// characters rather than expanded. Both are refused up front; write a literal URL.
        #[arg(value_name = "TO")]
        to: String,
        /// The redirect HTTP status (must be in 300..=399). Defaults to 302.
        #[arg(value_name = "STATUS", default_value_t = 302)]
        status: u16,
    },
    /// Show the current serve configuration.
    Status {
        /// Output as JSON (the raw ServeConfig).
        #[arg(long)]
        json: bool,
    },
    /// Clear the entire serve configuration.
    Reset,
}

/// `tnet funnel` subcommands. Go's `funnel status`/`funnel reset` are plain aliases for their
/// `serve` counterparts (one config backs both), and so are these.
#[derive(Subcommand)]
enum FunnelCmd {
    /// Show the current serve/funnel configuration (Go `funnel status`; same output as `serve
    /// status`, funnel section included).
    Status {
        /// Output as JSON (the raw ServeConfig).
        #[arg(long)]
        json: bool,
    },
    /// Clear the entire serve configuration, funnel included (Go `funnel reset`; identical to
    /// `serve reset` — one ServeConfig backs both).
    Reset,
}

/// The Go v1.100.0 `serve`/`funnel` flag grammar (`cmd/tailscale/cli/serve_v2.go`), shared verbatim
/// by both commands exactly as Go shares it: `tnet <serve|funnel> [flags] <target> [off]`.
///
/// Four of these flags are accepted by the parser but REFUSED at runtime
/// ([`check_serve_flags`]). That is deliberate: a script written against Go gets an error naming
/// the missing capability instead of clap's opaque "unexpected argument", and the grammar stays a
/// superset so the same command line keeps working the day the gap closes. Go's OWN refusals for
/// those flags come first, though, so a command line Go would have rejected is rejected here for
/// Go's reason and in Go's words — see [`check_serve_flags`].
#[derive(clap::Args, Debug, Default, Clone)]
struct ServeFlags {
    /// Persist the serve and exit, instead of holding it for the lifetime of this command. Go's
    /// `--bg`; like Go, the default is the FOREGROUND — the serve is installed, this process blocks,
    /// and the previous serve config is restored when you interrupt it (Ctrl-C / `SIGTERM`).
    ///
    /// Go's `bgBoolFlag` takes an optional value, so `--bg=false` is how a Go command line asks for
    /// the foreground explicitly; `require_equals` reproduces that, and leaves a following bare
    /// `false` in the target position exactly as Go's flag package does. `None` means "not given",
    /// which [`serve_background`] resolves Go's way.
    #[arg(long, num_args = 0..=1, default_missing_value = "true", require_equals = true)]
    bg: Option<bool>,
    /// Terminate TLS on this tailnet port and reverse-proxy to `<TARGET>` (Go `--https=PORT`). This
    /// is the default listener: with none of the four port flags given, `serve`/`funnel` act as
    /// `--https=443`, matching Go.
    ///
    /// Go counts a port flag as given only when it is NON-ZERO, so the exclusivity of the four is
    /// decided at runtime by [`serve_kind_and_port`], not by clap: `--https=0 --tcp=22` names one
    /// listener under Go, and a genuine pair still gets Go's `cannot serve multiple types for a
    /// single mount point`.
    #[arg(long, value_name = "PORT")]
    https: Option<u16>,
    /// Serve plain HTTP on this tailnet port, reverse-proxying to `<TARGET>` (Go `--http=PORT`).
    #[arg(long, value_name = "PORT")]
    http: Option<u16>,
    /// Forward raw TCP on this tailnet port to `<TARGET>` with no TLS (Go `--tcp=PORT`). Served by
    /// the daemon's own accept loop.
    #[arg(long, value_name = "PORT")]
    tcp: Option<u16>,
    /// Terminate TLS on this tailnet port with the node's cert, then splice the plaintext stream to
    /// `<TARGET>` as raw TCP (Go `--tls-terminated-tcp=PORT`) — no HTTP parsing or reverse-proxying.
    /// Needs an issuable cert, like `--https`.
    #[arg(long = "tls-terminated-tcp", value_name = "PORT")]
    tls_terminated_tcp: Option<u16>,
    /// Mount the handler at this URL path prefix instead of `/` (Go `--set-path`). HTTP(S) only;
    /// with several mounts on one port the longest-matching prefix wins (unmatched = 404).
    #[arg(long = "set-path", value_name = "MOUNT")]
    set_path: Option<String>,
    /// NOT SUPPORTED by this build (Go `--service=svc:<name>`): attach the serve to a Tailscale
    /// Service (VIP) rather than to this node. Refused rather than ignored — the LocalAPI
    /// `ServeConfig` here carries no `Services` map, and Services are a control-plane + netmap
    /// feature the pinned engine does not surface. Go's own two refusals for the flag (with
    /// `funnel`, and with a foreground serve) still come first, in Go's words.
    #[arg(long, value_name = "SERVICE")]
    service: Option<String>,
    /// NOT SUPPORTED by this build (Go `--tun`): serve on the kernel TUN interface instead of the
    /// userspace netstack. Refused rather than ignored — this daemon's serve lanes are netstack-only.
    ///
    /// Go models `--tun` as a fifth serve type ([`ServeKind::Tun`]), mutually exclusive with the
    /// four port flags and legal only alongside `--service`; since `--service` is refused here, the
    /// refusal a `tnet` command line actually reaches is Go's own `tun mode is only supported for
    /// services`.
    #[arg(long)]
    tun: bool,
    /// NOT SUPPORTED by this build (Go `--proxy-protocol=1|2`): prepend a PROXY-protocol header to
    /// each `--tls-terminated-tcp` connection. Refused rather than ignored — the engine's TCP serve
    /// target cannot emit the header, and the daemon already fails such a config closed rather than
    /// silently dropping it (which would hand the backend an unmarked, wrongly-attributed stream).
    ///
    /// Go's two conditional refusals run first (see [`check_serve_flags`]), so an HTTP(S) serve and
    /// a version that is neither 1 nor 2 are rejected for Go's reason. Typed wide like Go's `uint`
    /// so an out-of-range version reaches Go's message instead of clap's integer-range error; `0`
    /// means unset there, and here.
    #[arg(long = "proxy-protocol", value_name = "VERSION")]
    proxy_protocol: Option<u64>,
    /// NOT SUPPORTED by this build (Go `--accept-app-caps=<domain>/<name>,…`): forward the caller's
    /// app capabilities to the backend. Refused rather than ignored — the daemon's serve lanes add
    /// no such headers, so accepting the flag would promise an authorization signal that never
    /// arrives.
    ///
    /// It still takes Go's VALUE, a comma-separated capability list, and repeats accumulate the way
    /// Go's `acceptAppCapsFlag.Set` appends: a Go command line has to parse before it can be told
    /// what is missing, and a malformed list is refused with Go's own message
    /// ([`parse_accept_app_caps`]).
    #[arg(long = "accept-app-caps", value_name = "CAPS")]
    accept_app_caps: Vec<String>,
    /// Accepted and ignored (Go `--yes`): pre-approve Go's interactive funnel confirmation. This
    /// CLI never prompts, so the flag is a no-op kept so Go-shaped scripts run unedited.
    #[arg(long)]
    yes: bool,
    /// What to serve: a proxy backend (`host:port`, a bare port for `127.0.0.1:<port>`, or a
    /// `tcp://host:port` URL), or `text:<body>` for a fixed plaintext body on an HTTP(S) port. The
    /// literal `off` here removes the serve on the named port instead (Go `serve <target> off`).
    #[arg(value_name = "TARGET")]
    target: Option<String>,
    /// A trailing `off` (Go `serve --https=PORT <target> off`), which removes that port's serve. For
    /// `funnel` this position also takes the legacy `on`/`off` of `funnel <port> on|off`.
    #[arg(value_name = "OFF")]
    off: Option<String>,
}

/// `tnet metrics` subcommands. Bare `tnet metrics` prints to stdout; `print` is the explicit
/// stdout form (Go `tailscale metrics print`); `write <path>` writes a file.
#[derive(Subcommand)]
enum MetricsCmd {
    /// Print the metrics to stdout (Go `tailscale metrics print`) — the explicit form of bare
    /// `tnet metrics`.
    Print,
    /// Write the metrics to a file instead of stdout.
    Write {
        /// Destination path.
        #[arg(value_name = "PATH")]
        path: PathBuf,
    },
}

/// `tnet lock` subcommands.
#[derive(Subcommand)]
enum LockCmd {
    /// Initialize Tailnet Lock for this tailnet (Go `tailscale lock init`). The positional arguments
    /// are Go's, and mean what they mean in Go: the tailnet lock public keys (`tlpub:<hex>`,
    /// optionally `<key>?<votes>`) initially trusted to sign nodes, and/or pre-computed
    /// `disablement:<hex>` values. They are NOT a disablement secret — this command MINTS the
    /// disablement secrets itself (`--gen-disablements`, default 1) and prints them once, after
    /// which they cannot be shown again. Nothing happens without `--confirm`: without it the command
    /// prints what it would do and the exact command to re-run.
    ///
    /// What this daemon can initialize is NARROWER than Go, and the difference is refused by name
    /// rather than reinterpreted. The engine's `tka_init` takes no trusted-key set — it always
    /// initializes trusting this node's own tailnet lock key alone, with one vote — stores exactly
    /// one disablement value, which it derives itself from a secret, and exposes no way to read this
    /// node's lock key back. So `<trusted-key>` arguments, `disablement:` values,
    /// `--gen-disablement-for-support` and a `--gen-disablements` other than 1 are all refused
    /// naming what is missing (docs/ENGINE_ASKS.md #36). `tnet lock init --confirm`, with no
    /// positional arguments, is the whole of the supported subset: this node as the sole trusted
    /// key, one minted disablement secret, printed once.
    ///
    /// Also unlike Go: the engine transmits that one secret to the coordination server as the
    /// support disablement, which Go does only when asked with `--gen-disablement-for-support`.
    /// Submit-only either way — the lock takes effect on the next verified netmap sync.
    Init {
        /// The tailnet lock keys initially trusted to sign nodes (`tlpub:<hex>`, or `<key>?<votes>`
        /// to weight one), and/or pre-computed `disablement:<hex>` values — Go's positionals. This
        /// daemon can honour neither (see the command help): they are parsed with Go's grammar and
        /// then refused, never reinterpreted as something else.
        #[arg(value_name = "TRUSTED-KEY")]
        trusted_keys: Vec<String>,
        /// Number of disablement secrets to generate (Go `--gen-disablements`, default 1). Only the
        /// default can be initialized here — the engine stores exactly one disablement value.
        #[arg(long = "gen-disablements", value_name = "N")]
        gen_disablements: Option<usize>,
        /// Generate one ADDITIONAL disablement secret and transmit it to the coordination server so
        /// support can disable the lock (Go `--gen-disablement-for-support`). Refused here — see the
        /// command help.
        #[arg(long = "gen-disablement-for-support")]
        gen_disablement_for_support: bool,
        /// Do it (Go `--confirm`). Without this flag the command prints the keys it would trust, how
        /// many secrets it would mint, and the exact command to re-run — and changes nothing.
        #[arg(long)]
        confirm: bool,
        /// NOT a Go flag — an addition, and the only way to choose the secret yourself. Use this
        /// hex-encoded secret as the lock's single disablement secret instead of minting one. This
        /// is what `tnet lock init` used to take as its positional argument; it keeps working under
        /// a name that cannot be confused with Go's `<trusted-key>` positional.
        #[arg(long = "disablement-secret", value_name = "HEX-SECRET")]
        disablement_secret: Option<String>,
    },
    /// Show Tailnet Lock status (read-only).
    Status {
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },
    /// List the changes applied to Tailnet Lock — the update (AUM) chain, newest first (Go
    /// `tailscale lock log`). Read-only, and read *locally*: the entries come from the AUM chain this
    /// node has already synced and verified, so there is no control round-trip and the history stops
    /// at whatever this node has seen.
    Log {
        /// Maximum number of updates to list, counted back from the chain head (Go `--limit`, same
        /// default of 50).
        #[arg(long, value_name = "N", default_value_t = 50)]
        limit: usize,
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Co-sign a node key into Tailnet Lock so that node may join the locked tailnet (Go `tailscale
    /// lock sign <node-key>`). This node must itself be a trusted signing node under the current
    /// authority. Submits the signature to control; the local trusted-key state advances on the next
    /// verified netmap sync. Requires Tailnet Lock to be enabled (`tnet lock status`).
    Sign {
        /// The node key to sign, in the `nodekey:<hex>` form (as shown by `tnet status`/`whois`).
        #[arg(value_name = "NODE-KEY")]
        node_key: String,
    },
    /// Disable Tailnet Lock for the tailnet by presenting the disablement secret (Go `tailscale lock
    /// disable <secret>`). The secret is the operator-held capability minted when the lock was
    /// created; control verifies it against the authority's disablement set. IRREVERSIBLE for the
    /// tailnet — turns the lock off everywhere, not just this node.
    Disable {
        /// The disablement secret, hex-encoded (the value recorded when the lock was initialized).
        #[arg(value_name = "SECRET")]
        secret: String,
    },
    /// Derive the tailnet-lock disablement VALUE from a disablement SECRET (Go `tailscale lock
    /// disablement-kdf`). Pure local, offline compute — no daemon, no node needed. You run this BEFORE
    /// enabling lock to pre-compute the value(s) to embed in the authority, keeping the raw secret(s)
    /// offline; presenting the matching secret later (`lock disable`) turns the lock off. Prints
    /// `disablement:<hex>` exactly like Go. The KDF is Argon2i (NOT Argon2id) over the secret with
    /// Tailscale's fixed salt — byte-for-byte matching `tka.DisablementKDF`.
    #[command(name = "disablement-kdf")]
    DisablementKdf {
        /// The disablement secret, hex-encoded.
        #[arg(value_name = "HEX-SECRET")]
        secret: String,
    },
}

/// `tnet dns` subcommands: `status` (the control-pushed config) and `query` (resolve a name through
/// the node's own MagicDNS path).
#[derive(Subcommand)]
enum DnsCmd {
    /// Show the control-pushed MagicDNS configuration (read-only).
    Status {
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Resolve a name through the node's MagicDNS path (Go `tailscale dns query`), showing the RCODE,
    /// which upstream resolver(s) were consulted, and the raw response. Answers tailnet/MagicDNS
    /// names authoritatively and forwards the rest exactly as the node itself would — a faithful way
    /// to see what this node resolves, distinct from the host's system resolver.
    Query {
        /// The DNS name to resolve (e.g. `host.tailnet.ts.net` or `example.com`).
        #[arg(value_name = "NAME")]
        name: String,
        /// The query type: a name (`A`, `AAAA`, `CNAME`, `PTR`, `TXT`, `MX`, `NS`, `SRV`, `SOA`,
        /// `CAA`) or a numeric RFC 1035 TYPE. Defaults to `A`. (Go takes the same optional positional
        /// type.)
        #[arg(value_name = "TYPE", default_value = "A")]
        qtype: String,
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },
}

/// `tnet exit-node` subcommands.
#[derive(Subcommand)]
enum ExitNodeCmd {
    /// List tailnet peers offering to be exit nodes.
    List,
    /// Suggest the best available exit node (Go `tailscale exit-node suggest`). The daemon picks a
    /// candidate by DERP-region proximity / latency and prints its name plus the `tnet set
    /// --exit-node=<id>` command to engage it. Prints a clear notice when no candidate is available.
    Suggest,
}

/// `tnet syspolicy` subcommands (Go `tailscale syspolicy`). Both honor `--json`.
#[derive(Subcommand)]
enum SyspolicyCmd {
    /// Print the effective system policy (Go `tailscale syspolicy list`). On Linux/Unix no policy
    /// store is registered, so this normally prints "No policy settings".
    List {
        /// Output as JSON (the snapshot as `{"scope":..,"settings":[..]}`).
        #[arg(long)]
        json: bool,
    },
    /// Force a re-read of the system policy, then print it (Go `tailscale syspolicy reload`).
    /// Re-reads the external policy sources; mutates no node state. With no registered store the
    /// result matches `list`.
    Reload {
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },
}

/// `tnet service` subcommands (Go `tailscale service`). Go registers exactly one, `list`; its bare
/// parent prints help, which is clap's behaviour for a subcommand group too.
#[derive(Subcommand)]
enum ServiceCmd {
    /// List the Tailscale Services this node can access (Go `tailscale service list`).
    List {
        /// Output as JSON — Go's own array shape, one object per Service.
        #[arg(long)]
        json: bool,
    },
}

/// The `tnet switch` subcommands. Mirrors Go's `tailscale switch remove`.
#[derive(Subcommand)]
enum SwitchCmd {
    /// Remove a profile (delete its prefs + node key). The profile may be named by id or by display
    /// name, like `switch` itself; a name that matches no profile is refused (Go: `No profile named
    /// %q`) rather than reported as a removal. Naming the profile you are currently on removes
    /// nothing and succeeds, as in Go (`Already on account %q`, exit 0) — switch away first to
    /// remove it. The reserved `default` profile cannot be removed at all.
    Remove {
        /// The profile id (or display name) to remove.
        ///
        /// Required, so clap supplies the arity refusal Go hand-rolls as
        /// `usage: tailscale switch remove NAME`.
        #[arg(value_name = "PROFILE")]
        target: String,
    },
}

/// The `tnet file` subcommands (Taildrop). Mirrors Go's `tailscale file cp` / `file get`. Like
/// `Command`, this deliberately does not derive `Debug` (it travels alongside `Command` through the
/// same parse path; keeping the choice uniform avoids reintroducing a debug-print surface).
#[derive(Subcommand)]
enum FileCmd {
    /// Send local files to a tailnet peer via Taildrop (Go `tailscale file cp <files...> <target>:`).
    ///
    /// The final argument is the destination peer and MUST end in a colon (`peer-b:`,
    /// `100.64.0.9:`, or `[fd7a::1]:` for an IPv6 literal) — matching Go, which uses the trailing
    /// colon to disambiguate a peer from a file path. One or more files may precede it. With
    /// `--targets` (and no files/target), instead lists the peers you can send to.
    ///
    /// NOTE: unlike Go, this build does NOT support `-` (stdin) as a file — the daemon opens each
    /// path itself (tnet + tailnetd are same-host/same-user), so there is no stdin to hand it; pass a
    /// real file path. Streaming stdin over the LocalAPI is a tracked follow-up.
    Cp {
        /// The files to send, followed by the destination `<peer>:` (trailing colon required). Empty
        /// only when `--targets` is given. `-` (stdin) is not supported by this build.
        #[arg(value_name = "FILES... TARGET:")]
        args: Vec<String>,
        /// Destination filename override (Go `--name`): with a single explicit file, send it under
        /// this name instead of its base name. Cannot be combined with multiple files. (Go also uses
        /// `--name` to name stdin content, but this build does not support stdin.)
        #[arg(long, value_name = "NAME")]
        name: Option<String>,
        /// Instead of sending, list the tailnet peers you can Taildrop to (Go `file cp --targets` /
        /// the `file-targets` LocalAPI): one line per peer — its tailnet IP, name, and online status.
        #[arg(long)]
        targets: bool,
    },
    /// List files waiting in the Taildrop inbox.
    List,
    /// Receive waiting Taildrop files. Two shapes:
    ///
    /// * `get <target-directory>` — drain the ENTIRE inbox into a directory (the Go-faithful
    ///   `tailscale file get <dir>`). Use `--conflict` to choose what happens when a same-named file
    ///   already exists. The special target `/dev/null` wipes the inbox without writing anything.
    /// * `get <name> <dest>` — fetch ONE named waiting file (from `tnet file list`) to an exact path
    ///   (a fork convenience; not a Go command shape).
    ///
    /// Which one runs is decided by the argument count: one positional = directory drain, two = the
    /// single-file fetch.
    Get {
        /// The target directory to drain into, OR (when a second positional is given) the waiting
        /// file's base name to fetch.
        #[arg(value_name = "TARGET")]
        target: String,
        /// Optional. When present, switches to single-file mode: the local destination path to write
        /// the file named by `TARGET` to.
        #[arg(value_name = "DEST")]
        dest: Option<String>,
        /// Directory-drain mode only: what to do when a same-named file already exists in the target
        /// directory (Go `--conflict`). `skip` (default) never overwrites — it leaves the file in the
        /// inbox and reports it; `overwrite` replaces the existing file (removing it first, so a
        /// planted symlink is never followed); `rename` keeps both by writing a numbered variant
        /// (`name (1).ext`). Ignored in single-file (`get <name> <dest>`) mode.
        #[arg(long, value_enum, default_value_t = ConflictArg::Skip)]
        conflict: ConflictArg,
        /// Single-file mode only: delete the file from the inbox after a successful fetch. (The
        /// directory-drain mode always removes received files from the inbox, like Go.)
        #[arg(long)]
        delete_after: bool,
        /// Directory-drain mode only: print per-file progress in Go's `tailscale file get
        /// --verbose` shape — a `wrote <name> as <path> (<n> bytes)` line per received file,
        /// followed by the `moved <received>/<waiting> files` tally. Without it the drain prints
        /// the fork's compact result lines. Ignored in single-file (`get <name> <dest>`) mode.
        #[arg(long)]
        verbose: bool,
    },
}

/// CLI surface for the `--conflict` flag (Go `onConflict`). Maps to the wire
/// [`ConflictPolicy`](tailscaled_rs::localapi::ConflictPolicy).
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum ConflictArg {
    /// Never overwrite: leave a conflicting file in the inbox and report it (the safe default).
    Skip,
    /// Replace an existing file (removed first, so a symlink at the name is not followed).
    Overwrite,
    /// Keep both: write a Chrome-style numbered variant, `name (1).ext`.
    Rename,
}

impl From<ConflictArg> for tailscaled_rs::localapi::ConflictPolicy {
    fn from(a: ConflictArg) -> Self {
        use tailscaled_rs::localapi::ConflictPolicy;
        match a {
            ConflictArg::Skip => ConflictPolicy::Skip,
            ConflictArg::Overwrite => ConflictPolicy::Overwrite,
            ConflictArg::Rename => ConflictPolicy::Rename,
        }
    }
}

/// Map the `--exit-node` / `--clear-exit-node` flag pair to the wire field's double `Option`.
/// `--exit-node <sel>` → `Some(Some(sel))` (set it); `--clear-exit-node` → `Some(None)` (stop using
/// an exit node); neither → `None` (leave the persisted pref unchanged). A set value wins if both
/// somehow arrive, though clap's `conflicts_with` already guarantees they are never both present.
fn resolve_exit_node(set: Option<String>, clear: bool) -> Option<Option<String>> {
    match (set, clear) {
        (Some(s), _) => Some(Some(s)),
        (_, true) => Some(None),
        _ => None,
    }
}

/// Map the `--accept-routes` / `--no-accept-routes` flag pair to a tri-state `Option<bool>`.
/// Enable → `Some(true)`; disable → `Some(false)`; neither → `None` (leave the persisted pref
/// unchanged). Mirrors the `--tun`/`--no-tun` mapping; clap's `conflicts_with` guarantees the two
/// are never both set.
fn resolve_accept_routes(accept: bool, no_accept: bool) -> Option<bool> {
    match (accept, no_accept) {
        (true, _) => Some(true),
        (_, true) => Some(false),
        _ => None,
    }
}

/// Map the `--accept-dns` / `--no-accept-dns` flag pair to a tri-state `Option<bool>`.
/// Enable → `Some(true)`; disable → `Some(false)`; neither → `None` (leave the persisted pref
/// unchanged). clap's `conflicts_with` guarantees the two are never both set.
fn resolve_accept_dns(accept: bool, no_accept: bool) -> Option<bool> {
    match (accept, no_accept) {
        (true, _) => Some(true),
        (_, true) => Some(false),
        _ => None,
    }
}

/// Map the `--ephemeral` / `--no-ephemeral` flag pair to a tri-state `Option<bool>`.
/// Enable → `Some(true)`; disable → `Some(false)`; neither → `None` (leave the persisted pref
/// unchanged). clap's `conflicts_with` guarantees the two are never both set.
fn resolve_ephemeral(ephemeral: bool, no_ephemeral: bool) -> Option<bool> {
    match (ephemeral, no_ephemeral) {
        (true, _) => Some(true),
        (_, true) => Some(false),
        _ => None,
    }
}

/// Resolve the `--until-direct` / `--no-until-direct` flag pair into a plain `bool`, **defaulting to
/// `true`** to match Go's `tailscale ping` (where `--until-direct` is a bool flag that defaults
/// true). Unlike the prefs toggles this is NOT tri-state: there is no "leave unchanged" — every ping
/// invocation needs a concrete stop policy, and the Go default is "stop once direct". `--until-direct`
/// → `true`; `--no-until-direct` → `false`; neither → `true` (the default). clap's `conflicts_with`
/// guarantees the two are never both set. Pure → unit-testable.
fn resolve_until_direct(until_direct: bool, no_until_direct: bool) -> bool {
    match (until_direct, no_until_direct) {
        // `--no-until-direct` explicitly turns the early-stop off (ping the full count).
        (_, true) => false,
        // `--until-direct` explicitly turns it on (redundant with the default, but a user may pass it).
        (true, _) => true,
        // Neither flag → Go's default: stop once a direct path is established.
        (false, false) => true,
    }
}

/// Parse and validate a `file cp` destination argument into the bare peer selector (IP or MagicDNS
/// name), enforcing Go's `runCp` rules:
///
/// - The argument MUST end in a colon (`peer-b:`, `100.64.0.9:`) — Go uses the trailing colon to
///   tell a destination apart from a file path; a missing colon is an error.
/// - An IPv6 literal MUST be bracketed (`[fd7a::1]:`); a bare `fd7a::1:` is rejected with Go's
///   "an IPv6 literal must be written as [..]" guidance. Brackets are only valid around an actual
///   IPv6 literal (Go rejects `[peer-b]:` / `[1.2.3.4]:`).
///
/// Returns the inner selector with the colon (and any brackets) stripped. Pure → unit-testable
/// without a daemon. Mirrors `cmd/tailscale/cli/file.go` `runCp`.
fn parse_cp_target(arg: &str) -> Result<String> {
    let target = arg.strip_suffix(':').ok_or_else(|| {
        anyhow::anyhow!("final argument to 'file cp' must end in a colon (e.g. {arg}:)")
    })?;

    let had_brackets = target.starts_with('[') && target.ends_with(']');
    let inner = if had_brackets {
        &target[1..target.len() - 1]
    } else {
        target
    };

    // An empty peer (`:` or `[]:`) can't resolve — reject at the CLI with a clear message rather than
    // sending `""` to the daemon for a less-precise "no peer matches" round-trip.
    if inner.is_empty() {
        anyhow::bail!("empty peer in 'file cp' target (expected e.g. `peer-b:`)");
    }

    // Bracket/IPv6 consistency, mirroring Go: a bare IPv6 literal must be bracketed, and brackets are
    // only valid around an actual IPv6 literal.
    match inner.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V6(ip)) if !had_brackets => {
            anyhow::bail!("an IPv6 literal must be written as [{ip}]");
        }
        _ if had_brackets && !matches!(inner.parse(), Ok(std::net::IpAddr::V6(_))) => {
            anyhow::bail!("unexpected brackets around target {target:?}");
        }
        _ => {}
    }
    Ok(inner.to_string())
}

/// Map the `--shields-up` / `--no-shields-up` flag pair to a tri-state `Option<bool>`.
/// Enable → `Some(true)`; disable → `Some(false)`; neither → `None` (leave the persisted pref
/// unchanged). Mirrors the `--tun`/`--no-tun` mapping; clap's `conflicts_with` guarantees the two
/// are never both set.
fn resolve_shields_up(shields_up: bool, no_shields_up: bool) -> Option<bool> {
    match (shields_up, no_shields_up) {
        (true, _) => Some(true),
        (_, true) => Some(false),
        _ => None,
    }
}

/// Map the `--tun` / `--no-tun` flag pair to a tri-state `Option<bool>` — enable → `Some(true)`,
/// disable → `Some(false)`, neither → `None` (leave the persisted pref unchanged). A named helper
/// for symmetry with the other tri-state resolvers (`resolve_accept_routes` / `resolve_ssh` / …),
/// rather than inlining the same `match` at the call site. clap's `conflicts_with` guarantees the
/// two flags are never both set.
fn resolve_tun(tun: bool, no_tun: bool) -> Option<bool> {
    match (tun, no_tun) {
        (true, _) => Some(true),
        (_, true) => Some(false),
        _ => None,
    }
}

/// Map the `--advertise-exit-node` / `--no-advertise-exit-node` flag pair to a tri-state
/// `Option<bool>`. Enable → `Some(true)`; disable → `Some(false)`; neither → `None` (leave the
/// persisted pref unchanged). Mirrors the `--tun`/`--no-tun` mapping; clap's `conflicts_with`
/// guarantees the two are never both set.
fn resolve_advertise_exit_node(advertise: bool, no_advertise: bool) -> Option<bool> {
    match (advertise, no_advertise) {
        (true, _) => Some(true),
        (_, true) => Some(false),
        _ => None,
    }
}

/// Map the `--ssh` / `--no-ssh` flag pair to a tri-state `Option<bool>`. Enable → `Some(true)` (run
/// the Tailscale SSH server); disable → `Some(false)`; neither → `None` (leave the persisted pref
/// unchanged). Mirrors the `--tun`/`--no-tun` mapping; clap's `conflicts_with` guarantees the two
/// are never both set.
fn resolve_ssh(ssh: bool, no_ssh: bool) -> Option<bool> {
    match (ssh, no_ssh) {
        (true, _) => Some(true),
        (_, true) => Some(false),
        _ => None,
    }
}

/// Whether `status --web` should open a browser, from the two spellings of the same switch: this
/// fork's `--no-browser` and Go's `--browser[=BOOL]` (default true). clap already refuses the pair
/// together, so at most one is set; with neither, the browser opens — Go's default.
fn resolve_browser(browser: Option<bool>, no_browser: bool) -> bool {
    if no_browser {
        return false;
    }
    browser.unwrap_or(true)
}

/// Whether `ip` is a Tailscale-assigned address — the Rust analogue of Go `tsaddr.IsTailscaleIP`.
/// CGNAT `100.64.0.0/10` **minus** the ChromeOS-VM subrange `100.115.92.0/23` (Go excludes it —
/// `IsTailscaleIPv4 = CGNATRange.Contains && !ChromeOSVMRange.Contains`), plus the Tailscale ULA
/// `fd7a:115c:a1e0::/48`. Used by the risk gate to decide whether an SSH session originates from the
/// tailnet (a `--force-reauth` then risks dropping that very session). Pure → unit-testable.
fn is_tailscale_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            // CGNAT 100.64.0.0/10: octet0 == 100 AND octet1's top two bits == 0b01 (64..=127).
            let in_cgnat = o[0] == 100 && (o[1] & 0xc0) == 0x40;
            // ChromeOS-VM 100.115.92.0/23: 100.115.{92,93}.x — excluded from the Tailscale set.
            let in_chromeos_vm = o[0] == 100 && o[1] == 115 && (o[2] == 92 || o[2] == 93);
            in_cgnat && !in_chromeos_vm
        }
        // Tailscale ULA fd7a:115c:a1e0::/48 — match the full /48 (all three leading segments).
        std::net::IpAddr::V6(v6) => {
            let s = v6.segments();
            s[0] == 0xfd7a && s[1] == 0x115c && s[2] == 0xa1e0
        }
    }
}

/// Whether an `SSH_CLIENT` value denotes a session whose client is a Tailscale IP — the Rust analogue
/// of Go's `isSSHOverTailscale()`. `SSH_CLIENT` is `<client-ip> <client-port> <server-port>`; take the
/// first space-separated token, parse it, and test it with [`is_tailscale_ip`]. An empty or
/// unparseable value (or a non-tailnet client) → false. Split out from [`is_ssh_over_tailscale`] so it
/// is testable without mutating the process environment. Pure.
fn ssh_client_is_tailscale(ssh_client: &str) -> bool {
    // `split_once(' ')` mirrors Go's `strings.Cut(sshClient, " ")` + its `!ok` (no-space) → false:
    // a well-formed SSH_CLIENT is always `<ip> <client-port> <server-port>`, so a value with no space
    // is malformed and rejected (rather than parsing a bare IP).
    let Some((ip_str, _rest)) = ssh_client.split_once(' ') else {
        return false;
    };
    ip_str
        .parse::<std::net::IpAddr>()
        .map(is_tailscale_ip)
        .unwrap_or(false)
}

/// Whether this CLI is running over a Tailscale-SSH session (Go `isSSHOverTailscale`): resolves the
/// `SSH_CLIENT` value via [`ssh_client_env_value`] and delegates the IP test to
/// [`ssh_client_is_tailscale`]. Reads the process environment (+ `/proc` under sudo on Linux), so it
/// is not pure — but the decision logic it wraps is.
fn is_ssh_over_tailscale() -> bool {
    ssh_client_env_value()
        .map(|c| ssh_client_is_tailscale(&c))
        .unwrap_or(false)
}

/// Resolve the `SSH_CLIENT` value, the Rust analogue of Go's `getSSHClientEnvVar`. Normally this is
/// just `std::env::var("SSH_CLIENT")`, but `sudo` STRIPS `SSH_CLIENT` from the environment — so a
/// `sudo tnet up --force-reauth` / `sudo tnet ssh` over a Tailscale-SSH session would otherwise lose
/// the very signal the lock-out guard depends on. To match Go, on **Linux when `SUDO_USER` is set**
/// (the sudo case, and the only case where the var was stripped) we fall back to reading the login
/// session leader's environment from `/proc/<sid>/environ` and parsing it for `SSH_CLIENT=` — the
/// session leader is the original login shell, which still has the var. `getsid(getpid())` gives that
/// pid; the environ file is NUL-separated. Best-effort + fail-OPEN throughout (a missing/unreadable
/// `/proc`, a no-`SSH_CLIENT` environ, or a non-sudo/non-Linux host yields `None`): this gate is
/// advisory, not a security boundary (the operator can always bypass it with `--accept-risk`), so a
/// missed refusal only costs a warning and the lock-out it guards is recoverable out-of-band.
fn ssh_client_env_value() -> Option<String> {
    // The plain env var first — present for a direct SSH session (no sudo).
    if let Ok(v) = std::env::var("SSH_CLIENT")
        && !v.is_empty()
    {
        return Some(v);
    }
    // Sudo stripped it: walk the session leader's environ (Linux only, only when under sudo).
    #[cfg(target_os = "linux")]
    {
        if std::env::var_os("SUDO_USER").is_some() {
            return ssh_client_from_session_leader_environ();
        }
    }
    None
}

/// Read `SSH_CLIENT` from the login session leader's `/proc/<sid>/environ` (Go's `/proc` fallback in
/// `ssh_unix.go`). The session leader (`getsid(getpid())`) is the original login shell, which retains
/// `SSH_CLIENT` even when the current `sudo`-elevated process does not. The environ file is a
/// NUL-separated list of `KEY=VALUE` entries. Fail-OPEN: any error (no `/proc`, permission denied, no
/// `SSH_CLIENT` entry) yields `None`. Linux-only.
#[cfg(target_os = "linux")]
fn ssh_client_from_session_leader_environ() -> Option<String> {
    // SAFETY: getsid() with a real pid (our own) is infallible in practice and has no preconditions;
    // it returns the session id (or -1 on error, which we treat as "no session" → fail open).
    let sid = unsafe { libc::getsid(libc::getpid()) };
    if sid < 0 {
        return None;
    }
    let path = format!("/proc/{sid}/environ");
    let bytes = std::fs::read(&path).ok()?;
    // environ is NUL-separated `KEY=VALUE` entries; find the `SSH_CLIENT=` one and return its value.
    const PREFIX: &[u8] = b"SSH_CLIENT=";
    for entry in bytes.split(|&b| b == 0) {
        if let Some(value) = entry.strip_prefix(PREFIX) {
            // The value is the SSH_CLIENT string (`<ip> <cport> <sport>`); lossy-decode (it is ASCII
            // in practice) and reject an empty one.
            let v = String::from_utf8_lossy(value).into_owned();
            return (!v.is_empty()).then_some(v);
        }
    }
    None
}

/// Whether a named `risk` is in the operator's `--accept-risk` value — the Rust analogue of Go's
/// `isRiskAccepted`: split on `,` and accept if any token equals the risk name or the catch-all `all`.
/// Like Go, tokens are matched **raw** (NOT trimmed): Go compares `strings.SplitSeq(accepted, ",")`
/// members verbatim, so `--accept-risk="foo, lose-ssh"` does NOT accept `lose-ssh` there (the token is
/// `" lose-ssh"`); use `foo,lose-ssh` (no spaces) or `all`. Matching Go is the safer default for a
/// safety gate (fewer accidental accepts). Pure.
fn risk_accepted(accepted: &str, risk: &str) -> bool {
    accepted.split(',').any(|r| r == risk || r == "all")
}

/// The pure decision behind the SSH-server-toggle `lose-ssh` risk — the Rust analogue of Go's
/// `presentSSHToggleRisk` (`up.go`). Returns the *direction* of a refusal, or `None` to allow:
/// - `None` (allow) when the toggle isn't mentioned (`want` is `None`), or we're not over a Tailscale
///   SSH session (`!over_ssh`), or the operator pre-accepted the risk (`lose-ssh`/`all`), or the
///   toggle is a no-op (`want == Some(have)`) — Go's `!isSSHOverTailscale() || wantSSH == haveSSH`.
/// - `Some(true)` when ENABLING the SSH server (`want = Some(true)`, `have = false`) — Go reroutes SSH
///   traffic to Tailscale SSH and the current session disconnects.
/// - `Some(false)` when DISABLING it (`want = Some(false)`, `have = true`) — the session over Tailscale
///   SSH disconnects.
///
/// Pure (no I/O), so the branch logic is unit-testable; the async [`refuse_ssh_toggle_risk_if_needed`]
/// supplies `over_ssh` (the env probe) + `have` (a `GetPrefs` round-trip) and renders the message.
fn ssh_toggle_refusal(
    want: Option<bool>,
    have: bool,
    over_ssh: bool,
    accepted: &str,
) -> Option<bool> {
    let want = want?;
    if !over_ssh || want == have || risk_accepted(accepted, "lose-ssh") {
        return None;
    }
    Some(want) // want == true → enabling refusal; false → disabling refusal
}

/// Refuse an SSH-server toggle that would drop the operator's own Tailscale SSH session, unless they
/// pre-accepted `lose-ssh` (Go's `presentSSHToggleRisk`, enforced fail-closed). Shared by the `up` and
/// `set` handlers. **Short-circuits cheaply**: it only performs the `GetPrefs` round-trip (to learn the
/// current `ssh` pref = `haveSSH`) when the toggle is actually mentioned AND we're over a Tailscale SSH
/// session AND the risk wasn't pre-accepted — so the common path (no `--ssh`/`--no-ssh`, or not over
/// SSH) makes no extra daemon call. On a real refusal it prints the direction-appropriate message +
/// the `--accept-risk=lose-ssh` override and exits non-zero, before the caller builds/sends its
/// request. `want_ssh` is `resolve_ssh(ssh, no_ssh)` (the mentioned toggle, or `None`).
async fn refuse_ssh_toggle_risk_if_needed(
    socket: &std::path::Path,
    want_ssh: Option<bool>,
    accept_risk: Option<&str>,
) -> Result<()> {
    let accepted = accept_risk.unwrap_or("");
    // Cheap pre-conditions first — avoid the GetPrefs round-trip unless a refusal is even possible.
    let Some(want) = want_ssh else { return Ok(()) };
    if !is_ssh_over_tailscale() || risk_accepted(accepted, "lose-ssh") {
        return Ok(());
    }
    // Now learn haveSSH (the persisted ssh pref) via the same one-shot read the `get` command uses.
    let have = match round_trip(socket, &Request::GetPrefs).await {
        Ok(Response::Prefs(v)) => v.ssh,
        Ok(Response::Error { message }) => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        Ok(other) => anyhow::bail!("unexpected response to get-prefs (ssh-risk check): {other:?}"),
        Err(e) => {
            return Err(e).with_context(|| {
                format!(
                    "reading prefs for the ssh-toggle risk check at {}",
                    socket.display()
                )
            });
        }
    };
    match ssh_toggle_refusal(Some(want), have, true, accepted) {
        // Go's `presentSSHToggleRisk` strings, verbatim (up.go), so the operator-facing wording
        // matches upstream exactly; the override hint is added (Go prompts interactively; this CLI
        // refuses fail-closed and points at the same `--accept-risk=lose-ssh` escape hatch).
        Some(true) => {
            eprintln!(
                "You are connected over Tailscale; this action will reroute SSH traffic to \
                 Tailscale SSH and will result in your session disconnecting."
            );
            eprintln!("To override, re-run with --accept-risk=lose-ssh");
            std::process::exit(1);
        }
        Some(false) => {
            eprintln!(
                "You are connected using Tailscale SSH; this action will result in your session \
                 disconnecting."
            );
            eprintln!("To override, re-run with --accept-risk=lose-ssh");
            std::process::exit(1);
        }
        None => Ok(()),
    }
}

/// Map a `--<list>` / `--<list>-clear` flag pair to the wire field's `Option<Vec<String>>` — a
/// **value-neutral** "replace, clear, or leave unchanged" resolver shared by every set-a-list pref
/// (`--advertise-routes`, `--advertise-tags`, …). A non-empty `items` → `Some(items)` (replace the
/// set); else `clear` → `Some(vec![])` (set to empty); else `None` (leave the persisted set
/// unchanged). A non-empty list takes precedence over the clear flag. The name is deliberately NOT
/// `*_routes` — it carries no route/tag-specific semantics, so reusing it for tags is correct, not a
/// footgun. (Any value VALIDATION — CIDR parsing for routes, `tag:` form for tags — happens elsewhere,
/// daemon-side; this only resolves the three-way replace/clear/unchanged intent.)
fn resolve_list_or_clear(items: Vec<String>, clear: bool) -> Option<Vec<String>> {
    if !items.is_empty() {
        Some(items)
    } else if clear {
        Some(vec![])
    } else {
        None
    }
}

/// Restore the default `SIGPIPE` disposition (terminate) before doing any output.
///
/// The Rust runtime installs `SIG_IGN` for `SIGPIPE` before `main`, which turns a write to a closed
/// pipe into an `EPIPE` error — and `print!`/`println!` then **panic** ("failed printing to stdout",
/// exit 101). For a Unix CLI that is wrong: piping a large output into `head`, or any reader that
/// exits early, should make the writer terminate *silently* on the broken pipe, exactly as Go's
/// `tailscale` (and every well-behaved CLI) does. Resetting to `SIG_DFL` here restores that: a broken
/// pipe kills the process with `SIGPIPE` (exit 141) instead of an ugly Rust panic. Output-only — no
/// effect on the daemon's socket I/O (the daemon binary does the same for symmetry).
fn reset_sigpipe() {
    // SAFETY: `signal` with `SIG_DFL` for `SIGPIPE` is async-signal-safe and has no preconditions; we
    // call it once at the very start of `main`, before any threads/output. This is the standard CLI
    // fix (ripgrep/fd do the same); the `unsafe` is only because `libc::signal` is an FFI call.
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // FIRST: restore default SIGPIPE so a broken output pipe (`tnet status | head`) terminates
    // cleanly instead of panicking the print. Must run before any stdout write.
    reset_sigpipe();
    let cli = Cli::parse();
    // Capture the EXPLICIT `--socket` override (if any) before resolving the default — `ssh`'s
    // ProxyCommand must re-pass it to the `tnet nc` subprocess so the tunnel hits the same daemon
    // (Go threads the same `socketArg` only when a non-default socket is set). `None` ⇒ default socket
    // ⇒ no `--socket` needed on the ProxyCommand.
    let explicit_socket = cli.socket.clone();
    let socket = cli.socket.unwrap_or_else(tailscaled_rs::socket_path);

    match cli.command {
        Command::Up {
            authkey,
            authkey_file,
            hostname,
            control_url,
            tun,
            no_tun,
            tun_name,
            tun_mtu,
            exit_node,
            clear_exit_node,
            advertise_exit_node,
            no_advertise_exit_node,
            advertise_routes,
            advertise_routes_clear,
            advertise_tags,
            advertise_tags_clear,
            accept_routes,
            no_accept_routes,
            accept_dns,
            no_accept_dns,
            shields_up,
            no_shields_up,
            ssh,
            no_ssh,
            operator,
            exit_node_allow_lan_access,
            no_exit_node_allow_lan_access,
            advertise_connector,
            no_advertise_connector,
            report_posture,
            no_report_posture,
            reset,
            force_reauth,
            ephemeral,
            no_ephemeral,
            timeout,
            accept_risk,
            client_id,
            client_secret,
            id_token,
            audience,
            json,
            host_routes,
            nickname,
        } => {
            // Resolve the newer pref flags into their wire sentinels HERE and pass them as one named
            // struct (see `UpPrefFlags`): `run_up`'s positional list is long enough that another four
            // bare `Option<bool>`s would be a transposition waiting to happen.
            let up_prefs = UpPrefFlags {
                operator: resolve_clearable_string(operator),
                exit_node_allow_lan_access: resolve_tristate(
                    exit_node_allow_lan_access,
                    no_exit_node_allow_lan_access,
                ),
                advertise_connector: resolve_tristate(advertise_connector, no_advertise_connector),
                report_posture: resolve_tristate(report_posture, no_report_posture),
            };
            // The two Go `up` spellings this CLI carries on the parser without a pref behind them
            // (see `PortedUpFlags`); `run_up` gates them where Go's flag parser does — first.
            let ported = PortedUpFlags {
                host_routes,
                nickname,
            };
            run_up(
                &socket,
                authkey,
                authkey_file,
                hostname,
                control_url,
                tun,
                no_tun,
                tun_name,
                tun_mtu,
                exit_node,
                clear_exit_node,
                advertise_exit_node,
                no_advertise_exit_node,
                advertise_routes,
                advertise_routes_clear,
                advertise_tags,
                advertise_tags_clear,
                accept_routes,
                no_accept_routes,
                accept_dns,
                no_accept_dns,
                shields_up,
                no_shields_up,
                ssh,
                no_ssh,
                up_prefs,
                reset,
                force_reauth,
                ephemeral,
                no_ephemeral,
                timeout,
                accept_risk,
                resolve_wif(client_id, client_secret, id_token, audience).await?,
                json,
                ported,
            )
            .await
        }
        Command::Set {
            hostname,
            accept_routes,
            no_accept_routes,
            accept_dns,
            no_accept_dns,
            shields_up,
            no_shields_up,
            exit_node,
            clear_exit_node,
            advertise_exit_node,
            no_advertise_exit_node,
            advertise_routes,
            advertise_routes_clear,
            advertise_tags,
            advertise_tags_clear,
            ssh,
            no_ssh,
            advertise_connector,
            no_advertise_connector,
            auto_update,
            no_auto_update,
            update_check,
            no_update_check,
            operator,
            nickname,
            report_posture,
            no_report_posture,
            webclient,
            no_webclient,
            exit_node_allow_lan_access,
            no_exit_node_allow_lan_access,
            relay_server_port,
            relay_server_static_endpoints,
            remote_config,
            no_remote_config,
            sync,
            no_sync,
            accept_risk,
        } => {
            // Same grouping as the `up` arm above (see `SetPrefFlags`): resolve the eight newer pref
            // flags into wire sentinels by NAME here, rather than growing `run_set`'s positional list
            // by another fourteen booleans.
            let set_prefs = SetPrefFlags {
                advertise_connector: resolve_tristate(advertise_connector, no_advertise_connector),
                auto_update: resolve_tristate(auto_update, no_auto_update),
                update_check: resolve_tristate(update_check, no_update_check),
                operator: resolve_clearable_string(operator),
                nickname: resolve_clearable_string(nickname),
                report_posture: resolve_tristate(report_posture, no_report_posture),
                webclient: resolve_tristate(webclient, no_webclient),
                exit_node_allow_lan_access: resolve_tristate(
                    exit_node_allow_lan_access,
                    no_exit_node_allow_lan_access,
                ),
            };
            // The four Go `set` flags this build parses but models no pref for (see
            // `UnmodelledSetFlags`); `run_set` gates them where Go's `runSet` does.
            let unmodelled = UnmodelledSetFlags {
                relay_server_port,
                relay_server_static_endpoints,
                remote_config: resolve_tristate(remote_config, no_remote_config),
                sync: resolve_tristate(sync, no_sync),
            };
            run_set(
                &socket,
                hostname,
                accept_routes,
                no_accept_routes,
                accept_dns,
                no_accept_dns,
                shields_up,
                no_shields_up,
                exit_node,
                clear_exit_node,
                advertise_exit_node,
                no_advertise_exit_node,
                advertise_routes,
                advertise_routes_clear,
                advertise_tags,
                advertise_tags_clear,
                ssh,
                no_ssh,
                set_prefs,
                unmodelled,
                accept_risk,
            )
            .await
        }
        Command::Bugreport { note } => dispatch_simple(&socket, Request::BugReport { note }).await,
        Command::Cert {
            domain,
            cert_file,
            key_file,
            min_validity,
            serve_demo,
            listen,
        } => {
            run_cert(
                &socket,
                domain,
                cert_file,
                key_file,
                min_validity,
                serve_demo,
                listen,
            )
            .await
        }
        // `nc` hijacks its connection (the daemon splices to the overlay after a one-line ack), so it
        // is handled by a dedicated piping path, not the generic round-trip.
        Command::Nc { host, port } => run_nc(&socket, &host, port)
            .await
            .with_context(|| format!("nc to {host}:{port} via {}", socket.display())),
        // `ssh`: resolve the peer + its host keys via Status, write a pinned ssh_known_hosts, then
        // exec the system `ssh` with a ProxyCommand through `tnet nc`. On success this never returns
        // (it execs); on a resolution/setup failure it returns an error.
        Command::Ssh { target, args } => {
            run_ssh(&socket, explicit_socket.as_deref(), &target, &args).await
        }
        // `serve`: read-modify-write the ServeConfig (every set/off path) or render it (status).
        // Inline because each mutation must GET the current config, mutate, then SET it.
        Command::Serve { cmd, flags } => run_serve(&socket, cmd, flags)
            .await
            .with_context(|| format!("serve via {}", socket.display())),
        // `funnel`: the same read-modify-write, plus the AllowFunnel toggle keyed by the node's
        // MagicDNS name (fetched from Status).
        Command::Funnel { cmd, flags } => run_funnel(&socket, cmd, flags)
            .await
            .with_context(|| format!("funnel via {}", socket.display())),
        // `debug capture`: send DebugCapture (a long-lived write — the daemon taps the dataplane for
        // `seconds`, then replies with the byte count). Inline early-return like the other subcommand
        // groups.
        Command::Debug { cmd } => match cmd {
            DebugCmd::Capture { path, seconds } => run_debug_capture(&socket, path, seconds).await,
            DebugCmd::Prefs => run_debug_prefs(&socket).await,
            // `debug env` is purely local (reads this process's environment) — no socket round-trip.
            DebugCmd::Env => {
                run_debug_env();
                Ok(())
            }
            // `debug metrics` is the same data as `tnet metrics` (reuse the handler) — a Go alias.
            DebugCmd::Metrics => run_metrics(&socket, Some(MetricsCmd::Print)).await,
            // `debug via` is pure local bit-math (4via6 encode/decode) — no socket round-trip.
            DebugCmd::Via {
                site_or_route,
                cidr,
            } => run_debug_via(&site_or_route, cidr.as_deref()),
            // `debug rebind` is a write-gated daemon round-trip (re-creates the engine's UDP sockets).
            DebugCmd::Rebind => run_debug_rebind(&socket).await,
            // `debug restun` is a write-gated daemon round-trip (re-probes STUN; no socket swap).
            DebugCmd::Restun => run_debug_restun(&socket).await,
            DebugCmd::CheckIpForwarding => run_check_ip_forwarding(&socket).await,
            DebugCmd::CheckPrefs {
                exit_node,
                advertise_exit_node,
                advertise_routes,
                ssh,
            } => {
                run_check_prefs(
                    &socket,
                    exit_node,
                    advertise_exit_node,
                    advertise_routes,
                    ssh,
                )
                .await
            }
            // `debug watch-ipn` streams the IPN-bus notify path (masked watch) — a long-lived
            // read-only stream printing one JSON `Notify` per line.
            DebugCmd::WatchIpn => run_debug_watch_ipn(&socket).await,
            // `debug local-creds` prints the `curl` command for the resolved LocalAPI socket — purely
            // local (it describes the socket the CLI WOULD talk to; no round-trip).
            DebugCmd::LocalCreds => {
                run_debug_local_creds(&socket);
                Ok(())
            }
            // `debug stat` lstats each path locally — no socket round-trip.
            DebugCmd::Stat { files } => {
                run_debug_stat(&files);
                Ok(())
            }
            // `debug statedir` reports the CLI's own path resolution — purely local, no round-trip.
            DebugCmd::Statedir => {
                run_debug_statedir(&socket);
                Ok(())
            }
            // `debug resolve` is a host-resolver lookup in THIS process — no socket round-trip.
            DebugCmd::Resolve { net, hostname } => run_debug_resolve(&hostname, &net).await,
            // `debug build-info` prints compile-time build facts — purely local, no round-trip.
            DebugCmd::BuildInfo => {
                run_debug_build_info();
                Ok(())
            }
        },
        // `install` / `uninstall` (Go `tailscaled install-system-daemon` / `uninstall-system-daemon`):
        // purely LOCAL, privileged file + service-manager work — they never touch the LocalAPI socket.
        // Handled inline (early return), root-gated inside `run_install`/`run_uninstall`.
        Command::Install => tailscaled_rs::ipn::install::run_install()
            .context("installing the tailnetd system service"),
        Command::Uninstall => tailscaled_rs::ipn::install::run_uninstall()
            .context("removing the tailnetd system service"),
        Command::Down => dispatch_simple(&socket, Request::Down).await,
        Command::Logout { reason } => dispatch_simple(&socket, Request::Logout { reason }).await,
        // `reload-config` (Go `tailscaled`'s `reload-config`): re-read the daemon's `--config` and adopt
        // it into the running node. A dedicated renderer (not `dispatch_simple`) so it prints a clean
        // success line and exits 1 on the daemon's error (no `--config` in use / malformed file), like
        // `debug rebind`.
        Command::ReloadConfig => run_reload_config(&socket).await,
        // `login` (Go `tailscale login`): interactive (or authkey) (re)authentication that changes no
        // prefs — `up`'s auth half on its own. Reuses the interactive-login machinery.
        Command::Login {
            authkey,
            authkey_file,
            login_server,
        } => run_login(&socket, authkey, authkey_file, login_server).await,
        // `switch` (Go `tailscale switch`): --list renders a table; `remove <id>` deletes; a bare
        // `<target>` switches. Handled inline — `--list` renders the Profiles reply, and the three
        // modes map to different requests.
        Command::Switch {
            list,
            json,
            target,
            cmd,
        } => run_switch(&socket, list, json, target, cmd).await,
        // `version` answers from the CLI's own crate version. WITHOUT `--daemon` it never contacts
        // the daemon (Go also prints the client version with no LocalAPI call) — handle it here and
        // return. WITH `--daemon` it round-trips `Request::Version` to learn the daemon's version,
        // then renders both; we do that inline here (rather than falling through to the generic
        // response printer) so the client/daemon pairing + `--json` shape stay in one place.
        // `--track` selects the release track `--upstream` would query. This build has no upstream
        // fetcher (`--upstream` refuses, as Go's does without its clientupdate hook), so the track
        // never reaches a fetch — accepted and ignored, exactly like Go's.
        Command::Version {
            daemon,
            json,
            upstream,
            track: _,
        } => run_version(&socket, daemon, json, upstream).await,
        // `get` (Go `tailscale get`): round-trip GetPrefs, then render. Handled inline (early return)
        // because its `setting`/`json` args shape the output and are not part of the wire request —
        // keeping the projection→render in one place, like `version`.
        Command::Get {
            setting,
            json,
            set_flags,
        } => run_get(&socket, setting, json, set_flags).await,
        // `wait` (Go `tailscale wait`): poll until the node is Running with a tailnet IP, honoring an
        // optional timeout. Handled inline (it loops + has its own exit-code contract), not a
        // one-shot request.
        Command::Wait { timeout } => wait_for_running(&socket, timeout)
            .await
            .with_context(|| format!("waiting for the node to come up at {}", socket.display())),
        // `whoami` (Go `tailscale whoami`): resolve this node's own identity — Status to learn the
        // self tailnet IP, then Whois on that IP. Handled inline because it chains two requests and
        // its `--json` shape is the whois record. Reuses the same `format_whois` renderer as `whois`.
        Command::Whoami { json } => run_whoami(&socket, json).await,
        // `status` (Go `tailscale status`): plain status round-trips one `Status`; `--web`/`--watch`
        // are long-lived and return inside `run_status`.
        Command::Status {
            watch,
            json,
            active,
            no_peers,
            no_self,
            web,
            listen,
            no_browser,
            browser,
        } => {
            run_status(
                &socket,
                watch,
                json,
                active,
                no_peers,
                no_self,
                web,
                listen,
                resolve_browser(browser, no_browser),
            )
            .await
        }
        // `ip` (Go `tailscale ip`): self addresses by default, or a peer's if named, with -4/-6/-1
        // filters. Handled inline because the filters + the optional peer lookup shape the output
        // (and the peer case fetches Status to resolve by name/IP against the netmap).
        Command::Ip {
            v4,
            v6,
            first,
            peer,
            assert,
        } => run_ip(&socket, v4, v6, first, peer, assert).await,
        Command::Whois {
            target,
            proto,
            json,
        } => run_whois(&socket, &target, proto.as_deref(), json).await,
        Command::IdToken { audience } => {
            dispatch_simple(&socket, Request::IdToken { audience }).await
        }
        // `ping` (Go `tailscale ping [-c N]`): the engine pings one-at-a-time, so `-c` is a CLI-side
        // loop over `Request::Ping`. Handled inline (the loop + summary + exit-code contract); each
        // attempt prints a result line, a failure is counted but does not abort the rest, and the
        // command exits non-zero only if NOTHING was received.
        Command::Ping {
            ip,
            timeout,
            count,
            until_direct,
            no_until_direct,
        } => {
            run_ping(
                &socket,
                ip,
                timeout,
                count,
                resolve_until_direct(until_direct, no_until_direct),
            )
            .await
        }
        // Taildrop. The nested subcommand picks which wire `Request` to send: `cp` and `get` are
        // writes (the daemon reads/consumes a file) and reply `Ok`; `list` is read-only and replies
        // `Files`.
        // `metrics` (Go `tailscale metrics`): fetch the Prometheus text, then print or write it.
        // Inline because `write <path>` chooses a file sink over stdout.
        Command::Metrics { cmd } => run_metrics(&socket, cmd).await,
        // `licenses` is purely local (Go contacts no daemon either) — print + return.
        Command::Licenses => {
            print!("{}", format_licenses());
            Ok(())
        }
        // `update` (Go `tailscale update`): version-check against GitHub Releases; report by default,
        // self-install with `--yes`. Local-only (no daemon socket).
        Command::Update {
            check,
            dry_run,
            yes,
            version,
            track,
        } => run_update(check || dry_run, yes, version, track).await,
        // `web` (Go `tailscale web`): serve the read-only status UI. Reuses the same embedded HTTP
        // server as `status --web`, but with Go's command name + flags (default localhost:8088). The
        // `--readonly` flag is a no-op (this build's web UI is always read-only). `--prefix` serves
        // the page under a URL path prefix (for reverse proxies), `--origin` states the absolute URL
        // the UI is reached at, and `--cgi` swaps the listener for one CGI request/response.
        Command::Web {
            listen,
            readonly: _,
            prefix,
            no_browser,
            cgi,
            origin,
        } => {
            run_web(
                &socket,
                listen,
                prefix.unwrap_or_default(),
                !no_browser,
                cgi,
                origin.as_deref(),
            )
            .await
        }
        // `lock status` (Go `tailscale lock status`): fetch + render the TKA status.
        // `lock init` (Go `tailscale lock init`): initialize the lock with this node as sole trusted key.
        Command::Lock {
            cmd:
                LockCmd::Init {
                    trusted_keys,
                    gen_disablements,
                    gen_disablement_for_support,
                    confirm,
                    disablement_secret,
                },
        } => {
            run_lock_init(
                &socket,
                &LockInitArgs {
                    positionals: &trusted_keys,
                    gen_disablements,
                    gen_disablement_for_support,
                    confirm,
                    supplied_secret: disablement_secret.as_deref(),
                },
            )
            .await
        }
        Command::Lock {
            cmd: LockCmd::Status { json },
        } => run_lock_status(&socket, json).await,
        // `lock log` (Go `tailscale lock log`): fetch + render the TKA update-chain history.
        Command::Lock {
            cmd: LockCmd::Log { limit, json },
        } => run_lock_log(&socket, limit, json).await,
        // `lock sign` (Go `tailscale lock sign`): co-sign a node key into the lock.
        Command::Lock {
            cmd: LockCmd::Sign { node_key },
        } => run_lock_sign(&socket, &node_key).await,
        // `lock disable` (Go `tailscale lock disable`): present the disablement secret.
        Command::Lock {
            cmd: LockCmd::Disable { secret },
        } => run_lock_disable(&socket, &secret).await,
        // `lock disablement-kdf` (Go `tailscale lock disablement-kdf`): pure-local Argon2i derivation,
        // no socket round-trip.
        Command::Lock {
            cmd: LockCmd::DisablementKdf { secret },
        } => run_lock_disablement_kdf(&secret),
        // `dns status` (Go `tailscale dns status`): fetch + render the control-pushed MagicDNS config.
        Command::Dns {
            cmd: DnsCmd::Status { json },
        } => run_dns_status(&socket, json).await,
        Command::Dns {
            cmd: DnsCmd::Query { name, qtype, json },
        } => run_dns_query(&socket, &name, &qtype, json).await,
        // `netcheck` (Go `tailscale netcheck`): fetch + render the net-report (DERP-region latency).
        Command::Netcheck {
            json,
            format,
            every,
            verbose,
        } => run_netcheck(&socket, json, format, every, verbose).await,
        // `exit-node list` (Go `tailscale exit-node list`): reuse Status, filter to exit-node peers.
        Command::ExitNode {
            cmd: ExitNodeCmd::List,
        } => run_exit_node_list(&socket).await,
        // `exit-node suggest` (Go `tailscale exit-node suggest`): ask the daemon for the best candidate.
        Command::ExitNode {
            cmd: ExitNodeCmd::Suggest,
        } => run_exit_node_suggest(&socket).await,
        // `syspolicy list`/`reload` (Go `tailscale syspolicy`): fetch + render the effective policy.
        Command::Syspolicy {
            cmd: SyspolicyCmd::List { json },
        } => run_syspolicy(&socket, Request::SyspolicyList, json).await,
        Command::Syspolicy {
            cmd: SyspolicyCmd::Reload { json },
        } => run_syspolicy(&socket, Request::SyspolicyReload, json).await,
        // `service list` (Go `tailscale service list`): the Services this node can reach, from the
        // daemon's `services` verb, decorated with each Service's MagicDNS hostname (which needs the
        // tailnet suffix `status` carries) — the same two LocalAPI calls Go makes.
        Command::Service {
            cmd: ServiceCmd::List { json },
        } => run_service_list(&socket, json).await,
        Command::File { cmd } => run_file(&socket, cmd).await,
        // `configure kubeconfig` (Go `tailscale configure kubeconfig`): resolve the auth-proxy peer
        // against Status, then render the kubeconfig locally. No daemon verb of its own.
        Command::Configure {
            cmd:
                ConfigureCmd::Kubeconfig {
                    host,
                    http,
                    output,
                    force,
                },
        } => run_configure_kubeconfig(&socket, &host, http, output.as_deref(), force).await,
        // `configure sysext` / `configure mac-vpn` (Go `tailscale configure sysext|mac-vpn`): the
        // macOS system extension and the VPN profile belong to the GUI client, so Go's open-source
        // CLI answers with an explanatory error and this fork does the same. Purely local — the
        // refusal is decided in the CLI process, with no daemon round trip (matching Go, whose
        // `Exec` returns the error without touching the LocalAPI).
        Command::Configure {
            cmd: ConfigureCmd::Sysext { cmd },
        } => run_configure_sysext(cmd),
        Command::Configure {
            cmd: ConfigureCmd::MacVpn { cmd },
        } => run_configure_mac_vpn(cmd),
    }
}

/// Print `tnet version` output (thin wrapper over [`format_version`], which is pure + unit-tested).
/// `cap` is the engine's current capability version (the `cap` field of Go's `version.Meta`).
fn print_version(client: &str, daemon: Option<&str>, cap: u16, json: bool) {
    print!("{}", format_version(client, daemon, cap, json));
}

/// Send a write `Request` that replies `Ok`/`Error`, printing `ok: <msg>` on success or the error +
/// exit 1 on failure. Used by the `switch`/`switch remove` inline arms (they're plain writes whose
/// success is just an acknowledgement). Returns `Ok(())` so the caller can `return` it directly.
async fn send_ok_or_die(socket: &std::path::Path, request: Request) -> Result<()> {
    match round_trip(socket, &request).await {
        Ok(Response::Ok { message }) => {
            println!("ok: {message}");
            Ok(())
        }
        Ok(Response::Error { message }) => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        Ok(other) => anyhow::bail!("unexpected response: {other:?}"),
        Err(e) => Err(e).with_context(|| format!("talking to daemon at {}", socket.display())),
    }
}

/// Round-trip a one-shot `Request` whose reply is rendered with no command-specific state, then
/// return. Covers the truly-generic writes — `down`/`logout` (reply `Ok`), `bugreport` (reply
/// `BugReport`), and `id-token` (reply `IdToken`) — distributing the former shared post-match render
/// arms for those response shapes into one place. Models its error/exit handling on
/// [`send_ok_or_die`]: a `Response::Error` prints `error: <msg>` and exits 1; a transport error is
/// returned with the same "talking to daemon" context the old fall-through block used.
async fn dispatch_simple(socket: &std::path::Path, request: Request) -> Result<()> {
    let response = round_trip(socket, &request)
        .await
        .with_context(|| format!("talking to daemon at {}", socket.display()))?;
    match response {
        Response::Ok { message } => {
            println!("ok: {message}");
        }
        // `bugreport`: print the local marker + a one-line honesty note (no logs were uploaded).
        Response::BugReport { marker } => {
            println!("{marker}");
            eprintln!(
                "(local diagnostic marker — this client uploads no logs; quote it when reporting an issue)"
            );
        }
        // `id-token`: print the raw JWT on its own line (Go's `outln(tr.IDToken)`) for easy capture
        // into a variable / piping to a verifier. The token is opaque base64url — no sanitization
        // needed (it is control-minted, not free-form text).
        Response::IdToken { token } => println!("{token}"),
        Response::Error { message } => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }
    Ok(())
}

/// The refusal `tnet up` owes its own flags *before* it contacts the daemon, or `None` when the
/// invocation is usable. Ported from Go's `prefsFromUpArgs` (`cmd/tailscale/cli/up.go` @ v1.100.0),
/// which refuses the one flag combination that cannot mean anything — `if upArgs.exitNodeIP == "" &&
/// upArgs.exitNodeAllowLANAccess { return nil, fmt.Errorf("--exit-node-allow-lan-access can only be
/// used with --exit-node") }`.
///
/// `--exit-node-allow-lan-access` only shapes traffic that is *already* leaving through an exit
/// node, so on its own it asks for an exemption from routing that is not happening. Go decides this
/// from the FLAGS, not from the resulting state — `prefsFromUpArgs` runs before any LocalAPI call —
/// so the refusal here is likewise on the invocation: an `up` that does not itself name an exit node
/// is refused even when one is already persisted (Go's `up` would have cleared it anyway; re-passing
/// `--exit-node` is the answer in both). The negative form (`--no-exit-node-allow-lan-access`, Go's
/// `--exit-node-allow-lan-access=false`) turns the setting OFF and needs no exit node, so it passes.
///
/// `--clear-exit-node` is this fork's spelling of Go's `--exit-node=""`, which lands on the same
/// empty `exitNodeIP` — so it is refused alongside it rather than treated as naming an exit node.
///
/// The refusal is `up`-only, exactly as in Go: `prefsFromUpArgs` is not on the `set` path, so
/// `tnet set --exit-node-allow-lan-access` stays accepted (it edits one pref on an existing node).
///
/// The message goes to **stderr** and the caller exits **1**, matching Go's error return from
/// `prefsFromUpArgs` (printed by the CLI's top-level error handler) rather than clap's stderr +
/// exit 2 — which is why this is a hand-rolled check and not an `#[arg(requires = ...)]`. Pure →
/// unit-testable.
fn up_usage_refusal(
    exit_node: Option<&str>,
    clear_exit_node: bool,
    exit_node_allow_lan_access: Option<bool>,
) -> Option<&'static str> {
    // Go's `exitNodeIP != ""`: an exit node is named only by a non-empty selector. `--clear-exit-node`
    // is the empty selector, so it names none.
    let names_exit_node = !clear_exit_node && exit_node.is_some_and(|sel| !sel.trim().is_empty());
    if exit_node_allow_lan_access == Some(true) && !names_exit_node {
        return Some("--exit-node-allow-lan-access can only be used with --exit-node");
    }
    None
}

/// `up` (Go `tailscale up`): bring the node up / re-apply prefs. Runs the two SSH-risk pre-flight
/// gates, resolves the auth key, builds the wire `Request::Up`, round-trips it, then renders the
/// reply. On a successful `Ok`, a keyless (interactive) up polls `status` to surface the login URL,
/// and `--timeout` bounds a client-side wait for Running. The accidental-revert guard
/// (`RevertGuard`) and `Error` both exit non-zero without changing the node. The pre-flight ORDER is
/// load-bearing: usage refusal → force-reauth refusal → SSH-toggle gate → `--timeout` capture →
/// authkey resolution → interactive flag → build request. The usage refusal comes first because it
/// is the only one that judges the command line alone (Go decides it in `prefsFromUpArgs`, before it
/// asks the daemon anything), so a malformed invocation never reaches a risk prompt about a node it
/// was never going to touch.
#[allow(clippy::too_many_arguments)]
async fn run_up(
    socket: &std::path::Path,
    authkey: Option<String>,
    authkey_file: Option<std::path::PathBuf>,
    hostname: Option<String>,
    control_url: Option<String>,
    tun: bool,
    no_tun: bool,
    tun_name: Option<String>,
    tun_mtu: Option<u16>,
    exit_node: Option<String>,
    clear_exit_node: bool,
    advertise_exit_node: bool,
    no_advertise_exit_node: bool,
    advertise_routes: Vec<String>,
    advertise_routes_clear: bool,
    advertise_tags: Vec<String>,
    advertise_tags_clear: bool,
    accept_routes: bool,
    no_accept_routes: bool,
    accept_dns: bool,
    no_accept_dns: bool,
    shields_up: bool,
    no_shields_up: bool,
    ssh: bool,
    no_ssh: bool,
    up_prefs: UpPrefFlags,
    reset: bool,
    force_reauth: bool,
    ephemeral: bool,
    no_ephemeral: bool,
    timeout: Option<u64>,
    accept_risk: Option<String>,
    wif: WifFlags,
    json: bool,
    ported: PortedUpFlags,
) -> Result<()> {
    // The two Go `up` spellings this build carries with no pref behind them (see `PortedUpFlags`):
    // Go decides both in its flag parser, before `runUp` looks at anything, so they are gated here
    // ahead of every other check — a `--host-routes=false` command line must not first be told
    // about some other flag it also got wrong.
    check_ported_up_flags(&ported)?;
    // Go's own flag refusal first (stderr + exit 1), before any risk gate or daemon round-trip —
    // see `up_usage_refusal` for the ported check and why it is `up`-only.
    if let Some(message) = up_usage_refusal(
        exit_node.as_deref(),
        clear_exit_node,
        up_prefs.exit_node_allow_lan_access,
    ) {
        eprintln!("{message}");
        std::process::exit(1);
    }
    // Risk gate (Go `--accept-risk`/`riskLoseSSH`): `--force-reauth` re-registers the node,
    // which can drop the very Tailscale-SSH session you're typing from. Refuse it over such a
    // session unless the operator pre-accepted `lose-ssh` (or `all`). Detected entirely
    // CLI-side from `$SSH_CLIENT` (like Go's `isSSHOverTailscale`), BEFORE anything reaches the
    // daemon. Unlike Go's interactive y/N, this daemon CLI refuses non-interactively (it has no
    // TTY-prompt path) — faithful to Go's own non-interactive branch + the same flag/values.
    if force_reauth
        && is_ssh_over_tailscale()
        && !risk_accepted(accept_risk.as_deref().unwrap_or(""), "lose-ssh")
    {
        eprintln!(
            "refusing --force-reauth: you appear to be connected over a Tailscale SSH \
             session, and re-registering the node may drop it (you could lock yourself out)."
        );
        eprintln!("To override, re-run with --accept-risk=lose-ssh");
        std::process::exit(1);
    }
    // Risk gate 2 (Go `presentSSHToggleRisk`): toggling the Tailscale SSH server over a
    // Tailscale SSH session reroutes/drops that session. Refuse unless `--accept-risk=lose-ssh`.
    // Short-circuits (no daemon call) unless `--ssh`/`--no-ssh` is mentioned, we're over SSH,
    // and the risk wasn't accepted; only then does it read `haveSSH` to compare. Runs before
    // the request is built, so a refusal changes nothing on the node. (bead tsd-eqx)
    refuse_ssh_toggle_risk_if_needed(socket, resolve_ssh(ssh, no_ssh), accept_risk.as_deref())
        .await?;
    // `--timeout` is a CLIENT-SIDE wait, not a pref and not a wire field: capture it so the
    // post-`up` success path waits for Running (Go `up --timeout`). `None` here means the post-up
    // path will not wait; `Some(secs)` arms the wait (0 = forever, per `wait_for_running`).
    let up_timeout = timeout;
    // Resolve the secret through the precedence chain and hold it as a `SecretString`
    // (zeroized on drop, never `Debug`-printed). Expose it only here, at the moment we
    // serialize the wire `Request` — the field on the wire stays a plain `Option<String>`.
    let authkey = resolve_authkey(authkey, authkey_file).await?;
    // `--force-reauth` re-registers fresh; with no authkey that is an interactive login (the
    // daemon wipes the key, the engine reaches NeedsLogin, and the poll below surfaces the new
    // auth URL) — exactly the keyless-up interactive path, so the same `interactive_up` gate
    // (authkey absent) drives it. No separate polling logic is needed for force-reauth.
    let interactive_up = authkey.is_none();
    let request = Request::Up {
        authkey: authkey.map(|k| k.expose_secret().to_owned()),
        control_url,
        hostname,
        // `--tun` → Some(true) (enable); `--no-tun` → Some(false) (disable); neither →
        // None (leave the pref unchanged), so `tnet up` without either flag never silently
        // flips a TUN node. clap's `conflicts_with` guarantees the two are never both set.
        tun: resolve_tun(tun, no_tun),
        tun_name,
        tun_mtu,
        // `--exit-node <sel>` sets, `--clear-exit-node` stops using one, neither leaves it
        // unchanged; clap's `conflicts_with` guarantees the two are never both set.
        exit_node: resolve_exit_node(exit_node, clear_exit_node),
        // `--advertise-exit-node`/`--no-advertise-exit-node` tri-state (mirrors `--tun`).
        advertise_exit_node: resolve_advertise_exit_node(
            advertise_exit_node,
            no_advertise_exit_node,
        ),
        // Passed routes replace the set; `--advertise-routes-clear` empties it; neither
        // leaves the persisted set unchanged.
        advertise_routes: resolve_list_or_clear(advertise_routes, advertise_routes_clear),
        // Passed tags replace the set; `--clear-advertise-tags` empties it; neither leaves it
        // unchanged. Reuses the same Vec+clear→Option resolver as advertise-routes.
        advertise_tags: resolve_list_or_clear(advertise_tags, advertise_tags_clear),
        // `--accept-routes`/`--no-accept-routes` tri-state (mirrors `--tun`); reuses the same
        // resolver as the `set` arm.
        accept_routes: resolve_accept_routes(accept_routes, no_accept_routes),
        // `--accept-dns`/`--no-accept-dns` tri-state (default-on; mirrors the `set` arm).
        accept_dns: resolve_accept_dns(accept_dns, no_accept_dns),
        // `--shields-up`/`--no-shields-up` tri-state (mirrors `--tun`); reuses the same
        // resolver as the `set` arm.
        shields_up: resolve_shields_up(shields_up, no_shields_up),
        // `--ssh`/`--no-ssh` tri-state (mirrors `--tun`).
        ssh: resolve_ssh(ssh, no_ssh),
        // The four Go pref flags `up` shares with `set`, already resolved into their wire sentinels
        // in `main`'s `Command::Up` arm and carried here by name (see `UpPrefFlags`).
        operator: up_prefs.operator,
        exit_node_allow_lan_access: up_prefs.exit_node_allow_lan_access,
        advertise_connector: up_prefs.advertise_connector,
        report_posture: up_prefs.report_posture,
        // `--reset`: reset unmentioned settings to default + bypass the accidental-revert
        // guard. A plain bool flag (Go's `--reset`), passed straight through.
        reset,
        // `--force-reauth`: discard the node key so the bring-up re-registers fresh (new
        // login). A plain bool flag (Go's `--force-reauth`), passed straight through.
        force_reauth,
        // `--ephemeral`/`--no-ephemeral` tri-state (registration-time intent; default persistent).
        ephemeral: resolve_ephemeral(ephemeral, no_ephemeral),
        // Workload-identity-federation creds (Go `--client-id/--client-secret/--id-token/--audience`):
        // registration-time only, NOT prefs. Expose the two secrets only here, at wire-serialize time
        // (the wire field is a plain `Option<String>`, like `authkey` above); `client_id`/`audience`
        // are non-secret identifiers. All absent in the common (authkey/interactive) case.
        client_id: wif.client_id,
        client_secret: wif
            .client_secret
            .as_ref()
            .map(|s| s.expose_secret().to_owned()),
        id_token: wif.id_token.as_ref().map(|s| s.expose_secret().to_owned()),
        audience: wif.audience,
    };
    let response = round_trip(socket, &request)
        .await
        .with_context(|| format!("talking to daemon at {}", socket.display()))?;
    match response {
        Response::Ok { message } => {
            // Human mode prints the `ok:` acknowledgement; JSON mode emits NO human chatter — only
            // the terminal JSON object below — so suppress it (Go `up --json` likewise prints just the
            // JSON, no "Success." line).
            if !json {
                println!("ok: {message}");
            }
            // Interactive login: an authkey-less `up` succeeds at the daemon, but the node now needs
            // a human to authorize it. The auth URL isn't known yet at `up`-time — it arrives once
            // the engine reaches `NeedsLogin` — so poll `status` briefly to surface it (or a
            // terminal registration failure).
            if interactive_up {
                match poll_for_auth_url(socket).await {
                    AuthOutcome::Url(url) => {
                        if json {
                            // Go's auth-URL JSON path: `{AuthURL, BackendState}`. An auth URL is only
                            // ever set in the `NeedsLogin` state (the engine reports
                            // `DeviceState::NeedsLogin(url)`), so emit that state literal rather than
                            // burning a second status round-trip just to read back a value we already
                            // know — simple and correct.
                            println!("{}", up_json_string(Some(&url), Some("NeedsLogin"), None));
                        } else {
                            println!();
                            println!("To authenticate this node, visit:");
                            println!("    {url}");
                            println!();
                            println!(
                                "(the node will finish connecting automatically once authorized; \
                                  run `tnet status` to check)"
                            );
                        }
                    }
                    AuthOutcome::Failed(reason) => {
                        // Registration hard-failed. An interactive `up` that terminally fails must
                        // not exit 0 implying success, and must not tell the operator to log in —
                        // re-running with the same key loops forever. Surface the reason and exit
                        // non-zero (mirroring the `Response::Error` path below).
                        if json {
                            // Go's `printUpDoneJSON` on failure: `{BackendState, Error}`. Fetch the
                            // daemon's actual state string for fidelity (a terminal failure leaves the
                            // engine in a canonical `ipn.State`); if the status round-trip is
                            // unavailable, omit BackendState and still report the Error. The reason is
                            // control-influenced, so sanitize it (same as the human branch).
                            let state = fetch_backend_state(socket).await;
                            println!(
                                "{}",
                                up_json_string(
                                    None,
                                    state.as_deref(),
                                    Some(&sanitize_multiline(&reason)),
                                )
                            );
                        } else {
                            eprintln!();
                            eprintln!("registration failed: {}", sanitize_multiline(&reason));
                            eprintln!(
                                "(this is a permanent failure — re-run `tnet up --authkey <NEW_KEY>` \
                                 with a fresh key; the same key will keep failing)"
                            );
                        }
                        std::process::exit(1);
                    }
                    AuthOutcome::None => {}
                }
            }
            // `up --timeout`: bound the wait for the node to reach Running (Go `tailscale up
            // --timeout`). Only an `up` that passed `--timeout` arms this (`up_timeout` is `None` for
            // an `up` without the flag, preserving the fire-and-return default). The auth URL above is
            // printed FIRST, so an interactive up still surfaces it before waiting (Go waits for
            // Running regardless of interactive vs keyed). A timeout is a non-zero exit — the daemon
            // accepted the up, but the node did not come up in time.
            if let Some(secs) = up_timeout
                && let Err(e) = wait_for_running(socket, Some(secs)).await
            {
                // A timeout failing the wait is a terminal `up` failure. In JSON mode report it as
                // `{BackendState, Error}` (Go's `printUpDoneJSON` error path) rather than the human
                // stderr line; the daemon accepted the up but the node never reached Running.
                if json {
                    let state = fetch_backend_state(socket).await;
                    println!(
                        "{}",
                        up_json_string(None, state.as_deref(), Some(&format!("{e:#}")))
                    );
                } else {
                    eprintln!("{e:#}");
                }
                std::process::exit(1);
            }
            // Successful done path. In JSON mode, mirror Go's `printUpDoneJSON` on success:
            // `{BackendState}` (the daemon's current state string). Fetch it via a status round-trip
            // for fidelity rather than assuming "Running" — a non-`--timeout` up returns the instant
            // the daemon accepts it, so the node may still be `Starting`; reporting the real state is
            // the faithful choice. If status is momentarily unavailable, the object is empty (`{}`),
            // never a fabricated state.
            if json {
                let state = fetch_backend_state(socket).await;
                println!("{}", up_json_string(None, state.as_deref(), None));
            }
            Ok(())
        }
        // The daemon refused an `up` that would silently revert non-default settings the command did
        // not mention (Go's accidental-revert guard). Render Go's guidance with a copy-pasteable
        // command and exit non-zero — nothing was changed on the node.
        Response::RevertGuard { reverts } => {
            if json {
                // This guard is a fork-specific pre-flight refusal with no Go-CLI equivalent in the
                // same shape, so there is no Go JSON to mirror. In JSON mode, collapse the full human
                // guide to a single short `{Error}` (JSON mode emits only JSON objects, never the
                // multi-line copy-pasteable guide); the human path keeps the full guidance.
                println!(
                    "{}",
                    up_json_string(
                        None,
                        None,
                        Some(
                            "refusing to revert unmentioned settings; re-run with --reset or \
                             re-state them (run `tnet up` without --json to see the full guidance)",
                        ),
                    )
                );
            } else {
                eprint!("{}", format_revert_guard(&reverts));
            }
            std::process::exit(1);
        }
        Response::Error { message } => {
            // Go's `printUpDoneJSON` carries the daemon state, but a transport/daemon-refusal
            // `Response::Error` gives us only a message (no state), so the faithful JSON shape here is
            // `{Error}` alone. Human mode keeps the existing `error:` stderr line.
            if json {
                println!("{}", up_json_string(None, None, Some(&message)));
            } else {
                eprintln!("error: {message}");
            }
            std::process::exit(1);
        }
        other => anyhow::bail!("unexpected response to up: {other:?}"),
    }
}

/// Best-effort fetch of the daemon's current IPN state string (`BackendState`) for `up --json`'s
/// `{BackendState}` field. Does a single read-only `status` round-trip and returns the `state`
/// (one of the seven [`crate::ipn::State`] names, e.g. `Running`/`Starting`/`NeedsLogin`); on any
/// transport error it returns `None` so the caller simply omits the field rather than fabricating a
/// state. Kept separate from [`poll_for_auth_url`] (which classifies into an [`AuthOutcome`]) because
/// the JSON paths want the raw state string, exactly as Go reads `st.BackendState`.
async fn fetch_backend_state(socket: &std::path::Path) -> Option<String> {
    match round_trip(socket, &Request::Status).await {
        Ok(Response::Status(s)) => Some(s.state),
        _ => None,
    }
}

/// Build the `tnet up --json` output object as a pretty-printed JSON string, mirroring Go
/// `up --json`'s `upOutputJSON` (`{AuthURL, BackendState, Error}`). Each field is omitted when absent
/// **or empty**, matching Go's `,omitempty` on every field; an all-empty call yields `{}`. The `QR`
/// field Go gates behind `HasQRCodes` is intentionally absent in this fork (no QR encoder) — the same
/// reduced shape as a Go build without that build tag.
///
/// Pure (no I/O) so the shape is unit-testable without a socket. Uses `serde_json` for escape-safe
/// encoding; 2-space pretty (Go uses a tab on the auth-URL path and 2-space on the done path — the
/// exact indent is not load-bearing, so this fork is consistently 2-space, the `serde_json` default).
/// A serialization failure (not reachable for a flat string map) degrades to `{}` rather than panics.
fn up_json_string(
    auth_url: Option<&str>,
    backend_state: Option<&str>,
    error: Option<&str>,
) -> String {
    let mut map = serde_json::Map::new();
    // `,omitempty` semantics: skip both `None` and `Some("")`.
    let mut insert_nonempty = |key: &str, val: Option<&str>| {
        if let Some(v) = val
            && !v.is_empty()
        {
            map.insert(key.to_owned(), serde_json::Value::String(v.to_owned()));
        }
    };
    insert_nonempty("AuthURL", auth_url);
    insert_nonempty("BackendState", backend_state);
    insert_nonempty("Error", error);
    serde_json::to_string_pretty(&map).unwrap_or_else(|_| "{}".to_string())
}

/// `login` (Go `tailscale login`): (re)authenticate this node **without changing any prefs** — the
/// auth half of `up` on its own. Resolves the auth key through the usual precedence
/// (`--authkey-file` > `--authkey` > `$TS_AUTH_KEY`); with none, it is an interactive login (the
/// control auth URL is printed). Sends an `up` request that **mentions no pref** (so the
/// accidental-revert guard never fires — a no-pref `up` is exempt) with `force_reauth: true` so the
/// node re-authenticates even if it already holds a key (mirroring Go `login` →
/// `StartLoginInteractive`). Reuses `poll_for_auth_url` to surface the URL, exactly like an
/// interactive `up`.
async fn run_login(
    socket: &std::path::Path,
    authkey: Option<String>,
    authkey_file: Option<std::path::PathBuf>,
    login_server: Option<String>,
) -> Result<()> {
    // Refuse a re-auth that could drop the very Tailscale-SSH session we're on (same gate as `up
    // --force-reauth`): `login` re-registers the node. Without an explicit accept-risk flag on
    // `login` (Go's `login` has no such flag — it always StartLoginInteractive), we mirror `up`'s
    // safety by refusing over a detected Tailscale SSH session.
    if is_ssh_over_tailscale() {
        eprintln!(
            "refusing `login`: you appear to be connected over a Tailscale SSH session, and \
             re-authenticating may drop it (you could lock yourself out). Run it from a local \
             console, or use `tnet up --force-reauth --accept-risk=lose-ssh` if you accept the risk."
        );
        std::process::exit(1);
    }
    // Resolve the secret (zeroized `SecretString`); `None` → interactive login.
    let authkey = resolve_authkey(authkey, authkey_file).await?;
    let interactive = authkey.is_none();
    // An `up` that mentions NO pref (every override `None`) + force_reauth: just (re)authenticate.
    // `force_reauth` is not a "mentioned pref", so the no-pref shape keeps the accidental-revert
    // guard from firing — `login` must never refuse-to-revert; it changes nothing but auth state.
    let request = Request::Up {
        authkey: authkey.as_ref().map(|k| k.expose_secret().to_owned()),
        control_url: login_server,
        hostname: None,
        tun: None,
        tun_name: None,
        tun_mtu: None,
        exit_node: None,
        advertise_exit_node: None,
        advertise_routes: None,
        advertise_tags: None,
        accept_routes: None,
        accept_dns: None,
        shields_up: None,
        ssh: None,
        operator: None,
        exit_node_allow_lan_access: None,
        advertise_connector: None,
        report_posture: None,
        reset: false,
        force_reauth: true,
        ephemeral: None,
        client_id: None,
        client_secret: None,
        id_token: None,
        audience: None,
    };
    match round_trip(socket, &request)
        .await
        .with_context(|| format!("talking to daemon at {}", socket.display()))?
    {
        Response::Ok { message } => {
            println!("ok: {message}");
            // Interactive login → surface the control auth URL once the engine reaches NeedsLogin.
            if interactive {
                match poll_for_auth_url(socket).await {
                    AuthOutcome::Url(url) => {
                        println!();
                        println!("To authenticate this node, visit:");
                        println!("    {url}");
                        println!();
                        println!(
                            "(the node will finish connecting automatically once authorized; \
                             run `tnet status` to check)"
                        );
                    }
                    AuthOutcome::Failed(reason) => {
                        eprintln!();
                        eprintln!("login failed: {}", sanitize_multiline(&reason));
                        std::process::exit(1);
                    }
                    AuthOutcome::None => {}
                }
            }
            Ok(())
        }
        Response::Error { message } => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        // `login` mentions no pref, so the revert guard never triggers; any other reply is unexpected.
        other => anyhow::bail!("unexpected response to login: {other:?}"),
    }
}

/// `set` (Go `tailscale set`): patch individual prefs on an already-configured node — never
/// (re)authenticates, never changes up/down. Runs the SSH-toggle risk gate and then the unmodelled-
/// flag gate ([`check_unmodelled_set_flags`]) BEFORE building the request (so a refusal changes
/// nothing), builds the wire `Request::Set`, round-trips it, then
/// renders the reply: `Ok` acknowledges, the accidental-revert guard (`RevertGuard`) and `Error`
/// both exit non-zero without changing the node.
#[allow(clippy::too_many_arguments)]
async fn run_set(
    socket: &std::path::Path,
    hostname: Option<String>,
    accept_routes: bool,
    no_accept_routes: bool,
    accept_dns: bool,
    no_accept_dns: bool,
    shields_up: bool,
    no_shields_up: bool,
    exit_node: Option<String>,
    clear_exit_node: bool,
    advertise_exit_node: bool,
    no_advertise_exit_node: bool,
    advertise_routes: Vec<String>,
    advertise_routes_clear: bool,
    advertise_tags: Vec<String>,
    advertise_tags_clear: bool,
    ssh: bool,
    no_ssh: bool,
    set_prefs: SetPrefFlags,
    unmodelled: UnmodelledSetFlags,
    accept_risk: Option<String>,
) -> Result<()> {
    // Risk gate (Go `presentSSHToggleRisk`, the `set` call site): toggling the Tailscale SSH
    // server over a Tailscale SSH session reroutes/drops that session — refuse unless
    // `--accept-risk=lose-ssh`. Short-circuits (no daemon call) unless `--ssh`/`--no-ssh` is
    // mentioned, we're over SSH, and the risk wasn't accepted. Runs before the request is
    // built, so a refusal changes nothing. (bead tsd-eqx — same enforcement as the `up` path.)
    refuse_ssh_toggle_risk_if_needed(socket, resolve_ssh(ssh, no_ssh), accept_risk.as_deref())
        .await?;
    // The four Go `set` pref flags this build models no pref for: Go's own parsing, then this
    // build's named refusal. Go's `runSet` runs the same parses AFTER the risk gate above and
    // before `EditPrefs`, so the ordering — and the fact that a refusal here changes nothing on the
    // node — matches upstream.
    check_unmodelled_set_flags(&unmodelled)?;
    let request = Request::Set {
        hostname,
        // `--accept-routes`/`--no-accept-routes` tri-state (mirrors `--tun`).
        accept_routes: resolve_accept_routes(accept_routes, no_accept_routes),
        // `--accept-dns`/`--no-accept-dns` tri-state (default-on).
        accept_dns: resolve_accept_dns(accept_dns, no_accept_dns),
        // `--shields-up`/`--no-shields-up` tri-state (mirrors `--tun`).
        shields_up: resolve_shields_up(shields_up, no_shields_up),
        // `--exit-node <sel>` sets, `--clear-exit-node` stops using one, neither leaves it
        // unchanged; clap's `conflicts_with` guarantees the two are never both set. Reuses the
        // same resolver as the `up` arm.
        exit_node: resolve_exit_node(exit_node, clear_exit_node),
        // `--advertise-exit-node`/`--no-advertise-exit-node` tri-state (mirrors `--tun`).
        advertise_exit_node: resolve_advertise_exit_node(
            advertise_exit_node,
            no_advertise_exit_node,
        ),
        // Passed routes replace the set; `--advertise-routes-clear` empties it; neither leaves
        // the persisted set unchanged.
        advertise_routes: resolve_list_or_clear(advertise_routes, advertise_routes_clear),
        // Passed tags replace the set; `--clear-advertise-tags` empties it; neither unchanged.
        advertise_tags: resolve_list_or_clear(advertise_tags, advertise_tags_clear),
        // `--ssh`/`--no-ssh` tri-state (mirrors `--tun`).
        ssh: resolve_ssh(ssh, no_ssh),
        // The eight newer Go `set` pref flags, already resolved into their wire sentinels in `main`'s
        // `Command::Set` arm and carried here by name (see `SetPrefFlags`).
        advertise_connector: set_prefs.advertise_connector,
        auto_update: set_prefs.auto_update,
        update_check: set_prefs.update_check,
        operator: set_prefs.operator,
        nickname: set_prefs.nickname,
        report_posture: set_prefs.report_posture,
        webclient: set_prefs.webclient,
        exit_node_allow_lan_access: set_prefs.exit_node_allow_lan_access,
    };
    let response = round_trip(socket, &request)
        .await
        .with_context(|| format!("talking to daemon at {}", socket.display()))?;
    match response {
        Response::Ok { message } => {
            println!("ok: {message}");
            Ok(())
        }
        // The daemon refused a `set` that would silently revert non-default settings the command did
        // not mention (Go's accidental-revert guard). Render Go's guidance + exit non-zero — nothing
        // was changed on the node.
        Response::RevertGuard { reverts } => {
            eprint!("{}", format_revert_guard(&reverts));
            std::process::exit(1);
        }
        Response::Error { message } => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        other => anyhow::bail!("unexpected response to set: {other:?}"),
    }
}

/// `status` (Go `tailscale status`): render the node + peer table. `--web` serves a long-lived
/// embedded HTTP page and `--watch` streams updates (both return without the one-shot path); plain
/// `status` round-trips one `Status`, applies the client-side `--active`/`--no-peers`/`--no-self`
/// filters, then renders the human table or (`--json`) the Go `ipnstate.Status`-shaped object.
#[allow(clippy::too_many_arguments)]
async fn run_status(
    socket: &std::path::Path,
    watch: bool,
    json: bool,
    active: bool,
    no_peers: bool,
    no_self: bool,
    web: bool,
    listen: Option<String>,
    browser: bool,
) -> Result<()> {
    // `status --web` is a long-lived embedded HTTP server, not a one-shot — handle it here and
    // return (like --watch). Default listen 127.0.0.1:8384; the browser opens unless it was turned
    // off (`--no-browser`, or Go's `--browser=false`).
    if web {
        let listen = listen.unwrap_or_else(|| "127.0.0.1:8384".to_string());
        // `status --web` serves at `/` (no path prefix) and has no `--origin` of its own — Go
        // registers that flag on `web`, not on `status`.
        return run_status_web(socket, &listen, browser, "/", None)
            .await
            .with_context(|| format!("serving status --web on {listen}"));
    }
    let status_filter = StatusFilter {
        active_only: active,
        hide_peers: no_peers,
        hide_self: no_self,
    };
    if watch {
        // `--watch` honors `--json` and the `--active`/`--no-peers`/`--no-self` filters per frame,
        // matching Go (`tailscale status --watch --json` streams JSON; the filters apply to each
        // pushed snapshot). The filter is moved in (it is not used again on this path).
        return watch_status(socket, json, status_filter)
            .await
            .with_context(|| format!("watching status at {}", socket.display()));
    }
    let response = round_trip(socket, &Request::Status)
        .await
        .with_context(|| format!("talking to daemon at {}", socket.display()))?;
    match response {
        Response::Status(s) => {
            // Apply the client-side --active / --no-peers / --no-self filters before rendering, so
            // both the human and --json paths honor them identically.
            let s = status_filter.apply(s);
            if json {
                // Go `status --json`: the ipnstate.Status-shaped object (faithful subset).
                match format_status_json(&s) {
                    Ok(out) => print!("{out}"),
                    Err(e) => {
                        eprintln!("error: serializing status: {e}");
                        std::process::exit(1);
                    }
                }
            } else {
                print_status(&s);
            }
            Ok(())
        }
        Response::Error { message } => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        other => anyhow::bail!("unexpected response to status: {other:?}"),
    }
}

/// `debug capture`: send DebugCapture (a long-lived write — the daemon taps the dataplane for
/// `seconds`, then replies with the byte count).
async fn run_debug_capture(
    socket: &std::path::Path,
    path: std::path::PathBuf,
    seconds: u64,
) -> Result<()> {
    let path = path.to_string_lossy().into_owned();
    let resp = round_trip(
        socket,
        &Request::DebugCapture {
            path,
            seconds: Some(seconds),
        },
    )
    .await
    .with_context(|| format!("debug capture via {}", socket.display()))?;
    match resp {
        Response::Ok { message } => {
            println!("{message}");
            Ok(())
        }
        Response::Error { message } => anyhow::bail!("debug capture failed: {message}"),
        other => anyhow::bail!("unexpected response to debug capture: {other:?}"),
    }
}

/// `debug prefs` (Go `tailscale debug prefs`): round-trip `GetPrefs` and print the prefs view as
/// pretty JSON. The raw-object counterpart to `tnet get`'s human/flag rendering — same data
/// (`Response::Prefs`), different shape, for scripting/debugging. Read-only.
async fn run_debug_prefs(socket: &std::path::Path) -> Result<()> {
    let view = match round_trip(socket, &Request::GetPrefs).await {
        Ok(Response::Prefs(v)) => v,
        Ok(Response::Error { message }) => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        Ok(other) => anyhow::bail!("unexpected response to debug prefs: {other:?}"),
        Err(e) => {
            return Err(e).with_context(|| format!("getting prefs at {}", socket.display()));
        }
    };
    // Pretty JSON of the prefs view (Go's `json.MarshalIndent(prefs, "", "\t")`). `PrefsView` is a
    // plain serde struct, so this cannot fail in practice; fall back to `{}` rather than panic.
    println!(
        "{}",
        serde_json::to_string_pretty(&view).unwrap_or_else(|_| "{}".to_string())
    );
    Ok(())
}

/// `debug rebind` (Go `tailscale debug rebind`): ask the daemon to re-create the engine's UDP
/// sockets. A write (gated root/same-uid by the daemon); needs the node up. Prints the daemon's
/// confirmation, or surfaces a clear error (node down / not authorized / engine failure).
async fn run_debug_rebind(socket: &std::path::Path) -> Result<()> {
    match round_trip(socket, &Request::DebugRebind).await {
        Ok(Response::Ok { message }) => {
            println!("{message}");
            Ok(())
        }
        Ok(Response::Error { message }) => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        Ok(other) => anyhow::bail!("unexpected response to debug rebind: {other:?}"),
        Err(e) => Err(e).with_context(|| format!("requesting rebind at {}", socket.display())),
    }
}

/// `debug restun` (Go `tailscale debug restun`): ask the daemon to force a STUN re-probe without
/// rebinding the socket. A write (gated root/same-uid by the daemon); needs the node up. Prints the
/// daemon's confirmation, or surfaces a clear error (node down / not authorized / engine failure).
/// Mirrors [`run_debug_rebind`]'s Ok/Error shape.
async fn run_debug_restun(socket: &std::path::Path) -> Result<()> {
    match round_trip(socket, &Request::DebugReStun).await {
        Ok(Response::Ok { message }) => {
            println!("{message}");
            Ok(())
        }
        Ok(Response::Error { message }) => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        Ok(other) => anyhow::bail!("unexpected response to debug restun: {other:?}"),
        Err(e) => Err(e).with_context(|| format!("requesting restun at {}", socket.display())),
    }
}

/// `reload-config` (Go `tailscaled`'s `reload-config`): ask the daemon to re-read its `--config` file
/// and adopt the changes into the running node. Prints the daemon's confirmation on success; on the
/// daemon's error (no `--config` in use, or a now-malformed file — the node is left untouched in both
/// cases) it prints the message and exits 1. Mirrors `run_debug_rebind`'s Ok/Error shape.
async fn run_reload_config(socket: &std::path::Path) -> Result<()> {
    match round_trip(socket, &Request::ReloadConfig).await {
        Ok(Response::Ok { message }) => {
            println!("{message}");
            Ok(())
        }
        Ok(Response::Error { message }) => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        Ok(other) => anyhow::bail!("unexpected response to reload-config: {other:?}"),
        Err(e) => {
            Err(e).with_context(|| format!("requesting reload-config at {}", socket.display()))
        }
    }
}

/// `debug check-ip-forwarding` (Go `check-ip-forwarding`): print the OS IP-forwarding readiness
/// warning, or "IP forwarding looks OK" when empty. A diagnostic — exit 0 either way (a warning is
/// informational, not an error), matching how Go surfaces it as a non-fatal notice on `up`/`set`.
async fn run_check_ip_forwarding(socket: &std::path::Path) -> Result<()> {
    match round_trip(socket, &Request::CheckIpForwarding).await {
        Ok(Response::IpForwardingCheck { warning }) => {
            if warning.is_empty() {
                println!("IP forwarding looks OK (or is not applicable in this mode).");
            } else {
                println!("{warning}");
            }
            Ok(())
        }
        Ok(Response::Error { message }) => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        Ok(other) => anyhow::bail!("unexpected response to check-ip-forwarding: {other:?}"),
        Err(e) => Err(e).with_context(|| format!("checking IP forwarding at {}", socket.display())),
    }
}

/// `debug check-prefs` (Go `check-prefs`): validate a prospective prefs change without applying it.
/// Prints the daemon's confirmation on success, or the violation(s) + exit 1 on a conflict — the same
/// fail-fast contract `up`/`set` use internally.
async fn run_check_prefs(
    socket: &std::path::Path,
    exit_node: Option<String>,
    advertise_exit_node: Option<bool>,
    advertise_routes: Option<Vec<String>>,
    ssh: Option<bool>,
) -> Result<()> {
    // A bare `--exit-node ""` clears (Set's double-option convention); a present value sets it.
    let exit_node = exit_node.map(|s| if s.is_empty() { None } else { Some(s) });
    let req = Request::CheckPrefs {
        exit_node,
        advertise_exit_node,
        advertise_routes,
        ssh,
    };
    match round_trip(socket, &req).await {
        Ok(Response::Ok { message }) => {
            println!("{message}");
            Ok(())
        }
        Ok(Response::Error { message }) => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        Ok(other) => anyhow::bail!("unexpected response to check-prefs: {other:?}"),
        Err(e) => Err(e).with_context(|| format!("checking prefs at {}", socket.display())),
    }
}

/// `debug env` (Go `tailscale debug env`): print this CLI process's Tailscale-relevant environment +
/// build version. Purely local — no daemon round-trip (Go's `debug env` likewise dumps the process
/// environment). We print the daemon/client `TS_*` / `TAILNETD_*` knobs (each as `NAME=value` when
/// set, or `NAME (unset)` when absent) so an operator can see exactly which env is in effect; nothing
/// is mutated. Values are printed verbatim — these are the operator's own env, not off-box data.
fn run_debug_env() {
    // The Tailscale/daemon-relevant env vars, in a stable order. This is the set that actually
    // influences `tnet`/`tailnetd` resolution (control URL, socket, state dir, log filter, the
    // experiment gate, the auth-key fallback) — the faithful analogue of Go dumping its `TS_*` knobs.
    const VARS: &[&str] = &[
        "TS_RS_EXPERIMENT",
        "TS_CONTROL_URL",
        "TS_AUTH_KEY",
        "TAILNETD_SOCKET",
        "TAILNETD_STATE_DIR",
        "TAILNETD_LOG",
        "TAILNETD_NO_HARDEN",
    ];
    println!("tnet {} (client build)", env!("CARGO_PKG_VERSION"));
    for name in VARS {
        match std::env::var(name) {
            // Never print a secret's value: TS_AUTH_KEY is a credential — show only set/unset, like a
            // careful `debug env` would (Go redacts auth keys in its diagnostics too).
            Ok(_) if *name == "TS_AUTH_KEY" => println!("{name}=<set, redacted>"),
            Ok(v) => println!("{name}={v}"),
            Err(_) => println!("{name} (unset)"),
        }
    }
}

/// The Tailscale 4via6 `via` range, `fd7a:115c:a1e0:b1a::/64` (Go `tsaddr.TailscaleViaRange`; "b1a"
/// ≈ "via"). A 4via6 route encodes an IPv4 CIDR + a 32-bit site id into a /64-prefixed IPv6 route so
/// that multiple subnet routers can advertise the *same* private IPv4 space without colliding.
const VIA_RANGE_PREFIX: [u8; 8] = [0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0x0b, 0x1a];

/// Encode `(site_id, v4)` into a 4via6 IPv6 `via` route (Go `tsaddr.MapVia`). Layout (16 bytes):
/// `[0..8] = via prefix`, `[8..12] = site id big-endian`, `[12..16] = the IPv4 address`. The result
/// prefix length is the v4 prefix bits + 96 (64 for the via prefix + 32 for the site id). Errors if
/// `v4` is not an IPv4 prefix.
fn map_via(site_id: u32, v4: &ipnet::Ipv4Net) -> Result<ipnet::Ipv6Net> {
    let mut bytes = [0u8; 16];
    bytes[0..8].copy_from_slice(&VIA_RANGE_PREFIX);
    bytes[8..12].copy_from_slice(&site_id.to_be_bytes());
    bytes[12..16].copy_from_slice(&v4.addr().octets());
    let addr = std::net::Ipv6Addr::from(bytes);
    // v4.prefix_len() is 0..=32; +96 stays within the u8 IPv6 prefix range (max 128).
    let prefix = v4.prefix_len() + 96;
    ipnet::Ipv6Net::new(addr, prefix).context("constructing the 4via6 route")
}

/// Decode a 4via6 IPv6 `via` route back to `(site_id, IPv4-CIDR)` (the inverse of [`map_via`], Go
/// `tsaddr.UnmapVia` + the CLI's site-id extraction). Errors if `via` is not inside the via range or
/// is too short to carry a site id + IPv4 (Go requires `Bits() >= 96`).
fn unmap_via(via: &ipnet::Ipv6Net) -> Result<(u32, ipnet::Ipv4Net)> {
    let octets = via.addr().octets();
    if octets[0..8] != VIA_RANGE_PREFIX {
        anyhow::bail!(
            "{via} is not a 4via6 route (not within the fd7a:115c:a1e0:b1a::/64 via range)"
        );
    }
    if via.prefix_len() < 96 {
        anyhow::bail!(
            "{via} is too short to be a 4via6 route (need at least a /96 to carry the site id + IPv4)"
        );
    }
    let site_id = u32::from_be_bytes([octets[8], octets[9], octets[10], octets[11]]);
    let v4_addr = std::net::Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15]);
    // The IPv4 prefix bits are the IPv6 route's bits minus the 96 the via prefix + site id occupy.
    let v4 = ipnet::Ipv4Net::new(v4_addr, via.prefix_len() - 96)
        .context("reconstructing the IPv4 CIDR")?;
    Ok((site_id, v4))
}

/// `debug via` (Go `tailscale debug via`): 4via6 encode/decode. With one argument, decode an IPv6
/// `via` route into its site id + IPv4 CIDR; with two, encode `(site-id, IPv4-CIDR)` into the route.
/// Purely local bit-math — no daemon round-trip (matches Go).
fn run_debug_via(site_or_route: &str, cidr: Option<&str>) -> Result<()> {
    match cidr {
        // Two-arg form: `debug via <site-id> <ipv4-cidr>` → encode.
        Some(cidr) => {
            let site_id: u32 = site_or_route.parse().with_context(|| {
                format!("site id must be a non-negative integer, got {site_or_route:?}")
            })?;
            // Go rejects a site id above 0xffff (the encoding reserves 32 bits but the CLI caps it at
            // 16 to match the documented site-id space). Mirror that bound.
            if site_id > 0xffff {
                anyhow::bail!("site id {site_id} is out of range (must be 0..=65535)");
            }
            let v4: ipnet::Ipv4Net = cidr
                .parse()
                .with_context(|| format!("invalid IPv4 CIDR {cidr:?}"))?;
            let route = map_via(site_id, &v4)?;
            println!("{route}");
            Ok(())
        }
        // One-arg form: `debug via <ipv6-route>` → decode.
        None => {
            let via: ipnet::Ipv6Net = site_or_route.parse().with_context(|| {
                format!("expected an IPv6 4via6 route to decode, got {site_or_route:?}")
            })?;
            let (site_id, v4) = unmap_via(&via)?;
            println!("site {site_id} ({site_id:#x}), {v4}");
            Ok(())
        }
    }
}

/// `debug local-creds` (Go `tailscale debug local-creds`): print a ready-to-run `curl` command for the
/// LocalAPI. Purely local — it only describes the socket the CLI resolved (`--socket`/`$TAILNETD_SOCKET`
/// else the default `socket_path()`), never connecting. On this fork the LocalAPI is a Unix-domain
/// socket, so we emit Go's Unix form (`curl --unix-socket <path> http://local-tailscaled.sock/…`); Go's
/// alternate TCP-port-plus-token form is Windows-only (named-pipe / `safesocket.LocalTCPPortAndToken`)
/// and has no analogue here. The host in the URL is a placeholder the socket transport ignores — kept as
/// Go's `local-tailscaled.sock` literal so the printed command matches Go byte-for-byte where it applies.
fn run_debug_local_creds(socket: &std::path::Path) {
    println!(
        "curl --unix-socket {} http://local-tailscaled.sock/localapi/v0/status",
        socket.display()
    );
}

/// `debug stat` (Go `tailscale debug stat`): `lstat` each path and print its mode + size; for a
/// directory, list its entries (capped at 25, then `...`, matching Go). Purely local — no daemon
/// round-trip. One bad path never aborts the batch (each is reported inline). Delegates the per-path
/// formatting to the pure [`stat_report`] so the output shape is unit-testable.
fn run_debug_stat(files: &[String]) {
    for f in files {
        print!("{}", stat_report(std::path::Path::new(f)));
    }
}

/// Build the `debug stat` output for ONE path (pure → unit-testable; no stdout). `lstat`s `path`
/// (symlinks NOT followed = Go's `os.Lstat`, so a symlink reports as a symlink, not its target). On
/// success: `<path>: mode <octal>, size <n> bytes\n`, plus — for a directory — its entries (`  - <name>`,
/// capped at 25 then `  ...`, matching Go's 25-entry cap). On any error (unstattable path, or a dir that
/// cannot be read) the error is rendered inline so the caller's batch continues. The string always ends
/// in a newline.
fn stat_report(path: &std::path::Path) -> String {
    use std::fmt::Write as _;
    use std::os::unix::fs::PermissionsExt as _;
    let mut out = String::new();
    let shown = path.display();
    match std::fs::symlink_metadata(path) {
        Err(e) => {
            let _ = writeln!(out, "{shown}: {e}");
        }
        Ok(meta) => {
            // Go prints `os.FileMode` (symbolic) + size; we print the raw unix mode bits octal (like
            // `stat`/`ls`) + the size in bytes — the same two facts, in this fork's idiom.
            let mode = meta.permissions().mode();
            let _ = writeln!(out, "{shown}: mode {mode:o}, size {} bytes", meta.len());
            // For a directory, list entries — capped at 25 (Go's cap), then a trailing `  ...`.
            if meta.is_dir() {
                match std::fs::read_dir(path) {
                    Err(e) => {
                        let _ = writeln!(out, "  (cannot read directory: {e})");
                    }
                    Ok(entries) => {
                        for (i, entry) in entries.enumerate() {
                            if i >= 25 {
                                let _ = writeln!(out, "  ...");
                                break;
                            }
                            match entry {
                                Ok(e) => {
                                    let _ =
                                        writeln!(out, "  - {}", e.file_name().to_string_lossy());
                                }
                                Err(e) => {
                                    let _ = writeln!(out, "  - (unreadable entry: {e})");
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    out
}

/// How long `debug resolve` gives the host resolver before giving up (Go's
/// `context.WithTimeout(ctx, 5*time.Second)`).
const RESOLVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// The address family `debug resolve --net` selects (Go's `-net` flag: `ip`, `ip4`, `ip6`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResolveNet {
    /// `ip`: both families — whatever the resolver returns, unfiltered.
    Ip,
    /// `ip4`: IPv4 addresses only.
    Ip4,
    /// `ip6`: IPv6 addresses only.
    Ip6,
}

/// Parse `debug resolve --net`. Go hands the raw flag string to `net.DefaultResolver.LookupIP`, which
/// refuses anything outside `ip`/`ip4`/`ip6` with `UnknownNetworkError` — rendered `unknown network
/// <net>`. That is an error from the command, so it is reproduced here rather than delegated to clap.
/// Pure → unit-testable.
fn parse_resolve_net(net: &str) -> Result<ResolveNet> {
    match net {
        "ip" => Ok(ResolveNet::Ip),
        "ip4" => Ok(ResolveNet::Ip4),
        "ip6" => Ok(ResolveNet::Ip6),
        other => anyhow::bail!("unknown network {other}"),
    }
}

/// Keep only the addresses of the family `net` selects — Go's `filterAddrList` with the `ipv4only` /
/// `ipv6only` filters that `internetAddrList` picks per network.
///
/// An empty result is an ERROR, not an empty print: Go's `filterAddrList` returns `&AddrError{Err:
/// "no suitable address found", Addr: host}` when the filter empties the list, which renders as
/// `address <host>: no suitable address found`. So `--net ip6` against an IPv4-only name fails
/// loudly instead of silently printing nothing. Pure → unit-testable.
fn filter_resolve_addrs(
    addrs: Vec<std::net::IpAddr>,
    net: ResolveNet,
    host: &str,
) -> Result<Vec<std::net::IpAddr>> {
    let kept: Vec<std::net::IpAddr> = addrs
        .into_iter()
        .filter(|ip| match net {
            ResolveNet::Ip => true,
            ResolveNet::Ip4 => ip.is_ipv4(),
            ResolveNet::Ip6 => ip.is_ipv6(),
        })
        .collect();
    if kept.is_empty() {
        anyhow::bail!("address {host}: no suitable address found");
    }
    Ok(kept)
}

/// Render resolved addresses one per line (Go's `for _, ip := range ips { fmt.Printf("%s\n", ip) }`).
/// Pure → unit-testable; the result ends in a newline whenever it is non-empty.
fn resolve_report(addrs: &[std::net::IpAddr]) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    for ip in addrs {
        let _ = writeln!(out, "{ip}");
    }
    out
}

/// Resolve `host` through the OS resolver, bounded to [`RESOLVE_TIMEOUT`], filtered to `net`'s family.
///
/// Mirrors Go's `net.DefaultResolver.LookupIP(ctx, net, host)`: an empty host is refused before any
/// query, an IP literal short-circuits to itself (Go's resolver parses it before querying) while still
/// going through the family filter, and everything else reaches the host resolver — `getaddrinfo(3)`
/// via `tokio::net::lookup_host` on a blocking thread, the same resolver Go's cgo path uses. The `0`
/// port is a placeholder: `lookup_host` resolves a host+port pair and only the address half is kept.
///
/// A resolver failure is surfaced with its own message intact (`lookup <host>: <error>`, the shape
/// Go's `DNSError` renders), never swallowed into an empty list. On the deadline we report Go's
/// `lookup <host>: i/o timeout`; the abandoned `getaddrinfo` call is not cancellable, so it runs to
/// completion on its blocking thread and its result is dropped.
async fn resolve_lookup(host: &str, net: ResolveNet) -> Result<Vec<std::net::IpAddr>> {
    if host.is_empty() {
        // Go's `LookupIP` guard: `&DNSError{Err: "no suitable address found", Name: ""}`.
        anyhow::bail!("lookup : no suitable address found");
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return filter_resolve_addrs(vec![ip], net, host);
    }
    let addrs =
        match tokio::time::timeout(RESOLVE_TIMEOUT, tokio::net::lookup_host((host, 0u16))).await {
            Err(_elapsed) => anyhow::bail!("lookup {host}: i/o timeout"),
            Ok(Err(e)) => anyhow::bail!("lookup {host}: {e}"),
            Ok(Ok(addrs)) => addrs.map(|a| a.ip()).collect::<Vec<_>>(),
        };
    filter_resolve_addrs(addrs, net, host)
}

/// `debug resolve` (Go `tailscale debug resolve`): resolve ONE hostname through the host resolver and
/// print each address on its own line. Purely local — no daemon round-trip and nothing is mutated.
///
/// The refusals are Go's, in Go's order: the argument count is checked first (`len(args) != 1` →
/// `usage: …`, before the flag is interpreted at all), then `--net`, then the lookup. Both go to
/// stderr with exit 1 — Go returns them as errors from `Exec`, which its `main` prints and exits 1
/// on — which is why the count is checked by hand instead of being declared to clap, whose own
/// refusal would print a usage block to stderr and exit 2.
async fn run_debug_resolve(hostname: &[String], net: &str) -> Result<()> {
    if hostname.len() != 1 {
        anyhow::bail!("usage: tnet debug resolve <hostname>");
    }
    let net = parse_resolve_net(net)?;
    let addrs = resolve_lookup(&hostname[0], net).await?;
    print!("{}", resolve_report(&addrs));
    Ok(())
}

/// `debug statedir` (Go `tailscale debug statedir`): print the resolved state dir, the cascade rule
/// that chose it, and the LocalAPI socket the CLI resolved. Purely local — it only reports paths, and
/// deliberately does NOT create the state dir (a diagnostic that creates the thing it is diagnosing
/// would mask the very "wrong dir" it exists to reveal). `socket` is the socket the CLI actually
/// resolved (so an explicit `--socket`/`$TAILNETD_SOCKET` is reflected, not re-derived).
fn run_debug_statedir(socket: &std::path::Path) {
    let (dir, source) = tailscaled_rs::state_dir_with_source();
    print!("{}", statedir_report(&dir, source, socket));
}

/// Build the `debug statedir` output (pure → unit-testable; no stdout, no filesystem writes).
/// Three lines: the state dir with its on-disk status, the rule that selected it, and the socket with
/// its on-disk status. The string always ends in a newline.
fn statedir_report(
    dir: &std::path::Path,
    source: tailscaled_rs::StateDirSource,
    socket: &std::path::Path,
) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(out, "state dir: {} ({})", dir.display(), path_status(dir));
    let _ = writeln!(out, "resolved:  {}", source.describe());
    let _ = writeln!(
        out,
        "socket:    {} ({})",
        socket.display(),
        path_status(socket)
    );
    out
}

/// One-word on-disk status of `path` for [`statedir_report`]: `present` (plus the unix permission
/// bits for a directory, since a state dir that is not `0700` is itself a finding), `absent`, or the
/// stat error when the path exists but cannot be inspected (e.g. a parent the caller cannot traverse).
///
/// Symlinks are FOLLOWED (`stat`, not `lstat` — the opposite of `debug stat`, which mirrors Go's
/// `os.Lstat`): the question here is whether there is a usable state dir / a live socket at the end
/// of the path, so a dangling symlink is correctly `absent` rather than a "present" that would read
/// as "the daemon is up".
fn path_status(path: &std::path::Path) -> String {
    use std::os::unix::fs::PermissionsExt as _;
    match std::fs::metadata(path) {
        Ok(meta) if meta.is_dir() => {
            format!("present, mode {:o}", meta.permissions().mode() & 0o777)
        }
        Ok(_) => "present".to_string(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => "absent".to_string(),
        Err(e) => format!("cannot stat: {e}"),
    }
}

/// `debug build-info` (Go `tailscale debug go-buildinfo`): print this binary's build metadata as
/// pretty JSON. Purely local — every value is a compile-time constant stamped in by `build.rs` or by
/// cargo, so there is no daemon round-trip and nothing to fail at runtime.
fn run_debug_build_info() {
    // The cargo features this binary was actually compiled with. Read via `cfg!` (not a manifest
    // parse) so the answer is what the compiler saw, which is the only answer worth reporting.
    let features: Vec<&str> = [
        ("tun", cfg!(feature = "tun")),
        ("ssh", cfg!(feature = "ssh")),
        ("acme", cfg!(feature = "acme")),
        ("identity-federation", cfg!(feature = "identity-federation")),
    ]
    .into_iter()
    .filter_map(|(name, on)| on.then_some(name))
    .collect();

    let info = build_info_json(
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        env!("TAILNETD_TARGET"),
        env!("TAILNETD_PROFILE"),
        env!("TAILNETD_RUSTC_VERSION"),
        env!("TAILNETD_GIT_COMMIT"),
        &features,
    );
    println!("{info:#}");
}

/// Build the `debug build-info` JSON (pure → unit-testable; no stdout, no env reads).
///
/// `git_commit` arrives in `build.rs`'s stamp form — a short SHA, optionally suffixed `-dirty`, or the
/// literal `unknown` — and is split into the Go-`BuildInfo` setting pair `vcs.revision` / `vcs.modified`.
/// Any field `build.rs` could not determine (the literal `unknown`) becomes JSON `null`: an honest gap
/// is more useful in a bug report than a placeholder that reads like a real value.
fn build_info_json(
    package: &str,
    version: &str,
    target: &str,
    profile: &str,
    rustc: &str,
    git_commit: &str,
    features: &[&str],
) -> serde_json::Value {
    /// `unknown` (build.rs's "could not determine") → JSON `null`; anything else → a JSON string.
    fn or_null(v: &str) -> serde_json::Value {
        if v == "unknown" {
            serde_json::Value::Null
        } else {
            serde_json::Value::String(v.to_string())
        }
    }

    // `-dirty` is appended by build.rs when the tracked tree had uncommitted changes at build time —
    // Go's `vcs.modified` setting. With no revision at all there is nothing honest to say about
    // modification either, so the whole `vcs` object is null rather than half-invented.
    let vcs = match git_commit {
        "unknown" => serde_json::Value::Null,
        stamp => serde_json::json!({
            "revision": stamp.strip_suffix("-dirty").unwrap_or(stamp),
            "modified": stamp.ends_with("-dirty"),
        }),
    };

    serde_json::json!({
        "binary": "tnet",
        "package": package,
        "version": version,
        "target": or_null(target),
        "profile": or_null(profile),
        "rustcVersion": or_null(rustc),
        "vcs": vcs,
        "features": features,
    })
}

/// `switch` (Go `tailscale switch`): `--list` renders a table; `remove <id>` deletes; a bare
/// `<target>` switches. `--list` renders the Profiles reply, and the three modes map to different
/// requests.
/// The refusal `tnet switch` owes its own flags *before* it contacts the daemon, or `None` when the
/// invocation is usable. Ported from Go's `switchProfile` (`cmd/tailscale/cli/switch.go`), which
/// checks in exactly this order:
///
/// 1. `--list` wins outright — Go dispatches to `listProfiles`/`listProfilesJSON` first, so
///    `--list --json` is the JSON listing and a stray `<target>` alongside `--list` is ignored
///    (never a refusal).
/// 2. `--json` without `--list` is refused: `--json` only ever selects the *listing's* format, so
///    pairing it with a switch target asks for JSON output that does not exist. Go prints
///    `--json argument cannot be used with tailscale switch NAME` and exits 1.
/// 3. no target left → the usage line, exit 1.
///
/// The `remove` subcommand is exempt: Go's ffcli dispatches the subcommand before `switch`'s own
/// `Exec` ever runs, so `switch`'s flag rules do not apply to it (clap parses the same shape here).
///
/// Both messages go to **stdout** and exit **1**, matching Go's `outln` + `os.Exit(1)` — not clap's
/// stderr + exit 2, which is why this is a hand-rolled check and not an `#[arg(requires = ...)]`.
/// Pure (no I/O, no process exit) so the whole refusal table is unit-testable.
fn switch_usage_refusal(
    list: bool,
    json: bool,
    target: Option<&str>,
    has_subcommand: bool,
) -> Option<&'static str> {
    if has_subcommand || list {
        return None;
    }
    if json {
        return Some("--json argument cannot be used with tnet switch NAME");
    }
    if target.is_none() {
        return Some("usage: tnet switch NAME");
    }
    None
}

async fn run_switch(
    socket: &std::path::Path,
    list: bool,
    json: bool,
    target: Option<String>,
    cmd: Option<SwitchCmd>,
) -> Result<()> {
    // Go's own flag refusals first (stdout + exit 1), before any daemon round-trip.
    if let Some(message) = switch_usage_refusal(list, json, target.as_deref(), cmd.is_some()) {
        println!("{message}");
        std::process::exit(1);
    }
    // `switch remove <id>` (subcommand) takes precedence.
    if let Some(SwitchCmd::Remove { target }) = cmd {
        return send_ok_or_die(socket, Request::DeleteProfile { target }).await;
    }
    if list {
        match round_trip(socket, &Request::ProfileList).await {
            Ok(Response::Profiles { profiles }) => {
                if json {
                    println!("{}", format_profiles_json(&profiles));
                } else {
                    print!("{}", format_profiles(&profiles));
                }
                return Ok(());
            }
            Ok(Response::Error { message }) => {
                eprintln!("error: {message}");
                std::process::exit(1);
            }
            Ok(other) => anyhow::bail!("unexpected response to profile list: {other:?}"),
            Err(e) => {
                return Err(e).with_context(|| format!("listing profiles at {}", socket.display()));
            }
        }
    }
    match target {
        Some(target) => send_ok_or_die(socket, Request::SwitchProfile { target }).await,
        // Unreachable: `switch_usage_refusal` above already exited on a missing target. Kept as a
        // total match (rather than an `expect`) so a future edit to the refusal table degrades into
        // the same usage line instead of a panic.
        None => {
            println!("usage: tnet switch NAME");
            std::process::exit(1);
        }
    }
}

/// Render the `tnet licenses` notice (Go `tailscale licenses`). Local-only, pure → unit-testable.
///
/// Faithful to Go's command shape (a short notice + a pointer to where the full license texts live)
/// but with content true to THIS fork rather than Tailscale's URL: this is a Rust port under
/// BSD-3-Clause, and its dependency-license texts are reproducible offline via `cargo` tooling
/// (`cargo about`/`cargo license` over `Cargo.lock`), so we point there instead of a hosted page that
/// would not describe this project's actual dependency set.
fn format_licenses() -> String {
    format!(
        "\n\
         {name} is a Rust reimplementation of the Tailscale daemon + CLI, licensed under \
         {license}.\n\
         It wouldn't be possible without thousands of open-source contributors. For this project's \
         license and the licenses of its dependencies:\n\
         \n    \
         {repo}\n    \
         (dependency licenses: `cargo install cargo-about && cargo about generate` over Cargo.lock)\n",
        name = env!("CARGO_PKG_NAME"),
        license = env!("CARGO_PKG_LICENSE"),
        repo = env!("CARGO_PKG_REPOSITORY"),
    )
}

/// The GitHub owner/repo this client updates from — derived from `CARGO_PKG_REPOSITORY`
/// (`https://github.com/GeiserX/tailscaled-rs`). Used to build the Releases API URLs.
const UPDATE_REPO_SLUG: &str = "GeiserX/tailscaled-rs";

/// A semantic version `major.minor.patch`, parsed from a `vX.Y.Z` tag or a bare `X.Y.Z` string, for
/// comparing the running version against a release tag. Pre-release/build suffixes are ignored (the
/// fork tags plain `vX.Y.Z`). Pure → unit-testable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct SemVer {
    major: u64,
    minor: u64,
    patch: u64,
}

impl SemVer {
    /// Parse `v1.2.3` / `1.2.3` (a leading `v` is optional; anything after the patch — `-rc1`, `+meta`
    /// — is ignored). Returns `None` if the three core numbers aren't present.
    fn parse(s: &str) -> Option<SemVer> {
        let s = s.trim().strip_prefix('v').unwrap_or(s.trim());
        // Drop any pre-release/build suffix so `1.2.3-rc1` still parses to (1,2,3).
        let core = s.split(['-', '+']).next().unwrap_or(s);
        let mut it = core.split('.');
        let major = it.next()?.parse().ok()?;
        let minor = it.next()?.parse().ok()?;
        let patch = it.next()?.parse().ok()?;
        if it.next().is_some() {
            return None; // more than 3 dotted components → not a plain semver
        }
        Some(SemVer {
            major,
            minor,
            patch,
        })
    }
}

impl std::fmt::Display for SemVer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// The host target triple this build's release assets are named with (`tailscaled-rs-vX.Y.Z-<triple>`,
/// see the release workflow). The fork publishes Linux glibc assets only; `None` on a platform with no
/// published asset (e.g. macOS) so the updater can report that honestly instead of 404-ing.
fn host_release_triple() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Some("x86_64-unknown-linux-gnu"),
        ("linux", "aarch64") => Some("aarch64-unknown-linux-gnu"),
        // Only Linux x86_64/aarch64 release assets are published today (see `.github/workflows/release.yml`).
        _ => None,
    }
}

/// The Homebrew formula that owns the file at `exe`, if any — the `<formula>` of a
/// `<prefix>/Cellar/<formula>/<version>/bin/<binary>` path. Pure → unit-testable.
///
/// Homebrew installs every file of a package under `<prefix>/Cellar/<formula>/<version>/` and links
/// the binaries into `<prefix>/bin` as symlinks, so a *resolved* executable path is always the Cellar
/// one. Matching on the `Cellar` component rather than a hard-coded prefix covers every prefix
/// Homebrew uses — `/usr/local` (Intel macOS), `/opt/homebrew` (Apple Silicon),
/// `/home/linuxbrew/.linuxbrew` (Linux), and an operator's custom one.
fn homebrew_formula_owning(exe: &std::path::Path) -> Option<String> {
    let mut comps = exe.components();
    while let Some(c) = comps.next() {
        if c.as_os_str() != "Cellar" {
            continue;
        }
        let formula = comps.next()?.as_os_str().to_str()?.to_string();
        // `Cellar/<formula>/<version>/…`: a path that stops at the formula directory names no
        // installed file, so it is not evidence that this binary came from Homebrew.
        comps.next()?;
        return Some(formula);
    }
    None
}

/// The Homebrew formula that owns the *running* `tnet`, if any. Resolves symlinks first, since the
/// binary on `PATH` is `<prefix>/bin/tnet`, a symlink into the Cellar.
fn running_binary_homebrew_formula() -> Option<String> {
    let exe = std::env::current_exe().ok()?;
    let exe = std::fs::canonicalize(&exe).unwrap_or(exe);
    homebrew_formula_owning(&exe)
}

/// Why `update --yes` refuses on a Homebrew-installed binary, and what to run instead.
///
/// The same refusal Go makes when its binary came from a package manager rather than from a release
/// tarball (`clientupdate/clientupdate.go`, `updateFreeBSD`: "Tailscale was not installed via pkg,
/// binary updates on FreeBSD are not supported; please reinstall Tailscale using pkg or update
/// manually", plus the `pkg upgrade tailscale` hint). Swapping the binary in place would overwrite a
/// file Homebrew owns: the Cellar keeps one directory per installed version, so the next `brew`
/// command would report a version that is no longer on disk, and the following `brew upgrade` would
/// silently discard the update. Pure → unit-testable.
fn homebrew_update_refusal(formula: &str) -> String {
    format!(
        "this `tnet` was installed by Homebrew (it is a file of the `{formula}` formula, under \
         Homebrew's Cellar), and binary updates are not supported for a Homebrew install: replacing \
         it in place would overwrite a file Homebrew owns and leave `brew` reporting a version that \
         is no longer installed. Update it with `brew update && brew upgrade {formula}` instead \
         (or install a release tarball outside the Homebrew prefix and update that)"
    )
}

/// One GitHub release, as much of the Releases-API JSON as `update` needs.
#[derive(Debug, serde::Deserialize)]
struct GithubRelease {
    tag_name: String,
    #[serde(default)]
    prerelease: bool,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    html_url: String,
    #[serde(default)]
    assets: Vec<GithubAsset>,
}

#[derive(Debug, serde::Deserialize)]
struct GithubAsset {
    name: String,
    #[serde(default)]
    browser_download_url: String,
}

/// Blocking HTTP GET via `ureq` (rustls), returning the response body as bytes. Bounded by a size cap
/// so a hostile/huge response can't exhaust memory. Sends the GitHub-required `User-Agent`. Run from
/// `spawn_blocking` (ureq is blocking). `accept` sets the `Accept` header (the GitHub API wants
/// `application/vnd.github+json`; an asset download wants the default).
fn http_get_bytes(url: &str, accept: Option<&str>, max_bytes: u64) -> Result<Vec<u8>> {
    use std::io::Read as _;
    let ua = concat!(
        "tailscaled-rs/",
        env!("CARGO_PKG_VERSION"),
        " (tnet update)"
    );
    let mut req = ureq::get(url).header("User-Agent", ua);
    if let Some(a) = accept {
        req = req.header("Accept", a);
    }
    let resp = req.call().with_context(|| format!("HTTP GET {url}"))?;
    // Read up to `max_bytes + 1` so an over-cap body is an explicit ERROR, not a silent truncation
    // (`Read::take` alone would quietly cut the body, which a downstream consumer could mistake for a
    // complete response). The cap still bounds memory against a hostile/huge response.
    let mut reader = resp.into_body().into_reader().take(max_bytes + 1);
    let mut buf = Vec::new();
    reader
        .read_to_end(&mut buf)
        .with_context(|| format!("reading response body from {url}"))?;
    if buf.len() as u64 > max_bytes {
        anyhow::bail!("response from {url} exceeds the {max_bytes}-byte cap");
    }
    Ok(buf)
}

/// Resolve which release `update` should target, by querying the GitHub Releases API:
///
/// - explicit `version` (e.g. `0.42.0`) → fetch `releases/tags/v0.42.0`.
/// - `track = unstable` → the newest release including prereleases (`releases?per_page=…`, pick max).
/// - default / `track = stable` → `releases/latest` (GitHub's "latest non-prerelease, non-draft").
///
/// Returns the chosen `GithubRelease`. Blocking (ureq) — call from `spawn_blocking`.
fn resolve_target_release(version: Option<&str>, unstable: bool) -> Result<GithubRelease> {
    const API_MAX: u64 = 4 << 20; // 4 MiB cap on the JSON response
    let json = "application/vnd.github+json";
    if let Some(v) = version {
        let tag = if v.starts_with('v') {
            v.to_string()
        } else {
            format!("v{v}")
        };
        let url = format!("https://api.github.com/repos/{UPDATE_REPO_SLUG}/releases/tags/{tag}");
        let body = http_get_bytes(&url, Some(json), API_MAX)
            .with_context(|| format!("no release found for {tag}"))?;
        return serde_json::from_slice(&body).context("parsing release JSON");
    }
    if unstable {
        // Newest release of any kind (prereleases included). The API lists newest-first; pick the
        // highest semver among non-draft releases so a prerelease can win.
        let url = format!("https://api.github.com/repos/{UPDATE_REPO_SLUG}/releases?per_page=20");
        let body = http_get_bytes(&url, Some(json), API_MAX)?;
        let releases: Vec<GithubRelease> =
            serde_json::from_slice(&body).context("parsing releases JSON")?;
        releases
            .into_iter()
            .filter(|r| !r.draft)
            .filter(|r| SemVer::parse(&r.tag_name).is_some())
            .max_by_key(|r| SemVer::parse(&r.tag_name).unwrap())
            .context("no releases found")
    } else {
        let url = format!("https://api.github.com/repos/{UPDATE_REPO_SLUG}/releases/latest");
        let body = http_get_bytes(&url, Some(json), API_MAX)?;
        serde_json::from_slice(&body).context("parsing latest-release JSON")
    }
}

/// `update` (Go `tailscale update`): check GitHub Releases for a newer version and report it; with
/// `--yes`, download + SHA-256-verify + replace this binary in place. `report_only` (from
/// `--check`/`--dry-run`, or the default when `--yes` is absent) stops after reporting. All network
/// I/O is `ureq` (blocking) on a `spawn_blocking` thread.
async fn run_update(
    report_only: bool,
    yes: bool,
    version: Option<String>,
    track: Option<String>,
) -> Result<()> {
    let current = SemVer::parse(env!("CARGO_PKG_VERSION"))
        .context("parsing this build's own version (CARGO_PKG_VERSION)")?;
    // Track: stable (default, non-prerelease) vs unstable (include prereleases). An explicit
    // `--version` overrides track selection (clap already forbids both).
    let unstable = match track.as_deref() {
        None | Some("stable") => false,
        Some("unstable") => true,
        Some(other) => anyhow::bail!("unknown --track {other:?}: expected `stable` or `unstable`"),
    };

    // If `--yes` was NOT given, this is report-only regardless of `--check` (we never install without
    // an explicit `--yes`). Capture that up front so the messaging is honest.
    let will_install = yes && !report_only;

    // Is this binary a file of a Homebrew formula? If so, `--yes` refuses below — so the report must
    // not send the reader to a `--yes` that cannot work; it names `brew upgrade` instead.
    let homebrew_formula = running_binary_homebrew_formula();

    // Resolve the target release off the async runtime (ureq is blocking).
    let ver_owned = version.clone();
    let release =
        tokio::task::spawn_blocking(move || resolve_target_release(ver_owned.as_deref(), unstable))
            .await
            .context("update: version-check task panicked")??;

    let latest = SemVer::parse(&release.tag_name).with_context(|| {
        format!(
            "release tag {:?} is not a semantic version",
            release.tag_name
        )
    })?;

    // Report current vs latest (Go's `--dry-run` line), always — both report-only and pre-install.
    println!("current: {current}");
    println!(
        "latest:  {latest}  ({}{})",
        release.tag_name,
        if release.prerelease {
            ", prerelease"
        } else {
            ""
        }
    );
    if !release.html_url.is_empty() {
        println!("release: {}", release.html_url);
    }

    if version.is_none() && latest <= current {
        println!("you are already on the latest version.");
        return Ok(());
    }

    // Report-only (default / --check / --dry-run, or no --yes): stop here, having reported.
    if !will_install {
        if let Some(formula) = homebrew_formula.as_deref() {
            // Homebrew owns this binary: `--yes` would refuse, so point at the command that works.
            println!();
            if latest > current {
                println!(
                    "a newer version is available; this `tnet` is Homebrew-managed, so install it \
                     with `brew update && brew upgrade {formula}`."
                );
            } else {
                println!(
                    "this `tnet` is Homebrew-managed, so `--yes` cannot change its version — \
                     `brew` decides which one is installed (`brew upgrade {formula}`)."
                );
            }
            return Ok(());
        }
        if latest > current {
            println!();
            if version.is_some() {
                println!("to install {latest}, re-run with --yes.");
            } else {
                println!(
                    "a newer version is available; re-run with --yes to download + install it."
                );
            }
        } else if version.is_some() {
            // Explicit older/equal --version with no --yes.
            println!();
            println!("re-run with --yes to switch to {latest}.");
        }
        return Ok(());
    }

    // --- install path (--yes) ---

    // A package manager owns this binary: refuse before downloading anything, and name the command
    // that does the update properly. Checked ahead of the platform-artifact question below because
    // it is the more useful answer wherever both apply — a Homebrew install needs `brew upgrade`,
    // not a release tarball.
    if let Some(formula) = homebrew_formula.as_deref() {
        anyhow::bail!("{}", homebrew_update_refusal(formula));
    }

    let Some(triple) = host_release_triple() else {
        anyhow::bail!(
            "this build's platform ({}/{}) has no published release artifact (the project ships \
             Linux x86_64/aarch64 tarballs only) — install/update via your package or build from \
             source instead",
            std::env::consts::OS,
            std::env::consts::ARCH
        );
    };

    // The asset names are `tailscaled-rs-<tag>-<triple>.tar.gz` + `.sha256` (see release.yml).
    let tarball_name = format!("tailscaled-rs-{}-{triple}.tar.gz", release.tag_name);
    let sha_name = format!("{tarball_name}.sha256");
    let find = |name: &str| -> Option<String> {
        release
            .assets
            .iter()
            .find(|a| a.name == name && !a.browser_download_url.is_empty())
            .map(|a| a.browser_download_url.clone())
    };
    let tarball_url = find(&tarball_name).with_context(|| {
        format!(
            "release {} has no asset named {tarball_name}",
            release.tag_name
        )
    })?;
    let sha_url = find(&sha_name).with_context(|| {
        format!(
            "release {} has no SHA-256 sidecar {sha_name}",
            release.tag_name
        )
    })?;

    // Honest security note BEFORE downloading: integrity, not authenticity.
    eprintln!();
    eprintln!(
        "installing {latest} from {UPDATE_REPO_SLUG} release assets. NOTE: the download is verified \
         against its published SHA-256 sidecar (integrity — detects a corrupted download), NOT a \
         cryptographic signature (authenticity). This client publishes no signatures yet, so a \
         `--yes` install trusts GitHub Releases as the source of truth."
    );

    // Download tarball + sidecar off the runtime.
    const DL_MAX: u64 = 256 << 20; // 256 MiB cap (a tnet+tailnetd tarball is ~10 MiB)
    let (tarball_url2, sha_url2) = (tarball_url.clone(), sha_url.clone());
    let (tarball_bytes, sha_text) =
        tokio::task::spawn_blocking(move || -> Result<(Vec<u8>, Vec<u8>)> {
            let tb = http_get_bytes(&tarball_url2, None, DL_MAX)?;
            let sh = http_get_bytes(&sha_url2, None, 4096)?;
            Ok((tb, sh))
        })
        .await
        .context("update: download task panicked")??;

    // Verify SHA-256 against the GNU `sha256sum` sidecar (`<hex>  <filename>`).
    verify_sha256(&tarball_bytes, &sha_text, &tarball_name)?;
    println!(
        "verified SHA-256 of {tarball_name} ({} bytes).",
        tarball_bytes.len()
    );

    // Extract `tnet` from the tarball and atomically replace the running executable.
    let new_tnet = extract_tnet_from_tarball(&tarball_bytes)?;
    let exe = std::env::current_exe().context("resolving the running executable to replace")?;
    swap_binary_in_place(&exe, &new_tnet)
        .with_context(|| format!("replacing {} with the new tnet", exe.display()))?;
    println!("updated {} to {latest}.", exe.display());
    println!(
        "(note: only this `tnet` binary was replaced; update `tailnetd` and restart the daemon \
         separately — the tarball at the release contains both.)"
    );
    Ok(())
}

/// Verify `data`'s SHA-256 against a GNU `sha256sum` sidecar line (`<64-hex>  <filename>`). The
/// sidecar may name the file; we match the expected hex regardless of the filename column (the
/// sidecar from the release names the tarball). Errors on a hex mismatch or a malformed sidecar. The
/// digest compared here is a public hash of a public release artifact (not a secret), so a plain
/// string compare is fine — no constant-time requirement. Pure → unit-testable.
fn verify_sha256(data: &[u8], sidecar: &[u8], expected_name: &str) -> Result<()> {
    use sha2::{Digest as _, Sha256};
    let sidecar = std::str::from_utf8(sidecar).context("SHA-256 sidecar is not valid UTF-8")?;
    // First whitespace-delimited token of the (first non-empty) line is the hex digest.
    let line = sidecar
        .lines()
        .find(|l| !l.trim().is_empty())
        .context("empty SHA-256 sidecar")?;
    let want_hex = line
        .split_whitespace()
        .next()
        .context("malformed SHA-256 sidecar (no digest)")?
        .to_ascii_lowercase();
    if want_hex.len() != 64 || !want_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        anyhow::bail!("malformed SHA-256 sidecar for {expected_name}: not a 64-char hex digest");
    }
    let mut hasher = Sha256::new();
    hasher.update(data);
    let got = hasher.finalize();
    let got_hex: String = got.iter().map(|b| format!("{b:02x}")).collect();
    if got_hex != want_hex {
        anyhow::bail!(
            "SHA-256 mismatch for {expected_name}: download is corrupt or has been tampered with \
             (expected {want_hex}, got {got_hex})"
        );
    }
    Ok(())
}

/// Extract the `tnet` binary's bytes from a gzip'd tar release tarball (`tailscaled-rs-…tar.gz`,
/// containing `tnet`, `tailnetd`, `LICENSE`, `README.md` at the root). Uses the `tar`/`flate2` the
/// engine already pulls transitively — no new dep. Errors if `tnet` isn't found.
fn extract_tnet_from_tarball(gz: &[u8]) -> Result<Vec<u8>> {
    use std::io::Read as _;
    let dec = flate2::read::GzDecoder::new(gz);
    let mut archive = tar::Archive::new(dec);
    for entry in archive.entries().context("reading tarball entries")? {
        let mut entry = entry.context("reading a tarball entry")?;
        let path = entry.path().context("tarball entry path")?;
        // The binary is `tnet` at the archive root.
        if path.file_name().and_then(|n| n.to_str()) == Some("tnet")
            && path.components().count() == 1
        {
            // Cap the DECOMPRESSED read: the 256 MiB download cap bounds the *compressed* tarball, but
            // gzip can expand ~1000:1, so an unbounded `read_to_end` on a hostile archive could exhaust
            // memory. A real `tnet` binary is ~10-30 MiB; 128 MiB is a generous ceiling. Read one byte
            // past it so an over-size entry is an explicit error (decompression-bomb guard), not OOM.
            const MAX_TNET_BYTES: u64 = 128 << 20;
            let mut buf = Vec::new();
            let n = entry
                .by_ref()
                .take(MAX_TNET_BYTES + 1)
                .read_to_end(&mut buf)
                .context("reading tnet from tarball")?;
            if n as u64 > MAX_TNET_BYTES {
                anyhow::bail!(
                    "the `tnet` entry in the tarball exceeds {MAX_TNET_BYTES} bytes — refusing \
                     (possible decompression bomb)"
                );
            }
            if buf.is_empty() {
                anyhow::bail!("tnet in the tarball is empty");
            }
            return Ok(buf);
        }
    }
    anyhow::bail!("the release tarball does not contain a `tnet` binary")
}

/// Atomically replace the binary at `exe` with `new_bytes`: write to a same-directory temp file,
/// `chmod 0755`, then `rename` over `exe`. Same-directory + rename is atomic on POSIX and works even
/// though `exe` is the *running* binary (Linux/macOS keep the old inode mapped until exit; renaming
/// over a busy executable is allowed, unlike writing into it which would `ETXTBSY`). The temp lives in
/// `exe`'s directory so the rename stays on one filesystem.
fn swap_binary_in_place(exe: &std::path::Path, new_bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let dir = exe
        .parent()
        .context("the running executable has no parent directory")?;
    // Temp name: pid + a nanosecond timestamp for uniqueness. The REAL race defense is `create_new`
    // (`O_EXCL`) below — it refuses to open a pre-existing file OR symlink, so a local attacker can't
    // pre-plant the temp path to redirect the write or feed us their bytes. (No `rand` dep here — it's
    // gated behind the `ssh` feature; `O_EXCL` is the security control, the suffix is just uniqueness.)
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = dir.join(format!(".tnet.update.{}.{nanos:x}", std::process::id()));
    let cleanup = |t: &std::path::Path| {
        let _ = std::fs::remove_file(t);
    };
    // Create exclusively (O_EXCL) with mode 0755 directly — fails if the path already exists (defeats a
    // pre-planted file/symlink) and avoids a separate chmod window.
    let create = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o755)
        .open(&tmp);
    let mut f = match create {
        Ok(f) => f,
        Err(e) => {
            return Err(e).with_context(|| format!("creating the update temp {}", tmp.display()));
        }
    };
    if let Err(e) = f.write_all(new_bytes).and_then(|()| f.sync_all()) {
        drop(f);
        cleanup(&tmp);
        return Err(e).with_context(|| format!("writing the new binary to {}", tmp.display()));
    }
    drop(f);
    if let Err(e) = std::fs::rename(&tmp, exe) {
        cleanup(&tmp);
        return Err(e).with_context(|| {
            format!(
                "renaming {} over {} (is the target on a different filesystem, or not writable?)",
                tmp.display(),
                exe.display()
            )
        });
    }
    Ok(())
}

/// `version` answers from the CLI's own crate version. WITHOUT `--daemon` it never contacts the
/// daemon (Go also prints the client version with no LocalAPI call). WITH `--daemon` it round-trips
/// `Request::Version` to learn the daemon's version, then renders both inline (rather than falling
/// through to the generic response printer) so the client/daemon pairing + `--json` shape stay in
/// one place.
async fn run_version(
    socket: &std::path::Path,
    daemon: bool,
    json: bool,
    upstream: bool,
) -> Result<()> {
    // `--upstream` would fetch the latest release from a release server; this build does no
    // such network call, so return Go's verbatim message + a non-zero exit (faithful, offline,
    // names no infrastructure). Checked before the local render so `version --upstream` never
    // prints a version line implying success.
    if upstream {
        eprintln!("fetching latest version not supported in this build");
        std::process::exit(1);
    }
    let client_version = env!("CARGO_PKG_VERSION");
    let daemon_version = if daemon {
        match round_trip(socket, &Request::Version).await {
            Ok(Response::Version { version }) => Some(version),
            Ok(other) => {
                anyhow::bail!("unexpected response to version request: {other:?}")
            }
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("querying daemon version at {}", socket.display()));
            }
        }
    } else {
        None
    };
    // `cap` = the engine's current capability version (Go `version.Meta.cap`), read from the
    // engine's `ts_capabilityversion` crate (pinned to the same rev as the engine facade).
    let cap = u16::from(ts_capabilityversion::CapabilityVersion::CURRENT);
    print_version(client_version, daemon_version.as_deref(), cap, json);
    Ok(())
}

/// `get` (Go `tailscale get`): round-trip GetPrefs, then render. Inline because its
/// `setting`/`json`/`set_flags` args shape the output and are not part of the wire request — keeping
/// the projection→render in one place, like `version`.
async fn run_get(
    socket: &std::path::Path,
    setting: Option<String>,
    json: bool,
    set_flags: bool,
) -> Result<()> {
    let view = match round_trip(socket, &Request::GetPrefs).await {
        Ok(Response::Prefs(v)) => v,
        Ok(Response::Error { message }) => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        Ok(other) => anyhow::bail!("unexpected response to get request: {other:?}"),
        Err(e) => {
            return Err(e).with_context(|| format!("getting prefs at {}", socket.display()));
        }
    };
    // `--set-flags` (Go `get --set-flags`): emit every setting as one re-appliable `set` arg line,
    // regardless of a single-SETTING arg (Go's set-flags mode always emits all). clap's
    // `conflicts_with` guarantees `json` is false here.
    if set_flags {
        println!("{}", format_get_set_flags(&view));
        return Ok(());
    }
    match format_get(&view, setting.as_deref(), json) {
        Ok(out) => print!("{out}"),
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
    Ok(())
}

/// `whoami` (Go `tailscale whoami`): resolve this node's own identity — Status to learn the self
/// tailnet IP, then Whois on that IP. Inline because it chains two requests and its `--json` shape is
/// the whois record. Reuses the same `format_whois` renderer as `whois`.
async fn run_whoami(socket: &std::path::Path, json: bool) -> Result<()> {
    let status = match round_trip(socket, &Request::Status).await {
        Ok(Response::Status(s)) => s,
        Ok(other) => anyhow::bail!("unexpected response to status request: {other:?}"),
        Err(e) => {
            return Err(e).with_context(|| format!("querying status at {}", socket.display()));
        }
    };
    let Some(self_ip) = status.self_ipv4.clone() else {
        // No tailnet IP yet → not up (Go errors here too, citing the backend state).
        eprintln!(
            "no current tailnet IP address (state: {}); is the node up?",
            status.state
        );
        std::process::exit(1);
    };
    match round_trip(
        socket,
        // `whoami` is Go's `whois` against this node's own tailnet IP: an address, never a flow,
        // so it carries neither of Go's flow selectors.
        &Request::Whois {
            ip: self_ip.clone(),
            port: None,
            proto: None,
        },
    )
    .await
    {
        Ok(Response::Whois(w)) => {
            if json {
                // The whois record as JSON (Go `whoami --json` emits the WhoIsResponse).
                match serde_json::to_string_pretty(&w) {
                    Ok(s) => println!("{s}"),
                    Err(e) => {
                        eprintln!("error: serializing whois: {e}");
                        std::process::exit(1);
                    }
                }
            } else {
                print!("{}", format_whois(&w, &self_ip));
            }
            Ok(())
        }
        Ok(Response::Error { message }) => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        Ok(other) => anyhow::bail!("unexpected response to whois request: {other:?}"),
        Err(e) => {
            Err(e).with_context(|| format!("resolving self identity at {}", socket.display()))
        }
    }
}

/// `ip` (Go `tailscale ip`): self addresses by default, or a peer's if named, with -4/-6/-1
/// filters. Inline because the filters + the optional peer lookup shape the output (and the peer
/// case fetches Status to resolve by name/IP against the netmap).
///
/// An argument that matches no peer but IS an address falls through to the Tailscale Service set
/// (Go `serviceAddrsMatchingIP`): a Service is a virtual service with its own VIPs, which belong to
/// no peer, so without that arm naming one could only fail with "no peer found".
/// The refusal `tnet ip` owes its own flags before it looks at anything else — Go's `runIP`
/// (`cmd/tailscale/cli/ip.go`, upstream v1.102.3 `53a0d659afa51835dd7a9283873cca44261454f8`) counts
/// its three address selectors and rejects any two of them together:
///
/// ```text
/// nflags := 0
/// for _, b := range []bool{ipArgs.want1, v4, v6} { if b { nflags++ } }
/// if nflags > 1 {
///     return errors.New("tailscale ip -1, -4, and -6 are mutually exclusive")
/// }
/// ```
///
/// All three answer "which addresses print", and Go resolves that with one flag rather than a
/// combination: `-1` means the first address of the node's (or Service's) whole list, NOT the first
/// of a selected family. So `-6 -1` on a dual-stack target asks for something Go does not offer, and
/// Go's own evaluation order — truncate to the first address, THEN filter by family — would answer
/// it with an empty set. Refusing it is what keeps a plausible-looking command from printing nothing
/// and calling that an answer.
///
/// `-4 -6` is the same Go check, which is why this is NOT a clap `conflicts_with`: clap would answer
/// that one pair with its own stderr + exit 2 text while the other two pairs got Go's, and one
/// upstream check should have one message. Go's is returned as an error (stderr, exit 1) rather than
/// `outln`-ed, so the caller `bail!`s it instead of following [`switch_usage_refusal`]'s stdout path.
/// Pure (no I/O, no process exit) so the whole refusal table is unit-testable.
fn ip_usage_refusal(v4: bool, v6: bool, first: bool) -> Option<&'static str> {
    if [first, v4, v6].into_iter().filter(|b| *b).count() > 1 {
        return Some("tnet ip -1, -4, and -6 are mutually exclusive");
    }
    None
}

async fn run_ip(
    socket: &std::path::Path,
    v4: bool,
    v6: bool,
    first: bool,
    peer: Option<String>,
    assert: Option<String>,
) -> Result<()> {
    // Go's flag refusal runs before `--assert` and before the `Status` call, so an unusable
    // invocation costs no daemon round trip and says the same thing whether the daemon is up.
    if let Some(message) = ip_usage_refusal(v4, v6, first) {
        anyhow::bail!(message);
    }
    let sel = IpSelect { v4, v6, first };
    // `--assert <ip>`: verify one of this node's own IPs matches; exit 0 on a match, 1 otherwise.
    // Prints nothing on success (Go's behavior) — it is a script predicate, not a display. Compares
    // by parsed `IpAddr` so `100.64.0.1` and `100.064.000.001`-style spellings normalize.
    if let Some(want) = assert {
        let want_ip: std::net::IpAddr = want
            .parse()
            .with_context(|| format!("--assert: {want:?} is not a valid IP address"))?;
        let (ipv4, ipv6) = match round_trip(socket, &Request::Ip).await {
            Ok(Response::Ip { ipv4, ipv6 }) => (ipv4, ipv6),
            Ok(Response::Error { message }) => {
                eprintln!("error: {message}");
                std::process::exit(1);
            }
            Ok(other) => anyhow::bail!("unexpected response to ip request: {other:?}"),
            Err(e) => {
                return Err(e).with_context(|| format!("querying ip at {}", socket.display()));
            }
        };
        let matches = [ipv4.as_deref(), ipv6.as_deref()]
            .into_iter()
            .flatten()
            .filter_map(|s| s.parse::<std::net::IpAddr>().ok())
            .any(|ip| ip == want_ip);
        if matches {
            return Ok(());
        }
        eprintln!("assertion failed: this node does not hold {want_ip}");
        std::process::exit(1);
    }
    let out = if let Some(peer) = peer {
        // Peer address: resolve the named peer against the status peer set (by MagicDNS name
        // or tailnet IP). We fetch Status (not whois, which is IP-only) so a NAME also works.
        let status = match round_trip(socket, &Request::Status).await {
            Ok(Response::Status(s)) => s,
            Ok(other) => anyhow::bail!("unexpected response to status request: {other:?}"),
            Err(e) => {
                return Err(e).with_context(|| format!("querying status at {}", socket.display()));
            }
        };
        match status
            .peers
            .iter()
            .find(|p| p.name == peer || p.ipv4 == peer)
        {
            // Project both families so `ip -6 <peer>` / a bare `ip <peer>` show the peer's IPv6
            // (Go prints `peer.TailscaleIPs` filtered by family). `PeerReport.ipv6` is populated by
            // the daemon's status projection when the peer has one.
            Some(p) => format_ip_filtered(Some(&p.ipv4), p.ipv6.as_deref(), sel),
            // No peer matched. Go then asks whether the address belongs to a Tailscale Service and,
            // if so, prints THAT Service's addresses instead of failing — a Service is not a peer,
            // so its VIP is in no peer's address list and used to be reported as "no peer found".
            // The Service set is fetched only on this miss, the way `configure kubeconfig` fetches
            // the DNS config only when the peer lookup came up empty: one fewer round trip on the
            // common path, and a daemon that cannot answer `services` no longer breaks a lookup the
            // netmap alone already settled.
            None => match peer.parse::<std::net::IpAddr>() {
                Ok(want) => {
                    let services = match round_trip(socket, &Request::Services).await {
                        Ok(Response::Services { services }) => services,
                        Ok(Response::Error { message }) => {
                            eprintln!("error: {message}");
                            std::process::exit(1);
                        }
                        Ok(other) => {
                            anyhow::bail!("unexpected response to services request: {other:?}")
                        }
                        Err(e) => {
                            return Err(e).with_context(|| {
                                format!("querying services at {}", socket.display())
                            });
                        }
                    };
                    match service_addrs_matching_ip(&services, want) {
                        Some(addrs) => format_service_ips(addrs, sel),
                        None => {
                            // Go: `no peer or service found with IP %v`.
                            eprintln!("no peer or service found with IP {want}");
                            std::process::exit(1);
                        }
                    }
                }
                // A name that matches no peer never reaches Go's Service arm either: Go resolves the
                // argument to an address first (`tailscaleIPFromArg`), and only an address can match
                // a Service VIP. Say so, and name the command that lists the Services.
                Err(_) => {
                    eprintln!(
                        "no peer matching {peer:?} in the current netmap (a Tailscale Service is \
                         matched by its VIP address — run `tnet service list` for the Services this \
                         node can reach)"
                    );
                    std::process::exit(1);
                }
            },
        }
    } else {
        // Self addresses.
        match round_trip(socket, &Request::Ip).await {
            Ok(Response::Ip { ipv4, ipv6 }) => {
                format_ip_filtered(ipv4.as_deref(), ipv6.as_deref(), sel)
            }
            Ok(Response::Error { message }) => {
                eprintln!("error: {message}");
                std::process::exit(1);
            }
            Ok(other) => anyhow::bail!("unexpected response to ip request: {other:?}"),
            Err(e) => {
                return Err(e).with_context(|| format!("querying ip at {}", socket.display()));
            }
        }
    };
    print!("{out}");
    Ok(())
}

/// `ping` (Go `tailscale ping [-c N] [--until-direct]`): the engine pings one-at-a-time, so the
/// count + the `--until-direct` early-stop are a CLI-side loop over `Request::Ping`. Inline (the
/// loop + summary + exit-code contract); each attempt prints a result line reporting the path the
/// pong took (`via <endpoint>` direct vs `via DERP` relayed), a failure is counted but does not
/// abort the rest, and the exit verdict follows Go's [`ping_verdict`].
///
/// `count == 0` means infinity (Go `-c 0`): loop until a direct path is established (when
/// `until_direct`) or forever. `until_direct` (Go's default-true) returns as soon as the overlay
/// upgrades to a direct path — the ICMP echo each attempt sends is itself what nudges magicsock to
/// attempt that upgrade.
async fn run_ping(
    socket: &std::path::Path,
    ip: String,
    timeout: Option<u64>,
    count: u32,
    until_direct: bool,
) -> Result<()> {
    // Self-IP early return (Go ping.go: `if self { printf("%v is local Tailscale IP\n", ip); return nil }`).
    // Pinging the node's OWN tailnet IP is a no-op that would otherwise hit the local netstack echo;
    // Go short-circuits with a clear note + exit 0. We compare the target against this node's own
    // addresses (Request::Ip). Parse both sides to an IpAddr so spelling variants normalize; a target
    // that isn't a bare IP (or a status round-trip failure) simply falls through to the normal ping.
    if let Ok(want) = ip.parse::<std::net::IpAddr>()
        && let Ok(Response::Ip { ipv4, ipv6 }) = round_trip(socket, &Request::Ip).await
    {
        let is_self = [ipv4.as_deref(), ipv6.as_deref()]
            .into_iter()
            .flatten()
            .filter_map(|s| s.parse::<std::net::IpAddr>().ok())
            .any(|self_ip| self_ip == want);
        if is_self {
            println!("{want} is local Tailscale IP");
            return Ok(());
        }
    }

    let infinite = count == 0;
    let mut received = 0u32;
    let mut went_direct = false;
    let mut seq = 0u32;
    loop {
        seq += 1;
        // The last attempt of a finite run (an infinite run only stops on a direct path or ^C).
        let last = !infinite && seq >= count;
        match round_trip(
            socket,
            &Request::Ping {
                ip: ip.clone(),
                timeout_ms: timeout,
            },
        )
        .await
        {
            Ok(Response::Ping {
                rtt_ms,
                ip,
                endpoint,
            }) => {
                received += 1;
                let direct = endpoint.is_some();
                if direct {
                    went_direct = true;
                }
                println!(
                    "{}",
                    format_ping_line(&ip, rtt_ms, endpoint.as_deref(), seq, count)
                );
                // Early stop: a direct (non-DERP) path is exactly what `--until-direct` waits for
                // (Go returns success here without sending the rest of the count).
                if until_direct && direct {
                    break;
                }
                if last {
                    break;
                }
                // Pace at ~1 ping/second like Go, so `-c N` is a steady stream rather than a burst.
                // Go sleeps ONLY after a pong (a timeout already consumed its own wait), so the
                // sleep lives in this arm, not after a miss.
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
            Ok(Response::Error { message }) => {
                // A per-attempt failure (timeout, transient unreachability) is counted as a miss
                // but does not abort the run — keep pinging like Go. No sleep after a miss: the
                // per-attempt timeout already elapsed (matches Go's immediate retry on deadline).
                eprintln!("{}", format_ping_miss(&ip, &message, seq, count));
                if last {
                    break;
                }
            }
            Ok(other) => anyhow::bail!("unexpected response to ping: {other:?}"),
            Err(e) => {
                return Err(e).with_context(|| format!("pinging at {}", socket.display()));
            }
        }
    }
    // Summary for any multi-attempt run (a single ping's one line is self-explanatory). `seq` is the
    // number actually sent, which is honest when `--until-direct` stopped the run early.
    if count != 1 {
        println!("{}", format_ping_summary(seq, received));
    }
    // Exit verdict (Go's end-of-loop logic): non-zero if nothing replied, or if `--until-direct` was
    // asked for but no direct path was ever established.
    match ping_verdict(received, went_direct, until_direct) {
        PingVerdict::Ok => Ok(()),
        PingVerdict::NoReply => {
            eprintln!("no reply");
            std::process::exit(1);
        }
        PingVerdict::NoDirect => {
            eprintln!("direct connection not established");
            std::process::exit(1);
        }
    }
}

/// The process-exit verdict for a `ping` run, decided from the run tally. A separate enum (rather
/// than threading exit codes inline) so the Go end-of-loop logic is a pure, unit-testable function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PingVerdict {
    /// At least one reply (and, if `--until-direct`, a direct path was reached) → exit 0.
    Ok,
    /// Nothing replied at all → Go's `"no reply"` error, exit non-zero.
    NoReply,
    /// `--until-direct` was requested but no direct path was ever established → Go's
    /// `"direct connection not established"` error, exit non-zero.
    NoDirect,
}

/// Decide the `ping` exit verdict (Go's end-of-loop logic), pure → unit-testable.
///
/// Go order: no reply at all → `"no reply"`; otherwise if `--until-direct` was set but the path
/// never went direct → `"direct connection not established"`; otherwise success.
fn ping_verdict(received: u32, went_direct: bool, until_direct: bool) -> PingVerdict {
    if received == 0 {
        PingVerdict::NoReply
    } else if until_direct && !went_direct {
        PingVerdict::NoDirect
    } else {
        PingVerdict::Ok
    }
}

/// Render the `via …` path descriptor for a ping result line. `Some(endpoint)` ⇒ a direct path
/// (Go prints `via <ip:port>`); `None` ⇒ the overlay is DERP-relayed (Go prints `via DERP`). Pure.
fn ping_via(endpoint: Option<&str>) -> String {
    match endpoint {
        Some(ep) => format!("via {ep}"),
        None => "via DERP".to_string(),
    }
}

/// The `seq N` / `seq N/M` attempt label for a ping line. An infinite run (`count == 0`) has no
/// denominator, so it shows just the attempt number; a finite run shows `N/M`. Pure.
fn ping_seq_label(seq: u32, count: u32) -> String {
    if count == 0 {
        format!("{seq}")
    } else {
        format!("{seq}/{count}")
    }
}

/// Format a successful-pong result line: the peer IP, the path (`via …`), the RTT, and the attempt
/// label. Pure → unit-testable. (Go also prints the node name; our `Response::Ping` carries only the
/// IP, so the IP stands in — the path + RTT, the operationally meaningful parts, match Go.)
fn format_ping_line(ip: &str, rtt_ms: f64, endpoint: Option<&str>, seq: u32, count: u32) -> String {
    format!(
        "pong from {ip} {} in {rtt_ms:.1} ms  (seq {})",
        ping_via(endpoint),
        ping_seq_label(seq, count)
    )
}

/// Format a missed-attempt line (a per-attempt failure that does not abort the run). The daemon
/// returns a bare cause (no `ping <ip> failed:` prefix — see [`crate::ipn`]'s `diag::ping`), so this
/// adds the single attempt label + destination IP. Pure → unit-testable.
fn format_ping_miss(ip: &str, message: &str, seq: u32, count: u32) -> String {
    format!(
        "ping {ip} ({}) failed: {message}",
        ping_seq_label(seq, count)
    )
}

/// `metrics` (Go `tailscale metrics`): fetch the Prometheus text, then print or write it. Inline
/// because `write <path>` chooses a file sink over stdout.
async fn run_metrics(socket: &std::path::Path, cmd: Option<MetricsCmd>) -> Result<()> {
    let text = match round_trip(socket, &Request::Metrics).await {
        Ok(Response::Metrics { text }) => text,
        Ok(Response::Error { message }) => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        Ok(other) => anyhow::bail!("unexpected response to metrics: {other:?}"),
        Err(e) => {
            return Err(e).with_context(|| format!("querying metrics at {}", socket.display()));
        }
    };
    match cmd {
        Some(MetricsCmd::Write { path }) => {
            tokio::fs::write(&path, text.as_bytes())
                .await
                .with_context(|| format!("writing metrics to {}", path.display()))?;
            println!("wrote metrics to {}", path.display());
        }
        // `print` (explicit, Go `metrics print`) and bare `metrics` (no subcommand) both go to stdout.
        Some(MetricsCmd::Print) | None => print!("{text}"),
    }
    Ok(())
}

/// `lock status` (Go `tailscale lock status`): fetch + render the TKA status.
async fn run_lock_status(socket: &std::path::Path, json: bool) -> Result<()> {
    let report = match round_trip(socket, &Request::LockStatus).await {
        Ok(Response::Lock(r)) => r,
        Ok(Response::Error { message }) => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        Ok(other) => anyhow::bail!("unexpected response to lock status: {other:?}"),
        Err(e) => {
            return Err(e).with_context(|| format!("querying lock status at {}", socket.display()));
        }
    };
    print!("{}", format_lock_status(&report, json));
    Ok(())
}

/// `lock log [--limit N]` (Go `tailscale lock log`): fetch + render the TKA update-chain history.
async fn run_lock_log(socket: &std::path::Path, limit: usize, json: bool) -> Result<()> {
    let report = match round_trip(socket, &Request::LockLog { limit }).await {
        Ok(Response::LockLog(r)) => r,
        Ok(Response::Error { message }) => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        Ok(other) => anyhow::bail!("unexpected response to lock log: {other:?}"),
        Err(e) => {
            return Err(e).with_context(|| format!("querying lock log at {}", socket.display()));
        }
    };
    print!("{}", format_lock_log(&report, json));
    Ok(())
}

/// One tailnet-lock trusted key parsed off `lock init`'s positional arguments — Go's `tka.Key` as
/// far as this CLI needs it (`cmd/tailscale/cli/tailnet-lock.go` `parseTLArgs`): the 32-byte Ed25519
/// public key and its vote weight (`<key>?<votes>`, default 1).
#[derive(Debug, Clone, PartialEq, Eq)]
struct LockTrustedKey {
    /// The raw 32-byte tailnet-lock public key (the hex after the `tlpub:`/`nlpub:` prefix).
    public: [u8; 32],
    /// Go `tka.Key.Votes` — the key's weight in the authority, 1 unless `?<votes>` said otherwise.
    votes: u64,
}

/// Parse a tailnet-lock public key the way Go's `key.NLPublic.UnmarshalText` does
/// (`types/key/nl.go` + `types/key/util.go` `parseHex` @ the pinned ref): the wire prefix `nlpub:`
/// is tried first and the CLI prefix `tlpub:` second, so a string with neither reports the CLI one —
/// which is the prefix a `lock` command's argument is expected to carry. The three failures are Go's,
/// verbatim: wrong prefix, wrong hex length, non-hex character.
fn parse_lock_public_key(s: &str) -> Result<[u8; 32]> {
    let hex = match s.strip_prefix("nlpub:") {
        Some(rest) => rest,
        None => match s.strip_prefix("tlpub:") {
            Some(rest) => rest,
            None => anyhow::bail!("key hex string doesn't have expected type prefix tlpub:"),
        },
    };
    // Go measures and indexes BYTES here (`mem.RO.Len`/`.At`), so this does too: the length check is
    // already a byte count, and decoding out of `hex.as_bytes()` keeps the two consistent. Slicing
    // the `str` instead — `&hex[i..i + 2]` — aborts the process on a 64-*byte* argument whose
    // characters are multibyte (`tlpub:` + 21 × `€` + `a` is 64 bytes), because byte 2 is not a
    // char boundary. Go reports a bad hex character there, and so must this.
    let raw = hex.as_bytes();
    if raw.len() != 64 {
        anyhow::bail!("key hex has the wrong size, got {} want 64", raw.len());
    }
    let mut out = [0u8; 32];
    for (byte, pair) in out.iter_mut().zip(raw.as_chunks::<2>().0) {
        let (Some(hi), Some(lo)) = (hex_nibble(pair[0]), hex_nibble(pair[1])) else {
            anyhow::bail!("invalid hex character in key");
        };
        *byte = (hi << 4) | lo;
    }
    Ok(out)
}

/// One hex digit's value, or `None` when the byte is not `[0-9a-fA-F]` — Go's `fromHexChar`
/// (`types/key/util.go` @ v1.100.0). Deliberately not `u8::from_str_radix`, which is both
/// char-boundary sensitive and *more* permissive than Go: `u8::from_str_radix("+f", 16)` is
/// `Ok(15)`, so a leading sign used to decode as a valid hex byte.
fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Split `lock`'s positional arguments into trusted keys and disablement values — a port of Go's
/// `parseTLArgs(args, parseKeys, parseDisablements)` (`cmd/tailscale/cli/tailnet-lock.go`).
///
/// The grammar, and why it matters: an argument prefixed `disablement:` or `disablement-secret:` is
/// a hex-encoded disablement **value**; anything else is a tailnet lock **public key**, optionally
/// suffixed `?<votes>`. Nothing in this grammar is a disablement *secret* — the secrets are minted by
/// `lock init` itself. Go's four error messages are carried over, including their 1-based argument
/// index, because they are the whole feedback an operator gets on a mistyped key.
fn parse_lock_args(
    args: &[String],
    parse_keys: bool,
    parse_disablements: bool,
) -> Result<(Vec<LockTrustedKey>, Vec<Vec<u8>>)> {
    let mut keys = Vec::new();
    let mut disablements = Vec::new();
    for (i, a) in args.iter().enumerate() {
        let n = i + 1;
        if parse_disablements
            && (a.starts_with("disablement:") || a.starts_with("disablement-secret:"))
        {
            // Go slices from the FIRST colon, so `disablement-secret:` is handled by the same arm —
            // and, as upstream, its bytes are taken as a disablement value, not run through the KDF.
            let hex = a.split_once(':').map(|(_, rest)| rest).unwrap_or_default();
            let bytes =
                hex_decode_lower(hex).map_err(|e| anyhow!("parsing disablement {n}: {e}"))?;
            disablements.push(bytes);
            continue;
        }
        if !parse_keys {
            anyhow::bail!(
                "parsing argument {n}: expected value with \"disablement:\" or \
                 \"disablement-secret:\" prefix, got {a:?}"
            );
        }
        let (key_text, votes_text) = match a.split_once('?') {
            Some((k, v)) => (k, Some(v)),
            None => (a.as_str(), None),
        };
        let public =
            parse_lock_public_key(key_text).map_err(|e| anyhow!("parsing key {n}: {e}"))?;
        let votes = match votes_text {
            Some(v) => v
                .parse::<u64>()
                .map_err(|e| anyhow!("parsing key {n} votes: {e}"))?,
            None => 1,
        };
        keys.push(LockTrustedKey { public, votes });
    }
    Ok((keys, disablements))
}

/// The `lock init` command line after clap — Go's `nlInitArgs` plus this fork's one addition.
struct LockInitArgs<'a> {
    /// Go's `<trusted-key>...` positionals (which may also carry `disablement:` values).
    positionals: &'a [String],
    /// Go `--gen-disablements`; `None` = not given, which is Go's default of 1.
    gen_disablements: Option<usize>,
    /// Go `--gen-disablement-for-support`.
    gen_disablement_for_support: bool,
    /// Go `--confirm`.
    confirm: bool,
    /// This fork's `--disablement-secret` (not a Go flag): use this secret instead of minting one.
    supplied_secret: Option<&'a str>,
}

/// What `lock init` decided to do, once the arguments and the current lock state are both known.
#[derive(Debug, PartialEq, Eq)]
enum LockInitPlan {
    /// Go's `--confirm` two-step: print this and change nothing.
    Confirm(String),
    /// Go's confirmed path: print `preamble` (the trusted keys, which Go prints as soon as it has
    /// them, confirmed or not), hand `secret_hex` to the daemon, and print `notice` — which carries
    /// the minted secret — only once the daemon reports success, exactly as Go builds `successMsg`
    /// before the RPC and prints it after.
    Init {
        secret_hex: String,
        preamble: String,
        notice: String,
    },
}

/// Decide what `tnet lock init` does, from its arguments and the lock status the daemon just
/// reported. A port of Go's `runTailnetLockInit` (`cmd/tailscale/cli/tailnet-lock.go`) minus the
/// two RPCs, so the whole decision — Go's two refusals, the argument grammar, the `--confirm`
/// two-step and the minting — is one pure function the tests can drive.
///
/// Go's order is kept: the lock-already-enabled refusal comes before the arguments are even parsed
/// (upstream asks control for the status first), then the argument grammar, then the trusted-key
/// requirement, then the confirmation gate, and the secrets are minted last.
///
/// The trusted-key requirement is where this fork parts company with upstream, and it is the reason
/// this command's grammar changed: Go refuses when the current node's own lock key is not among the
/// trusted keys, and *this* daemon cannot even ask that question — the engine's `tka_init` takes no
/// key set and will not report this node's lock key (docs/ENGINE_ASKS.md #36). Every argument that
/// asks for something the engine cannot do is therefore refused by name. Accepting them would mean
/// doing something other than what was asked, silently, with the tailnet's lock.
///
/// `mint` is the entropy source, injected so a test can pin the output byte for byte; production
/// passes [`mint_disablement_secret`].
fn plan_lock_init(
    program: &str,
    args: &LockInitArgs<'_>,
    lock_enabled: bool,
    mint: &mut dyn FnMut() -> Result<[u8; 32]>,
) -> Result<LockInitPlan> {
    use std::fmt::Write as _;

    // Go: `if st.Enabled { return errors.New("tailnet lock is already enabled") }`, before anything
    // else. Initializing an initialized lock is not a thing control would accept anyway; the point
    // is that the operator hears it in one line instead of a control-side rejection.
    if lock_enabled {
        anyhow::bail!("tailnet lock is already enabled");
    }

    let (keys, disablements) = parse_lock_args(args.positionals, true, true)?;

    if !keys.is_empty() {
        anyhow::bail!(
            "this daemon cannot initialize tailnet lock with a chosen trusted-key set. Upstream's \
             rule is that \"the tailnet lock key of the current node must be one of the trusted \
             keys during initialization\"; here the engine's `tka_init` takes no key set at all — it \
             always initializes trusting this node's own tailnet lock key alone, with one vote — \
             and exposes no way to read that key back, so a key set can neither be honoured nor \
             checked. Re-run with no <trusted-key> arguments to initialize with this node as the \
             sole trusted key (docs/ENGINE_ASKS.md #36)"
        );
    }
    if !disablements.is_empty() {
        anyhow::bail!(
            "this daemon cannot initialize tailnet lock with a pre-computed disablement value. The \
             engine's `tka_init` takes a disablement SECRET and derives the value from it itself, \
             so a value computed offline with `tnet lock disablement-kdf` has nowhere to go. Supply \
             the secret with --disablement-secret instead, or let this command mint one \
             (docs/ENGINE_ASKS.md #36)"
        );
    }
    if args.gen_disablement_for_support {
        anyhow::bail!(
            "this daemon cannot honour --gen-disablement-for-support: it asks for an ADDITIONAL \
             disablement secret, minted separately and transmitted to the coordination server, and \
             the engine's `tka_init` carries exactly one secret — which it already transmits as the \
             support disablement. The secret this command uses is known to the coordination server \
             either way, with or without this flag (docs/ENGINE_ASKS.md #36)"
        );
    }
    if args.gen_disablements.is_some() && args.supplied_secret.is_some() {
        anyhow::bail!(
            "--gen-disablements can only be used without --disablement-secret: \
             --disablement-secret supplies the one disablement secret, --gen-disablements asks this \
             command to mint it"
        );
    }
    let gen_disablements = args.gen_disablements.unwrap_or(1);
    if args.supplied_secret.is_none() && gen_disablements == 0 {
        // Upstream never validates this in code, but its help is explicit — "Initializing tailnet
        // lock requires at least one disablement" — and a lock with no disablement value at all can
        // never be turned off again, so it is refused here rather than left to control.
        anyhow::bail!(
            "initializing tailnet lock requires at least one disablement, so --gen-disablements 0 \
             cannot be used: a lock with no disablement value could never be disabled"
        );
    }
    if args.supplied_secret.is_none() && gen_disablements != 1 {
        anyhow::bail!(
            "this daemon cannot honour --gen-disablements {gen_disablements}: the engine's \
             `tka_init` stores exactly one disablement value, so only --gen-disablements 1 (the \
             default) can be initialized (docs/ENGINE_ASKS.md #36)"
        );
    }
    // An unusable secret must fail before the confirmation step, not after it: Go likewise rejects
    // malformed arguments before it prints anything.
    if let Some(secret) = args.supplied_secret {
        hex_decode_lower(secret).context("--disablement-secret must be hex-encoded")?;
    }

    // Go prints the trusted keys it is about to write into the genesis, one per line. There is only
    // ever one here, and this daemon cannot print it — so it is named rather than shown.
    let mut out = String::new();
    let _ = writeln!(
        out,
        "You are initializing tailnet lock with the following trusted signing keys:"
    );
    let _ = writeln!(
        out,
        " - the tailnet lock key of this node (the only key this daemon can trust; it cannot print \
         it)"
    );
    let _ = writeln!(out);

    if !args.confirm {
        match args.supplied_secret {
            Some(secret) => {
                let _ = writeln!(
                    out,
                    "The disablement secret supplied with --disablement-secret will be used; none \
                     will be generated."
                );
                let _ = writeln!(out, "{SUPPORT_DISABLEMENT_NOTE}");
                let _ = writeln!(
                    out,
                    "\nIf this is correct, please re-run this command with the --confirm flag:"
                );
                let _ = writeln!(
                    out,
                    "\t{program} lock init --confirm --disablement-secret {secret}"
                );
            }
            None => {
                // Go's sentence, unpluralized as upstream leaves it.
                let _ = writeln!(
                    out,
                    "{gen_disablements} disablement secrets will be generated."
                );
                let _ = writeln!(out, "{SUPPORT_DISABLEMENT_NOTE}");
                let _ = writeln!(
                    out,
                    "\nIf this is correct, please re-run this command with the --confirm flag:"
                );
                let _ = writeln!(
                    out,
                    "\t{program} lock init --confirm --gen-disablements {gen_disablements}"
                );
            }
        }
        return Ok(LockInitPlan::Confirm(out));
    }

    // Confirmed. `out` already holds the trusted-key block Go prints on this path too; from here the
    // text is what gets printed only if the daemon accepts the init.
    let mut notice = String::new();
    let secret_hex = match args.supplied_secret {
        Some(secret) => secret.to_string(),
        None => {
            let secret = mint()?;
            let hex = hex_encode_upper(&secret);
            let _ = writeln!(
                notice,
                "{gen_disablements} disablement secrets have been generated and are printed below. \
                 Take note of them now, they WILL NOT be shown again."
            );
            let _ = writeln!(notice, "\tdisablement-secret:{hex}");
            hex
        }
    };
    let _ = writeln!(notice, "{SUPPORT_DISABLEMENT_NOTE}");
    Ok(LockInitPlan::Init {
        secret_hex,
        preamble: out,
        notice,
    })
}

/// The one line this fork has to add to Go's `lock init` output: upstream mints a separate secret
/// for the coordination server only when asked (`--gen-disablement-for-support`), while the engine's
/// `tka_init` sends the single secret it is given as `TKAInitFinishRequest.SupportDisablement`
/// unconditionally. An operator who is told nothing would believe the secret is theirs alone.
const SUPPORT_DISABLEMENT_NOTE: &str = "Note: this daemon's engine also transmits the disablement \
                                        secret to the coordination server as the support \
                                        disablement, so its operator can disable the lock. Upstream \
                                        does that only for --gen-disablement-for-support.";

/// Mint one 32-byte tailnet-lock disablement secret from the OS CSPRNG — Go's
/// `rand.Read(secret[:])` over `crypto/rand` in `runTailnetLockInit`. Failing to read entropy is
/// surfaced, never worked around: a predictable disablement secret is worse than no lock.
fn mint_disablement_secret() -> Result<[u8; 32]> {
    let mut secret = [0u8; 32];
    getrandom::fill(&mut secret).map_err(|e| {
        anyhow!(
            "reading {} bytes from the OS random source: {e}",
            secret.len()
        )
    })?;
    Ok(secret)
}

/// Encode bytes as UPPERCASE hex — Go prints the minted secret with `%X`, and the printed form is
/// the form the operator will later paste into `tnet lock disable`, so it is also what goes on the
/// wire (the daemon's hex decode is case-insensitive).
fn hex_encode_upper(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02X}");
        s
    })
}

/// `lock init` (Go `tailscale lock init`): initialize Tailnet Lock for the tailnet.
///
/// Go's shape, kept: ask the daemon for the lock status first (so an already-enabled lock is refused
/// in one line), decide everything in [`plan_lock_init`], and — only on the confirmed path — send
/// the init and print the minted secret *after* the daemon accepts it. A failed init must not leave
/// the operator holding a secret that gates nothing.
///
/// The secret is passed straight through on the wire (a local Unix-socket request, like the auth
/// key) and is never echoed back by the daemon.
async fn run_lock_init(socket: &std::path::Path, args: &LockInitArgs<'_>) -> Result<()> {
    let status = match round_trip(socket, &Request::LockStatus)
        .await
        .with_context(|| format!("querying lock status at {}", socket.display()))?
    {
        Response::Lock(report) => report,
        Response::Error { message } => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        other => anyhow::bail!("unexpected response to lock status: {other:?}"),
    };

    // Go prints `os.Args[0]` in the re-run line; the operator has to be able to paste it back.
    let program = std::env::args()
        .next()
        .unwrap_or_else(|| "tnet".to_string());
    let plan = plan_lock_init(&program, args, status.enabled, &mut mint_disablement_secret)?;
    let (secret_hex, notice) = match plan {
        LockInitPlan::Confirm(text) => {
            print!("{text}");
            return Ok(());
        }
        LockInitPlan::Init {
            secret_hex,
            preamble,
            notice,
        } => {
            // Go prints the trusted keys as soon as it has parsed them, before the init RPC.
            print!("{preamble}");
            (secret_hex, notice)
        }
    };

    let req = Request::LockInit { secret_hex };
    match round_trip(socket, &req)
        .await
        .with_context(|| format!("talking to daemon at {}", socket.display()))?
    {
        Response::Ok { message } => {
            print!("{notice}");
            println!("Initialization complete.");
            println!("{message}");
            Ok(())
        }
        Response::Error { message } => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        other => anyhow::bail!("unexpected response to lock init: {other:?}"),
    }
}

/// `lock sign <node-key>` (Go `tailscale lock sign`): submit a co-signature for the node key into
/// Tailnet Lock. Prints the daemon's `ok` message (the signature applies on the next netmap sync) or
/// surfaces the error and exits non-zero.
async fn run_lock_sign(socket: &std::path::Path, node_key: &str) -> Result<()> {
    let req = Request::LockSign {
        node_key: node_key.to_string(),
    };
    match round_trip(socket, &req)
        .await
        .with_context(|| format!("talking to daemon at {}", socket.display()))?
    {
        Response::Ok { message } => {
            println!("ok: {message}");
            Ok(())
        }
        Response::Error { message } => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        other => anyhow::bail!("unexpected response to lock sign: {other:?}"),
    }
}

/// `lock disable <secret>` (Go `tailscale lock disable`): present the hex-encoded disablement secret
/// to turn Tailnet Lock off for the tailnet. Prints the daemon's `ok` message or surfaces the error
/// and exits non-zero. The secret is passed straight through on the wire (a local Unix-socket
/// request, like the auth key) and is never echoed back by the daemon.
async fn run_lock_disable(socket: &std::path::Path, secret: &str) -> Result<()> {
    let req = Request::LockDisable {
        secret_hex: secret.to_string(),
    };
    match round_trip(socket, &req)
        .await
        .with_context(|| format!("talking to daemon at {}", socket.display()))?
    {
        Response::Ok { message } => {
            println!("ok: {message}");
            Ok(())
        }
        Response::Error { message } => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        other => anyhow::bail!("unexpected response to lock disable: {other:?}"),
    }
}

/// `lock disablement-kdf` (Go `tailscale lock disablement-kdf`): derive the disablement VALUE from a
/// hex-encoded disablement SECRET and print `disablement:<hex>`. Pure local, offline — no daemon.
///
/// The KDF is byte-for-byte Go `tka.DisablementKDF` (`tka/state.go`, v1.100.0):
/// `argon2.Key(secret, "tailscale network-lock disablement salt", time=4, mem=16*1024 KiB, threads=4,
/// keyLen=32)`. Go's `argon2.Key` is **Argon2i** (the data-independent variant) — NOT Argon2id, which
/// the `argon2` crate defaults to and which would produce entirely different digests — so the
/// algorithm is selected explicitly. Verified against Go goldens in the test below.
fn run_lock_disablement_kdf(secret_hex: &str) -> Result<()> {
    use argon2::{Algorithm, Argon2, Params, Version};

    let secret = hex_decode_lower(secret_hex)
        .with_context(|| "disablement secret must be hex-encoded".to_string())?;

    // Go `tka.DisablementKDF` parameters (tka/state.go): t=4, m=16 MiB (16*1024 KiB), p=4, out=32B.
    let salt = b"tailscale network-lock disablement salt";
    let params =
        Params::new(16 * 1024, 4, 4, Some(32)).map_err(|e| anyhow!("argon2 params: {e}"))?;
    // Argon2**i** + version 0x13 (the libargon2/Go default), to match Go's `argon2.Key` exactly.
    let argon = Argon2::new(Algorithm::Argon2i, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(&secret, salt, &mut out)
        .map_err(|e| anyhow!("argon2 derivation failed: {e}"))?;

    // Go prints `disablement:%x` (lower-hex), so render the bytes the same way.
    let mut hex = String::with_capacity(2 * out.len());
    for b in out {
        hex.push_str(&format!("{b:02x}"));
    }
    println!("disablement:{hex}");
    Ok(())
}

/// Decode a lower/upper-hex string to bytes (the disablement secret is hex). A small local helper so
/// the `lock disablement-kdf` path has no extra dependency beyond the `argon2` KDF itself.
fn hex_decode_lower(s: &str) -> Result<Vec<u8>> {
    // Byte-wise for the same reason as `parse_lock_public_key`: this decodes operator input — the
    // `--disablement-secret` flag and the `disablement:`/`disablement-secret:` positionals — so a
    // multibyte character has to come back as a bad hex byte, not as a panic from a `str` slice
    // taken through the middle of it.
    let raw = s.trim().as_bytes();
    if !raw.len().is_multiple_of(2) {
        anyhow::bail!("odd-length hex string");
    }
    raw.as_chunks::<2>()
        .0
        .iter()
        .map(|pair| match (hex_nibble(pair[0]), hex_nibble(pair[1])) {
            (Some(hi), Some(lo)) => Ok((hi << 4) | lo),
            _ => Err(anyhow!(
                "invalid hex byte {:?}",
                String::from_utf8_lossy(pair)
            )),
        })
        .collect()
}

/// `dns status` (Go `tailscale dns status`): fetch + render the control-pushed MagicDNS config.
async fn run_dns_status(socket: &std::path::Path, json: bool) -> Result<()> {
    let report = match round_trip(socket, &Request::DnsStatus).await {
        Ok(Response::DnsStatus(r)) => r,
        Ok(Response::Error { message }) => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        Ok(other) => anyhow::bail!("unexpected response to dns status: {other:?}"),
        Err(e) => {
            return Err(e).with_context(|| format!("querying dns status at {}", socket.display()));
        }
    };
    print!("{}", format_dns_status(&report, json));
    Ok(())
}

/// `tnet dns query <name> [type]` (Go `tailscale dns query`): resolve a name through the node's own
/// MagicDNS path and render the RCODE, the upstream resolver(s) consulted, and the response. The
/// `qtype` string (a name like `AAAA` or a number) is parsed CLI-side into the numeric RFC 1035 TYPE
/// the wire carries.
async fn run_dns_query(
    socket: &std::path::Path,
    name: &str,
    qtype: &str,
    json: bool,
) -> Result<()> {
    let qtype_num =
        parse_qtype(qtype).with_context(|| format!("unrecognized DNS query type {qtype:?}"))?;
    let report = match round_trip(
        socket,
        &Request::DnsQuery {
            name: name.to_string(),
            qtype: qtype_num,
        },
    )
    .await
    {
        Ok(Response::DnsQuery(r)) => r,
        Ok(Response::Error { message }) => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        Ok(other) => anyhow::bail!("unexpected response to dns query: {other:?}"),
        Err(e) => {
            return Err(e).with_context(|| format!("querying dns at {}", socket.display()));
        }
    };
    print!("{}", format_dns_query(&report, json));
    Ok(())
}

/// Parse a DNS query-type token into its numeric RFC 1035 TYPE: either a case-insensitive mnemonic
/// (`A`, `AAAA`, `CNAME`, `PTR`, `TXT`, `MX`, `NS`, `SRV`, `SOA`, `CAA`, `ANY`) or a decimal number
/// (so any TYPE the mnemonic table omits is still reachable, e.g. `tnet dns query x 257`). Returns
/// `None` for an unrecognized mnemonic that also is not a number. Pure → unit-testable.
fn parse_qtype(s: &str) -> Option<u16> {
    match s.to_ascii_uppercase().as_str() {
        "A" => Some(1),
        "NS" => Some(2),
        "CNAME" => Some(5),
        "SOA" => Some(6),
        "PTR" => Some(12),
        "MX" => Some(15),
        "TXT" => Some(16),
        "AAAA" => Some(28),
        "SRV" => Some(33),
        "CAA" => Some(257),
        "ANY" => Some(255),
        // Not a known mnemonic — accept a bare decimal TYPE number so uncommon types stay reachable.
        other => other.parse::<u16>().ok(),
    }
}

/// Map a numeric DNS TYPE back to its mnemonic for display (inverse of the common cases in
/// [`parse_qtype`]); an unknown number renders as `TYPE<n>` (the RFC 3597 convention). Pure.
fn qtype_name(qtype: u16) -> String {
    match qtype {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        255 => "ANY".into(),
        257 => "CAA".into(),
        n => format!("TYPE{n}"),
    }
}

/// Map a DNS RCODE (response-header low 4 bits) to its mnemonic for display; an unknown code renders
/// as `RCODE<n>`. Pure.
fn rcode_name(rcode: u8) -> String {
    match rcode {
        0 => "NoError".into(),
        1 => "FormErr".into(),
        2 => "ServFail".into(),
        3 => "NXDomain".into(),
        4 => "NotImp".into(),
        5 => "Refused".into(),
        n => format!("RCODE{n}"),
    }
}

/// `netcheck` (Go `tailscale netcheck`): fetch + render the net-report (DERP-region latency).
async fn run_netcheck(
    socket: &std::path::Path,
    json: bool,
    format: Option<String>,
    every: Option<u64>,
    verbose: bool,
) -> Result<()> {
    // Resolve the output mode: an explicit `--format` wins; the legacy `--json` bool maps to pretty
    // JSON; otherwise human-readable. (clap already rejects `--json` + `--format` together.)
    let mode = match format.as_deref() {
        Some("json-line") => NetcheckFormat::JsonLine,
        Some("json") => NetcheckFormat::Json,
        _ if json => NetcheckFormat::Json,
        _ => NetcheckFormat::Human,
    };

    // Go prints this to stderr before any JSON report: the report shape is not a stable interface.
    // It applies to the `--json` alias too — that is just another spelling of `--format json`.
    if matches!(mode, NetcheckFormat::Json | NetcheckFormat::JsonLine) {
        eprintln!("# Warning: this JSON format is not yet considered a stable interface");
    }

    match every {
        // Single report (the default).
        None => {
            let report = fetch_netcheck_timed(socket, verbose).await?;
            print!("{}", format_netcheck(&report, mode));
            Ok(())
        }
        // `--every N`: repeat every N seconds until interrupted, separating reports the way the mode
        // wants (a blank line between human reports; json-line is already one-per-line).
        Some(secs) => {
            let interval = std::time::Duration::from_secs(secs.max(1));
            let mut first = true;
            loop {
                let report = fetch_netcheck_timed(socket, verbose).await?;
                if !first && matches!(mode, NetcheckFormat::Human | NetcheckFormat::Json) {
                    println!();
                }
                first = false;
                print!("{}", format_netcheck(&report, mode));
                use std::io::Write as _;
                let _ = std::io::stdout().flush();
                tokio::time::sleep(interval).await;
            }
        }
    }
}

/// Fetch one report, and with `--verbose` log how long it took to stderr — Go's
/// `c.Logf("GetReport took %v; err=%v", ...)`, which its netcheck client prints after every report.
/// The timing is measured around the daemon round-trip because that is where the measurement happens
/// here (Go measures its in-process `GetReport` call). A failed fetch never reaches this line: like
/// Go, an error ends the command — [`fetch_netcheck`] prints the daemon's error and exits.
async fn fetch_netcheck_timed(
    socket: &std::path::Path,
    verbose: bool,
) -> Result<tailscaled_rs::localapi::NetcheckReport> {
    if !verbose {
        return fetch_netcheck(socket).await;
    }
    let started = std::time::Instant::now();
    let report = fetch_netcheck(socket).await?;
    eprintln!("{}", netcheck_verbose_line(started.elapsed()));
    Ok(report)
}

/// Render Go's verbose netcheck timing line. Go logs `netcheck: GetReport took 57ms; err=<nil>`
/// (a `time.Duration` rounded to milliseconds, and `%v` of a nil error). This prints whole
/// milliseconds rather than reimplementing Go's mixed-unit duration formatting, and always reports
/// `err=<nil>`: an errored report exits before this line, so the only report that gets timed here is
/// one that succeeded. Pure → unit-testable.
fn netcheck_verbose_line(elapsed: std::time::Duration) -> String {
    format!(
        "netcheck: GetReport took {}ms; err=<nil>",
        elapsed.as_millis()
    )
}

/// Fetch one netcheck report from the daemon (a single `Request::Netcheck` round-trip). A plain
/// `async fn` rather than a closure so the `&Path` borrow doesn't outlive a closure's return future
/// (the `--every` loop calls it repeatedly). A daemon `Error` reply exits 1 (the report can't be
/// produced); a transport error propagates with context.
async fn fetch_netcheck(
    socket: &std::path::Path,
) -> Result<tailscaled_rs::localapi::NetcheckReport> {
    match round_trip(socket, &Request::Netcheck).await {
        Ok(Response::Netcheck(r)) => Ok(r),
        Ok(Response::Error { message }) => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        Ok(other) => anyhow::bail!("unexpected response to netcheck: {other:?}"),
        Err(e) => Err(e).with_context(|| format!("querying netcheck at {}", socket.display())),
    }
}

/// How `tnet netcheck` renders a report (Go `--format`): human-readable, pretty/tab-indented JSON, or
/// a single compact JSON line per report (`json-line`, handy with `--every`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NetcheckFormat {
    Human,
    Json,
    JsonLine,
}

/// `syspolicy list` / `reload` (Go `tailscale syspolicy`): round-trip the given request (which the
/// caller picks — [`Request::SyspolicyList`] or [`Request::SyspolicyReload`]) and render the
/// effective-policy snapshot. Both verbs reply with [`Response::Policy`] and render identically; the
/// only difference is whether the daemon forced a re-read first.
async fn run_syspolicy(socket: &std::path::Path, request: Request, json: bool) -> Result<()> {
    let report = match round_trip(socket, &request).await {
        Ok(Response::Policy(r)) => r,
        Ok(Response::Error { message }) => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        Ok(other) => anyhow::bail!("unexpected response to syspolicy: {other:?}"),
        Err(e) => {
            return Err(e).with_context(|| format!("querying syspolicy at {}", socket.display()));
        }
    };
    print!("{}", format_policy(&report, json));
    Ok(())
}

/// `service list` (Go `tailscale service list`): print the Tailscale Services this node can reach.
///
/// Two round trips, exactly as Go's `runServiceList` makes two LocalAPI calls: the `services` verb
/// for the Service set, then `status` for the tailnet's MagicDNS suffix, which is what turns a
/// Service's `svc:<label>` name into the hostname the HOSTNAME column (and the JSON) carries.
async fn run_service_list(socket: &std::path::Path, json: bool) -> Result<()> {
    let services = match round_trip(socket, &Request::Services).await {
        Ok(Response::Services { services }) => services,
        Ok(Response::Error { message }) => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        Ok(other) => anyhow::bail!("unexpected response to services request: {other:?}"),
        Err(e) => {
            return Err(e).with_context(|| format!("querying services at {}", socket.display()));
        }
    };
    let status = match round_trip(socket, &Request::Status).await {
        Ok(Response::Status(s)) => s,
        Ok(Response::Error { message }) => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        Ok(other) => anyhow::bail!("unexpected response to status request: {other:?}"),
        Err(e) => {
            return Err(e).with_context(|| format!("querying status at {}", socket.display()));
        }
    };
    print!(
        "{}",
        format_service_list(&services, status.magic_dns_suffix.as_deref(), json,)
    );
    Ok(())
}

/// The MagicDNS hostname of a Service, porting Go's `serviceHostname`: the name without its `svc:`
/// prefix, joined to the tailnet's MagicDNS suffix. Empty when either half is missing — a name that
/// carries no `svc:` prefix is not a valid service name (Go's `ServiceName.WithoutPrefix` returns
/// `""` for it), and a node with no netmap suffix has no tailnet domain to build a name in.
fn service_hostname(name: &str, magic_dns_suffix: Option<&str>) -> String {
    let Some(bare) = name.strip_prefix("svc:") else {
        return String::new();
    };
    let suffix = magic_dns_suffix.unwrap_or("").trim_matches('.');
    if bare.is_empty() || suffix.is_empty() {
        return String::new();
    }
    format!("{bare}.{suffix}")
}

/// Go `wellKnownPortActions`: the TCP ports a Service action type is conventionally inferred from,
/// used for the TYPE column when a Service carries no explicit actions.
const WELL_KNOWN_PORT_ACTIONS: &[(u16, &str)] = &[
    (22, "ssh"),
    (80, "http"),
    (443, "http"),
    (1433, "mssql"),
    (3306, "mysql"),
    (3389, "rdp"),
    (5432, "postgresql"),
    (5900, "vnc"),
    (6443, "kubernetes"),
    (9200, "elasticsearch"),
    (26257, "cockroach"),
    (27017, "mongodb"),
];

/// The most action types [`service_action_types`] names before summarizing the rest as
/// "N other(s)" (Go `maxNamedTypes`).
const MAX_NAMED_TYPES: usize = 2;

/// Render a Service's action types for the TYPE column, porting Go's `serviceActionTypes`.
///
/// Explicit actions are shown by type; a Service carrying none has its types inferred from
/// well-known single TCP ports ([`WELL_KNOWN_PORT_ACTIONS`]). Types are deduplicated in first-seen
/// order, at most [`MAX_NAMED_TYPES`] are named, and the remainder is summarized — so `"-"` for
/// none, `"http"` for one, `"http, ssh"` for two, `"http, ssh, 2 others"` beyond that.
fn service_action_types(svc: &tailscaled_rs::localapi::ServiceReport) -> String {
    let raw: Vec<&str> = if !svc.actions.is_empty() {
        svc.actions.iter().map(|a| a.action_type.as_str()).collect()
    } else {
        svc.ports
            .iter()
            // Only a single (non-range) TCP port maps to a well-known action, as in Go.
            .filter_map(|p| p.single_tcp_port())
            .filter_map(|port| {
                WELL_KNOWN_PORT_ACTIONS
                    .iter()
                    .find(|(p, _)| *p == port)
                    .map(|(_, t)| *t)
            })
            .collect()
    };
    // Deduplicate, preserving first-seen order (Go's `seen` map + append).
    let mut types: Vec<&str> = Vec::new();
    for t in raw {
        if !types.contains(&t) {
            types.push(t);
        }
    }
    if types.is_empty() {
        return "-".to_string();
    }
    if types.len() <= MAX_NAMED_TYPES {
        return types.join(", ");
    }
    let extra = types.len() - MAX_NAMED_TYPES;
    let noun = if extra == 1 { "other" } else { "others" };
    format!("{}, {extra} {noun}", types[..MAX_NAMED_TYPES].join(", "))
}

/// Go's `cmp.Or(s, "-")`: the string, or `-` when it is empty. Every column of Go's Service table
/// falls back to a dash rather than printing a blank cell.
fn or_dash(s: String) -> String {
    if s.is_empty() { "-".to_string() } else { s }
}

/// Render `tnet service list` from a [`ServiceReport`](tailscaled_rs::localapi::ServiceReport) set
/// (Go `runServiceList`). Pure (returns the string including its trailing newline) → unit-testable;
/// the caller `print!`s it.
///
/// Human form reproduces Go's `text/tabwriter` table — a leading blank line, then a header and one
/// row per Service across the IP / HOSTNAME / DISPLAY NAME / ENDPOINTS / TYPE columns, each column
/// padded to `max(10, widest cell + 5)` which is what `tabwriter.NewWriter(…, 10, 5, 5, ' ', 0)`
/// computes. An empty set prints Go's sentence instead of an empty table. IP is always `Addrs[0]`,
/// as in Go: on a tailnet with IPv4 disabled the netmap carries only the v6 address, so index 0 is
/// the address to show either way.
///
/// Every cell but the fixed headers is control-pushed, so it goes through
/// [`sanitize_for_terminal`] before it is measured or printed — the same hardening
/// `format_dns_status`/`format_whois` apply, since a compromised control server could otherwise
/// smuggle terminal escapes into an operator's terminal. The `--json` path is serde-escaped.
///
/// `json` emits Go's own array shape — the `ServiceDetails` fields in Go's order plus the
/// `Hostname` the CLI decorates each entry with — so `tailscale service list --json` consumers
/// keep working: `Name`, `DisplayName`, `Addrs`, `Ports` (Go's `[<proto>:]<ports>` text form),
/// `Actions`, `Hostname`, with Go's `omitzero`/`omitempty` fields dropped when empty.
fn format_service_list(
    services: &[tailscaled_rs::localapi::ServiceReport],
    magic_dns_suffix: Option<&str>,
    json: bool,
) -> String {
    if json {
        /// One `service list --json` element: Go's embedded `ServiceDetails` fields, in Go's field
        /// order, then the `Hostname` Go's `serviceListEntry` decorates it with.
        #[derive(serde::Serialize)]
        struct Entry<'a> {
            #[serde(rename = "Name")]
            name: &'a str,
            #[serde(rename = "DisplayName", skip_serializing_if = "str::is_empty")]
            display_name: &'a str,
            #[serde(rename = "Addrs", skip_serializing_if = "<[String]>::is_empty")]
            addrs: &'a [String],
            #[serde(rename = "Ports", skip_serializing_if = "Vec::is_empty")]
            ports: Vec<String>,
            #[serde(rename = "Actions", skip_serializing_if = "Vec::is_empty")]
            actions: Vec<Action<'a>>,
            #[serde(rename = "Hostname")]
            hostname: String,
        }
        /// One action inside an [`Entry`], in Go's `ServiceAction` field order.
        #[derive(serde::Serialize)]
        struct Action<'a> {
            #[serde(rename = "Type")]
            action_type: &'a str,
            #[serde(rename = "Port")]
            port: u16,
            #[serde(rename = "DisplayName", skip_serializing_if = "str::is_empty")]
            display_name: &'a str,
            #[serde(
                rename = "Attributes",
                skip_serializing_if = "std::collections::BTreeMap::is_empty"
            )]
            attributes: &'a std::collections::BTreeMap<String, serde_json::Value>,
        }
        let entries: Vec<Entry<'_>> = services
            .iter()
            .map(|s| Entry {
                name: &s.name,
                display_name: &s.display_name,
                addrs: &s.addrs,
                ports: s.ports.iter().map(|p| p.to_string()).collect(),
                actions: s
                    .actions
                    .iter()
                    .map(|a| Action {
                        action_type: &a.action_type,
                        port: a.port,
                        display_name: &a.display_name,
                        attributes: &a.attributes,
                    })
                    .collect(),
                hostname: service_hostname(&s.name, magic_dns_suffix),
            })
            .collect();
        return format!(
            "{}\n",
            serde_json::to_string_pretty(&entries).unwrap_or_else(|_| "[]".to_string())
        );
    }

    if services.is_empty() {
        // Go's exact sentence — an empty tailnet-ACL grant is a normal answer, not an error.
        return "No Tailscale Services are available to this node.\n".to_string();
    }

    // Go's header + one row per Service. The leading space of the first cell is Go's (its format
    // string is `"\n %s\t…"`), so it is part of the cell and counts toward the column width.
    let mut rows: Vec<[String; 5]> = vec![[
        " IP".to_string(),
        "HOSTNAME".to_string(),
        "DISPLAY NAME".to_string(),
        "ENDPOINTS".to_string(),
        "TYPE".to_string(),
    ]];
    for svc in services {
        let ip = svc.addrs.first().cloned().unwrap_or_default();
        let endpoints = svc
            .ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        rows.push([
            format!(" {}", or_dash(sanitize_for_terminal(&ip))),
            or_dash(sanitize_for_terminal(&service_hostname(
                &svc.name,
                magic_dns_suffix,
            ))),
            or_dash(sanitize_for_terminal(&svc.display_name)),
            or_dash(sanitize_for_terminal(&endpoints)),
            sanitize_for_terminal(&service_action_types(svc)),
        ]);
    }
    // Go `tabwriter.NewWriter(Stdout, 10, 5, 5, ' ', 0)`: every column is tab-terminated, so each
    // one is padded to `max(minwidth, widest cell + padding)` — including the last, which is why
    // Go's rows carry trailing spaces.
    const MIN_WIDTH: usize = 10;
    const PADDING: usize = 5;
    let mut widths = [MIN_WIDTH; 5];
    for row in &rows {
        for (i, cell) in row.iter().enumerate() {
            widths[i] = widths[i].max(cell.chars().count() + PADDING);
        }
    }
    // Go writes a newline BEFORE each line (its format string opens with `\n`) and one final
    // `Fprintln`, so the table is preceded by a blank line and every row ends in a newline.
    let mut out = String::from("\n");
    for row in &rows {
        for (i, cell) in row.iter().enumerate() {
            let pad = widths[i].saturating_sub(cell.chars().count());
            out.push_str(cell);
            out.push_str(&" ".repeat(pad));
        }
        out.push('\n');
    }
    out
}

/// The Service arm of Go `ip.go`'s peer lookup: the addresses of the Service whose VIPs contain
/// `ip`, or `None` when no Service does. Ports Go's `allIPsForServiceWithIP`.
///
/// A Tailscale Service is not a peer — it is a virtual service with its own addresses — so an
/// argument that names a Service VIP matches no peer, and before this it could only be reported as
/// "no peer found". Addresses are compared PARSED, so a differently-spelled IPv6 literal still hits.
fn service_addrs_matching_ip(
    services: &[tailscaled_rs::localapi::ServiceReport],
    ip: std::net::IpAddr,
) -> Option<&[String]> {
    services
        .iter()
        .find(|svc| {
            svc.addrs
                .iter()
                .filter_map(|a| a.parse::<std::net::IpAddr>().ok())
                .any(|a| a == ip)
        })
        .map(|svc| svc.addrs.as_slice())
}

/// Apply an [`IpSelect`] to a Service's address list — Go `ip.go`'s tail, which prints every
/// address of the resolved target filtered by family (`-4`/`-6`) after `-1` has truncated the list
/// to the first.
///
/// A peer has exactly one address per family, so [`format_ip_filtered`] can take them positionally;
/// a Service carries a list, so the family of each address is determined by parsing it. An address
/// that does not parse is dropped rather than mis-filed under a family it may not belong to.
fn format_service_ips(addrs: &[String], sel: IpSelect) -> String {
    // Go truncates to the first address BEFORE the family filter — `ips = ips[:1]`, then its match
    // loop. Because Go refuses `-1` alongside `-4`/`-6` ([`ip_usage_refusal`] ports that check), the
    // two never narrow the same call, so the order is unobservable; it is kept as Go writes it so
    // this stays a port rather than a re-derivation.
    let considered = if sel.first {
        addrs.get(..1).unwrap_or(addrs)
    } else {
        addrs
    };
    let mut out = String::new();
    for addr in considered {
        let Ok(parsed) = addr.parse::<std::net::IpAddr>() else {
            continue;
        };
        let wanted = if parsed.is_ipv4() { !sel.v6 } else { !sel.v4 };
        if wanted {
            out.push_str(addr);
            out.push('\n');
        }
    }
    if out.is_empty() {
        return "(no matching tailnet address)\n".to_string();
    }
    out
}

/// clap value parser for `cert --min-validity`: Go's duration grammar, then the one restriction this
/// fork adds. Go's flag package accepts a negative duration here (where it simply has no effect, since
/// nothing is ever less valid than "already expired"); the wire field is an unsigned second count, so
/// rather than silently carrying a lie this refuses it. Everything else is Go's parser verbatim —
/// including its error text, so `--min-validity 1d` explains itself the way `tailscale` does.
fn parse_min_validity(value: &str) -> Result<std::time::Duration, String> {
    let nanos = parse_go_duration(value)?;
    if nanos < 0 {
        return Err(format!(
            "a negative minimum validity ({value:?}) asks for a certificate that is already expired"
        ));
    }
    Ok(std::time::Duration::from_nanos(nanos as u64))
}

/// The refusal `tnet cert` owes its own flags before it contacts the daemon, or `None` when the
/// invocation is usable. `--listen` names the address `--serve-demo` binds, so on its own it asks for
/// a listener that will never exist — Go refuses the same shape from the other direction, rejecting
/// the listen argument it only accepts alongside `--serve-demo` ("too many arguments; max 1 allowed
/// with --serve-demo (the listen address)"). The extra-positional half of Go's check is clap's job
/// here: this fork's `cert` takes exactly one positional (the domain), so a second one is already
/// refused.
///
/// The message goes to **stdout** and the caller exits **1**, matching Go's `outln` + `os.Exit(1)`
/// (and this CLI's [`switch_usage_refusal`]) rather than clap's stderr + exit 2 — which is why this
/// is a hand-rolled check and not an `#[arg(requires = ...)]`. Pure → unit-testable.
fn cert_usage_refusal(serve_demo: bool, has_listen: bool) -> Option<&'static str> {
    if has_listen && !serve_demo {
        return Some("--listen can only be used with --serve-demo");
    }
    None
}

/// Where `cert --serve-demo` listens when `--listen` is not given: Go's `:443`, the port a browser
/// reaches without a port in the URL. Binding it needs root.
const DEFAULT_CERT_DEMO_LISTEN: &str = ":443";

/// Turn a Go-style listen address into one Rust's resolver accepts. Go's `net.Listen` reads a bare
/// `:443` as "every interface"; Rust's `ToSocketAddrs` rejects it outright, so a leading colon
/// becomes an explicit `0.0.0.0`. Everything else is passed through untouched — `[::]:443`,
/// `127.0.0.1:8443` and a hostname all mean here exactly what they mean to Go.
///
/// DIVERGENCE, deliberate: Go's bare `:443` listens on IPv4 *and* IPv6; `0.0.0.0:443` is IPv4 only.
/// Binding both families needs two listeners, which a demo server does not warrant — pass
/// `[::]:443` for the IPv6 side. Pure → unit-testable.
fn normalize_demo_listen(listen: &str) -> String {
    match listen.strip_prefix(':') {
        Some(port) => format!("0.0.0.0:{port}"),
        None => listen.to_string(),
    }
}

/// Max concurrent in-flight `cert --serve-demo` connection handlers — the same count bound, for the
/// same reason, as [`MAX_WEB_CONNECTIONS`] on the status page. This listener can be reachable from
/// the tailnet (or, on `:443`, the internet), so shedding beyond the cap matters more here: a TLS
/// handshake is not free.
const MAX_CERT_DEMO_CONNECTIONS: usize = 64;

/// `cert --serve-demo` (Go `tailscale cert --serve-demo`): serve HTTPS with the certificate just
/// issued, so the operator can point a browser at the domain and see that it works, instead of
/// writing the PEMs to disk. Runs until interrupted (Ctrl-C).
///
/// Terminates TLS with the issued leaf+chain and its key, and answers every request with the same
/// short page Go serves. Each connection is handled on its own task under a
/// [`MAX_CERT_DEMO_CONNECTIONS`] semaphore, with a deadline on the handshake and on the request read,
/// so neither a flood nor a client that connects and says nothing can pile up handlers.
///
/// REDUCED SCOPE vs Go: Go's demo handler also redirects a bare-hostname request to the expanded
/// MagicDNS name (its `ExpandSNIName` LocalAPI call), and it serves whatever certificate matches the
/// SNI of each connection. This fork's LocalAPI offers neither, so the server presents the one
/// certificate `cert` was asked for and serves the page to every request.
async fn run_cert_serve_demo(
    domain: &str,
    cert_pem: &str,
    key_pem: &str,
    listen: &str,
) -> Result<()> {
    use std::sync::Arc;

    let certs = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .context("parsing the issued certificate PEM")?;
    if certs.is_empty() {
        anyhow::bail!("the daemon returned no certificate for {domain:?}");
    }
    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .context("parsing the issued private-key PEM")?
        .ok_or_else(|| anyhow!("the daemon returned no private key for {domain:?}"))?;
    // Name the crypto provider explicitly rather than relying on a process default: this binary also
    // links other TLS users, and an ambiguous default is a runtime panic, not a build error.
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .context("selecting TLS protocol versions")?
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .context("loading the issued certificate into the TLS server")?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

    let bind = normalize_demo_listen(listen);
    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .with_context(|| format!("binding the cert demo server to {bind} (:443 needs root)"))?;
    let addr = listener
        .local_addr()
        .context("resolving the listen address")?;
    println!("running TLS server on {addr} for {domain} ... (Ctrl-C to stop)");

    let conn_limit = Arc::new(tokio::sync::Semaphore::new(MAX_CERT_DEMO_CONNECTIONS));
    loop {
        let (conn, _peer) = match listener.accept().await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("cert --serve-demo: accept failed: {e}");
                continue;
            }
        };
        let Ok(permit) = Arc::clone(&conn_limit).try_acquire_owned() else {
            eprintln!("cert --serve-demo: connection cap reached; dropping connection");
            continue;
        };
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let _permit = permit;
            serve_cert_demo_connection(conn, acceptor).await;
        });
    }
}

/// Serve one `cert --serve-demo` connection: complete the TLS handshake, read the request line, and
/// write the demo page. Best-effort throughout — a handshake failure (a plain-HTTP client, a scanner)
/// or any read/write error just drops the connection; this is a demonstration server, not a hardened
/// endpoint. Both the handshake and the request-line read are bounded in time (and the read in bytes)
/// so a client that connects and then says nothing cannot hold a handler forever.
async fn serve_cert_demo_connection(
    conn: tokio::net::TcpStream,
    acceptor: tokio_rustls::TlsAcceptor,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let Ok(Ok(mut tls)) = tokio::time::timeout(CERT_DEMO_DEADLINE, acceptor.accept(conn)).await
    else {
        return; // Handshake timed out or failed (e.g. a plain-HTTP request to an HTTPS port).
    };
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    let read_line = async {
        loop {
            let n = tls.read(&mut chunk).await?;
            if n == 0 {
                break; // EOF before a full line — no request to answer.
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.contains(&b'\n') || buf.len() >= 8192 {
                break;
            }
        }
        Ok::<(), std::io::Error>(())
    };
    if !matches!(
        tokio::time::timeout(CERT_DEMO_DEADLINE, read_line).await,
        Ok(Ok(()))
    ) || buf.is_empty()
    {
        return;
    }
    let _ = tls.write_all(cert_demo_response().as_bytes()).await;
    let _ = tls.shutdown().await;
}

/// The whole HTTP response `cert --serve-demo` writes: Go's demo handler answers **every** request
/// the same way (no routing, no 404 path), so this takes no request and returns one `200` with the
/// page. Pure → unit-testable.
fn cert_demo_response() -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{CERT_DEMO_BODY}",
        CERT_DEMO_BODY.len()
    )
}

/// How long a `cert --serve-demo` connection gets for its TLS handshake, and then for its request
/// line. Matches the `status --web` handler's 5s read deadline.
const CERT_DEMO_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);

/// The page `cert --serve-demo` answers with — Go serves `<h1>Hello from Tailscale</h1>It works.`;
/// this names the daemon that actually served it.
const CERT_DEMO_BODY: &str = "<h1>Hello from tailscaled-rs</h1>It works.";

/// `cert <domain>` (Go `tailscale cert`): round-trip a [`Request::Cert`], then write the issued
/// cert+key PEMs. File handling mirrors Go's `runCert`: when neither `--cert-file` nor `--key-file`
/// is given, default to `DOMAIN.crt` + `DOMAIN.key` in the cwd (with `*.` → `wildcard_.` so a wildcard
/// domain is a legal filename); `-` writes that PEM to stdout instead of a file. The cert is written
/// `0644` (public), the key `0600` (Go's perms — the private key must not be world-readable). A
/// daemon built without `acme`, a down node, or any ACME failure comes back as a `Response::Error`
/// that we print and exit non-zero on (never a partial write).
async fn run_cert(
    socket: &std::path::Path,
    domain: String,
    cert_file: Option<String>,
    key_file: Option<String>,
    min_validity: Option<std::time::Duration>,
    serve_demo: bool,
    listen: Option<String>,
) -> Result<()> {
    // This command's own flag refusal, before any daemon round-trip (Go checks its own flag/argument
    // grammar first too).
    if let Some(message) = cert_usage_refusal(serve_demo, listen.is_some()) {
        println!("{message}");
        std::process::exit(1);
    }
    let (cert_pem, key_pem) = match round_trip(
        socket,
        &Request::Cert {
            domain: domain.clone(),
            // Whole seconds on the wire (an ACME lifetime is measured in days).
            min_validity_secs: min_validity.map(|d| d.as_secs()),
        },
    )
    .await
    {
        Ok(Response::Cert { cert_pem, key_pem }) => (cert_pem, key_pem),
        Ok(Response::Error { message }) => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        Ok(other) => anyhow::bail!("unexpected response to cert: {other:?}"),
        Err(e) => {
            return Err(e).with_context(|| format!("requesting cert at {}", socket.display()));
        }
    };

    // `--serve-demo`: serve the certificate instead of writing it out, and never return (Ctrl-C
    // stops it). Like Go, `--cert-file`/`--key-file` are not consulted on this path — nothing is
    // written to disk.
    if serve_demo {
        let listen = listen.unwrap_or_else(|| DEFAULT_CERT_DEMO_LISTEN.to_string());
        return run_cert_serve_demo(&domain, &cert_pem, &key_pem, &listen).await;
    }

    // Go's default-filename rule: only when BOTH flags are unset. `*.` → `wildcard_.` keeps a wildcard
    // domain a legal path. GUARD (L1): the domain is interpolated into the default filename, so refuse
    // a domain that would steer the path elsewhere (`/` or `..`). In practice the daemon only issues
    // for the tailnet's own cert domains (an arbitrary domain fails at ACME time), but the filename
    // derivation must not trust the domain shape regardless.
    let (cert_path, key_path) = match (cert_file, key_file) {
        (None, None) => {
            if domain.contains('/') || domain.contains("..") {
                anyhow::bail!(
                    "refusing to derive a cert filename from domain {domain:?} (contains '/' or '..'); \
                     pass explicit --cert-file/--key-file paths"
                );
            }
            let base = domain.replacen("*.", "wildcard_.", 1);
            (Some(format!("{base}.crt")), Some(format!("{base}.key")))
        }
        (c, k) => (c, k),
    };

    // Write one PEM to a path (mode-controlled) or to stdout for "-". A missing path (only one of the
    // two flags was given) skips that output, matching Go (each is written only when its path is set).
    fn emit(path: Option<&str>, pem: &str, mode: u32, label: &str) -> Result<()> {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        match path {
            None => Ok(()),
            Some("-") => {
                std::io::stdout()
                    .write_all(pem.as_bytes())
                    .with_context(|| format!("writing {label} to stdout"))?;
                Ok(())
            }
            Some(p) => {
                // ATOMIC write (Go `atomicfile` semantics): write to a fresh sibling temp file, fsync,
                // then `rename` over the target. This removes the partial-key window a truncate-in-place
                // would leave (a crash / disk-full / O_NOFOLLOW failure mid-write must not zero out a
                // pre-existing good key), and `rename` replaces a symlinked target WITHOUT following it.
                // The temp is created `O_EXCL | O_NOFOLLOW` with the exact mode (0644 cert / 0600 key),
                // so the key is mode-0600 from creation (no world-readable window) and a pre-planted
                // temp/symlink is refused. NOTE: O_NOFOLLOW guards only the FINAL path component — the
                // parent directory must be caller-controlled (an attacker-symlinked intermediate dir is
                // still traversed; same residual as Go).
                let path = std::path::Path::new(p);
                let dir = path.parent().filter(|d| !d.as_os_str().is_empty());
                let dir = dir.unwrap_or_else(|| std::path::Path::new("."));
                let file_name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .with_context(|| format!("{label} path {p} has no file name"))?;
                let tmp = dir.join(format!(".{file_name}.tmp{}", std::process::id()));

                // Clean up a stale temp from a prior interrupted run (best-effort) so create_new can
                // succeed; it is our own pid-suffixed name, so this only ever removes our leftover.
                let _ = std::fs::remove_file(&tmp);
                let write_tmp = || -> Result<()> {
                    let mut f = std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true) // O_EXCL: refuse a pre-existing temp (no symlink/clobber)
                        .mode(mode)
                        .custom_flags(libc::O_NOFOLLOW)
                        .open(&tmp)
                        .with_context(|| format!("creating {label} temp file {}", tmp.display()))?;
                    f.write_all(pem.as_bytes())
                        .with_context(|| format!("writing {label} temp file {}", tmp.display()))?;
                    f.sync_all()
                        .with_context(|| format!("fsync {label} temp file {}", tmp.display()))?;
                    Ok(())
                };
                if let Err(e) = write_tmp() {
                    let _ = std::fs::remove_file(&tmp); // don't leak the partial temp on failure
                    return Err(e);
                }
                if let Err(e) = std::fs::rename(&tmp, path)
                    .with_context(|| format!("renaming {label} into place at {p}"))
                {
                    let _ = std::fs::remove_file(&tmp);
                    return Err(e);
                }
                // (The "-" case is handled by the earlier arm, so `p` here is always a real path.)
                println!("Wrote {label} to {p}");
                Ok(())
            }
        }
    }

    emit(cert_path.as_deref(), &cert_pem, 0o644, "public cert")?;
    emit(key_path.as_deref(), &key_pem, 0o600, "private key")?;
    Ok(())
}

/// `exit-node list` (Go `tailscale exit-node list`): reuse Status, filter to exit-node peers.
async fn run_exit_node_list(socket: &std::path::Path) -> Result<()> {
    let status = match round_trip(socket, &Request::Status).await {
        Ok(Response::Status(s)) => s,
        Ok(other) => anyhow::bail!("unexpected response to status: {other:?}"),
        Err(e) => {
            return Err(e).with_context(|| format!("querying status at {}", socket.display()));
        }
    };
    print!("{}", format_exit_node_list(&status.peers));
    Ok(())
}

/// `exit-node suggest` (Go `tailscale exit-node suggest`): ask the daemon for the best available exit
/// node and print it with the `tnet set --exit-node=<id>` command to engage it. A `None` suggestion
/// (no eligible candidate) prints a clear notice and exits 0 (not an error — there was simply nothing
/// to suggest, matching Go's empty response). The suggested name is control-supplied text, so it is
/// run through `sanitize_for_terminal` before printing.
async fn run_exit_node_suggest(socket: &std::path::Path) -> Result<()> {
    let response = round_trip(socket, &Request::SuggestExitNode)
        .await
        .with_context(|| format!("talking to daemon at {}", socket.display()))?;
    match response {
        Response::ExitNodeSuggestion {
            suggestion: Some(s),
        } => {
            // Name is control-supplied — sanitize before printing. The id is a stable node id
            // (`[A-Za-z0-9]`-ish), echoed verbatim as the selector for `set --exit-node`.
            println!("Suggested exit node: {}", sanitize_for_terminal(&s.name));
            println!("To use it, run: tnet set --exit-node={}", s.id);
            Ok(())
        }
        Response::ExitNodeSuggestion { suggestion: None } => {
            // No eligible candidate — an honest empty result, not an error. Exit 0.
            println!("No exit node suggestion available (no eligible exit-node peer right now).");
            Ok(())
        }
        Response::Error { message } => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        other => anyhow::bail!("unexpected response to exit-node suggest: {other:?}"),
    }
}

/// Pick the single positional argument of `tnet whois`, porting Go's two arity refusals verbatim.
///
/// Go `runWhoIs` (cmd/tailscale/cli/whois.go) checks `len(args) > 1` first and `len(args) == 0`
/// second, returning `too many arguments, expected at most one peer` and `missing argument, expected
/// one peer`. clap would otherwise answer with its own wording, so the positional is a `Vec` and the
/// count is judged here. Pure → unit-testable.
fn whois_target(args: &[String]) -> Result<&str> {
    if args.len() > 1 {
        anyhow::bail!("too many arguments, expected at most one peer");
    }
    match args.first() {
        Some(target) => Ok(target),
        None => anyhow::bail!("missing argument, expected one peer"),
    }
}

/// Split Go's `ip[:port]` whois argument into the wire request's address and optional port.
///
/// Mirrors the order Go's `serveWhoIs` tries: `netip.ParseAddr` first (a bare IP → port 0, carried
/// here as `None`), then `netip.ParseAddrPort` (`1.2.3.4:22`, `[fd7a::1]:22`). Anything else is
/// refused before the daemon round trip, so an unusable argument costs no socket connection and says
/// the same thing whether or not the daemon is up. (Go's `nodekey:` whois form is a LocalAPI-only
/// spelling with no CLI surface upstream, so it is not accepted here either.) Pure → unit-testable.
fn parse_whois_target(target: &str) -> Result<(String, Option<u16>)> {
    if let Ok(ip) = target.parse::<std::net::IpAddr>() {
        return Ok((ip.to_string(), None));
    }
    match target.parse::<std::net::SocketAddr>() {
        Ok(sock) => Ok((sock.ip().to_string(), Some(sock.port()))),
        Err(_) => anyhow::bail!(
            "invalid address {target:?}: expected an IP or Go's ip[:port] form \
             (e.g. 100.64.0.9 or 100.64.0.9:22)"
        ),
    }
}

/// Parse `--proto` into the wire enum: Go's empty value (flag absent, or `--proto=`) is "both" →
/// `None`; `tcp`/`udp` → the matching [`WhoisProto`]. Any other value is refused by
/// [`WhoisProto::from_str`], which carries the message. Pure → unit-testable.
fn parse_whois_proto(proto: Option<&str>) -> Result<Option<tailscaled_rs::localapi::WhoisProto>> {
    match proto {
        None | Some("") => Ok(None),
        Some(value) => value
            .parse::<tailscaled_rs::localapi::WhoisProto>()
            .map(Some)
            .map_err(|e| anyhow::anyhow!(e)),
    }
}

/// `whois` (Go `tailscale whois [--json] ip[:port]`): round-trip Whois for the given address, then
/// render the owner. The node name is control-supplied text, so it is run through
/// `sanitize_for_terminal` inside the formatter before printing. The queried address is echoed as the
/// operator typed it (port included) on the not-found line, so the render needs no read-back from the
/// request.
///
/// Argument arity, the `ip[:port]` split and `--proto` are all resolved before the daemon round trip
/// — Go likewise fails in `runWhoIs` before it calls `WhoIsProto`.
async fn run_whois(
    socket: &std::path::Path,
    args: &[String],
    proto: Option<&str>,
    json: bool,
) -> Result<()> {
    let target = whois_target(args)?;
    let (ip, port) = parse_whois_target(target)?;
    let proto = parse_whois_proto(proto)?;
    let response = round_trip(socket, &Request::Whois { ip, port, proto })
        .await
        .with_context(|| format!("talking to daemon at {}", socket.display()))?;
    match response {
        Response::Whois(w) => {
            if json {
                // Go `whois --json`: the raw report object (escape-safe via serde). A WhoisReport is a
                // plain serde struct, so this cannot fail in practice; fall back to `{}` over a panic.
                println!(
                    "{}",
                    serde_json::to_string_pretty(&w).unwrap_or_else(|_| "{}".to_string())
                );
            } else {
                print!("{}", format_whois(&w, target));
            }
            Ok(())
        }
        Response::Error { message } => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        other => anyhow::bail!("unexpected response to whois request: {other:?}"),
    }
}

/// Taildrop (`tnet file`). The nested subcommand picks the wire `Request`: `cp` and `get` are writes
/// (the daemon reads/consumes a file) and reply `Ok`; `list` is read-only and replies `Files`. The
/// file name in a `list` reply is engine/peer-supplied, so it is run through `sanitize_for_terminal`
/// inside `format_files` before printing (a sender could craft a hostile name).
///
/// `get <dir> --verbose` sends the same request and only swaps the progress renderer for the
/// drain's reply — [`format_files_got_verbose`] (Go's `tailscale file get --verbose` lines) in place
/// of the compact [`format_files_got`]; the failures and the exit status are the same either way,
/// which is what [`render_files_got`] assembles.
async fn run_file(socket: &std::path::Path, cmd: FileCmd) -> Result<()> {
    // `--verbose` changes nothing about the request — it only picks a different renderer for the
    // drain's `FilesGot` reply — so read it off the subcommand here, before `cmd` is consumed below.
    let verbose = matches!(cmd, FileCmd::Get { verbose: true, .. });
    // `cp` has its own handler: it may `--targets`-list, or send 1..N files (a round-trip each), so
    // it does not fit the single-request-then-match shape the other verbs share.
    let request = match cmd {
        FileCmd::Cp {
            args,
            name,
            targets,
        } => return run_file_cp(socket, args, name, targets).await,
        FileCmd::List => Request::FileList,
        FileCmd::Get {
            target,
            dest,
            conflict,
            delete_after,
            verbose: _,
        } => match dest {
            // A literal `-` dest means "stream to stdout" in the CLI convention (Go's `file get` uses
            // it; `tnet cert -` does too). The single-file fetch is a daemon-writes-the-path operation
            // (the daemon, not the CLI, has the Taildrop store), so `-` cannot mean the CLI's stdout
            // without a new stream-back-to-client protocol — and silently sending `dest="-"` to the
            // daemon would write a file literally NAMED `-` in the daemon's cwd (a footgun: the user
            // expects stdout, gets a stray file on the daemon host). So reject `-` clearly with the
            // working alternative, rather than do the surprising thing. (Faithful: we never pretend to
            // support a mode we don't; stdout streaming is tracked as a larger follow-up if wanted.)
            Some(dest) if dest == "-" => {
                eprintln!(
                    "file get: streaming to stdout (`-`) is not supported — the daemon writes the \
                     file directly, so give a real destination path (`tnet file get <name> \
                     ./out`), or drain the whole inbox to a directory (`tnet file get <dir>`)"
                );
                std::process::exit(1);
            }
            // Two positionals (`get <name> <dest>`) → the single-file fetch (fork convenience).
            Some(dest) => Request::FileGet {
                name: target,
                dest,
                delete_after,
            },
            // One positional (`get <dir>`) → the Go-faithful inbox drain into a directory.
            None => Request::FileGetDir {
                dir: target,
                conflict: conflict.into(),
            },
        },
    };
    let response = round_trip(socket, &request)
        .await
        .with_context(|| format!("talking to daemon at {}", socket.display()))?;
    match response {
        // Waiting Taildrop files (`tnet file list`). One line per file; an empty inbox prints a
        // clear placeholder rather than nothing.
        Response::Files { files } => print!("{}", format_files(&files)),
        // Inbox-drain outcomes (`tnet file get <dir>`). Go's `runFileGetOneBatch` prints the
        // batch's progress as it goes and *accumulates* the failures; `runFileGet` then prints all
        // but the last of those and returns the last as the command's error (non-zero exit). So the
        // failures land after the progress, not interleaved with it, and a drain that cleared
        // nothing out of a non-empty inbox is itself one of those failures. `render_files_got`
        // reproduces that split; the caller only has to place the two halves.
        Response::FilesGot { results } => {
            let (out, last_error) = render_files_got(&results, verbose);
            print!("{out}");
            if let Some(err) = last_error {
                eprintln!("{err}");
                std::process::exit(1);
            }
        }
        Response::Ok { message } => {
            println!("ok: {message}");
        }
        Response::Error { message } => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        other => anyhow::bail!("unexpected response to file request: {other:?}"),
    }
    Ok(())
}

/// `tnet file cp` — the Go `tailscale file cp <files...> <target>:` path, plus `--targets`.
///
/// With `targets` (and no positional args), lists the Taildrop-able peers. Otherwise the LAST arg is
/// the destination peer and MUST end in a colon (Go's disambiguator); the rest are files to send, one
/// `FileCp` round-trip each, with the `--name` override (when given) carried to the daemon so the
/// file is sent under that name. `--name` is rejected with multiple files (matching Go). NOTE: stdin
/// (`-`) is NOT supported by this build — the daemon opens each path itself (same-host); a `-` is
/// rejected by `resolve_cp_file`.
async fn run_file_cp(
    socket: &std::path::Path,
    args: Vec<String>,
    name: Option<String>,
    targets: bool,
) -> Result<()> {
    // `--targets`: list peers, ignore (reject) any positional args — matches Go's `runCpTargets`.
    if targets {
        if !args.is_empty() {
            anyhow::bail!("invalid arguments with --targets");
        }
        return run_file_targets(socket).await;
    }

    // Need at least one file + the `<target>:` (Go: "usage: tailscale file cp <files...> <target>:").
    if args.len() < 2 {
        anyhow::bail!("usage: tnet file cp <files...> <target>:");
    }
    let (files, raw_target) = args.split_at(args.len() - 1);
    let peer = parse_cp_target(&raw_target[0])?;

    // Multi-file guards (Go): --name is single-file only, and stdin can't mix with named files.
    if files.len() > 1 {
        if name.is_some() {
            anyhow::bail!("can't use --name with multiple files");
        }
        if files.iter().any(|f| f == "-") {
            anyhow::bail!("can't use '-' (stdin) together with other files");
        }
    }

    // Send each file as its own transfer. A failure on one file is reported and makes the command
    // exit non-zero, but does not abort the remaining sends (mirrors a best-effort batch).
    let mut had_error = false;
    for file in files {
        let (path, send_name) = resolve_cp_file(file, name.as_deref())?;
        let req = Request::FileCp {
            path,
            peer: peer.clone(),
            // Thread `--name` onto the wire so the daemon actually sends the file under that name
            // (Go `--name`); `None` lets the daemon derive the basename. The multi-file guard above
            // already rejects `--name` with >1 file, so this only ever overrides a single send.
            name: name.clone(),
        };
        match round_trip(socket, &req)
            .await
            .with_context(|| format!("talking to daemon at {}", socket.display()))?
        {
            Response::Ok { message } => println!("ok: {message}"),
            Response::Error { message } => {
                eprintln!("error: sending {send_name}: {message}");
                had_error = true;
            }
            other => anyhow::bail!("unexpected response to file cp: {other:?}"),
        }
    }
    if had_error {
        std::process::exit(1);
    }
    Ok(())
}

/// `tnet file cp --targets`: round-trip [`Request::FileTargets`] and render the peer list.
async fn run_file_targets(socket: &std::path::Path) -> Result<()> {
    match round_trip(socket, &Request::FileTargets)
        .await
        .with_context(|| format!("talking to daemon at {}", socket.display()))?
    {
        Response::FileTargets { targets } => {
            print!("{}", format_file_targets(&targets));
            Ok(())
        }
        Response::Error { message } => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        other => anyhow::bail!("unexpected response to file targets: {other:?}"),
    }
}

/// Resolve one `cp` file argument to `(path_to_send, display_name)`. A `-` means stdin, which this
/// daemon's same-host `FileCp` (the daemon opens the path itself) cannot stream, so `-` is rejected
/// with an actionable message rather than silently mis-sent. Pure enough to reason about; the stdin
/// limitation is a fork constraint documented at the call site.
fn resolve_cp_file(file: &str, name: Option<&str>) -> Result<(String, String)> {
    if file == "-" {
        // The daemon opens the file by path (tnet + tailnetd are same-host/same-user); there is no
        // path for stdin to hand it. Rather than fake it, reject clearly. (A future stdin path would
        // need the CLI to stream bytes over the LocalAPI — tracked separately.)
        anyhow::bail!(
            "stdin ('-') is not supported by this build's `file cp`; pass a file path instead"
        );
    }
    // Display name for error/progress lines: the override, else the file's base name.
    let display = name
        .map(str::to_string)
        .unwrap_or_else(|| basename(file).to_string());
    Ok((file.to_string(), display))
}

/// The base name of a path (the final `/`-separated component), for `cp` display. Pure.
fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Render `tnet lock status` from a [`LockReport`](tailscaled_rs::localapi::LockReport). Human form
/// states whether Tailnet Lock is in use and, if so, the authority head + any pending disablement;
/// `json` emits a small serde object. Pure → unit-testable.
fn format_lock_status(r: &tailscaled_rs::localapi::LockReport, json: bool) -> String {
    if json {
        let mut m = serde_json::Map::new();
        m.insert("enabled".into(), serde_json::json!(r.enabled));
        m.insert("head".into(), serde_json::json!(r.head));
        m.insert("disabled".into(), serde_json::json!(r.disabled));
        return format!(
            "{}\n",
            serde_json::to_string_pretty(&m).unwrap_or_else(|_| "{}".to_string())
        );
    }
    // Status line + a blank line, matching Go `runTailnetLockStatus` (tailnet-lock.go: prints
    // `Tailnet Lock is {ENABLED.|NOT enabled.}` then an unconditional `fmt.Println()`). The wording is
    // byte-for-byte Go's — no "on this tailnet" suffix.
    if !r.enabled {
        return "Tailnet Lock is NOT enabled.\n\n".to_string();
    }
    let mut out = String::from("Tailnet Lock is ENABLED.\n\n");
    // The rich Go sections (this-node key, trusted-keys table, filtered peers) are engine-gated — the
    // engine's read-only `tka_status` carries only the authority head + a pending-disablement signal
    // (ENGINE_ASKS #17). `authority head` is itself a fork-specific extra (Go has no such line).
    if !r.head.is_empty() {
        // `head` is control's AUMHash, copied verbatim from the engine with no daemon-side charset
        // check — sanitize before terminal display (defense-in-depth, like the dns/file formatters).
        out.push_str(&format!(
            "  authority head: {}\n",
            sanitize_for_terminal(&r.head)
        ));
    }
    if r.disabled {
        out.push_str("  status: a disablement is pending (control signalled disable).\n");
    }
    out
}

/// Render `tnet lock log` from a [`LockLogReport`](tailscaled_rs::localapi::LockLogReport), mirroring
/// Go `tailscale lock log` (`runNetworkLockLog` over `LocalClient.NetworkLockLog`): one stanza per
/// update, **newest first**, each headed by the update's AUM hash and change kind.
///
/// Two deliberate fork deviations, both stated rather than faked:
///
/// - **No per-kind key detail.** Go decodes each update's raw AUM CBOR and prints what the change
///   did (the added key's kind/id/metadata, the removed key id). This build carries the raw CBOR on
///   the wire but does not decode it — the daemon has no AUM decoder — so a stanza reports the hash,
///   the change kind and the ids of the keys that signed it. `--json` emits the raw CBOR (hex) so the
///   full AUM can still be decoded out-of-band.
/// - **The empty history says why.** Go's `NetworkLockLog` errors out when lock is not enabled; here
///   the engine simply returns no entries, so the report carries the lock-enabled flag and this
///   renderer prints "not enabled" or "enabled, nothing synced yet" rather than an empty table.
///
/// `json` emits a fork-specific object (`enabled` + `entries`), NOT Go's `[]ipnstate.NetworkLockUpdate`
/// array. Pure (returns the string incl. its trailing newline) → unit-testable.
fn format_lock_log(r: &tailscaled_rs::localapi::LockLogReport, json: bool) -> String {
    if json {
        use serde_json::{Map, Value, json};
        let entries: Vec<Value> = r
            .entries
            .iter()
            .map(|e| {
                let mut m = Map::new();
                m.insert("hash".into(), json!(e.hash));
                m.insert("change".into(), json!(e.change));
                m.insert("signer_key_ids".into(), json!(e.signer_key_ids));
                m.insert("raw".into(), json!(e.raw));
                Value::Object(m)
            })
            .collect();
        let mut root = Map::new();
        root.insert("enabled".into(), json!(r.enabled));
        root.insert("entries".into(), Value::Array(entries));
        return format!(
            "{}\n",
            serde_json::to_string_pretty(&root).unwrap_or_else(|_| "{}".to_string())
        );
    }
    // Nothing to list: say which of the two empty cases this is (Go never reaches here — it errors
    // instead — but an empty table would leave an operator guessing).
    if r.entries.is_empty() {
        if !r.enabled {
            // Same wording as `lock status`'s not-enabled line, so the two verbs agree.
            return "Tailnet Lock is NOT enabled.\n\n".to_string();
        }
        return "Tailnet Lock is ENABLED, but no update-chain history has synced to this node \
                yet.\n\n"
            .to_string();
    }
    let mut out = String::new();
    for e in &r.entries {
        // The change kind and hash are engine-produced (a fixed AUM-kind string; our own base32 of a
        // 32-byte hash), but they are rendered verbatim into a structured line — sanitize anyway, as
        // the status/dns/file formatters do.
        out.push_str(&format!(
            "update {} ({})\n",
            sanitize_for_terminal(&e.hash),
            sanitize_for_terminal(&e.change)
        ));
        if e.signer_key_ids.is_empty() {
            // The genesis checkpoint carries no signatures; anything else unsigned would not have
            // verified into the chain in the first place.
            out.push_str("  signed by: (unsigned)\n");
        } else {
            let ids: Vec<String> = e
                .signer_key_ids
                .iter()
                .map(|id| sanitize_for_terminal(id))
                .collect();
            out.push_str(&format!("  signed by: {}\n", ids.join(", ")));
        }
        // Blank line between stanzas, like Go's `fmt.Fprintln` after each description.
        out.push('\n');
    }
    out
}

/// Render `tnet dns status` from a [`DnsStatusReport`](tailscaled_rs::localapi::DnsStatusReport)
/// (Go `tailscale dns status`). Human form prints Go's MagicDNS-configuration sections — MagicDNS
/// on/off, resolvers in preference order, split-DNS routes, search domains, fallback resolvers,
/// certificate domains, additional DNS records, and exit-node-filtered suffixes — each empty section
/// printing a parenthetical none-line, then a one-line honest note that the Go "Use Tailscale DNS"
/// line *here* + the "System DNS configuration" section are not surfaced by this build (no engine
/// OS-DNS accessor). The accept-dns pref itself IS modelled — surfaced via `tnet get accept-dns` (it
/// just isn't echoed in this `dns status` view). `json` emits a REDUCED, fork-specific object — NOT
/// byte-compatible with Go's `jsonoutput.DNSStatusResult`: resolvers/fallback-resolvers are plain
/// `addr:port` STRINGS (Go nests `DNSResolverInfo{Addr, BootstrapResolution}` objects), MagicDNS-on
/// is a top-level `MagicDNS` bool (Go nests it as `CurrentTailnet.MagicDNSEnabled`, with a separate
/// top-level `TailscaleDNS`=accept-dns not surfaced in this `dns status` JSON), `ExtraRecords` is a name→addr map
/// (Go: an array of `{Name,Type,Value}`), and there is no `SystemDNS`/`SystemDNSError`. Built via
/// `serde_json` (escape-safe, 2-space pretty). Pure (returns the string incl. its trailing newline)
/// → unit-testable.
fn format_dns_status(r: &tailscaled_rs::localapi::DnsStatusReport, json: bool) -> String {
    if json {
        use serde_json::{Map, Value, json};
        let mut root = Map::new();
        root.insert("MagicDNS".into(), json!(r.magic_dns));
        root.insert("Resolvers".into(), json!(r.resolvers));
        // Split-DNS routes: a suffix → list-of-addrs object (Go `SplitDNSRoutes`).
        let routes: Map<String, Value> = r
            .routes
            .iter()
            .map(|(suffix, addrs)| (suffix.clone(), json!(addrs)))
            .collect();
        root.insert("SplitDNSRoutes".into(), Value::Object(routes));
        root.insert("SearchDomains".into(), json!(r.search_domains));
        root.insert("FallbackResolvers".into(), json!(r.fallback_resolvers));
        root.insert("CertDomains".into(), json!(r.cert_domains));
        // Extra records: a name → addr object (Go `ExtraRecords`).
        let extra: Map<String, Value> = r
            .extra_records
            .iter()
            .map(|(name, addr)| (name.clone(), json!(addr)))
            .collect();
        root.insert("ExtraRecords".into(), Value::Object(extra));
        root.insert(
            "ExitNodeFilteredSet".into(),
            json!(r.exit_node_filtered_set),
        );
        return format!(
            "{}\n",
            serde_json::to_string_pretty(&root).unwrap_or_else(|_| "{}".to_string())
        );
    }

    let mut out = String::from("=== MagicDNS configuration ===\n");
    if r.magic_dns {
        out.push_str("MagicDNS: enabled tailnet-wide\n");
    } else {
        out.push_str("MagicDNS: disabled tailnet-wide.\n");
    }

    // Every resolver/suffix/domain/record below is CONTROL-PUSHED (from the netmap DNS config), so it
    // is run through `sanitize_for_terminal` before rendering — a malicious/compromised control server
    // could otherwise smuggle ANSI/OSC escape sequences into the operator's terminal. Mirrors the
    // hardening already applied to `format_files`/`format_whois`. The `--json` path is serde-escaped.
    out.push_str("Resolvers (in preference order):\n");
    if r.resolvers.is_empty() {
        out.push_str("  (none configured)\n");
    } else {
        for addr in &r.resolvers {
            out.push_str(&format!("  - {}\n", sanitize_for_terminal(addr)));
        }
    }

    out.push_str("Split DNS Routes:\n");
    if r.routes.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for (suffix, addrs) in &r.routes {
            let suffix = sanitize_for_terminal(suffix);
            if addrs.is_empty() {
                // A negative route (no upstreams) — names under the suffix are not resolved.
                out.push_str(&format!("  - {suffix:<30} -> (no resolvers)\n"));
            } else {
                for addr in addrs {
                    out.push_str(&format!(
                        "  - {suffix:<30} -> {}\n",
                        sanitize_for_terminal(addr)
                    ));
                }
            }
        }
    }

    out.push_str("Search Domains:\n");
    if r.search_domains.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for domain in &r.search_domains {
            out.push_str(&format!("  - {}\n", sanitize_for_terminal(domain)));
        }
    }

    out.push_str("Fallback Resolvers:\n");
    if r.fallback_resolvers.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for addr in &r.fallback_resolvers {
            out.push_str(&format!("  - {}\n", sanitize_for_terminal(addr)));
        }
    }

    out.push_str("Certificate Domains:\n");
    if r.cert_domains.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for domain in &r.cert_domains {
            out.push_str(&format!("  - {}\n", sanitize_for_terminal(domain)));
        }
    }

    out.push_str("Additional DNS Records:\n");
    if r.extra_records.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for (name, addr) in &r.extra_records {
            out.push_str(&format!(
                "  - {} -> {}\n",
                sanitize_for_terminal(name),
                sanitize_for_terminal(addr)
            ));
        }
    }

    out.push_str("Filtered suffixes (exit-node):\n");
    if r.exit_node_filtered_set.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for suffix in &r.exit_node_filtered_set {
            out.push_str(&format!("  - {}\n", sanitize_for_terminal(suffix)));
        }
    }

    out.push_str(
        "(note: the accept-dns pref is shown by `tnet get accept-dns`; the 'Use Tailscale DNS' line \
         here and the 'System DNS configuration' section are not surfaced by this build)\n",
    );
    out
}

/// Render `tnet dns query` from a [`DnsQueryReport`](tailscaled_rs::localapi::DnsQueryReport). Human
/// form shows the queried name/type, the RCODE (mnemonic + number), the upstream resolver(s)
/// consulted (or "answered locally" when none egressed), the decoded fixed DNS header (id, flags,
/// section counts) and the raw response as hex; `json` emits a small serde object. The answer RECORDS
/// are deliberately NOT decoded — the engine returns raw bytes and this fork has no answer-record
/// decoder (the honest-omission boundary; surfaced as an explicit note rather than faked). Pure →
/// unit-testable.
fn format_dns_query(r: &tailscaled_rs::localapi::DnsQueryReport, json: bool) -> String {
    // Decode the fixed 12-byte DNS header from the raw response hex (RFC 1035 §4.1.1): id (2),
    // flags (2), then QD/AN/NS/AR counts (2 each). `None` if the response is shorter than a header.
    let header = decode_dns_header(&r.response_hex);

    if json {
        use serde_json::{Map, json};
        let mut root = Map::new();
        root.insert("Name".into(), json!(r.name));
        root.insert("QType".into(), json!(qtype_name(r.qtype)));
        root.insert("QTypeNum".into(), json!(r.qtype));
        root.insert("RCode".into(), json!(rcode_name(r.rcode)));
        root.insert("RCodeNum".into(), json!(r.rcode));
        root.insert("ResolversConsulted".into(), json!(r.resolvers_consulted));
        if let Some(h) = &header {
            root.insert(
                "Header".into(),
                json!({
                    "ID": h.id, "QDCount": h.qd, "ANCount": h.an,
                    "NSCount": h.ns, "ARCount": h.ar,
                }),
            );
        }
        root.insert("ResponseHex".into(), json!(r.response_hex));
        return format!(
            "{}\n",
            serde_json::to_string_pretty(&root).unwrap_or_else(|_| "{}".to_string())
        );
    }

    let mut out = String::new();
    // The queried name/type and the answer's RCODE — the headline result.
    out.push_str(&format!(
        "query:    {} {}\n",
        sanitize_for_terminal(&r.name),
        qtype_name(r.qtype)
    ));
    out.push_str(&format!(
        "rcode:    {} ({})\n",
        rcode_name(r.rcode),
        r.rcode
    ));
    // Which upstream resolver(s) answered — or that nothing egressed (a locally-answered tailnet
    // name / NODATA / fail-closed NXDOMAIN). The resolver strings are engine-supplied addr:port — run
    // them through the terminal sanitizer like the other diagnostics' control-influenced fields.
    if r.resolvers_consulted.is_empty() {
        out.push_str("resolvers: (answered locally — nothing egressed)\n");
    } else {
        out.push_str("resolvers:\n");
        for res in &r.resolvers_consulted {
            out.push_str(&format!("  - {}\n", sanitize_for_terminal(res)));
        }
    }
    // The decoded fixed header: section counts tell the operator at a glance whether there were any
    // answers, without us decoding the (undecodable, this build) records themselves.
    match &header {
        Some(h) => {
            out.push_str(&format!(
                "header:   id=0x{:04x} questions={} answers={} authority={} additional={}\n",
                h.id, h.qd, h.an, h.ns, h.ar
            ));
        }
        None => out.push_str("header:   (response too short to decode a DNS header)\n"),
    }
    out.push_str(&format!("response: {} (hex)\n", r.response_hex));
    out.push_str(
        "(note: this build returns the raw DNS response; individual answer records are not decoded \
         — use the hex above, or `dig`, for the full record set)\n",
    );
    out
}

/// The fixed 12-byte DNS message header (RFC 1035 §4.1.1) decoded from a response, for display.
struct DnsHeader {
    id: u16,
    qd: u16,
    an: u16,
    ns: u16,
    ar: u16,
}

/// Decode the fixed DNS header from a lowercase-hex response datagram. Returns `None` if the hex is
/// malformed or shorter than the 12-byte header. Pure → unit-testable. (We decode only the header —
/// fixed offsets, no name-compression to follow — never the variable-length question/answer sections.)
fn decode_dns_header(response_hex: &str) -> Option<DnsHeader> {
    // 12 header bytes = 24 hex chars.
    if response_hex.len() < 24 {
        return None;
    }
    let byte = |i: usize| u8::from_str_radix(response_hex.get(i * 2..i * 2 + 2)?, 16).ok();
    let be16 = |i: usize| Some(((byte(i)? as u16) << 8) | byte(i + 1)? as u16);
    Some(DnsHeader {
        id: be16(0)?,
        // bytes 2..4 are the flags (incl. the RCODE we already carry separately) — skip for the count view.
        qd: be16(4)?,
        an: be16(6)?,
        ns: be16(8)?,
        ar: be16(10)?,
    })
}

/// Render `tnet netcheck` from a [`NetcheckReport`](tailscaled_rs::localapi::NetcheckReport) (Go
/// `tailscale netcheck`). Human form prints a Go-`printNetCheckReport`-flavored block: a `Report:`
/// header, the nearest (preferred) DERP region, and the per-region DERP latency lowest-first (each
/// latency rounded to 0.1ms, e.g. `23.4ms`), with parenthetical none-lines when there is no preferred
/// region / no measured latency. It then prints a one-line honest note that Go's
/// UDP/IPv4/IPv6/`MappingVariesByDestIP`/PortMapping flags are not measured by this build, and that
/// DERP regions are shown by id (the engine carries no region name).
///
/// `json` emits the two fields this build can populate **with Go's field names + value encoding**, so
/// an upstream JSON consumer parses them: `PreferredDERP` is a plain integer (Go's `int`, `0` for
/// unknown — never `null`), and `RegionLatency` is a **map keyed by stringified DERP region id with
/// integer-nanosecond values** (Go's `map[int]time.Duration`, marshalled as ns). The many other Go
/// `Report` fields (UDP/IPv4/IPv6/PortMapping/GlobalV4…) are genuinely not measured by this build and
/// are simply absent — a reduction, not a renamed/reshaped field. Two honest non-byte-exact notes vs
/// Go's `json.MarshalIndent(report, "", "\t")`: the indent is a TAB (matching Go), but JSON object
/// **key order is `serde_json`'s lexicographic string order** (`"10"` before `"2"`), not Go's numeric
/// map order — immaterial, since JSON object key order is non-semantic (and Go marks this format
/// unstable). Pure (returns the string incl. its trailing newline) → unit-testable.
fn format_netcheck(r: &tailscaled_rs::localapi::NetcheckReport, mode: NetcheckFormat) -> String {
    if matches!(mode, NetcheckFormat::Json | NetcheckFormat::JsonLine) {
        use serde_json::{Map, Value, json};
        let mut root = Map::new();
        // Go's `PreferredDERP int // or 0 for unknown` — a plain number, 0 when unknown (never null).
        root.insert("PreferredDERP".into(), json!(r.preferred_derp.unwrap_or(0)));
        // Go's `RegionLatency map[int]time.Duration`: a JSON object keyed by the stringified region
        // id, values being the duration as integer NANOSECONDS (how Go marshals `time.Duration`). The
        // engine carries latency as f64 milliseconds, so ns = round(ms * 1e6). A BTreeMap dedups any
        // repeated region_id (last write wins) and gives a deterministic build; the FINAL on-the-wire
        // key order is serde_json's (lexicographic by string), which is fine — object key order is
        // non-semantic.
        let mut region_latency: std::collections::BTreeMap<u32, i64> =
            std::collections::BTreeMap::new();
        for rl in &r.region_latencies {
            region_latency.insert(rl.region_id, (rl.latency_ms * 1_000_000.0).round() as i64);
        }
        let mut latency_obj = Map::new();
        for (id, ns) in &region_latency {
            latency_obj.insert(id.to_string(), json!(ns));
        }
        root.insert("RegionLatency".into(), Value::Object(latency_obj));
        return match mode {
            // `json`: tab-indented, matching Go's `json.MarshalIndent(report, "", "\t")`.
            NetcheckFormat::Json => format!(
                "{}\n",
                to_string_pretty_tabs(&root).unwrap_or_else(|_| "{}".to_string())
            ),
            // `json-line`: one compact JSON object per line (Go's `--format json-line`), so `--every`
            // emits a clean stream a consumer can read line-by-line.
            NetcheckFormat::JsonLine => format!(
                "{}\n",
                serde_json::to_string(&root).unwrap_or_else(|_| "{}".to_string())
            ),
            NetcheckFormat::Human => unreachable!("guarded by the matches! above"),
        };
    }

    let mut out = String::from("Report:\n");
    match r.preferred_derp {
        Some(id) => out.push_str(&format!("  * Nearest DERP: region {id}\n")),
        None => out.push_str("  * Nearest DERP: (none — not measured yet)\n"),
    }
    out.push_str("  * DERP latency:\n");
    if r.region_latencies.is_empty() {
        out.push_str("      (no DERP latency measured)\n");
    } else {
        for rl in &r.region_latencies {
            // Round to 0.1ms (e.g. 23.4ms), matching Go's terse per-region latency rendering.
            out.push_str(&format!(
                "      - region {}: {:.1}ms\n",
                rl.region_id, rl.latency_ms
            ));
        }
    }
    out.push_str(
        "(note: this build's net-report measures DERP-region latency only — Go's \
         UDP/IPv4/IPv6/MappingVariesByDestIP/PortMapping flags are not measured, and DERP regions \
         are shown by id as the engine carries no region name)\n",
    );
    out
}

/// Render `tnet syspolicy list` / `reload`. The TEXT form is byte-faithful to Go's
/// `printPolicySettings` (which prints through `text/tabwriter`): the empty case is exactly
/// `No policy settings\n` (the normal result on Linux/Unix, where no policy store is registered);
/// the populated case is the four-column `Name / Origin / Value / Error` table with a dashed
/// separator, rows sorted by key, an error rendered `{...}` in the Error column (mutually exclusive
/// with Value), and a trailing blank line. Crucially, value rows END IN WHITESPACE — Go's tabwriter
/// pads the Value column out to width and the empty trailing Error cell leaves that padding at line
/// end — so we keep it (see the `render_row` note) to match Go's exact bytes.
///
/// The `--json` form is the ONE intentional deviation: it emits the daemon's own `PolicyReport`
/// (`{scope, settings:[{key,origin,value,error}, …]}`), tab-indented like Go's
/// `json.MarshalIndent(policy, "", "\t")`, NOT Go's internal `setting.Snapshot` shape
/// (`{Summary, Settings:{key:{…}}}`, which marshals an empty snapshot as `{}`). This is the daemon's
/// own stable IPC wire type rendered directly; the data (keys/origins/values) is the same, but a
/// script scraping `--json` should expect the fork's shape, not upstream's.
///
/// Every key/origin/value/error string is run through [`sanitize_for_terminal`] before display: a
/// managed-platform policy store is an external/semi-trusted source, so the same escape-neutralizing
/// hardening (each control char → `U+FFFD`) applied to control-supplied DNS/whois strings applies
/// here — and it runs BEFORE the column-width computation, so a smuggled escape can't desync the
/// columns (the `--json` path is serde-escaped). Pure (returns the string incl. its trailing
/// newline) → unit-testable.
fn format_policy(r: &tailscaled_rs::localapi::PolicyReport, json: bool) -> String {
    if json {
        use serde_json::Value;
        // Serialize the report itself (serde already escapes); tab-indent to match Go's MarshalIndent.
        let v: Value = serde_json::to_value(r).unwrap_or(Value::Null);
        return format!(
            "{}\n",
            to_string_pretty_tabs(&v).unwrap_or_else(|_| "{}".to_string())
        );
    }

    if r.settings.is_empty() {
        // Go's exact empty-case string (no table, no trailing blank line).
        return "No policy settings\n".to_string();
    }

    // Sort by key for stable output, matching Go's `slices.Sorted(policy.Keys())`. Clone the refs so
    // the daemon's wire order is irrelevant to the rendering.
    let mut rows: Vec<&tailscaled_rs::localapi::PolicySetting> = r.settings.iter().collect();
    rows.sort_by(|a, b| a.key.cmp(&b.key));

    // Width the columns to their contents (Go uses a tabwriter with padding 2). Compute the sanitized
    // cells once so width + render agree, and so no escape sequence can desync the columns.
    let header = ["Name", "Origin", "Value", "Error"];
    let dashes = ["----", "------", "-----", "-----"];
    let cells: Vec<[String; 4]> = rows
        .iter()
        .map(|s| {
            let key = sanitize_for_terminal(&s.key);
            let origin = sanitize_for_terminal(&s.origin);
            // Go renders EITHER the value OR the error, never both: an error blanks the Value column
            // and fills the Error column wrapped in `{...}`.
            match &s.error {
                Some(err) => [
                    key,
                    origin,
                    String::new(),
                    format!("{{{}}}", sanitize_for_terminal(err)),
                ],
                None => [
                    key,
                    origin,
                    sanitize_for_terminal(s.value.as_deref().unwrap_or("")),
                    String::new(),
                ],
            }
        })
        .collect();

    // Column widths = the widest cell (in CHARS, matching tabwriter's rune counting — use
    // `chars().count()` uniformly for header and cells so a non-ASCII header would still be correct).
    let mut widths = [0usize; 4];
    for (c, h) in header.iter().enumerate() {
        widths[c] = h.chars().count();
    }
    for row in &cells {
        for (c, cell) in row.iter().enumerate() {
            widths[c] = widths[c].max(cell.chars().count());
        }
    }

    // Render: header, dashed separator, then the rows. This reproduces Go's `text/tabwriter`
    // (minwidth 0, padding 2, no flags): the first three cells are tab-terminated, so each is
    // left-aligned to its column width plus 2 padding spaces; the fourth segment (Error) is the
    // line's *trailing text* (after the final tab), printed as-is and never padded. A value row's
    // Error segment is empty, so Go leaves the padded Value column's spaces at end of line — i.e.
    // value rows END IN WHITESPACE. We deliberately keep that (no trailing trim) so the output is
    // byte-identical to `tailscale syspolicy list`. Trailing blank line below = Go's `fmt.Println()`.
    let render_row = |row: &[String; 4], out: &mut String| {
        for (c, cell) in row.iter().enumerate() {
            if c + 1 == row.len() {
                // The trailing Error segment: raw, never padded (matches tabwriter's last cell).
                out.push_str(cell);
            } else {
                // A tab-terminated cell: pad to the column width + 2, as tabwriter does — including
                // the Value column on a value row, which is what produces Go's trailing whitespace.
                let pad = widths[c].saturating_sub(cell.chars().count()) + 2;
                out.push_str(cell);
                out.push_str(&" ".repeat(pad));
            }
        }
        out.push('\n');
    };

    let mut out = String::new();
    render_row(&header.map(String::from), &mut out);
    render_row(&dashes.map(String::from), &mut out);
    for row in &cells {
        render_row(row, &mut out);
    }
    out.push('\n');
    out
}

/// Render `tnet exit-node list`: one line per peer offering to be an exit node (IP, hostname, and
/// online state when known), or a placeholder when none. Country/City columns (Go) are omitted —
/// this fork has no control-supplied Location data. The hostname is control-supplied (netmap), so it
/// is run through `sanitize_for_terminal` before display — both to strip terminal escapes and so an
/// embedded `\n`/`\t` can't forge a fake exit-node row or shift the column (same hardening as
/// `format_file_targets`/`format_whois`; see THREAT_MODEL §4.8). Pure → unit-testable.
fn format_exit_node_list(peers: &[tailscaled_rs::localapi::PeerReport]) -> String {
    let exits: Vec<&tailscaled_rs::localapi::PeerReport> =
        peers.iter().filter(|p| p.is_exit_node).collect();
    if exits.is_empty() {
        return "(no exit nodes available in this tailnet)\n".to_string();
    }
    let mut out = String::from("IP               HOSTNAME\n");
    for p in exits {
        let online = match p.online {
            Some(true) => "  (online)",
            Some(false) => "  (offline)",
            None => "",
        };
        out.push_str(&format!(
            "{:<16} {}{}\n",
            p.ipv4,
            sanitize_for_terminal(&p.name),
            online
        ));
    }
    out
}

/// Render `tnet switch --list`: one line per profile, `* ` marking the current one, then the id and
/// (if different) the display name. Pure → unit-testable.
fn format_profiles(profiles: &[tailscaled_rs::localapi::ProfileEntry]) -> String {
    if profiles.is_empty() {
        return "(no profiles)\n".to_string();
    }
    let mut out = String::new();
    for p in profiles {
        let marker = if p.current { "*" } else { " " };
        // Show the name only when it adds information beyond the id.
        if p.name.is_empty() || p.name == p.id {
            out.push_str(&format!("{marker} {}\n", p.id));
        } else {
            out.push_str(&format!("{marker} {}  ({})\n", p.id, p.name));
        }
    }
    out
}

/// Render the profiles as a JSON array for `tnet switch --list --json` (Go `tailscale switch --list
/// --json`): one object per profile with `id`, `nickname`, `selected`, plus `tailnet`/`account` as
/// `null`. Pure → unit-testable. Go's objects carry `{id, nickname, tailnet, account, selected}`; this
/// fork's engine does not surface a per-profile tailnet/account (it has the profile id + display name +
/// which is current — see [`tailscaled_rs::localapi::ProfileEntry`]), so those two are emitted as
/// `null` rather than a fabricated value. `nickname` is the display name (Go's `ProfileStatus.Name`),
/// `null` when it adds nothing beyond the id. The shape (key set + types) matches Go so a JSON consumer
/// parses both identically; only the two engine-gated values are null here (an honest reduction).
fn format_profiles_json(profiles: &[tailscaled_rs::localapi::ProfileEntry]) -> String {
    let arr: Vec<serde_json::Value> = profiles
        .iter()
        .map(|p| {
            // nickname = the display name when it adds information beyond the id, else null (matches
            // the human renderer's "show the name only when it differs" rule).
            let nickname = if p.name.is_empty() || p.name == p.id {
                serde_json::Value::Null
            } else {
                serde_json::Value::String(p.name.clone())
            };
            serde_json::json!({
                "id": p.id,
                "nickname": nickname,
                // Engine-gated: this fork has no per-profile tailnet/account (Go fills these from the
                // login profile). Emitted as null — the key is present (shape parity) but honestly empty.
                "tailnet": serde_json::Value::Null,
                "account": serde_json::Value::Null,
                "selected": p.current,
            })
        })
        .collect();
    serde_json::to_string_pretty(&serde_json::Value::Array(arr))
        .unwrap_or_else(|_| "[]".to_string())
}

/// The canonical `(set-flag name, value)` projection of a [`PrefsView`], in the stable order
/// `tnet get` displays. The names match the `tnet set`/`tnet up` flags (Go keys its `get` output by
/// the same set-flag names). Values are kept **typed** (`serde_json::Value`) rather than pre-
/// stringified so the `--json` map emits Go-faithful **bare booleans** (`true`, not `"true"`) and so
/// JSON escaping is handled by serde (a future setting carrying a quote/backslash can't corrupt the
/// output). The plain-text table/single-value path derives display strings from these via
/// [`get_value_display`]. One source so the table, the `--json` map, and single-setting lookup agree.
///
/// This is a SUBSET of Go's `tailscale get` settings (Go derives its list from the full `set` flag
/// set). Still absent: the Linux OS-router knobs — `snat-subnet-routes`, `stateful-filtering`,
/// `netfilter-mode` — plus `unattended`, none of which this fork models yet; and the four
/// `set`-only flags this fork parses but stores no pref for — `relay-server-port`,
/// `relay-server-static-endpoints`, `remote-config` and `sync` (see [`UnmodelledSetFlags`]). Those
/// four have no row here on purpose: there is no persisted value to report, and inventing a
/// hard-coded row would claim a pref the daemon does not hold. One entry, `tun`, is a fork-specific
/// extension
/// (selecting the kernel-TUN vs userspace datapath) that Go's `get` has no counterpart for; it is
/// intentionally surfaced because it is a real `tnet set` flag in this build.
fn get_settings(
    view: &tailscaled_rs::localapi::PrefsView,
) -> Vec<(&'static str, serde_json::Value)> {
    use serde_json::Value;
    vec![
        // An unset hostname is JSON null (the OS hostname is used); the table renders it empty. Go's
        // `get` lists hostname, and the daemon holds it as a pref — surface it.
        (
            "hostname",
            view.hostname
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        ),
        // An unset exit-node is JSON null (Go uses the empty/zero value); the table renders it empty.
        (
            "exit-node",
            view.exit_node
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        ),
        ("advertise-exit-node", Value::Bool(view.advertise_exit_node)),
        // Routes are a comma-joined string (the `--advertise-routes` arg form), matching how you'd
        // re-pass them to `set`.
        (
            "advertise-routes",
            Value::String(view.advertise_routes.join(",")),
        ),
        (
            "advertise-tags",
            Value::String(view.advertise_tags.join(",")),
        ),
        ("accept-routes", Value::Bool(view.accept_routes)),
        ("accept-dns", Value::Bool(view.accept_dns)),
        ("shields-up", Value::Bool(view.shields_up)),
        ("ssh", Value::Bool(view.ssh)),
        ("tun", Value::Bool(view.tun)),
        ("advertise-connector", Value::Bool(view.advertise_connector)),
        // `auto-update` is Go's `opt.Bool` tri-state: never-stated renders as JSON null (and as an
        // empty cell in the table), distinct from an explicit `false`.
        (
            "auto-update",
            view.auto_update.map(Value::Bool).unwrap_or(Value::Null),
        ),
        ("update-check", Value::Bool(view.update_check)),
        // Unset operator/nickname are JSON null (Go's empty string); the table renders them empty.
        (
            "operator",
            view.operator
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        ),
        (
            "nickname",
            view.nickname
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        ),
        ("report-posture", Value::Bool(view.report_posture)),
        ("webclient", Value::Bool(view.webclient)),
        (
            "exit-node-allow-lan-access",
            Value::Bool(view.exit_node_allow_lan_access),
        ),
    ]
}

/// Plain-text display of a setting's [`serde_json::Value`] for the `get` table / single-value output:
/// a bare string for strings (no surrounding quotes), `true`/`false` for bools, empty for null, and
/// the compact JSON form for anything else. Mirrors the value you'd hand back to `tnet set`.
fn get_value_display(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Render every setting as a single re-appliable `tnet set …` flag-argument line (Go
/// `get --set-flags` / `getOutputSetFlags`): `--<name>=<value>` per setting, space-joined. Each
/// value uses the explicit `=value` form (Go's `fmtFlagValueArg`) — `--accept-routes=true`,
/// `--hostname=node-a`, `--exit-node=` for an unset/empty value — so the line is unambiguous and
/// re-pasteable into `tnet set`. Pure → unit-testable. (The names are the canonical set-flag names
/// the `get` table already uses, from [`get_settings`].)
fn format_get_set_flags(view: &tailscaled_rs::localapi::PrefsView) -> String {
    get_settings(view)
        .into_iter()
        .map(|(name, value)| format!("--{name}={}", get_value_display(&value)))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Render `tnet get` output from a [`PrefsView`] (Go `tailscale get`). `setting` selects a single
/// setting by its set-flag name (`None` or `"all"` = every setting); `json` selects the flattened
/// `{ "name": value }` map form (matching Go `get --json`, a name→value map — NOT a raw prefs-struct
/// dump — with **typed** values: bare booleans, not quoted). Default (no json) is a `NAME  VALUE`
/// table; a single named setting prints just its value. Returns `Err` for an unknown setting name (Go
/// errors too). Pure → unit-testable.
fn format_get(
    view: &tailscaled_rs::localapi::PrefsView,
    setting: Option<&str>,
    json: bool,
) -> Result<String> {
    let settings = get_settings(view);

    // Single named setting (not "all"): print just that value, or error on an unknown name.
    if let Some(name) = setting
        && name != "all"
    {
        let (_, value) = settings.iter().find(|(n, _)| *n == name).ok_or_else(|| {
            anyhow::anyhow!("unknown setting {name:?} (try `tnet get` to list all)")
        })?;
        return Ok(if json {
            // The single value as JSON (bare bool / quoted string / null), serde-encoded so escaping
            // is correct.
            format!("{}\n", serde_json::to_string(value)?)
        } else {
            format!("{}\n", get_value_display(value))
        });
    }

    // All settings.
    if json {
        // Flattened name→value map, built via serde (a `Map` preserves insertion order with the
        // `preserve_order` feature; even without it the keys are stable and the values are correct).
        // Typed values → Go-faithful bare booleans + correct escaping, fixing both the shape and the
        // hand-built-JSON escaping hazard.
        let map: serde_json::Map<String, serde_json::Value> = settings
            .into_iter()
            .map(|(name, value)| (name.to_string(), value))
            .collect();
        Ok(format!("{}\n", serde_json::to_string_pretty(&map)?))
    } else {
        // NAME/VALUE table. Go `getOutputTable` emits a `NAME\tVALUE` header through a `tabwriter`
        // (tab-elastic columns, 2-space padding); we produce the visually-equivalent layout by
        // space-padding the NAME column to the widest of the header and the setting names (so this is
        // column-faithful to Go, not byte-identical tab output). The `chain(once(4))` guarantees a
        // non-empty iterator, so `max()` is always `Some` (width ≥ 4, never the empty fallback).
        let width = settings
            .iter()
            .map(|(n, _)| n.len())
            .chain(std::iter::once("NAME".len()))
            .max()
            .unwrap_or(4);
        let mut out = format!("{:<width$}  VALUE\n", "NAME");
        for (name, value) in &settings {
            out.push_str(&format!("{name:<width$}  {}\n", get_value_display(value)));
        }
        Ok(out)
    }
}

/// Whether a version's minor number is odd — Go's `version.IsUnstableBuild` rule (an odd minor marks
/// an unstable/development track; even is stable). `minor` is the middle field of `major.minor.patch`.
/// Pure helper so the `unstableBranch` JSON field is unit-testable independent of the crate version.
fn is_unstable_minor(minor: u64) -> bool {
    minor % 2 == 1
}

/// The minor-version number parsed from a `major.minor.patch[-suffix]` string, or `None` if it isn't
/// in that shape. Used to derive `unstableBranch` faithfully (Go reads the minor field).
fn minor_of(version: &str) -> Option<u64> {
    // Strip any pre-release suffix first (the fork has none today, but be faithful to Go's parse).
    let core = version.split('-').next().unwrap_or(version);
    core.split('.').nth(1).and_then(|m| m.parse::<u64>().ok())
}

/// Render `tnet version` output. `client` is this CLI's crate version; `daemon` is the daemon's
/// version when `--daemon` was passed (else `None`); `cap` is the engine's current capability version
/// (Go `version.Meta.cap`). `json` selects the JSON object form. Mirrors Go `tailscale version`:
/// plain prints the bare client version (and a `Client:`/`Daemon:` pair when the daemon was queried);
/// `--json` emits Go's `version.Meta` shape — `majorMinorPatch`/`short`/`long`/`cap` always, plus
/// `unstableBranch` when the minor is odd and `daemonLong` when the daemon was queried. The fork is
/// not git-stamped (no build.rs), so Go's `gitCommit`/`gitDirty`/`gitCommitTime`/`extraGitCommit`/
/// `osVariant`/`tailscaleGoGitHash`/`isDev` Meta fields are honestly omitted rather than faked (a
/// fork git SHA is meaningless against Go's tailscale-repo commit semantics). Pure (returns the
/// string, trailing newline included) so it is unit-testable.
fn format_version(client: &str, daemon: Option<&str>, cap: u16, json: bool) -> String {
    if json {
        // Built via serde so escaping is correct + the two `--json` renderers stay consistent. The
        // fork has no pre-release suffix, so majorMinorPatch == short == long == the crate version
        // (Go's `short`/`long` diverge only when git-stamped, which the fork is not).
        let mut map = serde_json::Map::new();
        map.insert("majorMinorPatch".to_string(), client.into());
        map.insert("short".to_string(), client.into());
        map.insert("long".to_string(), client.into());
        map.insert("cap".to_string(), cap.into());
        // `unstableBranch` only when the minor is odd (Go omitempty — omitted on a stable/even line).
        if minor_of(client).is_some_and(is_unstable_minor) {
            map.insert("unstableBranch".to_string(), true.into());
        }
        // `daemonLong` only when the daemon was queried (Go omitempty).
        if let Some(d) = daemon {
            map.insert("daemonLong".to_string(), d.into());
        }
        // serde_json serialization of a Map<String, Value> cannot fail; fall back defensively.
        format!(
            "{}\n",
            serde_json::to_string_pretty(&map).unwrap_or_else(|_| "{}".to_string())
        )
    } else {
        match daemon {
            // Go prints `Client:`/`Daemon:` when `--daemon` is set.
            Some(d) => format!("Client: {client}\nDaemon: {d}\n"),
            // Plain `version`: just the client version, like Go's bare first line.
            None => format!("{client}\n"),
        }
    }
}

/// Map a daemon pref key (from [`Response::RevertGuard`]) to the `tnet up` flag the operator must
/// re-pass to keep that setting, rendered as a copy-pasteable `--flag` / `--flag=value` token.
///
/// The daemon deliberately speaks pref keys, not flag spellings (it has no notion of `--advertise-
/// routes`); this is the CLI-owned half of that split. Boolean prefs render as a bare `--flag` when
/// their current value is `true` (the only case the guard reports a bool — a `false` bool equals its
/// default and so never trips), and as `--no-flag` defensively otherwise. Value prefs render as
/// `--flag=value`. An unknown key (daemon newer than CLI) falls back to `--key=value` so the message
/// is still actionable rather than dropping the setting silently.
fn revert_pref_to_flag(key: &str, value: &str) -> String {
    match key {
        // Boolean up-managed prefs. The guard only reports these when non-default (i.e. `true`),
        // so the keep-it token is the bare enabling flag; `--no-*` is a defensive fallback.
        "accept_routes" => bool_keep_flag("accept-routes", "no-accept-routes", value),
        "shields_up" => bool_keep_flag("shields-up", "no-shields-up", value),
        "advertise_exit_node" => {
            bool_keep_flag("advertise-exit-node", "no-advertise-exit-node", value)
        }
        "ssh" => bool_keep_flag("ssh", "no-ssh", value),
        "tun" => bool_keep_flag("tun", "no-tun", value),
        "exit_node_allow_lan_access" => bool_keep_flag(
            "exit-node-allow-lan-access",
            "no-exit-node-allow-lan-access",
            value,
        ),
        "advertise_connector" => {
            bool_keep_flag("advertise-connector", "no-advertise-connector", value)
        }
        "report_posture" => bool_keep_flag("report-posture", "no-report-posture", value),
        // Value-bearing prefs: re-pass the current value verbatim. `advertise_routes` is already a
        // comma-joined list, which `--advertise-routes` accepts directly.
        "advertise_routes" => format!("--advertise-routes={value}"),
        "exit_node" => format!("--exit-node={value}"),
        "hostname" => format!("--hostname={value}"),
        "control_url" => format!("--control-url={value}"),
        "operator" => format!("--operator={value}"),
        "tun_name" => format!("--tun-name={value}"),
        "tun_mtu" => format!("--tun-mtu={value}"),
        // Daemon knows a pref this CLI build doesn't: keep the message actionable.
        other => format!("--{other}={value}"),
    }
}

/// Render a boolean "keep this setting" flag: the bare enabling flag when `value == "true"` (the
/// non-default case the guard reports), else the explicit disabling flag.
fn bool_keep_flag(enable: &str, disable: &str, value: &str) -> String {
    if value == "true" {
        format!("--{enable}")
    } else {
        format!("--{disable}")
    }
}

/// Render the accidental-revert guard message — the Rust analogue of Go's `accidentalUpPrefix`
/// guidance — listing the settings that would be lost and a copy-pasteable command to keep them.
/// Pure (returns the string) so it is unit-testable; the caller prints it to stderr.
fn format_revert_guard(reverts: &[RevertedPref]) -> String {
    // Deterministic order regardless of how the daemon happened to enumerate them.
    let mut flags: Vec<String> = reverts
        .iter()
        .map(|r| revert_pref_to_flag(&r.key, &r.value))
        .collect();
    flags.sort();
    let joined = flags.join(" ");
    let mut out = String::new();
    out.push_str(
        "error: this `tnet up` would revert settings you did not mention back to their defaults.\n",
    );
    out.push_str("To proceed, either re-run mentioning the current value of every non-default\n");
    out.push_str("setting, or pass --reset to accept the reverts:\n\n");
    out.push_str(&format!("    tnet up {joined}\n\n"));
    out.push_str("Or to reset the unmentioned settings to their defaults:\n\n");
    out.push_str("    tnet up --reset ...\n");
    out
}

/// Sanitize a control-plane-supplied string for printing as a **single-line / columnar cell** — the
/// safe default for terminal output.
///
/// Server-supplied text (a peer's `ComputedName`, a DNS resolver/suffix, an AUMHash, a Taildrop file
/// name, …) originates from the control server / a sending peer, which the daemon treats as only
/// semi-trusted. Two distinct injection classes have to be defused:
///
/// 1. **Terminal-escape injection.** Printing the value verbatim would let a malicious or compromised
///    server smuggle ANSI/terminal escape sequences (cursor moves, color, clear-screen, even
///    hyperlink/OSC injection) into the operator's terminal.
/// 2. **Delimiter / column / row injection.** Our human-readable renderers are *structured*:
///    `file cp --targets` prints TAB-separated columns (`<ip>\t<name>\t<status>`), and `whois` /
///    `file list` / `dns status` / `lock status` print one record per line. A control-supplied name
///    containing a literal `\t` could forge an extra column (a fake IP or a fake `offline` status),
///    and an embedded `\n` could forge an entirely fake row/line. Go's `tailscale` does no
///    sanitization here at all and *is* vulnerable to this; this fork is deliberately stricter.
///
/// So this neutralizes **every** C0/C1 control character — including the structural whitespace
/// `\t`/`\n`/`\r` — to a visible `U+FFFD` placeholder. The affected fields (IPs, DNS names, hostnames,
/// hashes) never legitimately contain those bytes, so this is lossless for real data and display
/// hardening only — the wire value is unchanged. For genuinely free-form, possibly multi-line text
/// (the registration-failure `reason`) use [`sanitize_multiline`] instead, which preserves `\t`/`\n`.
fn sanitize_for_terminal(s: &str) -> String {
    s.chars()
        .map(|c| if is_display_unsafe(c) { '\u{FFFD}' } else { c })
        .collect()
}

/// Whether a character is unsafe to print verbatim into a structured/columnar terminal line.
///
/// Covers, beyond the C0/C1 controls `char::is_control()` already catches (ESC/CSI/BEL, NEL, LF/CR/TAB):
/// - **U+2028 LINE SEPARATOR / U+2029 PARAGRAPH SEPARATOR** — some terminals treat these as line
///   breaks, so a control-supplied name carrying one could forge a fake row even though they are *not*
///   `is_control()`.
/// - **Unicode bidi overrides/isolates** — U+202A–U+202E (LRE/RLE/PDF/LRO/RLO) and U+2066–U+2069
///   (LRI/RLI/FSI/PDI). These reorder *displayed* text, so a hostile name could visually masquerade as
///   another (the "Trojan Source" class) or shuffle a rendered column. Neither range is `is_control()`.
///
/// Mapping any of these to `U+FFFD` is lossless for the real data these fields carry (IPs, DNS names,
/// hostnames, hashes never legitimately contain them) and closes the display-spoofing gap.
fn is_display_unsafe(c: char) -> bool {
    c.is_control()
        || matches!(c,
            '\u{2028}' | '\u{2029}'            // line / paragraph separators
            | '\u{202A}'..='\u{202E}'          // bidi embeddings + overrides (LRE..RLO)
            | '\u{2066}'..='\u{2069}'          // bidi isolates (LRI..PDI)
        )
}

/// Sanitize a control-supplied string that is rendered as **free-form, possibly multi-line** text
/// (the registration-failure `reason`, printed as `registration failed: <reason>`).
///
/// Unlike [`sanitize_for_terminal`], this preserves plain whitespace (`\t`, `\n`, `\r`) so a
/// multi-line reason still renders across lines — matching Go, which prints the reason raw. It is safe
/// to keep the newlines here precisely because the reason is *not* structured output: it is not parsed
/// into columns or rows, so an embedded `\n` can only wrap the message, not forge a fake table cell.
/// Every other C0/C1 control (ESC, BEL, …) is still stripped to `U+FFFD`, so escape-sequence injection
/// is defused exactly as in the single-line path. Use this ONLY for free-form message text; anything
/// rendered into a delimited/columnar line MUST use [`sanitize_for_terminal`].
fn sanitize_multiline(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c == '\t' || c == '\n' || c == '\r' {
                // Preserve the plain ASCII whitespace that legitimately formats a free-form message.
                c
            } else if is_display_unsafe(c) {
                // Everything else unsafe — C0/C1 escapes AND U+2028/U+2029 + bidi overrides — is
                // neutralized. (2028/2029 are NOT the `\n`/`\r` we preserve above: a Unicode line
                // separator in a "free-form" message is still a spoofing vector, so it is stripped.)
                '\u{FFFD}'
            } else {
                c
            }
        })
        .collect()
}

/// Serialize a JSON value pretty-printed with a **TAB** indent, matching Go's
/// `json.MarshalIndent(v, "", "\t")` (the indent `tailscale netcheck --format=json` uses).
/// `serde_json::to_string_pretty` is hard-wired to a two-space indent and cannot be configured, so we
/// drive a `PrettyFormatter::with_indent(b"\t")` directly.
fn to_string_pretty_tabs<T: serde::Serialize>(value: &T) -> Result<String, serde_json::Error> {
    let mut buf = Vec::new();
    let mut ser = serde_json::Serializer::with_formatter(
        &mut buf,
        serde_json::ser::PrettyFormatter::with_indent(b"\t"),
    );
    value.serialize(&mut ser)?;
    Ok(String::from_utf8(buf).expect("serde_json emits valid UTF-8"))
}

/// Format the `tnet ip` output: this node's tailnet addresses, one per line (IPv4 then IPv6), or a
/// placeholder when the node has no address yet (no netmap received). Pure (returns the string,
/// including its trailing newline) so the formatting is unit-testable; the caller `print!`s it.
//
// `tnet ip` itself renders through `format_ip_filtered` (it always carries an `IpSelect`), so this
// unfiltered variant now has no production call site — it is retained as the tested baseline
// renderer (see the `format_ip` unit tests). `allow(dead_code)` only outside `cfg(test)`.
#[cfg_attr(not(test), allow(dead_code))]
fn format_ip(ipv4: Option<&str>, ipv6: Option<&str>) -> String {
    let mut out = String::new();
    if let Some(v4) = ipv4 {
        out.push_str(v4);
        out.push('\n');
    }
    if let Some(v6) = ipv6 {
        out.push_str(v6);
        out.push('\n');
    }
    if out.is_empty() {
        out.push_str("(no tailnet address yet)\n");
    }
    out
}

/// Format the `tnet ping -c N` summary line: how many were sent vs received, with the loss percent.
/// Pure → unit-testable.
fn format_ping_summary(sent: u32, received: u32) -> String {
    let lost = sent.saturating_sub(received);
    let loss_pct = if sent == 0 {
        0.0
    } else {
        (lost as f64 / sent as f64) * 100.0
    };
    format!("--- {sent} sent, {received} received, {loss_pct:.0}% loss ---")
}

/// Address-family / count selection for `tnet ip` (Go `-4`/`-6`/`-1`). `v4`/`v6` are mutually
/// exclusive (clap enforces). Default = all addresses, both families.
#[derive(Default, Clone, Copy)]
struct IpSelect {
    v4: bool,
    v6: bool,
    first: bool,
}

/// Format `tnet ip` output applying an [`IpSelect`]: `-4` keeps only IPv4, `-6` only IPv6, `-1` only
/// the first address (Go's quad-one). With no flags, both families print (IPv4 then IPv6), one per
/// line. A placeholder is printed only when nothing is selectable. Pure → unit-testable.
///
/// The two narrowings run in Go's order — `-1` truncates the address list, and only then does the
/// family filter run over what survived — so this and [`format_service_ips`] answer the same
/// question the same way. [`ip_usage_refusal`] refuses `-1` alongside `-4`/`-6` exactly as Go does,
/// so in practice at most one of the two ever narrows a call.
fn format_ip_filtered(ipv4: Option<&str>, ipv6: Option<&str>, sel: IpSelect) -> String {
    // Go's `ips`, in netmap order: IPv4 then IPv6. A node has at most one address per family here,
    // so each one's family is positional — unlike a Service's list, nothing needs parsing.
    let all: Vec<(&str, bool)> = [(ipv4, true), (ipv6, false)]
        .into_iter()
        .filter_map(|(addr, is_v4)| addr.map(|addr| (addr, is_v4)))
        .collect();
    // -1: only the first (Go's quad-one — the primary address). Go's `ips = ips[:1]`, ahead of the
    // family filter below, which is its match loop.
    let considered = if sel.first {
        all.get(..1).unwrap_or(&all)
    } else {
        all.as_slice()
    };
    // Family filter: -4 drops v6, -6 drops v4; neither keeps both.
    let want_v4 = !sel.v6; // -6 hides v4
    let want_v6 = !sel.v4; // -4 hides v6
    let mut out = String::new();
    for (addr, is_v4) in considered {
        let wanted = if *is_v4 { want_v4 } else { want_v6 };
        if wanted {
            out.push_str(addr);
            out.push('\n');
        }
    }
    if out.is_empty() {
        return "(no matching tailnet address)\n".to_string();
    }
    out
}

/// Format the `tnet file list` output: one `"{name}  ({size} bytes)"` line per waiting file, or a
/// placeholder when the inbox is empty (never empty output). Each file name is engine/peer-supplied,
/// so it is passed through [`sanitize_for_terminal`] before rendering (a malicious sender could craft
/// a name with terminal escapes). Pure (returns the string, trailing newline included) so it is
/// unit-testable; the caller `print!`s it.
fn format_files(files: &[tailscaled_rs::localapi::WaitingFileReport]) -> String {
    if files.is_empty() {
        return "(no files waiting)\n".to_string();
    }
    let mut out = String::new();
    for f in files {
        out.push_str(&format!(
            "{}  ({} bytes)\n",
            sanitize_for_terminal(&f.name),
            f.size
        ));
    }
    out
}

/// Count the files a drain actually *moved* — Go's `deleted` in `runFileGetOneBatch`
/// (`cmd/tailscale/cli/file.go`). A file counts only when it was both written to the target
/// directory AND cleared from the inbox: one that landed on disk but could not be removed is not
/// moved (the next drain would fetch it again), and one that never landed is still waiting.
fn files_got_moved(results: &[tailscaled_rs::localapi::FileGotReport]) -> usize {
    results
        .iter()
        .filter(|r| r.written.is_some() && r.error.is_none())
        .count()
}

/// The failures of a `tnet file get <dir>` drain, in the order Go's `runFileGetOneBatch` appends
/// them to its `errs` slice: one per file that did not come through, and then — when the drain
/// cleared *nothing* out of a non-empty inbox — Go's `moved %d/%d files`.
///
/// That last one is the upstream subtlety this mirrors. Go emits the tally from two branches: under
/// `if deleted == 0 && len(wfs) > 0` it appends `moved %d/%d files` to `errs` ("persistently stuck
/// files are basically an error"), which happens whether or not `--verbose` was passed and which
/// `runFileGet` returns as the command's error; only in the `else if fileGetArgs.verbose` branch is
/// it the informational line [`format_files_got_verbose`] prints. So a fully stuck drain reports the
/// tally and exits non-zero even without `--verbose`.
///
/// Names are peer-supplied and reasons are daemon-supplied, so both go through
/// [`sanitize_for_terminal`]. Pure → unit-testable.
fn file_get_errors(results: &[tailscaled_rs::localapi::FileGotReport]) -> Vec<String> {
    let mut errs = Vec::new();
    for r in results {
        let name = sanitize_for_terminal(&r.name);
        match (&r.written, &r.error) {
            // A reason, with or without a file on disk. The written-but-not-cleared case is a
            // failure in Go too (its `DeleteWaitingFile` error), reported separately from the
            // `wrote` progress line the batch already printed.
            (_, Some(e)) => errs.push(format!("error: {name}: {}", sanitize_for_terminal(e))),
            // Neither written nor failed (should not happen — the daemon always sets one). Surface
            // it defensively rather than let it pass for a clean success.
            (None, None) => errs.push(format!("error: {name}: unknown outcome")),
            (Some(_), None) => {}
        }
    }
    let moved = files_got_moved(results);
    if moved == 0 && !results.is_empty() {
        errs.push(format!("moved {moved}/{} files", results.len()));
    }
    errs
}

/// Render a whole drain reply the way Go's `runFileGet` writes one: the batch's progress lines
/// first — compact, or [`format_files_got_verbose`] under `--verbose` — then the accumulated
/// failures, of which Go prints all but the last (`outln`, stdout) and *returns* the last as the
/// command's error.
///
/// Returns `(stdout, last_error)`: the caller prints `stdout`, and a `Some` last error goes to
/// stderr and exits non-zero. Splitting it this way (rather than interleaving `error:` lines into
/// the progress) is what keeps the exit status keyed on Go's `errs` — including the stuck-inbox
/// `moved 0/N files` that [`file_get_errors`] appends. Pure → unit-testable.
fn render_files_got(
    results: &[tailscaled_rs::localapi::FileGotReport],
    verbose: bool,
) -> (String, Option<String>) {
    let mut out = if verbose {
        format_files_got_verbose(results)
    } else {
        format_files_got(results)
    };
    let mut errs = file_get_errors(results);
    let last = errs.pop();
    for e in errs {
        out.push_str(&e);
        out.push('\n');
    }
    (out, last)
}

/// Render the per-file *progress* of `tnet file get <dir>` (a [`Response::FilesGot`]) in the compact
/// (non-`--verbose`) mode: one line per file that landed, naming where it landed and its size
/// (`wrote <name> -> <path> (<n> bytes)`; the path differs from `<dir>/<name>` under `rename`). An
/// empty inbox prints a clear placeholder.
///
/// Failures are deliberately absent here: Go accumulates them and prints them *after* the batch,
/// which [`file_get_errors`] and [`render_files_got`] reproduce, so emitting them inline as well
/// would print each one twice and put them in the wrong order. A file that never landed therefore
/// contributes no progress line at all — only its `error:` line, after.
///
/// (Printing anything per file is a fork addition: Go's non-verbose mode is silent on success. It
/// stays because the compact mode is this CLI's default and a silent drain tells an operator
/// nothing.)
///
/// All control-supplied names/paths are sanitized for terminal display. Pure → unit-testable.
fn format_files_got(results: &[tailscaled_rs::localapi::FileGotReport]) -> String {
    if results.is_empty() {
        return "(no files waiting)\n".to_string();
    }
    let mut out = String::new();
    for r in results {
        if let Some(path) = &r.written {
            out.push_str(&format!(
                "wrote {} -> {} ({} bytes)\n",
                sanitize_for_terminal(&r.name),
                sanitize_for_terminal(path),
                r.size
            ));
        }
    }
    out
}

/// Render `tnet file get <dir> --verbose` — the per-file progress Go's `tailscale file get
/// --verbose` prints (`runFileGetOneBatch` in `cmd/tailscale/cli/file.go`).
///
/// Go's two verbose lines, reproduced verbatim in shape:
/// * per received file: `wrote <inbox name> as <path it landed at> (<n> bytes)` — the path differs
///   from `<dir>/<name>` under the `rename` policy, which is exactly why Go prints both. Go prints
///   it before it tries to clear the inbox, so a file that landed but could not be removed still
///   gets its line (and then an `error:` line after the batch).
/// * once at the end: `moved <received>/<waiting> files`, where `received` counts only the files
///   that were both written AND cleared from the inbox ([`files_got_moved`], Go's `deleted`).
///
/// The tally is conditional, because Go's is: it belongs to the `else if fileGetArgs.verbose`
/// branch, so it is *not* printed here when the drain moved nothing out of a non-empty inbox — in
/// that case the same numbers are an error instead ([`file_get_errors`]), which prints in both
/// modes. Printing it here too would double it.
///
/// Failures are likewise not printed here — see [`format_files_got`]; they come after the batch.
/// An empty inbox keeps the fork's `(no files waiting)` placeholder ahead of Go's `moved 0/0 files`
/// tally, so the zero-file case says so in words instead of rendering as an empty list.
///
/// NOTE: a `/dev/null` (wipe) drain renders through this same shape. Go's `wipeInbox` has its own
/// verbose lines (`deleting <name> ...` / `deleted <n> files`); mirroring those is separate work and
/// deliberately not done here.
///
/// Every name/path is engine- or peer-supplied, so each goes through [`sanitize_for_terminal`].
/// Pure (returns the string, trailing newline included) → unit-testable; the caller `print!`s it.
fn format_files_got_verbose(results: &[tailscaled_rs::localapi::FileGotReport]) -> String {
    let mut out = String::new();
    if results.is_empty() {
        out.push_str("(no files waiting)\n");
    }
    for r in results {
        if let Some(path) = &r.written {
            out.push_str(&format!(
                "wrote {} as {} ({} bytes)\n",
                sanitize_for_terminal(&r.name),
                sanitize_for_terminal(path),
                r.size
            ));
        }
    }
    let moved = files_got_moved(results);
    if moved > 0 || results.is_empty() {
        out.push_str(&format!("moved {moved}/{} files\n", results.len()));
    }
    out
}

/// Render the `tnet file cp --targets` peer list (a [`Response::FileTargets`]). One tab-separated line
/// per peer — `<ip>\t<name>[\t<status>]` — mirroring Go's `runCpTargets` (which prints
/// `addr \t ComputedName` plus an `offline`/`unknown-status` detail column). An empty list prints a
/// clear placeholder. The peer name is control-supplied, so it is run through `sanitize_for_terminal`.
/// Pure → unit-testable.
fn format_file_targets(targets: &[tailscaled_rs::localapi::FileTargetReport]) -> String {
    if targets.is_empty() {
        return "(no Taildrop targets)\n".to_string();
    }
    let mut out = String::new();
    for t in targets {
        let name = sanitize_for_terminal(&t.name);
        // Go prints a detail column only when the peer is not known-online: `offline` for an explicit
        // offline, `unknown-status` when control reports no online state. A known-online peer gets no
        // extra column.
        let detail = match t.online {
            Some(true) => String::new(),
            Some(false) => "\toffline".to_string(),
            None => "\tunknown-status".to_string(),
        };
        out.push_str(&format!(
            "{}\t{name}{detail}\n",
            sanitize_for_terminal(&t.ip)
        ));
    }
    out
}

/// Format the `tnet whois` output for a [`WhoisReport`]. If the address matched no node, a single
/// "no tailnet node owns <ip>" line — the caller passes the address as the operator typed it, so an
/// `ip[:port]` flow argument is echoed with its port rather than silently narrowed. Otherwise: the owning node's
/// name, its IPv4, the owning user (when control retained it), its liveness (`online`, and a
/// `last-seen` line only when offline — an online node's last-seen is "now", matching `status`), its
/// control-granted ACL `tags` and node-key `key-expiry` (when present), any control-granted node-level
/// capabilities, and the flow-scoped `cap-grants` (Go `WhoIsResponse.CapMap` — the peer-capability
/// grants for this-node → queried-IP, name + values), each on its own line. The node name, tags,
/// node-level capabilities, and every cap-grant name + value are control-supplied, so each is passed
/// through [`sanitize_for_terminal`] before rendering (online/last-seen are a bool + timestamp, not
/// free-form text). Pure (returns the string, trailing newline included) so it is unit-testable; the
/// caller `print!`s it.
fn format_whois(w: &tailscaled_rs::localapi::WhoisReport, ip: &str) -> String {
    if !w.found {
        return format!("no tailnet node owns {ip}\n");
    }
    let mut out = String::new();
    if let Some(name) = w.node_name.as_deref() {
        out.push_str(&format!("node:         {}\n", sanitize_for_terminal(name)));
    }
    if let Some(v4) = w.node_ipv4.as_deref() {
        // Control-supplied like the rest of the whois fields; sanitize uniformly (defense-in-depth —
        // a parsed IP can't hold control bytes today, but the rule is "every off-box field", so there
        // is no per-field judgement call about which ones are "safe enough" to print raw).
        out.push_str(&format!("ipv4:         {}\n", sanitize_for_terminal(v4)));
    }
    if let Some(user) = w.user.as_deref() {
        // `user` originates from control too; sanitize it before printing.
        out.push_str(&format!("user:         {}\n", sanitize_for_terminal(user)));
    }
    // Liveness, following the `status` convention (`peer_status_cell`): show `online:` when the
    // control-connected state is known (omit when `None` = unknown, like status hides
    // unknown-liveness peers), and show `last-seen:` only when the node is OFFLINE and the time is
    // known — an online node's last-seen is "now", so status only surfaces it for offline peers.
    // `online`/`last_seen` are a bool + a chrono timestamp (not free-form control text), so they need
    // no terminal sanitization.
    match w.online {
        Some(true) => out.push_str("online:       yes\n"),
        Some(false) => {
            out.push_str("online:       no\n");
            if let Some(seen) = w.last_seen.as_deref() {
                out.push_str(&format!("last-seen:    {seen}\n"));
            }
        }
        None => {}
    }
    if !w.tags.is_empty() {
        // ACL tags are control-supplied; sanitize each before printing (same as capabilities).
        out.push_str("tags:\n");
        for tag in &w.tags {
            out.push_str(&format!("  - {}\n", sanitize_for_terminal(tag)));
        }
    }
    if let Some(expiry) = w.node_key_expiry.as_deref() {
        // An RFC3339 timestamp (`YYYY-MM-DDTHH:MM:SS+00:00`) from the daemon — not free-form control
        // text, but sanitize defensively anyway (cheap, keeps "every printed node datum is
        // sanitized" uniform).
        out.push_str(&format!(
            "key-expiry:   {}\n",
            sanitize_for_terminal(expiry)
        ));
    }
    if !w.capabilities.is_empty() {
        out.push_str("capabilities:\n");
        for cap in &w.capabilities {
            // Capability names come from control; sanitize each before printing.
            out.push_str(&format!("  - {}\n", sanitize_for_terminal(cap)));
        }
    }
    // Flow-scoped peer-capability grants (Go `WhoIsResponse.CapMap`), distinct from the node-level
    // `capabilities` above — these are the grants control's packet-filter authorizes for traffic from
    // this node to the queried IP, so they carry per-cap arg values (mirroring Go's `tailscale whois`
    // CapMap block). The map is a `BTreeMap`, so iteration is sorted by cap name → deterministic
    // output. Unlike Go, which prints a single `json.MarshalIndent` blob of the values, we render each
    // grant value on its own line, individually sanitized — both the cap name and every value are
    // control-supplied, and one-sanitized-value-per-line is this fork's terminal-injection-safe
    // discipline (no raw control bytes can reach the operator's terminal).
    if !w.cap_map.is_empty() {
        out.push_str("cap-grants:\n");
        for (cap, vals) in &w.cap_map {
            if vals.is_empty() {
                out.push_str(&format!("  - {}\n", sanitize_for_terminal(cap)));
            } else {
                out.push_str(&format!("  - {}:\n", sanitize_for_terminal(cap)));
                for v in vals {
                    out.push_str(&format!("      - {}\n", sanitize_for_terminal(v)));
                }
            }
        }
    }
    out
}

/// Render a [`StatusReport`] to stdout (the shared one-shot + watch formatter).
fn print_status(s: &tailscaled_rs::localapi::StatusReport) {
    print!("{}", format_status(s));
}

/// Render the human-readable `tnet status` text (a [`StatusReport`]). Pure (returns the whole block,
/// trailing newline included) so it is unit-testable — in particular so the sanitization of the
/// control-supplied `self`/`exit-node`/peer names is provable, not just printed. The caller `print!`s
/// it. Every off-box (control/netmap-supplied) name below is run through `sanitize_for_terminal` —
/// single-line cells, so an embedded `\t`/`\n` can neither forge a fake status line / peer row nor
/// break a fixed-width column — except the free-form registration `reason`, which uses
/// `sanitize_multiline` (multi-line message; see THREAT_MODEL §4.8).
fn format_status(s: &tailscaled_rs::localapi::StatusReport) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    // `writeln!` into a String is infallible; the `let _ =` keeps clippy quiet without `.unwrap()`.
    let _ = writeln!(out, "state:        {}", s.state);
    let _ = writeln!(out, "want_running: {}", s.want_running);
    // `self_name` is this node's control-supplied display name (netmap ComputedName); sanitize it so
    // it can't smuggle terminal escapes or, via an embedded `\n`, forge extra status lines (e.g. a
    // spoofed `registration failed:` / `peers:` line). Same hardening as the peer list; §4.8.
    let _ = writeln!(
        out,
        "self:         {} {}",
        s.self_name
            .as_deref()
            .map(sanitize_for_terminal)
            .unwrap_or_else(|| "(unknown)".to_string()),
        s.self_ipv4.as_deref().unwrap_or("-")
    );
    // Configured posture (the node's persisted prefs), so `tnet status` shows what `up`/`set` left
    // in effect — the analogue of the config Go's `tailscale status` reflects. Each line is printed
    // only when it carries non-default information, to keep a plain node's status uncluttered.
    let p = &s.prefs;
    if let Some(en) = p.exit_node.as_deref() {
        let _ = writeln!(out, "exit-node:    {en}");
    }
    if p.advertise_exit_node {
        let _ = writeln!(out, "advertising:  exit-node");
    }
    if !p.advertise_routes.is_empty() {
        let _ = writeln!(out, "adv-routes:   {}", p.advertise_routes.join(", "));
    }
    if p.accept_routes {
        let _ = writeln!(out, "accept-routes: on");
    }
    if p.shields_up {
        let _ = writeln!(out, "shields-up:   on");
    }
    if p.ssh {
        // Distinguish the *enabled* pref from the server actually *running*. The task can die at
        // bind time (no tailnet IPv4, `listen_ssh` error) while the pref stays on, so flag that
        // honestly rather than imply SSH is serving. Only warn when the node is in a state where the
        // server is expected to be up (Running/Starting) — a deliberately-down node has no task
        // (`ssh_running: false`) and must not be reported as a broken SSH server.
        let node_should_serve = s.state == "Running" || s.state == "Starting";
        if node_should_serve && !p.ssh_running {
            let _ = writeln!(out, "ssh-server:   on (NOT RUNNING — check logs)");
        } else {
            let _ = writeln!(out, "ssh-server:   on");
        }
    }
    if p.tun {
        let _ = writeln!(out, "tun:          on");
    }
    // Interactive login: when the node is waiting for a human to authorize it, the daemon surfaces
    // the control auth URL — make it prominent so the operator can click it.
    if let Some(url) = s.auth_url.as_deref() {
        let _ = writeln!(out);
        let _ = writeln!(out, "To authenticate this node, visit:");
        let _ = writeln!(out, "    {url}");
    }
    // Terminal registration failure: distinct from `auth_url`, this means registration hard-failed
    // and the engine will not retry. Re-running with the same key loops forever, so spell out that
    // the operator must re-authenticate with a fresh key.
    if let Some(reason) = s.error.as_deref() {
        let _ = writeln!(out);
        let _ = writeln!(out, "registration failed: {}", sanitize_multiline(reason));
        let _ = writeln!(
            out,
            "(this is a permanent failure — re-run `tnet up --authkey <NEW_KEY>` with a fresh \
             key; the same key will keep failing)"
        );
    }
    // The exit node currently engaged (Go `ExitNodeStatus`), distinct from the *configured* selector
    // above: this is what traffic actually egresses through right now (the engine's fail-closed answer).
    if let Some(active) = s.active_exit_node.as_deref() {
        // `active_exit_node` resolves to the exit peer's control-supplied display name (netmap), so
        // sanitize before display — same single-line hardening as `self_name`/the peer list (§4.8).
        let _ = writeln!(
            out,
            "exit-node:    {} (active)",
            sanitize_for_terminal(active)
        );
    }
    let _ = writeln!(out, "peers:        {}", s.peers.len());
    for p in &s.peers {
        // `p.name` is the peer's control-supplied hostname: sanitize before display so it cannot
        // smuggle terminal escapes or, via an embedded `\t`/`\n`, forge a fake peer row or break the
        // fixed-width column layout (same hardening as the other listings; §4.8).
        let _ = writeln!(
            out,
            "  - {:<28} {:<16}{}{}",
            sanitize_for_terminal(&p.name),
            p.ipv4,
            if p.is_exit_node { "  [exit]" } else { "" },
            peer_status_cell(p),
        );
    }
    // Health warnings last, in Go's `printHealth` shape (`cmd/tailscale/cli/status.go`):
    //
    //     # Health check:
    //     #     - <text>
    //
    // Printed only when something is actually wrong, exactly like Go (which guards on
    // `len(st.Health) > 0`), so a healthy node's status block is unchanged. The texts are
    // daemon-generated constants, not control-supplied, but they go through the same single-line
    // sanitizer as every other cell so the block cannot be broken by a future free-form message.
    if !s.health.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "# Health check:");
        for m in &s.health {
            let _ = writeln!(out, "#     - {}", sanitize_for_terminal(m));
        }
    }
    out
}

/// The Go-`printPS`-flavored status cell for a peer: direct-vs-relay + an offline/last-seen suffix.
/// Pure → unit-testable. Empty when there is nothing informative to add (online peer, no path known).
fn peer_status_cell(p: &tailscaled_rs::localapi::PeerReport) -> String {
    let mut parts: Vec<String> = Vec::new();
    // Path: a confirmed direct endpoint, else the DERP relay region (mutually exclusive, like Go's
    // CurAddr-vs-Relay). Quote the relay region to match Go's `relay "nyc"`.
    if let Some(addr) = p.cur_addr.as_deref() {
        parts.push(format!("direct {addr}"));
    } else if let Some(region) = p.relay.as_deref() {
        parts.push(format!("relay {region:?}"));
    }
    // Liveness: only call out offline (online is the unremarkable default), appending last-seen when
    // known — mirrors Go's "; offline, last seen …".
    if p.online == Some(false) {
        match p.last_seen.as_deref() {
            Some(seen) => parts.push(format!("offline, last seen {seen}")),
            None => parts.push("offline".to_string()),
        }
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!("  ({})", parts.join("; "))
    }
}

/// Client-side filters for `tnet status` (Go's `--active` / `--peers=false` / `--self=false`),
/// applied to the [`StatusReport`] before either renderer so the human and `--json` outputs honor
/// them identically. Default = show everything.
#[derive(Default, Clone, Copy)]
struct StatusFilter {
    /// Show only "active" peers. Go's `--active` means recent traffic; this fork has no per-peer
    /// traffic signal, so it approximates with the peer's *online* (control-connected) state —
    /// peers whose liveness is unknown (`online: None`) are hidden.
    active_only: bool,
    /// Hide the peer list entirely (Go `--peers=false`).
    hide_peers: bool,
    /// Hide this node's own self info (Go `--self=false`).
    hide_self: bool,
}

impl StatusFilter {
    /// Apply the filters to a [`StatusReport`], returning the projected report. Pure (consumes +
    /// returns), so it is unit-testable. `hide_self` blanks the self fields so both renderers omit
    /// the self line/object; `hide_peers` empties the peer list; `active_only` keeps only peers
    /// reported online.
    fn apply(
        &self,
        mut s: tailscaled_rs::localapi::StatusReport,
    ) -> tailscaled_rs::localapi::StatusReport {
        if self.hide_self {
            s.self_ipv4 = None;
            s.self_name = None;
            s.self_ipv6 = None;
        }
        if self.hide_peers {
            s.peers.clear();
        } else if self.active_only {
            // "active" ≈ online (the only liveness signal we have). Unknown liveness → hidden.
            s.peers.retain(|p| p.online == Some(true));
        }
        s
    }
}

/// Render `tnet status --json` as a Go `ipnstate.Status`-shaped object (a faithful subset). Built via
/// `serde_json` so it is escape-safe and emits bare booleans, 2-space indented like Go.
///
/// We populate only fields we can fill truthfully and use Go's exact key names (`BackendState`,
/// `AuthURL`, `TailscaleIPs`, `Self`, `Peer`, …). `BackendState` is our `state` string, which is
/// already one of Go's canonical `ipn.State` names (`NoState`/`NeedsLogin`/`NeedsMachineAuth`/
/// `Stopped`/`Starting`/`Running`). Each `PeerStatus` carries the subset we know: `HostName`/`DNSName`
/// (our peer name), `TailscaleIPs`, `ExitNodeOption` (our `is_exit_node`), and `Online` when known.
///
/// DEVIATION (documented): Go keys the `Peer` map by the node **public key** (`"nodekey:…"`); this
/// fork keys it by the engine's **StableNodeID** instead, since that is the durable per-peer
/// identifier the daemon surfaces (see [`tailscaled_rs::localapi::PeerReport::stable_id`]). A peer
/// missing a stable id (older daemon) falls back to its name as the key.
fn format_status_json(s: &tailscaled_rs::localapi::StatusReport) -> Result<String> {
    use serde_json::{Map, Value, json};

    // The self/peer TailscaleIPs slice: IPv4 then (if known) IPv6, like Go's TailscaleIPs.
    let self_ips: Vec<&String> = s.self_ipv4.iter().chain(s.self_ipv6.iter()).collect();

    // Self: a PeerStatus subset from the self_* fields.
    let self_node = if !self_ips.is_empty() || s.self_name.is_some() {
        let mut m = Map::new();
        if let Some(name) = &s.self_name {
            m.insert("HostName".into(), json!(name));
            m.insert("DNSName".into(), json!(name));
        }
        m.insert("TailscaleIPs".into(), json!(self_ips));
        Value::Object(m)
    } else {
        Value::Null
    };

    // Peer map, keyed by stable id (Go uses the node public key — see the doc note).
    let mut peers = Map::new();
    for p in &s.peers {
        let key = if p.stable_id.is_empty() {
            p.name.clone()
        } else {
            p.stable_id.clone()
        };
        let mut pm = Map::new();
        pm.insert("HostName".into(), json!(p.name));
        pm.insert("DNSName".into(), json!(p.name));
        // TailscaleIPs: IPv4 then IPv6 (Go's per-peer address slice).
        let ips: Vec<&String> = std::iter::once(&p.ipv4).chain(p.ipv6.iter()).collect();
        pm.insert("TailscaleIPs".into(), json!(ips));
        pm.insert("ExitNodeOption".into(), json!(p.is_exit_node));
        if let Some(online) = p.online {
            pm.insert("Online".into(), json!(online));
        }
        if !p.allowed_routes.is_empty() {
            pm.insert("AllowedIPs".into(), json!(p.allowed_routes));
        }
        if let Some(seen) = &p.last_seen {
            pm.insert("LastSeen".into(), json!(seen));
        }
        if let Some(addr) = &p.cur_addr {
            pm.insert("CurAddr".into(), json!(addr));
        }
        if let Some(region) = &p.relay {
            pm.insert("Relay".into(), json!(region));
        }
        peers.insert(key, Value::Object(pm));
    }

    let mut root = Map::new();
    root.insert("BackendState".into(), json!(s.state));
    // Version (Go `Status.Version`): the daemon's own version, carried on the report. Surfaced here
    // so `status --json | jq .Version` answers the way `version --daemon` does.
    if let Some(v) = &s.version {
        root.insert("Version".into(), json!(v));
    }
    // TUN (Go `Status.TUN`): whether the node runs on a kernel TUN interface vs the userspace
    // netstack. We report the configured pref (the human `status` already prints it); Go reports the
    // runtime reality. These agree on every success path (netstack default → false; `--tun` up → true)
    // and diverge only if a requested `--tun` failed to initialize (pref true, datapath netstack) —
    // the fork has no `tun_running` liveness signal today, so the pref is the answer. Go emits the
    // bare bool always.
    root.insert("TUN".into(), json!(s.prefs.tun));
    // HaveNodeKey (Go `Status.HaveNodeKey`, omitempty): whether a node key is on disk — taken from the
    // daemon's `have_node_key` (the analogue of Go's `hasNodeKeyLocked`, read from the key file), NOT
    // inferred from `state` (an expired node reports `NeedsLogin` but still holds its key). Go omits it
    // when false, so only emit it when true.
    if s.have_node_key {
        root.insert("HaveNodeKey".into(), json!(true));
    }
    // AuthURL: Go emits the field always (empty when none); mirror that.
    root.insert("AuthURL".into(), json!(s.auth_url.as_deref().unwrap_or("")));
    root.insert("TailscaleIPs".into(), json!(self_ips));
    root.insert("Self".into(), self_node);
    if let Some(suffix) = &s.magic_dns_suffix {
        root.insert("MagicDNSSuffix".into(), json!(suffix));
    }
    // ExitNodeStatus: Go's `ExitNodeStatus.ID` is a `tailcfg.StableNodeID` (it keys the `Peer` map),
    // NOT a display name — so emit the raw stable id there for Go-tooling compatibility (a script
    // doing `jq -r .ExitNodeStatus.ID` matches it against a `Peer` key). The friendlier resolved name
    // is for the human status line; we also surface it as a non-Go `Name` field for convenience. Fall
    // back to the resolved name only if an older daemon sent no id.
    if s.active_exit_node_id.is_some() || s.active_exit_node.is_some() {
        let id = s
            .active_exit_node_id
            .as_deref()
            .or(s.active_exit_node.as_deref())
            .unwrap_or("");
        let mut ens = serde_json::Map::new();
        ens.insert("ID".into(), json!(id));
        if let Some(name) = &s.active_exit_node {
            ens.insert("Name".into(), json!(name));
        }
        root.insert("ExitNodeStatus".into(), Value::Object(ens));
    }
    // Health (Go `Status.Health`, a `[]string` of health-check problems; empty means nothing known
    // to be wrong). DEVIATION: Go emits `null` for its nil slice, we always emit an array, so
    // `jq '.Health | length'` works without a null guard.
    root.insert("Health".into(), json!(s.health));
    root.insert("Peer".into(), Value::Object(peers));

    Ok(format!("{}\n", serde_json::to_string_pretty(&root)?))
}

/// Stream status: send a bare `Request::Watch` (no mask fields → the daemon keeps streaming
/// `Response::Status`, the back-compatible path) and print each [`StatusReport`] the daemon pushes (an
/// initial snapshot, then one per state transition) until the connection ends or the user
/// interrupts (Ctrl-C). The daemon closes the stream when the device is torn down. A `---` rule
/// separates successive snapshots so transitions are visually distinct.
async fn watch_status(socket: &std::path::Path, json: bool, filter: StatusFilter) -> Result<()> {
    let stream = UnixStream::connect(socket)
        .await
        .context("connect (is tailnetd running?)")?;
    let (read_half, mut write_half) = stream.into_split();

    // The BARE watch (no mask fields) — `status --watch` stays on the legacy status-stream path,
    // serializing to exactly `{"cmd":"watch"}`. The masked notify path is `tnet debug watch-ipn`.
    let mut line = serde_json::to_vec(&Request::Watch {
        initial_state: false,
        initial_netmap: false,
        prefs: false,
    })?;
    line.push(b'\n');
    write_half.write_all(&line).await?;
    write_half.flush().await?;

    let mut reader = BufReader::new(read_half);
    let mut buf = String::new();
    let mut first = true;
    loop {
        buf.clear();
        let n = reader.read_line(&mut buf).await?;
        if n == 0 {
            // Daemon closed the stream (device torn down / shutdown).
            break;
        }
        let trimmed = buf.trim();
        if trimmed.is_empty() {
            continue;
        }
        match serde_json::from_str::<Response>(trimmed)
            .with_context(|| format!("parsing daemon stream line: {trimmed:?}"))?
        {
            Response::Status(s) => {
                // Honor the same client-side filters as the one-shot path (per pushed frame).
                let s = filter.apply(s);
                if json {
                    // Stream one JSON object per snapshot (no `---` separator — a JSON consumer
                    // reads object-by-object). On a (practically impossible) serialize error, surface
                    // it and stop rather than emit a half object into the stream.
                    match format_status_json(&s) {
                        Ok(out) => print!("{out}"),
                        Err(e) => {
                            eprintln!("error: serializing status: {e}");
                            std::process::exit(1);
                        }
                    }
                } else {
                    if !first {
                        println!("---");
                    }
                    print_status(&s);
                }
                first = false;
            }
            Response::Error { message } => {
                eprintln!("error: {message}");
                std::process::exit(1);
            }
            // The watch stream only carries Status frames; any other reply (an `Ok`, or one of the
            // diagnostic Ip/Whois/Ping replies) is unexpected on this connection but harmless — note
            // it and keep streaming.
            other => eprintln!("warning: unexpected reply on status stream: {other:?}"),
        }
    }
    Ok(())
}

/// `debug watch-ipn` (Go `tailscale debug watch-ipn-bus`): stream the daemon's IPN notification bus,
/// printing one JSON [`NotifyView`](tailscaled_rs::localapi::NotifyView) per line. Sends the **masked**
/// `watch` request (`initial_state` + `initial_netmap` both set) so the first frame is the current
/// state + peer set and each later frame carries only what changed. Reuses `watch_status`'s
/// streaming-read shape — connect, write the one request line, then read [`Response`] lines until the
/// daemon closes the stream — but on the Notify path: `Notify` frames print as JSON, an `Error` frame
/// exits non-zero, and any other reply (impossible on this connection) is noted and skipped.
async fn run_debug_watch_ipn(socket: &std::path::Path) -> Result<()> {
    let stream = UnixStream::connect(socket)
        .await
        .context("connect (is tailnetd running?)")?;
    let (read_half, mut write_half) = stream.into_split();

    // The MASKED watch: all snapshots requested → the daemon streams `Response::Notify` frames (not
    // `Response::Status`), front-loading the current state + peer set + prefs, then streaming each
    // change (incl. a fresh prefs frame on every up/set/logout/switch/reload-config).
    let mut line = serde_json::to_vec(&Request::Watch {
        initial_state: true,
        initial_netmap: true,
        prefs: true,
    })?;
    line.push(b'\n');
    write_half.write_all(&line).await?;
    write_half.flush().await?;

    let mut reader = BufReader::new(read_half);
    let mut buf = String::new();
    loop {
        buf.clear();
        let n = reader.read_line(&mut buf).await?;
        if n == 0 {
            // Daemon closed the stream (device torn down / shutdown).
            break;
        }
        let trimmed = buf.trim();
        if trimmed.is_empty() {
            continue;
        }
        match serde_json::from_str::<Response>(trimmed)
            .with_context(|| format!("parsing daemon notify stream line: {trimmed:?}"))?
        {
            Response::Notify(_) => {
                // One JSON object per notification (a JSON consumer reads object-by-object). We parsed
                // it (above) only to validate the frame is a `Notify` and to route `Error`/unexpected
                // frames; echo the daemon's exact bytes rather than decode→re-encode (which would
                // re-order/normalize the JSON and add a dead serialize-error branch).
                println!("{trimmed}");
            }
            Response::Error { message } => {
                eprintln!("error: {message}");
                std::process::exit(1);
            }
            // The notify stream only carries Notify frames; any other reply is unexpected on this
            // connection but harmless — note it and keep streaming.
            other => eprintln!("warning: unexpected reply on notify stream: {other:?}"),
        }
    }
    Ok(())
}

/// Interval between `status` polls while [`wait_for_running`] waits for the node to come up.
const WAIT_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);

/// Block until the node reaches `Running` with a tailnet IP, then return `Ok(())` (exit 0). Mirrors
/// Go `tailscale wait`'s exit-code contract. Three exit conditions: **Running** → `Ok(())`; a
/// **terminal registration error** → `Err` with the reason (fail fast — the engine will not retry,
/// so it does not wait out the timeout; see [`wait_decision`]); **timeout** → `Err`. `timeout_secs`
/// of `None`/`Some(0)` waits forever; otherwise it bounds the wait. Shared by `tnet wait` and
/// `tnet up --timeout` (both want the same "wait for Running, bounded, fail-fast-on-error" semantics).
///
/// We poll `Request::Status` rather than stream the IPN bus: it reuses the existing one-shot
/// round-trip, and the daemon's derived `state` is authoritative. Mirroring Go `wait`'s
/// `checkForInterfaceIP`: in the userspace-netstack default (no OS interface to observe) `Running` +
/// a tailnet IP is the done condition (Go also short-circuits here — "if `!st.TUN` return
/// immediately"); on a `--tun` node we additionally confirm the kernel interface actually carries the
/// tailnet IP before returning (via [`tun_interface_has_ip`]), so a script chaining off `tnet up
/// --tun --timeout N` doesn't proceed before the address is usable.
async fn wait_for_running(socket: &std::path::Path, timeout_secs: Option<u64>) -> Result<()> {
    // `None` or `0` → wait forever (Go's "0 means wait indefinitely").
    let deadline = match timeout_secs {
        Some(secs) if secs > 0 => {
            Some(tokio::time::Instant::now() + std::time::Duration::from_secs(secs))
        }
        _ => None,
    };
    loop {
        // A failed round-trip (daemon not up yet / socket missing) is NOT fatal — keep waiting, like
        // Go's backoff loop while tailscaled comes up. The per-poll meaning is decided by the pure
        // `wait_decision`: a terminal registration error fails fast (the engine won't retry — the
        // analogue of Go surfacing a backend error promptly rather than burning the whole timeout;
        // bead tsd-lr6), `Running` succeeds, everything else keeps waiting until the deadline. The
        // failure reason is control-influenced, so sanitize it at the bail site (the decision fn
        // stays a pure classifier returning the raw reason — same split as `classify_auth`).
        if let Ok(Response::Status(s)) = round_trip(socket, &Request::Status).await {
            match wait_decision(&s) {
                WaitStep::Done => return Ok(()),
                // TUN mode: the node is Running with a tailnet IP, but Go `wait` also requires the
                // kernel interface to actually carry that IP before returning. Done once it does;
                // otherwise keep polling (the OS may take a moment to apply the address after the
                // engine reports Running).
                WaitStep::AwaitInterfaceIp(ip) => {
                    if tun_interface_has_ip(&ip) {
                        return Ok(());
                    }
                }
                WaitStep::Failed(reason) => {
                    anyhow::bail!("node registration failed: {}", sanitize_multiline(&reason))
                }
                WaitStep::Keep => {}
            }
        }
        if let Some(deadline) = deadline
            && tokio::time::Instant::now() >= deadline
        {
            anyhow::bail!(
                "timed out waiting for the node to reach Running (waited {}s)",
                timeout_secs.unwrap_or(0)
            );
        }
        tokio::time::sleep(WAIT_POLL_INTERVAL).await;
    }
}

/// The per-poll decision [`wait_for_running`] makes from a single [`StatusReport`]. Split out as a
/// pure function ([`wait_decision`]) so the precedence — Running wins over a terminal error, a
/// terminal error fails fast, everything else (incl. a transient `auth_url`) keeps waiting — is
/// unit-testable without a live socket.
#[derive(Debug, PartialEq, Eq)]
enum WaitStep {
    /// The node reached `Running` with a tailnet IP — the wait succeeded.
    Done,
    /// The node reached `Running` with a tailnet IP **and is in TUN mode**, so — mirroring Go
    /// `wait`'s `checkForInterfaceIP` — the wait is not done until the kernel TUN interface actually
    /// carries that IP. Carries the self tailnet IPv4 to look for on the OS interfaces. The impure
    /// [`wait_for_running`] performs the interface check (kept out of this pure classifier); when the
    /// IP is present it is `Done`, otherwise it keeps polling. (Netstack-mode nodes never reach this
    /// arm — they short-circuit to [`Done`](WaitStep::Done), exactly as Go returns early when `!st.TUN`.)
    AwaitInterfaceIp(String),
    /// A terminal registration failure, carrying control's **raw** reason (the caller sanitizes it
    /// at the print/bail site, like [`classify_auth`]). Fail fast; the engine will not retry, so
    /// waiting longer is futile.
    Failed(String),
    /// Nothing actionable yet — keep polling until the deadline. Covers both "not up yet" and a
    /// pending interactive login (`auth_url` set, which is transient, not a failure).
    Keep,
}

/// Decide what a single poll's [`StatusReport`] means for [`wait_for_running`]. **Pure** (no I/O), so
/// the precedence is unit-testable: a `Running` node with a tailnet IP short-circuits FIRST (a
/// Running node never carries a terminal error) — to [`Done`](WaitStep::Done) in netstack mode, or to
/// [`AwaitInterfaceIp`](WaitStep::AwaitInterfaceIp) in TUN mode (Go `wait` then confirms the kernel
/// interface carries the IP). Otherwise a `Some(error)` is a terminal failure
/// ([`Failed`](WaitStep::Failed), the raw reason — the caller sanitizes); otherwise — including a
/// pending `auth_url` (interactive login is transient, not a failure) — we [`Keep`](WaitStep::Keep)
/// waiting.
fn wait_decision(s: &tailscaled_rs::localapi::StatusReport) -> WaitStep {
    if s.state == "Running"
        && let Some(ip) = s.self_ipv4.as_deref()
    {
        // TUN mode: not done until the OS interface carries the IP (Go's `checkForInterfaceIP`); the
        // impure caller does the interface check. Netstack mode (the default, no kernel iface to
        // observe): done immediately, exactly as Go returns early on `!st.TUN`.
        return if s.prefs.tun {
            WaitStep::AwaitInterfaceIp(ip.to_string())
        } else {
            WaitStep::Done
        };
    }
    if let Some(reason) = s.error.as_deref() {
        return WaitStep::Failed(reason.to_string());
    }
    WaitStep::Keep
}

/// Whether the tailnet IP `want` is currently assigned to some non-loopback OS interface — the
/// daemon-side analogue of Go `wait`'s `checkForInterfaceIP`, used to confirm a `--tun` node's kernel
/// interface actually carries its tailnet address before [`wait_for_running`] returns. Enumerates the
/// host interfaces via `if_addrs` (the same crate the link monitor uses). A failure to enumerate, or
/// an unparseable `want`, reads as "not yet present" (keep waiting) rather than a spurious success —
/// the wait then relies on the timeout, never returning before the IP is observed.
fn tun_interface_has_ip(want: &str) -> bool {
    let Ok(want) = want.parse::<std::net::IpAddr>() else {
        return false;
    };
    match if_addrs::get_if_addrs() {
        Ok(ifaces) => ifaces
            .into_iter()
            .map(|i| i.ip())
            .any(|ip| !ip.is_loopback() && ip == want),
        Err(e) => {
            // Don't treat an enumeration error as "ready" — that would return before the iface holds
            // the addr. Log once per poll and keep waiting (the next poll retries; the deadline bounds).
            tracing::debug!(error = %e, "wait: failed to enumerate interfaces; treating IP as not-yet-present");
            false
        }
    }
}

/// Maximum time to wait, after an interactive `up`, for the control auth URL to appear. Measured
/// against the real control plane, the engine takes ~10s to register, be told "needs auth", and
/// propagate `DeviceState::NeedsLogin(url)`, so a too-short poll silently misses it; 20s gives
/// comfortable margin while still bounding a `tnet up` that will never get a URL (e.g. offline).
const AUTH_URL_POLL: std::time::Duration = std::time::Duration::from_secs(20);
/// Interval between `status` polls while waiting for the auth URL.
const AUTH_URL_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);

/// The outcome of an interactive-`up` poll, distinguishing the three terminal cases the caller must
/// render differently: a login URL arrived, registration *terminally failed*, or nothing actionable
/// surfaced before the deadline.
enum AuthOutcome {
    /// The control auth URL the operator must visit to authorize the node.
    Url(String),
    /// Registration hard-failed (terminal `error`); the reason is control's Display string. The
    /// operator must re-authenticate with a fresh key — re-running with the same one loops forever.
    Failed(String),
    /// Nothing to prompt: the node authorized instantly (pre-approved / `Running`) or no URL/error
    /// appeared before the deadline. The operator can re-run `tnet status`.
    None,
}

/// Classify a single [`StatusReport`] into an [`AuthOutcome`]. Pure (no I/O) so the bail logic is
/// unit-testable. Precedence: a terminal `error` wins over everything (it is the permanent state),
/// then a pending `auth_url`, then a node already past login (`Running`); otherwise keep waiting.
fn classify_auth(s: &tailscaled_rs::localapi::StatusReport) -> AuthOutcome {
    // Terminal failure is checked first: if both somehow co-occur, the permanent error must win
    // over a stale/pending URL (re-running with the same key would loop forever).
    if let Some(reason) = s.error.as_deref() {
        return AuthOutcome::Failed(reason.to_owned());
    }
    if let Some(url) = s.auth_url.as_deref() {
        return AuthOutcome::Url(url.to_owned());
    }
    // Already past NeedsLogin (authorized / running) — nothing to prompt.
    AuthOutcome::None
}

/// After an interactive (authkey-less) `up`, poll `status` for up to [`AUTH_URL_POLL`] to surface
/// either the control auth URL or a terminal registration failure. The engine reaches
/// `NeedsLogin(url)` ~10s after registration begins, so we wait a generous 20s for a URL; but a
/// permanent failure (`error`) short-circuits immediately — there is no point dwelling the full
/// window for a login that will never help. If the node authorizes instantly (pre-approved) or
/// never needs login, returns [`AuthOutcome::None`] and the operator can re-run `tnet status`.
///
/// Prints a one-time "contacting…" line on the first poll so an interactive `up` doesn't look
/// frozen during the ~10s the engine needs.
async fn poll_for_auth_url(socket: &std::path::Path) -> AuthOutcome {
    let deadline = tokio::time::Instant::now() + AUTH_URL_POLL;
    let mut announced = false;
    while tokio::time::Instant::now() < deadline {
        if let Ok(Response::Status(s)) = round_trip(socket, &Request::Status).await {
            match classify_auth(&s) {
                // A pending URL or a terminal failure are both decisive — return at once. The
                // failure case is the early-bail: we do NOT keep polling the full window.
                outcome @ (AuthOutcome::Url(_) | AuthOutcome::Failed(_)) => return outcome,
                // Already authorized / running before any URL appeared — nothing to prompt.
                AuthOutcome::None if s.state == "Running" => return AuthOutcome::None,
                // Still in flight (e.g. NoState/Starting and no URL yet) — keep polling.
                AuthOutcome::None => {}
            }
        }
        if !announced {
            announced = true;
            println!("contacting the control server… (run `tnet status` for the latest state)");
        }
        tokio::time::sleep(AUTH_URL_POLL_INTERVAL).await;
    }
    AuthOutcome::None
}

/// Resolve the pre-auth key from the available sources, in precedence order:
/// `--authkey-file` > `--authkey`/`--auth-key` > `$TS_AUTH_KEY`. Returns the secret wrapped so it is
/// zeroized on drop and kept out of any debug/log output; `None` means no key was supplied
/// (interactive login). `--authkey` and `--authkey-file` are mutually exclusive at the clap layer.
///
/// A `--authkey`/`--auth-key` value beginning with `file:` is a PATH to the key rather than the key
/// itself (Go `up.go` `resolveValueFromFile`, reached through `upArgsT.getAuthKey`), so the key can
/// stay out of argv and shell history under Go's own spelling. Only the flag value is resolved that
/// way, matching Go, which never applies the prefix to anything but the flag.
async fn resolve_authkey(
    authkey: Option<String>,
    authkey_file: Option<PathBuf>,
) -> Result<Option<SecretString>> {
    if let Some(path) = authkey_file {
        return Ok(Some(read_secret_file(&path, "auth key").await?));
    }
    if let Some(key) = authkey {
        if let Some(path) = key.strip_prefix("file:") {
            return Ok(Some(read_secret_file(path, "auth key").await?));
        }
        return Ok(Some(SecretString::from(key)));
    }
    // Fall back to the env var (read manually rather than via clap `env` so it never surfaces in
    // `--help` and so the precedence above stays explicit).
    match std::env::var(AUTHKEY_ENV) {
        Ok(key) if !key.is_empty() => Ok(Some(SecretString::from(key))),
        _ => Ok(None),
    }
}

/// Resolve a secret-bearing CLI value that may be either the literal secret or a `file:PATH`
/// reference (Go's `--client-secret`/`--id-token` convention: a value beginning with `file:` is a
/// path to a file containing the secret, so the secret never lands in argv / shell history). Returns
/// the secret wrapped in a [`SecretString`] (zeroized on drop, never logged). A bare value is taken
/// verbatim; a `file:` value is read from disk with leading/trailing whitespace trimmed (`str::trim`,
/// matching Go's `strings.TrimSpace` on a `file:` secret — so `echo > secret` and a CRLF file both
/// work without smuggling whitespace into the secret). `None` in → `None` out. Mirrors the
/// `--authkey-file` handling in [`resolve_authkey`].
async fn read_secret_arg(value: Option<String>) -> Result<Option<SecretString>> {
    let Some(v) = value else { return Ok(None) };
    if let Some(path) = v.strip_prefix("file:") {
        return Ok(Some(read_secret_file(path, "secret").await?));
    }
    Ok(Some(SecretString::from(v)))
}

/// Read a secret out of `path`, wrapped so it is zeroized on drop and never `Debug`-printed.
/// Surrounding whitespace is trimmed (Go's `strings.TrimSpace` on a `file:` value), so a here-doc,
/// `echo > key` or a CRLF file works without smuggling whitespace into the secret. `what` names the
/// secret in the error context (`reading auth key from …`). Async for consistency with the rest of
/// the CLI's I/O.
async fn read_secret_file(path: impl AsRef<std::path::Path>, what: &str) -> Result<SecretString> {
    let path = path.as_ref();
    let contents = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("reading {what} from {}", path.display()))?;
    Ok(SecretString::from(contents.trim().to_owned()))
}

/// The workload-identity-federation / OAuth registration flags (`tnet up
/// --client-id/--client-secret/--id-token/--audience`), bundled so they thread through `run_up` as
/// one parameter rather than four more positional args. `client_id`/`audience` are non-secret
/// identifiers; `client_secret`/`id_token` are secrets (held in [`SecretString`]). All four are
/// registration-time-only and never persisted as prefs — they ride the same one-shot channel as the
/// auth key.
/// The Go pref flags `tailscale up` shares with `tailscale set` (`up.go` `newUpFlagSet`), already
/// resolved from their CLI flag pairs into the wire sentinels. Grouped into one named value — the
/// same shape as [`WifFlags`] — so [`run_up`]'s already-long positional list does not grow four more
/// interchangeable `Option<bool>`s that a transposition could silently swap.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct UpPrefFlags {
    /// `--operator <user>` / `--operator=` (clear). `None` = flag absent = leave unchanged.
    operator: Option<Option<String>>,
    /// `--exit-node-allow-lan-access` / `--no-exit-node-allow-lan-access`.
    exit_node_allow_lan_access: Option<bool>,
    /// `--advertise-connector` / `--no-advertise-connector`.
    advertise_connector: Option<bool>,
    /// `--report-posture` / `--no-report-posture`.
    report_posture: Option<bool>,
}

/// The Go `up` flag spellings this CLI carries on the parser with **no pref behind them**, so a
/// command line copied from `tailscale up` reaches an answer that names what happened instead of
/// clap's "unexpected argument" (the same treatment the unmodelled `set` flags get — see
/// [`UnmodelledSetFlags`]). Gated by [`check_ported_up_flags`].
///
/// The other two spellings that batch was about need no struct: `--auth-key` and `--login-server`
/// are Go's names for flags this fork already has, so they are clap aliases of `--authkey` and
/// `--control-url` and behave identically to them, value for value.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct PortedUpFlags {
    /// `--host-routes[=<v>]`, hidden. `None` = absent; `Some("true")` = the flag's presence (Go's
    /// `IsBoolFlag` default); any other value is Go's `notFalseVar` refusal.
    host_routes: Option<String>,
    /// `--nickname <NAME>`, hidden. Carried only to be refused by name: neither this fork's `up`
    /// nor Go's takes a profile name.
    nickname: Option<String>,
}

/// Gate the Go `up` spellings that carry no pref (see [`PortedUpFlags`]). `Ok(())` means the
/// command line asked only for what this build already does, so `up` proceeds unchanged.
///
/// Ordering is Go's: both are decided in the flag parser (`notFalseVar.Set` for `--host-routes`;
/// `--nickname` is simply not in `up`'s flag set), which runs before `runUp` reads the daemon's
/// status or validates any other flag. So this runs before every other `up` check. Pure →
/// unit-testable.
fn check_ported_up_flags(flags: &PortedUpFlags) -> Result<()> {
    // Go's `notFalseVar.Set` rejects every value but "true", and Go's flag package wraps that in
    // `invalid boolean value %q for -host-routes: %v`. Same sentence, this CLI's flag spelling.
    if let Some(value) = flags.host_routes.as_deref()
        && value != "true"
    {
        anyhow::bail!(
            "invalid boolean value {value:?} for --host-routes: unsupported value; only 'true' \
             is allowed"
        );
    }
    if flags.nickname.is_some() {
        anyhow::bail!(
            "--nickname is not a `tnet up` flag, and it is not a `tailscale up` flag upstream \
             either: `up.go` builds one flag set for `up` and `login` and registers `--nickname` \
             only when the command is `login`, so no `up` carries a profile name. This fork's \
             profile naming lives on `tnet set --nickname <NAME>`, which renames the current login \
             profile exactly as Go's `set --nickname` does — run that instead. (Go's other home \
             for it, `login --nickname`, is not implemented here yet.)"
        );
    }
    Ok(())
}

/// The Go pref flags `tailscale set` carries (`set.go` `newSetFlagSet`) beyond the ones this CLI
/// already had — a superset of [`UpPrefFlags`], because Go registers `--webclient`, `--auto-update`
/// and `--update-check` on `set` only, and `--nickname` on `set` and `login` but never on `up`.
/// Resolved and grouped for the same reason.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct SetPrefFlags {
    /// `--advertise-connector` / `--no-advertise-connector` (reaches control; rebuilds a live node).
    advertise_connector: Option<bool>,
    /// `--auto-update` / `--no-auto-update` (reaches control; rebuilds a live node).
    auto_update: Option<bool>,
    /// `--update-check` / `--no-update-check`.
    update_check: Option<bool>,
    /// `--operator <user>` / `--operator=` (clear).
    operator: Option<Option<String>>,
    /// `--nickname <name>` / `--nickname=` (clear).
    nickname: Option<Option<String>>,
    /// `--report-posture` / `--no-report-posture`.
    report_posture: Option<bool>,
    /// `--webclient` / `--no-webclient`.
    webclient: Option<bool>,
    /// `--exit-node-allow-lan-access` / `--no-exit-node-allow-lan-access`.
    exit_node_allow_lan_access: Option<bool>,
}

/// The four Go `tailscale set` pref flags (`set.go` `newSetFlagSet`) this fork carries on the parser
/// but does **not** model as prefs: `--relay-server-port`, `--relay-server-static-endpoints`,
/// `--remote-config` and `--sync`. Grouped like [`SetPrefFlags`] so they thread through `run_set` as
/// one value.
///
/// They exist here so a command line ported from Go reaches a refusal that NAMES what is missing
/// instead of clap's "unexpected argument", the same treatment `serve`'s `--service` / `--tun` /
/// `--proxy-protocol` / `--accept-app-caps` get (see [`check_serve_flags`]). Two of the four are
/// two-valued, and for each of those exactly ONE value asks for a state this daemon is permanently
/// in — relay server disabled, no static endpoints advertised, no remote configuration delegated,
/// configuration synced from control. Those values are accepted as already-satisfied rather than
/// refused, so a ported line that merely turns the feature OFF keeps working; the other value is
/// refused by [`check_unmodelled_set_flags`].
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct UnmodelledSetFlags {
    /// `--relay-server-port <PORT>`; Go types it as a STRING (not a uint) precisely so the empty
    /// value `--relay-server-port=` can mean "disable", distinct from the flag being absent.
    relay_server_port: Option<String>,
    /// `--relay-server-static-endpoints <IP:PORT,…>`; a string for the same reason — the empty
    /// value means "advertise none".
    relay_server_static_endpoints: Option<String>,
    /// `--remote-config` → `Some(true)`, `--no-remote-config` → `Some(false)`, absent → `None`.
    remote_config: Option<bool>,
    /// `--sync` → `Some(true)`, `--no-sync` (Go `--sync=false`) → `Some(false)`, absent → `None`.
    sync: Option<bool>,
}

/// Parse a `--relay-server-port` value the way Go's `runSet` does — `strconv.ParseUint(s, 10, 16)`,
/// so `0` is legal ("pick a random unused port") and anything outside a `uint16` is refused with
/// Go's own `failed to set relay server port: …` prefix. Called only for a NON-empty value: Go's
/// empty string means "disable" and never reaches the parse. Pure → unit-testable.
fn parse_relay_server_port(value: &str) -> Result<u16> {
    // Go's `ParseUint` permits no sign prefix at all, where Rust's `u16::from_str` accepts `+80`.
    // Reject it here so `--relay-server-port=+80` fails the way Go's does rather than parsing.
    if value.starts_with('+') {
        anyhow::bail!("failed to set relay server port: invalid syntax");
    }
    value
        .parse::<u16>()
        .map_err(|e| anyhow::anyhow!("failed to set relay server port: {e}"))
}

/// Parse a `--relay-server-static-endpoints` value the way Go's `runSet` does: split on `,`, parse
/// each entry as a `netip.AddrPort` (so IPv6 must be bracketed — `[2001:db8::1]:40000`), collect
/// into a SET so duplicates collapse, then sort by `netip.AddrPort.Compare`. Called only for a
/// NON-empty value (the empty string means "advertise none"). A bad entry gets Go's own message,
/// `failed to set relay server static endpoints: "…" is not a valid IP:port` — the entry is rendered
/// with `{:?}`, which both matches Go's `%q` quoting and escapes any control characters an
/// adversarial argument might carry. Pure → unit-testable.
fn parse_relay_static_endpoints(value: &str) -> Result<Vec<std::net::SocketAddr>> {
    let mut endpoints: Vec<std::net::SocketAddr> = Vec::new();
    for entry in value.split(',') {
        let addr: std::net::SocketAddr = entry.parse().map_err(|_| {
            anyhow::anyhow!(
                "failed to set relay server static endpoints: {entry:?} is not a valid IP:port"
            )
        })?;
        // Go builds a `set.Set[netip.AddrPort]`, so a repeated endpoint appears once.
        if !endpoints.contains(&addr) {
            endpoints.push(addr);
        }
    }
    endpoints.sort_by_key(relay_endpoint_sort_key);
    Ok(endpoints)
}

/// Sort key reproducing Go's `netip.AddrPort.Compare`: the address's bit length first (so every IPv4
/// endpoint sorts before every IPv6 one), then the address bytes, then the port. Pure.
fn relay_endpoint_sort_key(addr: &std::net::SocketAddr) -> (u8, [u8; 16], u16) {
    match addr.ip() {
        std::net::IpAddr::V4(v4) => {
            let mut bytes = [0u8; 16];
            bytes[..4].copy_from_slice(&v4.octets());
            (0, bytes, addr.port())
        }
        std::net::IpAddr::V6(v6) => (1, v6.octets(), addr.port()),
    }
}

/// Gate the four unmodelled Go `set` pref flags (see [`UnmodelledSetFlags`]): run Go's OWN parsing
/// and its refusals first, then this build's named refusal for whichever value asks for behaviour
/// the daemon does not have. `Ok(())` means every mentioned flag asked only for a state this daemon
/// is permanently in, so `set` proceeds unchanged.
///
/// Ordering is Go's. `runSet` parses `--relay-server-port` and then
/// `--relay-server-static-endpoints` at the very end, after the risk gates, and a parse failure
/// returns before `EditPrefs` — so a malformed value is rejected here before any refusal fires, and
/// nothing is written either way. `--remote-config`/`--sync` have no Go-side validation at all; they
/// are checked last. Pure → unit-testable.
fn check_unmodelled_set_flags(flags: &UnmodelledSetFlags) -> Result<()> {
    // Go: `if setArgs.relayServerPort != ""` — the empty value skips the parse and disables.
    let port = match flags.relay_server_port.as_deref() {
        None | Some("") => None,
        Some(value) => Some(parse_relay_server_port(value)?),
    };
    // Go: `if setArgs.relayServerStaticEndpoints != ""` — likewise.
    let endpoints = match flags.relay_server_static_endpoints.as_deref() {
        None | Some("") => Vec::new(),
        Some(value) => parse_relay_static_endpoints(value)?,
    };

    if let Some(port) = port {
        anyhow::bail!(
            "--relay-server-port={port} is not supported by this build: running a peer relay \
             server needs a UDP relay listener in the engine's magicsock plus a `Hostinfo.PeerRelay` \
             advertisement for THIS node, and the pinned engine has neither — its `Config` carries \
             no relay listen port, and it only READS a peer's relay role. Filed as engine ask #34. \
             Drop the flag, or pass `--relay-server-port=` (disable), which is what this build \
             always does"
        );
    }
    if !endpoints.is_empty() {
        let list = endpoints
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join(",");
        anyhow::bail!(
            "--relay-server-static-endpoints={list} is not supported by this build: static \
             endpoints are candidates advertised BY a peer relay server, and this build runs none \
             (see --relay-server-port); the pinned engine's `Config` carries no static-endpoint \
             list either. Filed as engine ask #34. Drop the flag, or pass \
             `--relay-server-static-endpoints=` (advertise none), which is what this build always \
             does"
        );
    }
    if flags.remote_config == Some(true) {
        anyhow::bail!(
            "--remote-config is not supported by this build, and is not a gap this fork intends to \
             close: it delegates FULL remote control of this node's prefs and LocalAPI to the \
             tailnet admin, bypassing Tailscale's per-feature double opt-in. This daemon's \
             authorization model is local (THREAT_MODEL §4.1) — the control plane is a peer that is \
             not trusted to rewrite prefs or invoke LocalAPI endpoints — so a control-delegated \
             configuration channel is declined by design, not deferred to the engine. \
             `--no-remote-config` (Go's default) is what this build always does"
        );
    }
    if flags.sync == Some(false) {
        anyhow::bail!(
            "--no-sync (Go `--sync=false`) is not supported by this build: it is Go's kill switch \
             for the control-plane configuration sync, there to exercise netmap caching and offline \
             operation, and the pinned engine exposes no way to stop the map poll while the node \
             stays up. Filed as engine ask #34. `--sync` (Go's default) is what this build always \
             does"
        );
    }
    Ok(())
}

/// Map an `--x` / `--no-x` pref flag pair to the tri-state `Option<bool>` the wire uses: enable →
/// `Some(true)`, disable → `Some(false)`, neither → `None` (leave the persisted pref unchanged).
///
/// The general form of the older per-flag resolvers (`resolve_tun`, `resolve_shields_up`,
/// `resolve_ssh`, …), which each open-code this identical match; the flags added since share this
/// one. clap's `conflicts_with` guarantees the two are never both set (and, defensively, `on` wins).
/// Pure → unit-testable.
fn resolve_tristate(on: bool, off: bool) -> Option<bool> {
    match (on, off) {
        (true, _) => Some(true),
        (_, true) => Some(false),
        _ => None,
    }
}

/// Map a string-valued pref flag that Go clears with an EMPTY value (`--operator=`, `--nickname=`,
/// rendered by Go's own `fmtFlagValueArg` as exactly that) onto the daemon's double-`Option`
/// sentinel: flag absent → `None` (leave unchanged), `--flag=` → `Some(None)` (clear the pref),
/// `--flag=v` → `Some(Some(v))` (set it). Pure → unit-testable.
fn resolve_clearable_string(value: Option<String>) -> Option<Option<String>> {
    value.map(|v| if v.is_empty() { None } else { Some(v) })
}

struct WifFlags {
    client_id: Option<String>,
    client_secret: Option<SecretString>,
    id_token: Option<SecretString>,
    audience: Option<String>,
}

/// Resolve the raw `--client-secret`/`--id-token` CLI strings (each possibly `file:PATH`) into
/// [`SecretString`]s and bundle the WIF flags. Also enforces Go's `--id-token` ⇔ `--audience` mutual
/// exclusion (`up.go`: both feed the OIDC-token request, so passing both is ambiguous) before any
/// daemon round-trip. The non-secret `client_id`/`audience` pass through unchanged.
async fn resolve_wif(
    client_id: Option<String>,
    client_secret: Option<String>,
    id_token: Option<String>,
    audience: Option<String>,
) -> Result<WifFlags> {
    if id_token.is_some() && audience.is_some() {
        anyhow::bail!(
            "--id-token and --audience are mutually exclusive (both request an OIDC token)"
        );
    }
    Ok(WifFlags {
        client_id,
        client_secret: read_secret_arg(client_secret).await?,
        id_token: read_secret_arg(id_token).await?,
        audience,
    })
}

/// Send one request, read one newline-delimited JSON response.
async fn round_trip(socket: &std::path::Path, request: &Request) -> Result<Response> {
    let stream = UnixStream::connect(socket)
        .await
        .context("connect (is tailnetd running?)")?;
    let (read_half, mut write_half) = stream.into_split();

    let mut line = serde_json::to_vec(request)?;
    line.push(b'\n');
    write_half.write_all(&line).await?;
    write_half.flush().await?;

    let mut reader = BufReader::new(read_half);
    let mut response_line = String::new();
    reader.read_line(&mut response_line).await?;
    // A zero-byte read leaves the buffer empty: the daemon closed the connection without replying
    // (connection cap hit, or the handler crashed). Surface that plainly instead of falling through
    // to a confusing "parsing daemon response: EOF" from the empty-string parse below.
    if response_line.is_empty() {
        anyhow::bail!(
            "daemon closed the connection without a reply (is it overloaded, or did the request crash it?)"
        );
    }
    let response = serde_json::from_str(response_line.trim())
        .with_context(|| format!("parsing daemon response: {response_line:?}"))?;
    Ok(response)
}

/// HTML-escape a string for safe inclusion in `status --web` page text. Control-server-/peer-supplied
/// values (node/peer names, relay codes, the MagicDNS suffix) flow into the page, so they must never
/// be able to inject markup/script — map the five HTML-significant characters to entities. Pure.
fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Render a [`StatusReport`](tailscaled_rs::localapi::StatusReport) as a self-contained HTML status
/// page — the body `status --web` serves (the analogue of Go `ipnstate.Status.WriteHTML`, faithful in
/// content rather than a byte-copy of Go's template). A header block (state, version, TUN, this node's
/// name + IPs, MagicDNS suffix, active exit node) plus a peer table (name, IPs, online, exit-node,
/// relay, last-seen). Every control-/peer-supplied string is [`html_escape`]d. Pure → unit-testable.
fn render_status_html(
    s: &tailscaled_rs::localapi::StatusReport,
    canonical: Option<&str>,
) -> String {
    let mut h = String::new();
    h.push_str("<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">");
    h.push_str("<title>tailnetd status</title>");
    // The absolute URL this page is served at, when it is known (`web --origin`, or the address the
    // listener bound). Behind a reverse proxy the bound address is not the address anyone reached,
    // which is exactly what `--origin` supplies — so the page states the URL it is really served at
    // instead of leaving a reader to guess. Escaped as an attribute: an origin is operator-supplied,
    // but it lands in markup like every other value on this page.
    if let Some(url) = canonical {
        h.push_str(&format!(
            "<link rel=\"canonical\" href=\"{}\">",
            html_escape(url)
        ));
    }
    h.push_str(
        "<style>body{font-family:system-ui,sans-serif;margin:2rem;}\
         table{border-collapse:collapse;margin-top:1rem;}\
         th,td{border:1px solid #ccc;padding:4px 10px;text-align:left;}\
         th{background:#f4f4f4;}.k{color:#555;}</style></head><body>",
    );
    h.push_str("<h1>tailnetd status</h1>");
    h.push_str("<table>");
    let row = |h: &mut String, k: &str, v: String| {
        h.push_str(&format!("<tr><td class=\"k\">{k}</td><td>{v}</td></tr>"));
    };
    row(&mut h, "state", html_escape(&s.state));
    if let Some(v) = &s.version {
        row(&mut h, "version", html_escape(v));
    }
    row(&mut h, "TUN", s.prefs.tun.to_string());
    if let Some(n) = &s.self_name {
        row(&mut h, "self", html_escape(n));
    }
    let mut ips = Vec::new();
    if let Some(v4) = &s.self_ipv4 {
        ips.push(v4.clone());
    }
    if let Some(v6) = &s.self_ipv6 {
        ips.push(v6.clone());
    }
    if !ips.is_empty() {
        row(&mut h, "addresses", html_escape(&ips.join(", ")));
    }
    if let Some(suffix) = &s.magic_dns_suffix {
        row(&mut h, "magic-dns-suffix", html_escape(suffix));
    }
    if let Some(exit) = &s.active_exit_node {
        row(&mut h, "exit-node", html_escape(exit));
    }
    h.push_str("</table>");

    // Login affordance (Go `tailscale web` LoginServerMode): when the node needs interactive login,
    // surface the auth URL as a clickable link — the ONE action LoginServerMode exposes. This is
    // display-only (a link, NOT a mutating POST): the page does not change any pref, so it stays the
    // faithful read+login face and adds no unauthenticated-mutation surface (the full mutating manage
    // UI is Go's over-Tailscale ManageServerMode, engine-gated here — see ENGINE_ASKS). A terminal
    // registration failure is shown distinctly (it is NOT a pending login; re-running won't help).
    if let Some(url) = &s.auth_url {
        // `rel="noopener noreferrer"` so the opened auth page can't reach back into this origin.
        h.push_str(&format!(
            "<div style=\"margin-top:1rem;padding:12px;border:1px solid #d49b00;background:#fff8e1;\">\
             <strong>This node needs to be authenticated.</strong><br>\
             <a href=\"{href}\" target=\"_blank\" rel=\"noopener noreferrer\">Log in to authenticate this node</a>\
             <br><span class=\"k\">The node finishes connecting automatically once authorized; reload to check.</span>\
             </div>",
            // `auth_url` is control-supplied — escape it as an HTML attribute so it can't break out of
            // the href and inject markup/script.
            href = html_escape(url),
        ));
    } else if let Some(err) = &s.error {
        h.push_str(&format!(
            "<div style=\"margin-top:1rem;padding:12px;border:1px solid #c0392b;background:#fdecea;\">\
             <strong>Registration failed:</strong> {}<br>\
             <span class=\"k\">This is a permanent failure — re-authenticate with a fresh key \
             (`tnet up --authkey &lt;NEW_KEY&gt;`); the same key will keep failing.</span></div>",
            html_escape(err),
        ));
    }

    h.push_str(&format!("<h2>peers ({})</h2>", s.peers.len()));
    if s.peers.is_empty() {
        h.push_str("<p>no peers</p>");
    } else {
        h.push_str(
            "<table><tr><th>name</th><th>ipv4</th><th>ipv6</th><th>online</th>\
             <th>exit-node</th><th>relay</th><th>last-seen</th></tr>",
        );
        for p in &s.peers {
            let online = match p.online {
                Some(true) => "yes",
                Some(false) => "no",
                None => "?",
            };
            h.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                html_escape(&p.name),
                html_escape(&p.ipv4),
                html_escape(p.ipv6.as_deref().unwrap_or("")),
                online,
                if p.is_exit_node { "yes" } else { "" },
                html_escape(p.relay.as_deref().unwrap_or("")),
                html_escape(p.last_seen.as_deref().unwrap_or("")),
            ));
        }
        h.push_str("</table>");
    }
    h.push_str("</body></html>");
    h
}

/// Parse the method + target from an HTTP request line (`GET / HTTP/1.1`) → `(method, path)`. Returns
/// `None` for a malformed line (fewer than the two leading tokens). Pure → unit-testable; the
/// `status --web` serve loop routes only the exact path `/`.
fn parse_request_target(request_line: &str) -> Option<(&str, &str)> {
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?;
    let path = parts.next()?;
    Some((method, path))
}

/// Max concurrent in-flight `status --web` connection handlers. Defense-in-depth against a connection
/// flood: each accepted connection spawns a detached handler, so without a cap a flood of clients
/// could spawn handlers (and leak fds) without bound. The per-handler 5s read-deadline already bounds
/// a *slow* client; this bounds the COUNT. At cap a new connection is dropped (shed, not queued).
/// This is a local diagnostic server (default `127.0.0.1`), so 64 is far above normal single-user use.
const MAX_WEB_CONNECTIONS: usize = 64;

/// Normalize a `--prefix` value into the single URL path the web server serves at: `/` (empty/`"/"`)
/// or `/<prefix>` with exactly one leading slash and no trailing slash — so `--prefix /tailscale`,
/// `tailscale`, and `/tailscale/` all serve `/tailscale`. Pure → unit-testable.
fn normalize_served_path(path_prefix: &str) -> String {
    let trimmed = path_prefix.trim().trim_matches('/');
    if trimmed.is_empty() {
        "/".to_string()
    } else {
        format!("/{trimmed}")
    }
}

/// Where `tnet web` listens when `--listen` is not given: Go `web`'s `localhost:8088`. Loopback, so
/// the unauthenticated status page is not reachable from the network by default.
const DEFAULT_WEB_LISTEN: &str = "localhost:8088";

/// The body served for any path other than the one the UI is mounted at. Shared by both serving
/// modes (listener and `--cgi`) so they cannot drift.
const WEB_NOT_FOUND_BODY: &str = "<!DOCTYPE html><html><body>not found</body></html>";

/// The body served when the daemon round-trip for the page's status fails. Deliberately generic —
/// the cause is logged to stderr, not handed to whoever loaded the page.
const WEB_UNAVAILABLE_BODY: &str = "<!DOCTYPE html><html><body>status unavailable</body></html>";

/// The refusal `tnet web` owes its own flags before it binds anything or contacts the daemon, or
/// `None` when the invocation is usable.
///
/// `--cgi` replaces the listener entirely: the process serves ONE request out of the CGI/1.1
/// environment and exits, so there is no address to bind and `--listen` names a listener that will
/// never exist. Go registers both flags on the same command and simply ignores the listen address in
/// CGI mode; this fork refuses the combination instead, the same shape (and the same wording) it
/// already uses for `cert --listen` without `--serve-demo`, so an operator who thinks they are
/// choosing a port is told the port is not used rather than silently getting no listener.
///
/// The message goes to **stdout** and the caller exits **1**, matching this CLI's other usage
/// refusals ([`switch_usage_refusal`], [`cert_usage_refusal`]) rather than clap's stderr + exit 2 —
/// which is why this is a hand-rolled check and not an `#[arg(conflicts_with = ...)]`. Pure →
/// unit-testable.
fn web_usage_refusal(cgi: bool, has_listen: bool) -> Option<&'static str> {
    if cgi && has_listen {
        return Some("--listen can only be used without --cgi (a CGI script binds no listener)");
    }
    None
}

/// Validate + normalize a `web --origin` value into the base URL the UI is reached at, or the
/// refusal explaining why it is not one.
///
/// Go's `--origin` ("origin at which the web UI is served (if behind a reverse proxy or used with
/// cgi)") feeds the web server's origin override, which exists because the address the UI *bound* is
/// not the address a browser *reached* it at. So the value has to be an absolute URL: a scheme and a
/// host are exactly the two things `--prefix` cannot supply. A port and a path are optional (a proxy
/// that mounts the UI under a path names it here); a query, a fragment or userinfo are not — those
/// belong to a request, not to the base URL a page is served at, and silently dropping them would
/// emit links that differ from what was asked for.
///
/// Normalization is: keep the scheme, the host and an explicit non-default port, drop a trailing
/// slash from the path. So `https://ts.example.com/tailscale/` and `https://ts.example.com/tailscale`
/// are the same origin. Pure → unit-testable.
fn parse_web_origin(origin: &str) -> Result<String, String> {
    let raw = origin.trim();
    if raw.is_empty() {
        return Err(
            "--origin needs an absolute URL, e.g. https://ts.example.com/tailscale".to_string(),
        );
    }
    let parsed = url::Url::parse(raw)
        .map_err(|e| format!("--origin {raw:?} is not an absolute URL: {e}"))?;
    match parsed.scheme() {
        "http" | "https" => {}
        other => {
            return Err(format!(
                "--origin {raw:?} has scheme {other:?}; the web UI is reached over http or https"
            ));
        }
    }
    let Some(host) = parsed.host_str() else {
        return Err(format!("--origin {raw:?} names no host"));
    };
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(format!(
            "--origin {raw:?} carries a query or fragment; it names the base URL the UI is served \
             at, not one request to it"
        ));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(format!(
            "--origin {raw:?} carries credentials; it names the base URL the UI is served at"
        ));
    }
    let mut base = format!("{}://{host}", parsed.scheme());
    if let Some(port) = parsed.port() {
        base.push_str(&format!(":{port}"));
    }
    base.push_str(parsed.path().trim_end_matches('/'));
    Ok(base)
}

/// Split a [`parse_web_origin`] base into `(scheme://authority, path)` — the path is `""` when the
/// origin names only a scheme and a host. Pure → unit-testable via [`web_ui_url`].
fn split_origin_base(base: &str) -> (&str, &str) {
    let after_scheme = match base.find("://") {
        Some(i) => i + 3,
        None => return (base, ""),
    };
    match base[after_scheme..].find('/') {
        Some(j) => base.split_at(after_scheme + j),
        None => (base, ""),
    }
}

/// The absolute URL this UI is reached at — the one thing `--origin` exists to fix, and the only
/// thing it can affect in this build (the UI is read-only, so an origin gates no request and
/// authorizes nothing; it generates links).
///
/// - With `--origin`, that URL wins. An origin that already names a path (`https://ts.example.com/tailscale`)
///   states the OUTSIDE path in full and is used verbatim: `--prefix` names the path this process
///   answers on, which a proxy is free to map from a different one, so appending it would invent a
///   path nobody serves. An origin that names only scheme+host takes the served path from `--prefix`,
///   which is the pass-through case.
/// - Without `--origin`, the URL is `http://<bound address>` plus the served path — what the previous
///   behaviour always assumed.
/// - With neither an origin nor a bound address (`--cgi` without `--origin`), the URL is genuinely
///   unknown: a CGI script is told the path it was reached at but not the scheme or host the proxy
///   in front of it published. `None`, rather than a guess.
///
/// Pure → unit-testable.
fn web_ui_url(origin: Option<&str>, bound: Option<&str>, served_path: &str) -> Option<String> {
    let (authority, path) = match origin {
        Some(base) => {
            let (authority, origin_path) = split_origin_base(base);
            if !origin_path.is_empty() {
                return Some(base.to_string());
            }
            (authority.to_string(), served_path)
        }
        None => (format!("http://{}", bound?), served_path),
    };
    Some(if path == "/" {
        authority
    } else {
        format!("{authority}{path}")
    })
}

/// What the web UI answers a request with. The read-only page has exactly one route, so this is the
/// whole routing table — shared by the listener and `--cgi` so the two modes cannot answer the same
/// request differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WebRoute {
    /// A fresh `status` fetch, rendered as the HTML page.
    Page,
    /// Anything else: another path, or a method other than `GET`.
    NotFound,
}

/// Route one request: the status page is served at the configured path (`/` by default, `/<prefix>`
/// with `--prefix`) for `GET` only; everything else is a 404. Pure → unit-testable.
fn route_web_request(method: &str, path: &str, served_path: &str) -> WebRoute {
    if method == "GET" && path == served_path {
        WebRoute::Page
    } else {
        WebRoute::NotFound
    }
}

/// The request path a CGI invocation was reached at, from the CGI/1.1 environment. Go's
/// `net/http/cgi` builds the request URL from `REQUEST_URI` when the server supplied it and falls
/// back to `SCRIPT_NAME` + `PATH_INFO` otherwise; this follows the same order, and strips the query
/// string (the read-only page takes no parameters). An environment that carries none of the three
/// yields `/`. Pure → unit-testable.
fn cgi_request_path(
    request_uri: Option<&str>,
    script_name: Option<&str>,
    path_info: Option<&str>,
) -> String {
    let path = match request_uri.map(str::trim).filter(|u| !u.is_empty()) {
        Some(uri) => uri.split('?').next().unwrap_or("").to_string(),
        None => format!(
            "{}{}",
            script_name.unwrap_or_default(),
            path_info.unwrap_or_default()
        ),
    };
    if path.is_empty() {
        "/".to_string()
    } else {
        path
    }
}

/// Serialize one CGI response: the `Status:` line Go's `net/http/cgi` child writer always emits,
/// the content type, an explicit length, then the body after a blank line. Not an HTTP response —
/// the invoking web server turns these headers into one. Pure → unit-testable.
fn cgi_response(status: &str, body: &str) -> String {
    format!(
        "Status: {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
}

/// `tnet web` (Go `tailscale web`): resolve the flags, then serve the read-only status UI in
/// whichever of the two modes was asked for.
///
/// Order is load-bearing: the usage refusal first (it costs nothing and must not be reached only
/// after a bind), then the `--origin` validation (a bad origin is a usage error, not a serving
/// failure), then the mode split. `--cgi` serves exactly one request on stdout and returns; the
/// default binds a listener and runs until interrupted.
async fn run_web(
    socket: &std::path::Path,
    listen: Option<String>,
    prefix: String,
    browser: bool,
    cgi: bool,
    origin: Option<&str>,
) -> Result<()> {
    if let Some(message) = web_usage_refusal(cgi, listen.is_some()) {
        println!("{message}");
        std::process::exit(1);
    }
    let origin = match origin {
        Some(raw) => Some(parse_web_origin(raw).map_err(|e| anyhow::anyhow!(e))?),
        None => None,
    };
    if cgi {
        // CGI mode owns stdout: the response IS this process's stdout, so nothing may be printed
        // alongside it (no startup line) and no browser is opened (there is no server to browse).
        // Without `--origin` there is no way to know the scheme/host the proxy published, so the
        // page states no canonical URL rather than a wrong one.
        let served_path = normalize_served_path(&prefix);
        let canonical = web_ui_url(origin.as_deref(), None, &served_path);
        return run_web_cgi(socket, &served_path, canonical.as_deref()).await;
    }
    let listen = listen.unwrap_or_else(|| DEFAULT_WEB_LISTEN.to_string());
    run_status_web(socket, &listen, browser, &prefix, origin.as_deref())
        .await
        .with_context(|| format!("serving web UI on {listen}"))
}

/// `tnet web --cgi` (Go `web --cgi` → `cgi.Serve`): serve ONE request from the CGI/1.1 environment
/// and exit, instead of binding a listener. The web server in front of us set `REQUEST_METHOD` and
/// the request path; we route it exactly as the listener does ([`route_web_request`]), fetch the
/// live status for the page, and write the CGI response to stdout.
///
/// Errors are reported the way a CGI script must report them — as a response, not as a message on
/// stdout: a failed daemon round-trip becomes a `500` whose cause goes to stderr (which the invoking
/// server logs). The process still exits 0, because the response was delivered.
async fn run_web_cgi(
    socket: &std::path::Path,
    served_path: &str,
    canonical: Option<&str>,
) -> Result<()> {
    use std::io::Write as _;
    let method = std::env::var("REQUEST_METHOD").unwrap_or_default();
    let request_uri = std::env::var("REQUEST_URI").ok();
    let script_name = std::env::var("SCRIPT_NAME").ok();
    let path_info = std::env::var("PATH_INFO").ok();
    let path = cgi_request_path(
        request_uri.as_deref(),
        script_name.as_deref(),
        path_info.as_deref(),
    );
    let (status, body) = match route_web_request(&method, &path, served_path) {
        WebRoute::Page => match round_trip(socket, &Request::Status).await {
            Ok(Response::Status(s)) => ("200 OK", render_status_html(&s, canonical)),
            other => {
                if let Err(e) = other {
                    eprintln!("web --cgi: status fetch failed: {e}");
                }
                (
                    "500 Internal Server Error",
                    WEB_UNAVAILABLE_BODY.to_string(),
                )
            }
        },
        WebRoute::NotFound => ("404 Not Found", WEB_NOT_FOUND_BODY.to_string()),
    };
    let response = cgi_response(status, &body);
    let mut out = std::io::stdout().lock();
    out.write_all(response.as_bytes())
        .context("writing the CGI response to stdout")?;
    out.flush().context("flushing the CGI response")?;
    Ok(())
}

/// `tnet status --web`: serve an HTML status page from an embedded HTTP server (Go `tailscale status
/// --web`). Binds a TCP listener on `listen` (default `127.0.0.1:8384`), optionally opens a browser at
/// the URL, then accepts connections until interrupted: each request re-fetches the live status
/// ([`Request::Status`]) and, for `GET /`, replies `200 text/html` with [`render_status_html`]; any
/// other path is a `404`. Reuses the existing daemon read — no new daemon/engine surface.
///
/// Each connection is handled on its own detached task, bounded by a [`Semaphore`](tokio::sync::Semaphore)
/// cap ([`MAX_WEB_CONNECTIONS`]) so a flood can't leak handler tasks/fds without bound (the count
/// bound; the per-handler 5s read-deadline is the slow-client bound).
async fn run_status_web(
    socket: &std::path::Path,
    listen: &str,
    browser: bool,
    path_prefix: &str,
    origin: Option<&str>,
) -> Result<()> {
    let served_path = normalize_served_path(path_prefix);
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .with_context(|| format!("binding the status web server to {listen}"))?;
    let addr = listener
        .local_addr()
        .context("resolving the listen address")?;
    // The status page has no authentication (matching Go's `tailscale status --web`). On the default
    // 127.0.0.1 bind that's fine; if the operator widened it, warn that the tailnet topology (node
    // name, IPs, peers) is now reachable by anyone who can hit this address.
    if !addr.ip().is_loopback() {
        eprintln!(
            "warning: serving status on {addr}, which is reachable beyond localhost and has NO \
             authentication — this node's name, tailnet IPs, and peer topology are exposed to \
             anyone who can reach this address."
        );
    }
    // The browseable URL includes the path prefix (so `--prefix /foo` opens `http://addr/foo`), and
    // `--origin` replaces the bound address with the one a browser actually reaches — so behind a
    // reverse proxy the operator is told (and the browser is sent to) the URL that works, not the
    // private address this process happens to have bound. Always `Some` here: the address is bound.
    let url = web_ui_url(origin, Some(&addr.to_string()), &served_path)
        .unwrap_or_else(|| format!("http://{addr}"));
    println!("Serving Tailscale status at {url} ... (Ctrl-C to stop)");
    if browser {
        open_browser_best_effort(&url);
    }
    // Cap concurrent connection handlers; a permit is held for a handler's whole lifetime. Defense-in-
    // depth against a flood (the count bound — the 5s read-deadline in the handler is the slow-client
    // bound). At cap, a new connection is dropped (shed, not queued).
    let conn_limit = std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_WEB_CONNECTIONS));
    loop {
        let (conn, _peer) = match listener.accept().await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("status --web: accept failed: {e}");
                continue;
            }
        };
        // Acquire a handler permit BEFORE spawning; if the cap is exhausted, drop the connection
        // (closing it) rather than spawning unboundedly. Moved into the task, released when it ends.
        let Ok(permit) = std::sync::Arc::clone(&conn_limit).try_acquire_owned() else {
            eprintln!("status --web: connection cap reached; dropping connection");
            continue;
        };
        // Handle each connection on its own task. Go's `http.Serve` is goroutine-per-connection, so a
        // single slow or silent client can't head-of-line-block every other status request; the read
        // deadline inside the handler is what actually bounds a stalled client.
        let socket = socket.to_path_buf();
        let served_path = served_path.clone();
        let canonical = url.clone();
        tokio::spawn(async move {
            let _permit = permit;
            serve_status_connection(conn, &socket, &served_path, Some(&canonical)).await;
        });
    }
}

/// Serve one HTTP/1.1 connection for the `status --web` server: read the request line, route `GET /`
/// to a fresh status fetch, write the response, and close. Best-effort throughout — any read/write
/// error or timeout just drops the connection (this is a diagnostic server, not a hardened endpoint).
///
/// The request-line read is bounded in BOTH bytes (8 KiB cap) and time (a 5s deadline): TCP can split
/// the line across segments so a single read isn't enough, but a client that dribbles or never sends
/// must not park the task forever.
async fn serve_status_connection(
    mut conn: tokio::net::TcpStream,
    socket: &std::path::Path,
    served_path: &str,
    canonical: Option<&str>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    let read_line = async {
        loop {
            let n = conn.read(&mut chunk).await?;
            if n == 0 {
                break; // EOF before a full line — treat as no request.
            }
            buf.extend_from_slice(&chunk[..n]);
            // Stop once we have the end of the request line, or cap buffering from a hostile client.
            if buf.contains(&b'\n') || buf.len() >= 8192 {
                break;
            }
        }
        Ok::<(), std::io::Error>(())
    };
    match tokio::time::timeout(std::time::Duration::from_secs(5), read_line).await {
        Ok(Ok(())) => {}
        // Timed out, or a read error: drop the connection silently.
        _ => return,
    }
    if buf.is_empty() {
        return;
    }
    let request_line = String::from_utf8_lossy(&buf);
    let first_line = request_line.lines().next().unwrap_or("");
    // The status page is served at the configured path (default `/`, or `/<prefix>` when `--prefix`
    // is given) for `GET`. Any other request → 404. The routing decision is shared with `--cgi`
    // ([`route_web_request`]) so the two serving modes cannot answer the same request differently.
    let route = match parse_request_target(first_line) {
        Some((method, path)) => route_web_request(method, path, served_path),
        None => WebRoute::NotFound,
    };
    let (status, body) = match route {
        WebRoute::Page => match round_trip(socket, &Request::Status).await {
            Ok(Response::Status(s)) => ("200 OK", render_status_html(&s, canonical)),
            // Both the wrong-variant and the error case collapse to a 500; on a real error, log the
            // cause first so the failure isn't swallowed (the page itself stays generic).
            other => {
                if let Err(e) = other {
                    eprintln!("status --web: status fetch failed: {e}");
                }
                (
                    "500 Internal Server Error",
                    WEB_UNAVAILABLE_BODY.to_string(),
                )
            }
        },
        WebRoute::NotFound => ("404 Not Found", WEB_NOT_FOUND_BODY.to_string()),
    };
    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = conn.write_all(resp.as_bytes()).await;
    let _ = conn.flush().await;
}

/// Best-effort open `url` in the OS browser (macOS `open`, Linux `xdg-open`). Never fatal — a failure
/// (no browser, headless host) is logged and ignored; the served URL was already printed.
fn open_browser_best_effort(url: &str) {
    #[cfg(target_os = "macos")]
    let prog = "open";
    #[cfg(not(target_os = "macos"))]
    let prog = "xdg-open";
    if let Err(e) = std::process::Command::new(prog).arg(url).spawn() {
        eprintln!("(could not open a browser via `{prog}`: {e} — open {url} manually)");
    }
}

/// `tnet nc <host> <port>`: open a connection through the daemon and pipe stdin/stdout over it.
///
/// Protocol: send `Request::Nc`, read ONE ack line — `Ok` means the overlay connection is live (the
/// daemon has switched that socket into raw splice mode), `Error` means the connect failed (printed +
/// exit 1, the connection was never hijacked). On `Ok`, copy concurrently in both directions until
/// EOF: local stdin → socket (→ peer) and socket (← peer) → local stdout. A clean EOF on either side
/// ends the session (exit 0).
async fn run_nc(socket: &std::path::Path, host: &str, port: u16) -> Result<()> {
    let stream = UnixStream::connect(socket)
        .await
        .context("connect (is tailnetd running?)")?;
    let (read_half, mut write_half) = stream.into_split();

    // Send the nc request line.
    let mut line = serde_json::to_vec(&Request::Nc {
        host: host.to_string(),
        port,
    })?;
    line.push(b'\n');
    write_half.write_all(&line).await?;
    write_half.flush().await?;

    // Read exactly the one-line ack (the daemon writes nothing more before we send, so the BufReader
    // holds no peer payload past the newline — any subsequent bytes are the peer's, read below).
    let mut reader = BufReader::new(read_half);
    let mut ack = String::new();
    reader.read_line(&mut ack).await?;
    match serde_json::from_str::<Response>(ack.trim())
        .with_context(|| format!("parsing nc ack: {ack:?}"))?
    {
        Response::Ok { .. } => {} // connection live — proceed to pipe
        Response::Error { message } => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        other => anyhow::bail!("unexpected nc ack: {other:?}"),
    }

    // Splice local stdio <-> the socket. stdin → socket (→ peer); socket (← peer) → stdout. Run both
    // until EOF; the first side to close ends its copy, and we return once both finish.
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let stdin_to_peer = async {
        let r = tokio::io::copy(&mut stdin, &mut write_half).await;
        let _ = write_half.shutdown().await; // half-close so the peer sees our EOF
        r
    };
    let peer_to_stdout = async {
        let r = tokio::io::copy(&mut reader, &mut stdout).await;
        let _ = stdout.flush().await;
        r
    };
    let (_s2p, _p2s) = tokio::join!(stdin_to_peer, peer_to_stdout);
    Ok(())
}

/// `tnet ssh [user@]<host> [args...]` (Go `tailscale ssh`): resolve the peer + its advertised SSH host
/// keys via the daemon status, write a pinned `ssh_known_hosts`, then exec the system `ssh` with a
/// `ProxyCommand` that tunnels over the tailnet through `tnet nc`.
///
/// Faithful to Go's `runSSH`:
/// - Split `[user@]host` on the first `@`; an absent `user@` leaves the username UNSET, so `ssh`
///   applies the caller's own `ssh_config` `User` directive (upstream v1.102.3).
/// - Resolve `host` against the netmap (`Status`): match a peer by MagicDNS/display name OR tailnet
///   IP. The SSH destination host is the peer's display name (its DNSName) so the host-key line keyed
///   by that name matches; if it has none we fall back to its IPv4.
/// - Write `<config-dir>/tailscale/ssh_known_hosts` (dir `0700`, file `0644`) from the peer's
///   `ssh_host_keys` — one `<host> <key>` line per (host identifier × key), where host identifiers are
///   the peer's name and each of its tailnet IPs (Go's `genKnownHosts`).
/// - Exec `ssh` with `-o UpdateHostKeys no`, `-o StrictHostKeyChecking yes`,
///   `-o CanonicalizeHostname no`, `-o UserKnownHostsFile <file>`, and `-o ProxyCommand <tnet> [--socket
///   <s>] nc %h %p` (our own binary's `nc`), then the destination — `user@host` when the target
///   supplied a username, else the bare `host` — and the passthrough args.
///
/// Returns an error on a resolution/setup failure; on success it never returns (it `exec`s, replacing
/// this process with `ssh`). Requires the system `ssh` binary on `PATH`.
async fn run_ssh(
    socket: &std::path::Path,
    explicit_socket: Option<&std::path::Path>,
    target: &str,
    extra_args: &[String],
) -> Result<()> {
    use std::os::unix::process::CommandExt as _;

    // 1. Parse `[user@]host` (see `split_ssh_target`): an absent `user@` leaves the username unset.
    let (user, host) = split_ssh_target(target)?;

    // 2. Resolve the peer against the netmap. Fetch Status (not whois — that is IP-only) so a NAME
    //    also resolves, mirroring `ip <peer>` / Go's `peerStatusFromArg`.
    let status = match round_trip(socket, &Request::Status).await {
        Ok(Response::Status(s)) => s,
        Ok(Response::Error { message }) => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        Ok(other) => anyhow::bail!("unexpected response to status request: {other:?}"),
        Err(e) => {
            return Err(e).with_context(|| format!("querying status at {}", socket.display()));
        }
    };
    let peer = match status
        .peers
        .iter()
        .find(|p| p.name == host || p.ipv4 == host || p.ipv6.as_deref() == Some(host.as_str()))
    {
        Some(p) => p,
        None => {
            eprintln!("ssh: no peer matching {host:?} in the current netmap (run `tnet status`)");
            std::process::exit(1);
        }
    };

    // 3. Build the pinned known_hosts from the peer's advertised SSH host keys. Without them we cannot
    //    pin the host key; rather than silently downgrade to a TOFU prompt (a weaker posture than Go's
    //    StrictHostKeyChecking=yes), refuse — the operator gets a clear reason. (A peer that does not
    //    run Tailscale SSH simply has none; `tnet ssh` to it is not meaningful.)
    if peer.ssh_host_keys.is_empty() {
        eprintln!(
            "ssh: peer {host:?} advertises no SSH host keys (it is not running Tailscale SSH, or \
             control has not provisioned them) — cannot verify the host key, refusing to connect"
        );
        std::process::exit(1);
    }
    // The SSH destination host: prefer the peer's display name (its DNSName — the host-key line keyed
    // by it then matches), else fall back to its IPv4. Either way the known_hosts carries lines for
    // BOTH the name and the IPs, so the match holds regardless.
    let ssh_host = if peer.name.is_empty() {
        peer.ipv4.clone()
    } else {
        peer.name.clone()
    };
    let known_hosts_path =
        write_ssh_known_hosts(peer).context("writing the pinned ssh_known_hosts file")?;

    // 4. Locate the system `ssh` binary. We exec it (replacing this process) so the user gets a normal
    //    interactive ssh session with the terminal wired straight through.
    let ssh_bin = find_ssh().context("locating the system `ssh` binary")?;

    // 5. The ProxyCommand tunnels the TCP stream over the tailnet via our OWN binary's `nc`
    //    subcommand. `%h`/`%p` are ssh's host/port tokens. Re-pass `--socket` only when the user set a
    //    non-default one (so the tunnel hits the same daemon), matching Go's conditional `socketArg`.
    let self_exe =
        std::env::current_exe().context("resolving the running `tnet` executable path")?;
    let self_exe = self_exe.to_string_lossy();
    let proxy_command = match explicit_socket {
        // Bind the socket value to the flag with `=` (Go's `--socket=%q` form) so it is a SINGLE shell
        // token after ssh splits the ProxyCommand — the value can never be seen as a separate
        // argument, even before the inner `tnet` re-parses it. (The value is also `shell_quote`d, so
        // this is belt-and-suspenders.)
        Some(s) => format!(
            "ProxyCommand {} --socket={} nc %h %p",
            shell_quote(&self_exe),
            shell_quote(&s.to_string_lossy())
        ),
        None => format!("ProxyCommand {} nc %h %p", shell_quote(&self_exe)),
    };

    // 6. Build the ssh argv (Go's exact `-o` set) and exec.
    let mut cmd = std::process::Command::new(&ssh_bin);
    cmd.arg("-o").arg("UpdateHostKeys no");
    cmd.arg("-o").arg("StrictHostKeyChecking yes");
    // Per Go (tailscale/tailscale#10348): keep ssh from canonicalizing the MagicDNS name, which would
    // turn it into something the known_hosts line is not keyed by.
    cmd.arg("-o").arg("CanonicalizeHostname no");
    cmd.arg("-o")
        .arg(format!("UserKnownHostsFile {}", known_hosts_path.display()));
    cmd.arg("-o").arg(proxy_command);
    cmd.arg(ssh_destination(user.as_deref(), &ssh_host));
    cmd.args(extra_args);

    // exec replaces this process; it only returns on failure (e.g. ssh binary vanished between the
    // find and the exec). A returned value is therefore always an error.
    let err = cmd.exec();
    Err(anyhow::Error::from(err).context(format!("exec {}", ssh_bin.display())))
}

/// Split `tnet ssh`'s `[user@]host` target into an optional username and the host, on the FIRST `@`
/// (Go `strings.Cut`).
///
/// A target with no `user@` carries NO username: since upstream v1.102.3 `tailscale ssh host` hands
/// `ssh` the bare host, so the caller's own `ssh_config` (`Host` block, `User` directive) decides who
/// to log in as. Reading the local account and splicing it in — what this did before — silently
/// overrode that, and only for tailnet hosts.
///
/// Errors on an empty host (nothing to resolve) and on an empty or unsafe explicit username.
fn split_ssh_target(target: &str) -> Result<(Option<String>, String)> {
    let (user, host) = match target.split_once('@') {
        Some((u, h)) => (Some(u.to_string()), h.to_string()),
        None => (None, target.to_string()),
    };
    if host.is_empty() {
        anyhow::bail!("ssh: empty host in target {target:?} (expected `[user@]host`)");
    }
    if let Some(user) = &user {
        if user.is_empty() {
            anyhow::bail!(
                "ssh: empty user in target {target:?} (use `host` to let your ssh_config decide)"
            );
        }
        // SECURITY: an explicit username becomes the left half of the `user@host` argv element handed
        // to `ssh`. A username that LEADS WITH `-` would make `user@host` parse as an ssh option
        // (getopt flag injection — e.g. `-oProxyCommand=…@host` overrides the tunnel), and
        // whitespace/`@` would split or malform the destination. That half is argv the caller controls,
        // so guard it. Reject rather than sanitize — a `-`-leading or whitespace username is operator
        // error, and silently rewriting it would surprise. (The host half cannot lead with `-` because
        // `user@` is always prefixed; it is resolved against the netmap, not taken raw.)
        if user.starts_with('-') || user.contains([' ', '\t', '\n', '\r', '@']) {
            anyhow::bail!(
                "ssh: refusing unsafe username {user:?} (leads with '-' or contains whitespace/@) — \
                 pass an explicit `user@host` with a valid username"
            );
        }
    }
    Ok((user, host))
}

/// The `ssh` destination argv element: `user@host` when the target supplied a username, else the bare
/// host so `ssh` resolves the user from the caller's `ssh_config` (upstream v1.102.3).
fn ssh_destination(user: Option<&str>, ssh_host: &str) -> String {
    match user {
        Some(u) => format!("{u}@{ssh_host}"),
        None => ssh_host.to_string(),
    }
}

/// Locate the system `ssh` binary by scanning `$PATH` (Go's `findSSH` via `exec.LookPath`). Returns the
/// first executable `ssh` found, else an error naming the miss so the operator can install/adjust PATH.
fn find_ssh() -> Result<std::path::PathBuf> {
    let path = std::env::var_os("PATH").context("PATH is not set, cannot locate `ssh`")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join("ssh");
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    anyhow::bail!("could not find an `ssh` binary on PATH; install OpenSSH to use `tnet ssh`")
}

/// Write the peer's advertised SSH host keys to `<config-dir>/tailscale/ssh_known_hosts` (Go's
/// `writeKnownHosts`): dir created `0700`, file written `0644`. Returns the file path for ssh's
/// `UserKnownHostsFile`. The file content is built by [`render_known_hosts`] (pure, tested).
fn write_ssh_known_hosts(peer: &tailscaled_rs::localapi::PeerReport) -> Result<std::path::PathBuf> {
    use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};

    let dir = ssh_conf_dir().context("resolving the tailscale config directory")?;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)
        .with_context(|| format!("creating {}", dir.display()))?;
    let path = dir.join("ssh_known_hosts");
    let content = render_known_hosts(peer);
    // Write 0644 (world-readable host keys are not secret — they are public keys, and ssh reads the
    // file as the invoking user). Truncate+rewrite each run so a stale peer's keys never linger.
    use std::io::Write as _;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644)
        .open(&path)
        .with_context(|| format!("opening {}", path.display()))?;
    f.write_all(content.as_bytes())
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

/// The directory for the daemon's per-user config files (`<config-dir>/tailscale`), mirroring Go's
/// `tsConfDir` (the OS user-config dir joined with `tailscale`). Used for `ssh_known_hosts`.
fn ssh_conf_dir() -> Result<std::path::PathBuf> {
    // XDG_CONFIG_HOME, else ~/.config (Linux), else $HOME/Library/Application Support (macOS-ish) —
    // but keep it simple + cross-platform: XDG_CONFIG_HOME or $HOME/.config, then /tailscale.
    let base = if let Some(x) = std::env::var_os("XDG_CONFIG_HOME").filter(|s| !s.is_empty()) {
        std::path::PathBuf::from(x)
    } else if let Some(h) = std::env::var_os("HOME").filter(|s| !s.is_empty()) {
        std::path::PathBuf::from(h).join(".config")
    } else {
        anyhow::bail!("neither XDG_CONFIG_HOME nor HOME is set; cannot place ssh_known_hosts");
    };
    Ok(base.join("tailscale"))
}

/// Build the `ssh_known_hosts` content for `peer` (Go's `genKnownHosts`): for each advertised host key,
/// emit a `<host> <key>` line for the peer's name AND each of its tailnet IPs. Keys containing a
/// newline/carriage-return are skipped (a control-supplied key must not forge extra lines — the same
/// injection-class guard the structured CLI output uses). Pure → unit-testable.
fn render_known_hosts(peer: &tailscaled_rs::localapi::PeerReport) -> String {
    // Host identifiers: the display name (when non-empty) + every tailnet IP we know.
    //
    // SECURITY: the host field is control-supplied (peer.name derives from the wire Node.name, which
    // this fork — unlike Go talking to Tailscale's sanitizing coordination server — accepts verbatim
    // from arbitrary/self-hosted control). A name containing a newline could forge an extra
    // known_hosts line (e.g. a `*` wildcard pinning an attacker key), and a space/tab would split the
    // line into a bogus host token; a leading `#` would turn the line into a comment. So the host
    // identifier is guarded EXACTLY like the key below — a known_hosts host token must contain no
    // whitespace/CR/LF and not lead with `#`. The IPs are typed (`IpAddr` → always numeric) and so are
    // inherently safe, but we run them through the same `is_safe_known_hosts_host` gate uniformly. A
    // peer whose name is unsafe simply contributes no name-keyed line (its IP lines still work).
    fn is_safe_known_hosts_host(h: &str) -> bool {
        !h.is_empty() && !h.starts_with('#') && !h.contains([' ', '\t', '\n', '\r'])
    }
    let mut hosts: Vec<&str> = Vec::new();
    if is_safe_known_hosts_host(&peer.name) {
        hosts.push(peer.name.as_str());
    }
    if is_safe_known_hosts_host(&peer.ipv4) {
        hosts.push(peer.ipv4.as_str());
    }
    if let Some(v6) = peer.ipv6.as_deref().filter(|s| is_safe_known_hosts_host(s)) {
        hosts.push(v6);
    }
    let mut out = String::new();
    for key in &peer.ssh_host_keys {
        let key = key.trim();
        // Skip a key that would break the one-line-per-entry format (CR/LF injection guard).
        if key.is_empty() || key.contains('\n') || key.contains('\r') {
            continue;
        }
        for host in &hosts {
            out.push_str(host);
            out.push(' ');
            out.push_str(key);
            out.push('\n');
        }
    }
    out
}

/// Minimal POSIX single-quote shell-quoting for an ssh `-o ProxyCommand` token (the value is passed to
/// ssh, which re-parses it with a shell). Wrap in single quotes and escape any embedded single quote as
/// `'\''`. Our inputs are a binary path + a socket path, but quoting keeps a space/quote in either from
/// breaking the ProxyCommand.
fn shell_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

/// Normalize a `serve --tcp` forward target: a bare port `5000` → `127.0.0.1:5000`; a `host:port`
/// passes through. Mirrors Go's `ExpandProxyTargetValue(target, ["tcp"], "tcp")` host extraction.
fn normalize_serve_target(target: &str) -> String {
    if target.parse::<u16>().is_ok() {
        format!("127.0.0.1:{target}")
    } else {
        target.to_string()
    }
}

/// The redirect placeholder `to` carries, if it carries one this build cannot honour.
///
/// `serve redirect` sends its target verbatim: the engine's `serve_redirect` writes one fixed
/// response for every request on the port and never parses the request, so there is no per-request
/// value to substitute. `${HOST}` and `${REQUEST_URI}` were documented as expanded and never were —
/// a target holding either redirects the client to a URL with those literal characters in it. Catch
/// it where the config is authored instead of serving the broken `Location:`.
fn unexpanded_redirect_var(to: &str) -> Option<&'static str> {
    ["${HOST}", "${REQUEST_URI}"]
        .into_iter()
        .find(|placeholder| to.contains(placeholder))
}

/// Clean a `--set-path` mount point, faithful to Go `serve`'s `cleanURLPath`: empty → `/`; ensure a
/// leading `/`; `path.Clean`; accept only if the cleaned form equals the (slash-prefixed) input or
/// that input with a single trailing slash (so `/foo/` is allowed but `/foo/../bar` / `//foo` are
/// rejected). Returns the mount string or an "invalid mount point" error.
fn clean_url_path(url_path: &str) -> Result<String> {
    if url_path.is_empty() {
        return Ok("/".to_string());
    }
    let with_slash = if url_path.starts_with('/') {
        url_path.to_string()
    } else {
        format!("/{url_path}")
    };
    let cleaned = clean_path(&with_slash);
    if with_slash == cleaned || with_slash == format!("{cleaned}/") {
        Ok(with_slash)
    } else {
        anyhow::bail!("invalid mount point {with_slash:?}")
    }
}

/// Minimal `path.Clean` for absolute URL paths (lexical): resolve `.`/`..`, collapse `//`, no trailing
/// slash except the root. Matches Go `path.Clean` for the absolute-path inputs `clean_url_path` feeds
/// it (always starts with `/`).
fn clean_path(p: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    for seg in p.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            s => out.push(s),
        }
    }
    format!("/{}", out.join("/"))
}

/// The path suffix shown in a `serving …` line: empty for the default `/` mount, else the mount.
fn mount_suffix(set_path: &Option<String>) -> String {
    match set_path.as_deref() {
        None | Some("") | Some("/") => String::new(),
        Some(m) => clean_url_path(m).unwrap_or_else(|_| m.to_string()),
    }
}

/// Build a [`TcpPortHandler`](tailscaled_rs::localapi::TcpPortHandler) for a `serve https`/`http` web
/// entry and insert it into `cfg` at `port`, replacing any existing handler on that port. `target` is
/// either `text:<body>` (a fixed-body handler) or a proxy backend (`host:port` / bare port). When
/// `set_path` names a non-root mount, the handler is stored as a path mount (so multiple mounts can
/// coexist on the port); otherwise it is the bare web handler. `tls` selects `https` (true) vs `http`.
/// The existing web handlers on a port, as a mount map — migrating a **bare root** handler (a `text`
/// body or an `https`/`http` proxy `tcp_forward`) into a `/` mount so it survives when a new
/// `--set-path` mount is added to the same port (Go `SetWebHandler` accretes; the root is the `/`
/// handler). Returns the port's existing `mounts` as-is when it already is a mux. A non-web handler
/// (plain TCP forward / TLS-terminated) yields no web mounts.
/// The existing Go-`Web`-map handlers for `host:port`, MIGRATING any legacy per-handler bodies
/// (text/redirect/mounts/tcp_forward on the `TcpPortHandler`) into the equivalent `HttpHandler` map
/// so root + path mounts ACCRETE across `tnet serve` calls (Go `SetWebHandler` keeps both on the
/// port's `WebServerConfig.Handlers`). Prefers an already-present `Web[host:port]` entry; else folds a
/// legacy handler's bodies into a `/`-keyed (or per-mount) `HttpHandler` map. Empty when the port has
/// no web entry yet.
fn existing_web_handlers(
    cfg: &tailscaled_rs::localapi::ServeConfig,
    host: &str,
    port: u16,
) -> std::collections::BTreeMap<String, tailscaled_rs::localapi::HttpHandler> {
    use tailscaled_rs::localapi::{HttpHandler, WebMount};
    let hostport = format!("{host}:{port}");
    // Already migrated to the Web map → reuse it.
    if let Some(wsc) = cfg.web.get(&hostport) {
        return wsc.handlers.clone();
    }
    // Else migrate the legacy per-handler bodies on this port.
    let mut handlers = std::collections::BTreeMap::new();
    let Some(h) = cfg.tcp.get(&port.to_string()) else {
        return handlers;
    };
    let mount_to_handler = |m: &WebMount| match m {
        WebMount::Proxy { to } => HttpHandler {
            proxy: to.clone(),
            ..Default::default()
        },
        WebMount::Text { body } => HttpHandler {
            text: body.clone(),
            ..Default::default()
        },
        WebMount::Redirect { to, status } => HttpHandler {
            redirect: format!("{status}:{to}"),
            ..Default::default()
        },
    };
    if !h.mounts.is_empty() {
        for (mount, m) in &h.mounts {
            handlers.insert(mount.clone(), mount_to_handler(m));
        }
    } else if let Some(body) = &h.text {
        handlers.insert(
            "/".to_string(),
            HttpHandler {
                text: body.clone(),
                ..Default::default()
            },
        );
    } else if let Some(r) = &h.redirect {
        handlers.insert(
            "/".to_string(),
            HttpHandler {
                redirect: format!("{}:{}", r.status, r.to),
                ..Default::default()
            },
        );
    } else if (h.https || h.http) && !h.tcp_forward.is_empty() {
        handlers.insert(
            "/".to_string(),
            HttpHandler {
                proxy: h.tcp_forward.clone(),
                ..Default::default()
            },
        );
    }
    handlers
}

/// Build a web serve into Go's top-level `Web` map (Go `SetWebHandler`): set `TCP[port]={HTTPS|HTTP}`
/// (a flag pointing at `Web`, NO body on the handler) and write the handler under
/// `Web["{host}:{port}"].Handlers[mount]`. `host` is the node's MagicDNS name (resolved by the caller
/// from `status`). Root + path mounts accrete via [`existing_web_handlers`] (migrating any legacy
/// bodies on the way). A lone `/` mount stays a bare handler set; a `--set-path` adds a mux entry.
fn build_web_serve(
    mut cfg: tailscaled_rs::localapi::ServeConfig,
    host: &str,
    port: u16,
    target: &str,
    set_path: Option<&str>,
    tls: bool,
) -> Result<tailscaled_rs::localapi::ServeConfig> {
    use tailscaled_rs::localapi::{HttpHandler, TcpPortHandler, WebServerConfig};

    // Resolve `--set-path` to a cleaned mount; None / "/" mean the root.
    let mount = match set_path {
        None | Some("") | Some("/") => "/".to_string(),
        Some(m) => clean_url_path(m)?,
    };

    // Parse the target: `text:<body>` → a text handler; anything else → a proxy backend.
    let is_text = target.strip_prefix("text:");
    if let Some(body) = is_text
        && body.is_empty()
    {
        anyhow::bail!("unable to serve; text cannot be an empty string");
    }
    let entry = match is_text {
        Some(body) => HttpHandler {
            text: body.to_string(),
            ..Default::default()
        },
        None => HttpHandler {
            proxy: normalize_serve_target(target),
            ..Default::default()
        },
    };

    // Accrete onto the port's existing handlers (migrating any legacy bodies), then add/replace ours.
    let mut handlers = existing_web_handlers(&cfg, host, port);
    handlers.insert(mount, entry);

    // The port handler is just the HTTPS/HTTP flag (Go shape); the body lives in the Web map.
    cfg.tcp.insert(
        port.to_string(),
        TcpPortHandler {
            https: tls,
            http: !tls,
            ..Default::default()
        },
    );
    cfg.web
        .insert(format!("{host}:{port}"), WebServerConfig { handlers });
    Ok(cfg)
}

/// Drive `tnet serve <sub>`: `tcp`/`https`/`http`/`redirect` and `reset` read-modify-write the
/// ServeConfig (GET → mutate → SET); `status` GETs + renders. The ServeConfig is replaced wholesale on
/// SET (matching Go's SetServeConfig), so each set first fetches the current config and adds its entry.
/// Resolve the node's MagicDNS name (the `host` part of a Go `Web` key, and the shared TLS cert
/// name) by querying `status`. A web serve needs it before the node has a name yet — fail with a
/// clear message rather than authoring a `Web` key with an empty/placeholder host. Mirrors
/// `run_funnel`'s resolution.
async fn serve_host(socket: &std::path::Path) -> Result<String> {
    let status = match round_trip(socket, &Request::Status).await {
        Ok(Response::Status(s)) => s,
        Ok(other) => anyhow::bail!("unexpected response to status request: {other:?}"),
        Err(e) => return Err(e).context("querying status"),
    };
    match status.self_name.as_deref().filter(|h| !h.is_empty()) {
        Some(h) => Ok(h.trim_end_matches('.').to_string()),
        None => anyhow::bail!(
            "no MagicDNS name yet (state: {}); bring the node up before configuring a web serve",
            status.state
        ),
    }
}

/// Fetch the daemon's current [`ServeConfig`](tailscaled_rs::localapi::ServeConfig). `GetServeConfig`
/// is read-only and always replies `ServeConfig`, so anything else is a protocol error. Every
/// mutating serve/funnel path starts here: `SetServeConfig` replaces the config wholesale (matching
/// Go's `SetServeConfig`), so each set is a read-modify-write of the whole document.
async fn get_serve_config(
    socket: &std::path::Path,
) -> Result<tailscaled_rs::localapi::ServeConfig> {
    match round_trip(socket, &Request::GetServeConfig).await {
        Ok(Response::ServeConfig(c)) => Ok(c),
        Ok(other) => anyhow::bail!("unexpected response to get serve config: {other:?}"),
        Err(e) => Err(e).context("getting serve config"),
    }
}

/// Render `serve status` / `funnel status` (Go aliases each other — one ServeConfig backs both).
async fn run_serve_status(socket: &std::path::Path, json: bool) -> Result<()> {
    let cfg = get_serve_config(socket).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&cfg)?);
    } else {
        print!("{}", format_serve_status(&cfg, false));
    }
    Ok(())
}

/// Clear the whole serve config (`serve reset` / `funnel reset` — Go aliases, same single document).
async fn run_serve_reset(socket: &std::path::Path) -> Result<()> {
    send_ok_or_die(
        socket,
        Request::SetServeConfig {
            config: tailscaled_rs::localapi::ServeConfig::default(),
        },
    )
    .await?;
    println!("serve config cleared");
    Ok(())
}

/// Which listener a flag-grammar `serve`/`funnel` names, i.e. which of Go's four mutually exclusive
/// port flags was given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServeKind {
    /// `--https=PORT`: TLS terminated for the node's MagicDNS name, then reverse-proxied.
    Https,
    /// `--http=PORT`: plaintext HTTP, reverse-proxied.
    Http,
    /// `--tcp=PORT`: raw TCP splice, no TLS (the daemon's own accept loop).
    Tcp,
    /// `--tls-terminated-tcp=PORT`: TLS terminated, then the plaintext spliced as raw TCP.
    TlsTerminatedTcp,
    /// `--tun`: Go's `serveTypeTUN`, a port-less fifth serve type that forwards ALL traffic for a
    /// Service to the local machine. Modelled here for the same reason Go models it — it is one of
    /// the mutually exclusive listener choices — but never written: Go itself refuses it without
    /// `--service` (`tun mode is only supported for services`), and this build has no Services.
    Tun,
}

impl ServeKind {
    /// Whether this listener is an HTTP(S) web serve — the two kinds that take `--set-path`, a
    /// `text:` target and the `Web[host:port]` handler map.
    fn is_web(self) -> bool {
        matches!(self, ServeKind::Https | ServeKind::Http)
    }
}

/// Resolve the mutually exclusive listener flags into `(kind, port)` exactly as `serve_v2.go`'s
/// `srvTypeAndPortFromFlags` does, applying Go's default: with none of them given, `serve`/`funnel`
/// mean `--https=443`.
///
/// Go counts a port flag as given only when its value is NON-ZERO (`for k, v := range sourceMap { if
/// v != 0 { … } }`), because its flags are plain `uint`s whose zero value IS "unset". So
/// `serve --https=0 3000` contributes nothing, leaves the count at zero, and serves HTTPS on 443 —
/// it is not an error. `--tun` is Go's fifth, port-less type and counts in the same exclusivity
/// check, which is why the pair `--tun --https=443` is refused here rather than by clap.
fn serve_kind_and_port(flags: &ServeFlags) -> Result<(ServeKind, u16)> {
    let mut given: Vec<(ServeKind, u16)> = [
        (ServeKind::Https, flags.https),
        (ServeKind::Http, flags.http),
        (ServeKind::Tcp, flags.tcp),
        (ServeKind::TlsTerminatedTcp, flags.tls_terminated_tcp),
    ]
    .into_iter()
    .filter_map(|(kind, port)| port.filter(|p| *p != 0).map(|p| (kind, p)))
    .collect();
    if flags.tun {
        given.push((ServeKind::Tun, 0));
    }
    match given.as_slice() {
        [] => Ok((ServeKind::Https, 443)),
        [(kind, port)] => Ok((*kind, *port)),
        _ => anyhow::bail!(
            "cannot serve multiple types for a single mount point: give exactly one of --https / \
             --http / --tcp / --tls-terminated-tcp / --tun (they name the same listener)"
        ),
    }
}

/// Go's `--bg` default: unset means the FOREGROUND, except with `--service`, where Go flips the
/// default to the background (`if !e.bg.IsSet { e.bg.Value = forService }`). An explicit `--bg=false`
/// stays false either way, which is the only way to reach Go's background-mode refusal below.
fn serve_background(flags: &ServeFlags) -> bool {
    flags.bg.unwrap_or(flags.service.is_some())
}

/// Whether `cap` matches Go's `validAppCap` regexp `^([\pL\pN-]+\.)+[\pL\pN-]+\/[\pL\pN-/]+$`:
/// a `{domain}/{name}` app capability whose domain is a fully qualified name of two or more labels
/// drawn from letters, numbers and hyphens, and whose name may also contain forward slashes.
fn is_valid_app_cap(cap: &str) -> bool {
    let label_char = |c: char| c.is_alphabetic() || c.is_numeric() || c == '-';
    // The domain half has no slash, so the FIRST slash is the separator and everything after it is
    // the (slash-bearing) name.
    let Some((domain, name)) = cap.split_once('/') else {
        return false;
    };
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2
        || labels
            .iter()
            .any(|l| !l.chars().all(label_char) || l.is_empty())
    {
        return false;
    }
    !name.is_empty() && name.chars().all(|c| label_char(c) || c == '/')
}

/// Parse `--accept-app-caps` the way Go's `acceptAppCapsFlag.Set` does: every occurrence is a
/// comma-separated list, each element is trimmed and validated against the `{domain}/{name}` form,
/// and repeats append to one list. An empty value contributes nothing (Go returns early on `""`),
/// so `--accept-app-caps=` asks for no capabilities rather than for an unsupported feature.
fn parse_accept_app_caps(values: &[String]) -> Result<Vec<String>> {
    let mut caps = Vec::new();
    for value in values {
        if value.is_empty() {
            continue;
        }
        for cap in value.split(',') {
            let cap = cap.trim();
            if !is_valid_app_cap(cap) {
                anyhow::bail!(
                    "{:?} does not match the form {{domain}}/{{name}}, where domain must be a \
                     fully qualified domain name",
                    sanitize_for_terminal(cap)
                );
            }
            caps.push(cap.to_string());
        }
    }
    Ok(caps)
}

/// Validate a `serve`/`funnel` flag set and resolve its listener, running `serve_v2.go`'s own checks
/// in `serve_v2.go`'s order before any of this build's "not supported" refusals.
///
/// The ordering is the point. Go rejects plenty of these command lines itself — a `--service` funnel,
/// a `--proxy-protocol` on HTTP(S), a version that is neither 1 nor 2, a `--tun` without a service —
/// and a port of the flag has to bring those refusals with it, in Go's words, or a script that Go
/// told exactly what was wrong gets told instead that the whole feature is missing here. Only a
/// command line Go would have ACCEPTED reaches a "not supported by this build" message, which then
/// names the specific missing capability rather than degrading to a serve that silently lacks the
/// requested property.
fn check_serve_flags(flags: &ServeFlags, funnel: bool) -> Result<(ServeKind, u16)> {
    // Go validates --accept-app-caps inside the flag's `Set`, i.e. before every other check.
    let app_caps = parse_accept_app_caps(&flags.accept_app_caps)?;

    if let Some(service) = &flags.service {
        if funnel {
            anyhow::bail!("--service flag is not supported with funnel");
        }
        if !serve_background(flags) {
            anyhow::bail!("--service flag is only compatible with background mode");
        }
        anyhow::bail!(
            "--service={} is not supported by this build: Tailscale Services (VIP) are a control \
             plane + netmap feature the pinned engine does not surface, and this LocalAPI \
             ServeConfig carries no `Services` map to write. Serve on the node itself instead \
             (drop --service)",
            sanitize_for_terminal(service)
        );
    }

    let (kind, port) = serve_kind_and_port(flags)?;

    // Go's `uint` zero is "unset", so --proxy-protocol=0 asks for nothing and is not refused.
    let proxy_protocol = flags.proxy_protocol.filter(|v| *v != 0);
    if let Some(version) = proxy_protocol {
        if kind.is_web() {
            anyhow::bail!("PROXY protocol is only supported for TCP forwarding, not HTTP/HTTPS");
        }
        if version != 1 && version != 2 {
            anyhow::bail!("invalid PROXY protocol version {version}; must be 1 or 2");
        }
    }

    if kind == ServeKind::Tun {
        // Go: `!forService && srvType == serveTypeTUN`. --service is refused above, so this is the
        // only --tun outcome a tnet command line can reach, and it is Go's own.
        anyhow::bail!("tun mode is only supported for services");
    }

    if let Some(version) = proxy_protocol {
        anyhow::bail!(
            "--proxy-protocol={version} is not supported by this build: the engine's TCP serve \
             target cannot emit a PROXY-protocol header, and the daemon fails such a config closed \
             rather than handing the backend an unmarked stream it would attribute to the wrong \
             client. Drop --proxy-protocol"
        );
    }
    if !app_caps.is_empty() {
        anyhow::bail!(
            "--accept-app-caps={} is not supported by this build: the serve lanes forward no \
             capability headers to the backend, so the flag would promise an authorization signal \
             that never arrives. Drop --accept-app-caps",
            app_caps.join(",")
        );
    }
    Ok((kind, port))
}

/// Strip a `tcp://` scheme from a raw-TCP serve target, then normalize it the usual way (bare port →
/// `127.0.0.1:<port>`). Go's `ExpandProxyTargetValue` accepts `tcp://host:port` for `--tcp` /
/// `--tls-terminated-tcp`; the stored `TCPForward` is always the bare `host:port`.
fn normalize_tcp_serve_target(target: &str) -> String {
    normalize_serve_target(target.strip_prefix("tcp://").unwrap_or(target))
}

/// Drop every trace of a tailnet port from the serve config: its `TCP[port]` handler, any
/// `Web[host:port]` body, and any `AllowFunnel[host:port]` key. Used by `serve … off`.
///
/// The `Web`/`AllowFunnel` keys are matched by `:port` suffix across any host, the same rule
/// `port_is_web_serve`/`web_proxy_backend` use (one node has one MagicDNS name, and the stored key
/// may predate a rename). Returns whether anything was actually removed, so the caller can tell the
/// operator that the port was already clear rather than printing a misleading "removed".
fn remove_serve_port(cfg: &mut tailscaled_rs::localapi::ServeConfig, port: u16) -> bool {
    let suffix = format!(":{port}");
    let had_tcp = cfg.tcp.remove(&port.to_string()).is_some();
    let web_before = cfg.web.len();
    cfg.web.retain(|k, _| !k.ends_with(&suffix));
    let funnel_before = cfg.allow_funnel.len();
    cfg.allow_funnel.retain(|k, _| !k.ends_with(&suffix));
    had_tcp || cfg.web.len() != web_before || cfg.allow_funnel.len() != funnel_before
}

/// Hold a FOREGROUND `serve`/`funnel` open until the operator interrupts it, then put `previous`
/// back — the CLI half of Go's default (non-`--bg`) serve.
///
/// DEVIATION from Go, and the reason this build's foreground mode is the weaker of the two: Go ties
/// a foreground serve to the CLI's IPN-bus watch session, so the *daemon* drops the config the
/// instant the CLI's connection goes away — even on `SIGKILL` or a lost SSH session. This build has
/// no such session, so the restore runs from the CLI's own signal handler: `SIGINT`/`SIGTERM` are
/// honored, but a `SIGKILL`ed (or crashed) `tnet` leaves the serve installed. `tnet serve reset`
/// clears it.
async fn hold_foreground_serve(
    socket: &std::path::Path,
    previous: tailscaled_rs::localapi::ServeConfig,
) -> Result<()> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut sigint = signal(SignalKind::interrupt()).context("installing the SIGINT handler")?;
    let mut sigterm = signal(SignalKind::terminate()).context("installing the SIGTERM handler")?;
    println!("Press Ctrl-C to stop serving and restore the previous serve config.");
    tokio::select! {
        _ = sigint.recv() => {}
        _ = sigterm.recv() => {}
    }
    // The shell echoes `^C` without a newline; start the teardown report on its own line.
    eprintln!();
    send_ok_or_die(socket, Request::SetServeConfig { config: previous }).await?;
    println!("serve stopped; previous serve config restored");
    Ok(())
}

/// Drive the Go v1.100.0 flag grammar for `serve` and `funnel`: `tnet <serve|funnel> [flags]
/// <target> [off]`. `funnel` is the same code path plus the `AllowFunnel` toggle, exactly as Go
/// shares `serve_v2.go` between the two commands.
///
/// The literal `off` in either positional removes the entry for the named port. For `serve` that
/// clears the port outright (handler, web body and any funnel key — a funnel with no serve behind it
/// exposes nothing); for `funnel` it only switches the public ingress off and LEAVES the serve, so
/// `funnel --https=443 off` is the exact inverse of turning it on and the tailnet-internal serve
/// survives.
async fn run_serve_v2(socket: &std::path::Path, flags: ServeFlags, funnel: bool) -> Result<()> {
    let (kind, port) = check_serve_flags(&flags, funnel)?;
    let verb = if funnel { "funnel" } else { "serve" };

    // `off` is accepted in the target position (Go `serve --https=PORT off`) and after a target (Go
    // `serve <target> off`). Anything else in the trailing slot is a typo, not a target.
    let trailing_off = match flags.off.as_deref() {
        None | Some("off") => flags.off.is_some(),
        Some(other) => anyhow::bail!(
            "unexpected argument {:?} after the target: the only value allowed there is `off`",
            sanitize_for_terminal(other)
        ),
    };
    let off = trailing_off || flags.target.as_deref() == Some("off");

    if off {
        if flags.set_path.is_some() {
            anyhow::bail!(
                "--set-path cannot be combined with `off` (which removes the whole port)"
            );
        }
        let mut cfg = get_serve_config(socket).await?;
        if funnel {
            // Funnel-off leaves the serve alone; it only withdraws the public ingress.
            let host = serve_host(socket).await?;
            tailscaled_rs::ipn::serve::set_funnel(&mut cfg, &host, port, false);
            send_ok_or_die(socket, Request::SetServeConfig { config: cfg }).await?;
            println!("funnel disabled for {host}:{port} (the serve on :{port} is untouched)");
        } else if remove_serve_port(&mut cfg, port) {
            send_ok_or_die(socket, Request::SetServeConfig { config: cfg }).await?;
            println!("serve removed for :{port}");
        } else {
            println!("no serve configured on :{port}; nothing to remove");
        }
        return Ok(());
    }

    let Some(target) = flags.target.as_deref() else {
        anyhow::bail!(
            "{verb} needs a target: `tnet {verb} [--https=PORT|--http=PORT|--tcp=PORT|\
             --tls-terminated-tcp=PORT] <target>` (or `tnet {verb} status` / `tnet {verb} reset`)"
        );
    };
    if flags.set_path.is_some() && !kind.is_web() {
        anyhow::bail!(
            "--set-path applies to --https / --http only: a raw-TCP serve has no URL paths to mount"
        );
    }

    // Every kind needs the node's MagicDNS name: it is the `Web`/`AllowFunnel` key's host half and
    // the SNI a TLS-terminated forward is issued for. Resolving it first also fails fast, before any
    // config is written, when the node isn't up yet.
    let host = if kind.is_web() || kind == ServeKind::TlsTerminatedTcp || funnel {
        Some(serve_host(socket).await?)
    } else {
        None
    };
    let previous = get_serve_config(socket).await?;
    let mut cfg = previous.clone();
    // What the confirmation line says we did — built per kind, printed only once the SET succeeds.
    let what = match kind {
        ServeKind::Https | ServeKind::Http => {
            let host = host.as_deref().expect("web serve resolved a host above");
            let scheme = if kind == ServeKind::Https {
                "https"
            } else {
                "http"
            };
            cfg = build_web_serve(
                cfg,
                host,
                port,
                target,
                flags.set_path.as_deref(),
                kind == ServeKind::Https,
            )?;
            format!(
                "{scheme}://{host}:{port}{} -> {target}",
                mount_suffix(&flags.set_path)
            )
        }
        ServeKind::Tcp => {
            let fwd = normalize_tcp_serve_target(target);
            cfg.tcp.insert(
                port.to_string(),
                tailscaled_rs::localapi::TcpPortHandler {
                    tcp_forward: fwd.clone(),
                    ..Default::default()
                },
            );
            // Repurposing a port from a web serve to a plain TCP forward must drop the stale
            // `Web[host:port]` body a prior `--https` left behind: Go keeps `TCP[port]` and
            // `Web[hostport]` consistent, and an orphan would leave a phantom proxy in the persisted
            // config that a Go tool (or a future Web-consulting path) could act on.
            let suffix = format!(":{port}");
            cfg.web.retain(|k, _| !k.ends_with(&suffix));
            format!("tcp :{port} -> {fwd}")
        }
        ServeKind::TlsTerminatedTcp => {
            let host = host
                .as_deref()
                .expect("tls-terminated serve resolved a host above");
            let fwd = normalize_tcp_serve_target(target);
            cfg.tcp.insert(
                port.to_string(),
                tailscaled_rs::localapi::TcpPortHandler {
                    // Go stores the node's DNS name as the SNI to terminate for; the daemon's
                    // `is_terminate_tls_serve` lane then splices the plaintext to `TCPForward`.
                    terminate_tls: host.to_string(),
                    tcp_forward: fwd.clone(),
                    ..Default::default()
                },
            );
            let suffix = format!(":{port}");
            cfg.web.retain(|k, _| !k.ends_with(&suffix));
            format!("tls+tcp {host}:{port} -> {fwd} (TLS-terminated)")
        }
        // `check_serve_flags` refuses --tun above, for Go's reason, before anything is written.
        ServeKind::Tun => unreachable!("a TUN serve never reaches the config writer"),
    };
    if funnel {
        let host = host.as_deref().expect("funnel resolved a host above");
        tailscaled_rs::ipn::serve::set_funnel(&mut cfg, host, port, true);
    }
    // The funnel lane splices the public TLS-terminated stream to the port's PROXY backend, so it
    // arms only for a web serve WITH one. Check the exact condition `arm_funnel_lane` uses, before
    // the config leaves this process, so a funnel over `--tcp` / `--tls-terminated-tcp` / a
    // `text:`-only serve says so here instead of only in the daemon log.
    let funnel_has_backend =
        funnel && tailscaled_rs::ipn::serve::web_proxy_backend(&cfg, port).is_some();

    send_ok_or_die(socket, Request::SetServeConfig { config: cfg }).await?;
    println!("serving {what}");
    if funnel {
        let host = host.as_deref().expect("funnel resolved a host above");
        if funnel_has_backend {
            println!("funnel enabled: https://{host}:{port} is reachable from the PUBLIC internet");
        } else {
            // Don't claim public reachability the daemon is about to decline to provide.
            println!("funnel enabled for {host}:{port}");
            eprintln!(
                "warning: {host}:{port} has no web proxy backend, so this build will NOT arm the \
                 public ingress — funnel splices to a `--https`/`--http` serve's proxy target, not \
                 to a raw-TCP or `text:` serve"
            );
        }
    }

    if serve_background(&flags) {
        Ok(())
    } else {
        hold_foreground_serve(socket, previous).await
    }
}

/// Drive `tnet serve`: the Go v1.100.0 flag grammar when no sub-verb is given, or one of this
/// fork's positional sub-verbs (`tcp`/`https`/`http`/`redirect`) plus `status`/`reset`.
///
/// The sub-verbs predate the flag grammar here and are kept as a documented superset — `redirect` in
/// particular has no Go counterpart at v1.100.0 (the engine serves one, Go's CLI just cannot ask for
/// it). Both grammars write the same `ServeConfig`, and every set is a read-modify-write: the daemon
/// replaces the config wholesale on SET (matching Go's `SetServeConfig`), so each one first fetches
/// the current config and adds its entry.
async fn run_serve(
    socket: &std::path::Path,
    cmd: Option<ServeCmd>,
    flags: ServeFlags,
) -> Result<()> {
    let Some(cmd) = cmd else {
        return run_serve_v2(socket, flags, false).await;
    };
    let get_cfg = || get_serve_config(socket);
    match cmd {
        ServeCmd::Status { json } => run_serve_status(socket, json).await,
        ServeCmd::Tcp { port, target } => {
            let mut cfg = get_cfg().await?;
            let fwd = normalize_serve_target(&target);
            cfg.tcp.insert(
                port.to_string(),
                tailscaled_rs::localapi::TcpPortHandler {
                    tcp_forward: fwd.clone(),
                    ..Default::default()
                },
            );
            // Repurposing a port from `https`/`http` to a plain TCP forward must also drop any stale
            // `Web[host:port]` entry a prior `serve https <port>` left behind — Go keeps `TCP[port]`
            // and `Web[hostport]` mutually consistent (clearing the paired Web entry), and a lingering
            // orphan would leave a phantom proxy in the persisted config that a Go tool (or a future
            // Web-consulting path) could act on. Match by `:port` suffix across any host (the same
            // rule `port_is_web_serve`/`web_proxy_backend` use; one node = one MagicDNS name).
            let suffix = format!(":{port}");
            cfg.web.retain(|k, _| !k.ends_with(&suffix));
            send_ok_or_die(socket, Request::SetServeConfig { config: cfg }).await?;
            println!("serving tailnet :{port} -> {fwd}");
            Ok(())
        }

        ServeCmd::Https {
            port,
            target,
            set_path,
        } => {
            let host = serve_host(socket).await?;
            let cfg = get_cfg().await?;
            let cfg = build_web_serve(cfg, &host, port, &target, set_path.as_deref(), true)?;
            send_ok_or_die(socket, Request::SetServeConfig { config: cfg }).await?;
            println!(
                "serving https://{host}:{port}{} -> {target}",
                mount_suffix(&set_path)
            );
            Ok(())
        }
        ServeCmd::Http {
            port,
            target,
            set_path,
        } => {
            let host = serve_host(socket).await?;
            let cfg = get_cfg().await?;
            let cfg = build_web_serve(cfg, &host, port, &target, set_path.as_deref(), false)?;
            send_ok_or_die(socket, Request::SetServeConfig { config: cfg }).await?;
            println!(
                "serving http://{host}:{port}{} -> {target}",
                mount_suffix(&set_path)
            );
            Ok(())
        }
        ServeCmd::Redirect { port, to, status } => {
            if to.trim().is_empty() {
                anyhow::bail!("redirect target must not be empty");
            }
            if !(300..=399).contains(&status) {
                anyhow::bail!("redirect status must be in 300..=399 (got {status})");
            }
            if to.contains(['\r', '\n']) {
                anyhow::bail!("redirect target must not contain CR or LF");
            }
            if let Some(placeholder) = unexpanded_redirect_var(&to) {
                anyhow::bail!(
                    "redirect target must not contain {placeholder}: the target is sent verbatim \
                     in the Location: header and no variable expansion is performed. Use a literal URL."
                );
            }
            let host = serve_host(socket).await?;
            let mut cfg = get_cfg().await?;
            // Write into the Go Web map: TCP[port]={HTTPS:true} flag + a `/` redirect handler in the
            // Go string form `<status>:<to>`, accreting onto any existing handlers on the port.
            let mut handlers = existing_web_handlers(&cfg, &host, port);
            handlers.insert(
                "/".to_string(),
                tailscaled_rs::localapi::HttpHandler {
                    redirect: format!("{status}:{to}"),
                    ..Default::default()
                },
            );
            cfg.tcp.insert(
                port.to_string(),
                tailscaled_rs::localapi::TcpPortHandler {
                    https: true,
                    ..Default::default()
                },
            );
            cfg.web.insert(
                format!("{host}:{port}"),
                tailscaled_rs::localapi::WebServerConfig { handlers },
            );
            send_ok_or_die(socket, Request::SetServeConfig { config: cfg }).await?;
            println!("serving https://{host}:{port} -> redirect {status} -> {to}");
            Ok(())
        }
        ServeCmd::Reset => run_serve_reset(socket).await,
    }
}

/// Drive `tnet funnel`: `status`/`reset` (Go aliases for the `serve` ones), the legacy
/// `funnel <port> on|off` toggle, or the Go v1.100.0 flag grammar.
///
/// The legacy form is detected exactly the way Go detects its own v1 funnel grammar: a bare port in
/// the target slot followed by the literal `on` or `off`, with none of the port flags given. It only
/// flips `AllowFunnel`; the flag grammar (`tnet funnel --https=443 <target>`) configures the serve
/// AND the funnel in one call, like Go.
async fn run_funnel(
    socket: &std::path::Path,
    cmd: Option<FunnelCmd>,
    flags: ServeFlags,
) -> Result<()> {
    match cmd {
        Some(FunnelCmd::Status { json }) => return run_serve_status(socket, json).await,
        Some(FunnelCmd::Reset) => return run_serve_reset(socket).await,
        None => {}
    }
    if let Some((port, on)) = legacy_funnel_toggle(&flags) {
        check_serve_flags(&flags, true)?;
        return run_funnel_toggle(socket, port, on).await;
    }
    run_serve_v2(socket, flags, true).await
}

/// Recognize the fork's legacy `tnet funnel <port> on|off` toggle inside the shared flag grammar,
/// returning `(port, on)` when it matches. Pure → unit-testable.
///
/// The shape is a bare port in the target slot followed by the literal `on` or `off`, with none of
/// the four port flags given — the same discrimination Go uses to keep its own v1 funnel grammar
/// alive alongside `serve_v2.go`'s. `on` is not a word the flag grammar has, so `funnel <port> on`
/// can only be the legacy form.
///
/// `funnel <bare-port> off` IS ambiguous, and this build resolves it the legacy way: it turns the
/// funnel off on `<bare-port>`, whereas Go would read `<bare-port>` as a target and turn the funnel
/// off on the default port 443. Deliberate — silently retargeting an existing `tnet funnel 8443 off`
/// at port 443 would report success while leaving 8443 exposed to the public internet, which is a
/// far worse failure than the divergence. Spell the port flag (`funnel --https=443 off`) to get
/// Go's reading.
fn legacy_funnel_toggle(flags: &ServeFlags) -> Option<(u16, bool)> {
    let no_port_flag = flags.https.is_none()
        && flags.http.is_none()
        && flags.tcp.is_none()
        && flags.tls_terminated_tcp.is_none();
    if !no_port_flag {
        return None;
    }
    let on_off = flags.off.as_deref()?;
    if !matches!(on_off, "on" | "off") {
        return None;
    }
    let port = flags.target.as_deref()?.parse::<u16>().ok()?;
    Some((port, on_off == "on"))
}

/// Drive the legacy `tnet funnel <port> {on|off}` toggle: resolve this node's MagicDNS name (the
/// Funnel `HostPort` key), then read-modify-write the ServeConfig's `AllowFunnel` via
/// [`serve::set_funnel`]. On `on` for a port with no serve handler, prints a Go-faithful warning
/// (Funnel exposes a serve, so a bare funnel-on does nothing until a serve is configured on the
/// port). Unlike the flag grammar this touches ONLY `AllowFunnel` — it configures no serve.
async fn run_funnel_toggle(socket: &std::path::Path, port: u16, on: bool) -> Result<()> {
    // The node's MagicDNS name (from Status.self_name) is the Funnel HostPort key. Without it we
    // can't build the `host:port` key Go uses, so require the node to be up + named.
    let status = match round_trip(socket, &Request::Status).await {
        Ok(Response::Status(s)) => s,
        Ok(other) => anyhow::bail!("unexpected response to status request: {other:?}"),
        Err(e) => return Err(e).context("querying status"),
    };
    let Some(host) = status.self_name.as_deref().filter(|h| !h.is_empty()) else {
        anyhow::bail!(
            "no MagicDNS name yet (state: {}); bring the node up before enabling funnel",
            status.state
        );
    };

    let mut cfg = match round_trip(socket, &Request::GetServeConfig).await {
        Ok(Response::ServeConfig(c)) => c,
        Ok(other) => anyhow::bail!("unexpected response to get serve config: {other:?}"),
        Err(e) => return Err(e).context("getting serve config"),
    };
    tailscaled_rs::ipn::serve::set_funnel(&mut cfg, host, port, on);

    // Warn when funnel is on for a port the daemon can't actually expose. The funnel lane proxies a
    // raw TLS-terminated stream to the port's proxy backend, so it needs a web entry WITH a proxy
    // backend — match that EXACT arming condition by reusing `web_proxy_backend` (the same resolver
    // `arm_funnel_lane` uses). It consults both the legacy `tcp_forward` AND the Go `Web` map root
    // proxy, so the warning no longer cries wolf on every CLI-created serve (which writes the `Web`
    // map with an empty `tcp_forward`). A `text`/`redirect`/`mounts`-only serve has no backend to
    // splice, so it correctly still warns. Stricter than Go's "any serve config" check because our
    // funnel lane only splices a proxy backend.
    let has_proxy_backend = tailscaled_rs::ipn::serve::web_proxy_backend(&cfg, port).is_some();
    send_ok_or_die(socket, Request::SetServeConfig { config: cfg }).await?;
    if on {
        println!("funnel enabled for {host}:{port}");
        if !has_proxy_backend {
            eprintln!(
                "warning: funnel=on for {host}:{port}, but no proxy backend on that port — run \
                 `tnet funnel --https={port} <target>` (or `tnet serve https {port} <target>`) so \
                 there is something to expose (funnel splices to the serve's proxy backend)"
            );
        }
    } else {
        println!("funnel disabled for {host}:{port}");
    }
    Ok(())
}

/// Truncate a string for `serve status` display, faithful to Go `serve`'s `elipticallyTruncate`:
/// `<= max` bytes returned unchanged, else `s[..max-3] + "..."` (ASCII dots, total length `max`). Uses
/// a char-boundary-safe slice so multibyte UTF-8 is not split (a benign divergence from Go's byte
/// slice — we never panic on a multibyte boundary).
fn elliptically_truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let cut = max.saturating_sub(3);
    let mut end = cut;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &s[..end])
}

/// One-line description of a Go-shaped [`HttpHandler`](tailscaled_rs::localapi::HttpHandler) for
/// `serve status` (proxy / text / redirect / filesystem-path), mirroring the legacy `WebMount` render.
/// Control-supplied fields are terminal-sanitized; a long text body is elliptically truncated.
fn web_handler_desc(h: &tailscaled_rs::localapi::HttpHandler) -> String {
    if !h.proxy.is_empty() {
        format!("proxy -> {}", sanitize_for_terminal(&h.proxy))
    } else if !h.text.is_empty() {
        format!("text \"{}\"", elliptically_truncate(&h.text, 20))
    } else if !h.redirect.is_empty() {
        format!("redirect -> {}", sanitize_for_terminal(&h.redirect))
    } else if !h.path.is_empty() {
        format!(
            "path {} (filesystem serving NOT supported by this build)",
            sanitize_for_terminal(&h.path)
        )
    } else {
        "(empty handler)".to_string()
    }
}

/// Render `tnet serve status` from a [`ServeConfig`](tailscaled_rs::localapi::ServeConfig). Lists each
/// served entry: plain TCP forwards (the daemon's own accept loop), HTTPS/HTTP web entries (proxy /
/// text / redirect / path-mux — Go's top-level `Web` map, or the legacy per-handler bodies — served by
/// engine delegation), and TLS-terminated raw-TCP forwards (`--tls-terminated-tcp`, also
/// engine-delegated). A `TerminateTLS` entry with no backend, or one requesting PROXY-protocol (which
/// the engine `Proxy` target can't write), is flagged "NOT served". `_json` is handled by the caller.
/// Pure → unit-testable.
fn format_serve_status(cfg: &tailscaled_rs::localapi::ServeConfig, _json: bool) -> String {
    use tailscaled_rs::localapi::WebMount;
    // Go's `isServeConfigEmpty` (cmd/tailscale/cli/serve_status.go) is empty iff `len(TCP)==0 &&
    // len(Web)==0 && len(Services)==0 && len(AllowFunnel)==0`. This wire model carries `tcp` + `web`
    // + `allow_funnel` (no `Services` — see the ServeConfig DTO + bead tsd-6p4); checking those three
    // is exhaustive over everything this build can represent (a funnel-only or Web-only config is
    // correctly NOT empty). ⚠️ If `Services` is ever added, this `&&` MUST extend or a service-only
    // config would silently print "No serve config". Message matches Go's exact `No serve config`.
    if cfg.tcp.is_empty() && cfg.web.is_empty() && cfg.allow_funnel.is_empty() {
        return "No serve config\n".to_string();
    }
    let mut out = String::new();
    for (port, h) in &cfg.tcp {
        let scheme = if h.http { "http" } else { "https" };
        // Go-shaped Web-map handlers take precedence over the legacy per-handler bodies (when both
        // somehow coexist, the Web map is the authoritative target — it's what Stage B's translation
        // serves). Match the port's `Web[host:port]` entry by the `:port` suffix (the key carries the
        // real MagicDNS host, which we render instead of the `<node>` placeholder).
        let web_entry = (h.https || h.http)
            .then(|| {
                let suffix = format!(":{port}");
                cfg.web.iter().find(|(k, _)| k.ends_with(&suffix))
            })
            .flatten();
        if let Some((hostport, wsc)) = web_entry {
            let host = sanitize_for_terminal(hostport);
            if wsc.handlers.len() == 1
                && let Some(h0) = wsc.handlers.get("/")
            {
                out.push_str(&format!("{scheme}://{host} -> {}\n", web_handler_desc(h0)));
            } else {
                out.push_str(&format!("{scheme}://{host} (path mux)\n"));
                for (mount, hh) in &wsc.handlers {
                    out.push_str(&format!(
                        "  {} -> {}\n",
                        sanitize_for_terminal(mount),
                        web_handler_desc(hh)
                    ));
                }
            }
        } else if !h.mounts.is_empty() {
            // Legacy path-mux: one line per mount (sorted by the BTreeMap key).
            out.push_str(&format!("{scheme}://<node>:{port} (path mux)\n"));
            for (mount, m) in &h.mounts {
                let desc = match m {
                    WebMount::Proxy { to } => format!("proxy -> {to}"),
                    WebMount::Text { body } => {
                        format!("text \"{}\"", elliptically_truncate(body, 20))
                    }
                    WebMount::Redirect { to, status } => format!("redirect {status} -> {to}"),
                };
                out.push_str(&format!("  {mount} -> {desc}\n"));
            }
        } else if let Some(body) = &h.text {
            out.push_str(&format!(
                "{scheme}://<node>:{port} -> text \"{}\"\n",
                elliptically_truncate(body, 20)
            ));
        } else if let Some(r) = &h.redirect {
            out.push_str(&format!(
                "{scheme}://<node>:{port} -> redirect {} -> {}\n",
                r.status, r.to
            ));
        } else if (h.https || h.http) && !h.tcp_forward.is_empty() {
            out.push_str(&format!("{scheme}://<node>:{port} -> {}\n", h.tcp_forward));
        } else if !h.tcp_forward.is_empty() && !h.https && !h.http && h.terminate_tls.is_empty() {
            out.push_str(&format!("tcp :{port} -> {}\n", h.tcp_forward));
        } else if !h.terminate_tls.is_empty() && !h.tcp_forward.is_empty() && h.proxy_protocol == 0
        {
            // Servable TLS-terminated raw-TCP forward (engine terminates TLS + splices to the backend).
            out.push_str(&format!(
                "tls+tcp :{port} -> {} (TLS-terminated)\n",
                h.tcp_forward
            ));
        } else if !h.terminate_tls.is_empty() {
            // Not servable: no backend to splice to, or proxy-protocol requested (engine `Proxy`
            // doesn't write the PROXY header).
            let why = if h.tcp_forward.is_empty() {
                "no backend"
            } else {
                "proxy-protocol not supported"
            };
            out.push_str(&format!(
                "tcp :{port} -> {} (TLS-terminated; NOT served — {why})\n",
                h.tcp_forward
            ));
        } else if h.https || h.http {
            // A web flag with no backend to proxy to — can't be served.
            let kind = if h.https { "HTTPS" } else { "HTTP" };
            out.push_str(&format!(
                ":{port} {kind} web (NOT served — no proxy target configured)\n"
            ));
        } else {
            out.push_str(&format!(":{port} (empty handler)\n"));
        }
    }
    // Funnel summary: ports exposed to the PUBLIC internet (Go's "# Funnel on:" section). Listed
    // after the serve entries so the per-port lines stay clean; a funnel port should also appear
    // above as an https serve (funnel exposes a serve). The `host:port` key carries the real MagicDNS
    // name, so render that (not a `<node>` placeholder, unlike the per-port serve lines whose host the
    // config doesn't carry).
    let funnel = tailscaled_rs::ipn::serve::funnel_host_ports(cfg);
    if !funnel.is_empty() {
        out.push_str("Funnel (on the public internet):\n");
        for (host, port) in &funnel {
            // `host` is the control-assigned MagicDNS name — sanitize before terminal display.
            out.push_str(&format!(
                "  https://{}:{port}\n",
                sanitize_for_terminal(host)
            ));
        }
    }
    out
}

/// The command path a `configure sysext` refusal names — `configure sysext`, or the verb the user
/// typed. Go gives each verb its own `ShortUsage`, and refuses the bare command too, so the message
/// can always say which one was refused.
fn sysext_verb_path(cmd: Option<SysextCmd>) -> &'static str {
    match cmd {
        None => "configure sysext",
        Some(SysextCmd::Activate) => "configure sysext activate",
        Some(SysextCmd::Deactivate) => "configure sysext deactivate",
        Some(SysextCmd::Status) => "configure sysext status",
    }
}

/// The command path a `configure mac-vpn` refusal names. As with [`sysext_verb_path`], Go refuses
/// the bare command and each verb alike.
fn mac_vpn_verb_path(cmd: Option<MacVpnCmd>) -> &'static str {
    match cmd {
        None => "configure mac-vpn",
        Some(MacVpnCmd::Install) => "configure mac-vpn install",
        Some(MacVpnCmd::Uninstall) => "configure mac-vpn uninstall",
    }
}

/// Why `configure sysext` refuses. Go's `requiresStandalone` (`cmd/tailscale/cli/configure_apple.go`)
/// is the same shape: in a CLI-only build every `sysext` verb returns "unsupported command: requires
/// the Standalone (.pkg installer) GUI build of the client", because registering a macOS system
/// extension is the signed app's job, not the CLI's. This fork has no GUI build to defer to at all,
/// so the second sentence says what it does instead of implying one exists.
///
/// `on_macos` is the caller's platform (`cfg!(target_os = "macos")` in production). Off macOS Go
/// does not register the command at all — it is `nil` outside darwin — so there the message is about
/// the platform rather than the build.
fn sysext_refusal(cmd: Option<SysextCmd>, on_macos: bool) -> String {
    let path = sysext_verb_path(cmd);
    if on_macos {
        format!(
            "{path}: unsupported command: requires the Standalone (.pkg installer) GUI build of the \
             macOS client — this fork ships no macOS system extension, so there is none to activate, \
             deactivate or report on. `tailnetd` runs the data plane in userspace networking; \
             register it as a launchd service with `tnet install`."
        )
    } else {
        format!(
            "{path}: unsupported command: a system extension is a macOS concept, and Go registers \
             `configure sysext` on darwin only. This fork ships no system extension on any platform \
             — register the daemon as this host's system service with `tnet install`."
        )
    }
}

/// Why `configure mac-vpn` refuses. Go's `requiresGUI` (`cmd/tailscale/cli/configure_apple.go`)
/// returns "unsupported command: requires a GUI build of the macOS client" for `install`,
/// `uninstall` and the bare command: the VPN profile in System Settings > VPN is written by the app,
/// not the CLI. This fork writes no such profile, on macOS or anywhere else.
fn mac_vpn_refusal(cmd: Option<MacVpnCmd>, on_macos: bool) -> String {
    let path = mac_vpn_verb_path(cmd);
    if on_macos {
        format!(
            "{path}: unsupported command: requires a GUI build of the macOS client — this fork \
             writes no macOS VPN configuration, so no Tailscale entry appears in System Settings > \
             VPN. `tnet install` registers `tailnetd` as a launchd service instead."
        )
    } else {
        format!(
            "{path}: unsupported command: the macOS VPN configuration is a macOS concept, and Go \
             registers `configure mac-vpn` on darwin only. Use `tnet install` to register `tailnetd` \
             as this host's system service."
        )
    }
}

/// `configure sysext` (Go `tailscale configure sysext [activate|deactivate|status]`): always an
/// error, exactly as in Go's non-GUI build. Exits 1 with the reason, where an unregistered
/// subcommand would exit 2 with clap's parse error and explain nothing.
fn run_configure_sysext(cmd: Option<SysextCmd>) -> Result<()> {
    Err(anyhow!(sysext_refusal(cmd, cfg!(target_os = "macos"))))
}

/// `configure mac-vpn` (Go `tailscale configure mac-vpn [install|uninstall]`): always an error, as
/// in Go's non-GUI build. See [`mac_vpn_refusal`].
fn run_configure_mac_vpn(cmd: Option<MacVpnCmd>) -> Result<()> {
    Err(anyhow!(mac_vpn_refusal(cmd, cfg!(target_os = "macos"))))
}

/// `configure kubeconfig` (Go `tailscale configure kubeconfig <hostname-or-fqdn>`).
///
/// Go's flow, which this ports step for step: read Status, require the backend to be `Running`,
/// resolve the argument to a peer's MagicDNS name (falling back to a Tailscale Service record), then
/// merge a `cluster`/`context`/`user` triple named after that FQDN into the user's kubeconfig and
/// make it the current context.
///
/// The one addition is `--output`, which writes the triple as a standalone document instead of
/// merging — see [`ConfigureCmd::Kubeconfig`].
async fn run_configure_kubeconfig(
    socket: &std::path::Path,
    host: &str,
    http: bool,
    output: Option<&str>,
    force: bool,
) -> Result<()> {
    // Go parses the argument BEFORE it talks to the daemon, so a usage mistake is refused without a
    // round trip: an empty argument is `flag.ErrHelp`, and a scheme in the argument decides http-vs-
    // https regardless of `--http`.
    let (host, scheme) = kubeconfig_inputs(host, http)?;
    let host = host.as_str();
    let status = match round_trip(socket, &Request::Status).await {
        Ok(Response::Status(s)) => s,
        Ok(Response::Error { message }) => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
        Ok(other) => anyhow::bail!("unexpected response to status request: {other:?}"),
        Err(e) => {
            return Err(e).with_context(|| format!("querying status at {}", socket.display()));
        }
    };
    // Go: `if st.BackendState != "Running" { return errors.New("Tailscale is not running") }`. Any
    // other state means the netmap is stale or absent, so a resolved FQDN would be a guess.
    if status.state != "Running" {
        anyhow::bail!(
            "configure kubeconfig: the node is not running (state {}) — run `tnet up` first",
            sanitize_for_terminal(&status.state)
        );
    }
    // Go's `nodeOrServiceDNSNameFromArg`: try the peers first, and only on a miss look the argument
    // up as a Tailscale Service record in the tailnet's MagicDNS configuration.
    //
    // Go fetches the DNS config unconditionally, before resolving; this fetches it only on the peer
    // miss. Same answers and same errors — one fewer LocalAPI round trip on the common path, and a
    // daemon that cannot answer `dns status` no longer breaks a lookup that the netmap alone
    // already settled.
    let fqdn = match peer_dns_name_from_arg(&status, host) {
        Some(name) => name,
        None => {
            let dns = match round_trip(socket, &Request::DnsStatus).await {
                Ok(Response::DnsStatus(r)) => r,
                Ok(Response::Error { message }) => {
                    eprintln!("error: {message}");
                    std::process::exit(1);
                }
                Ok(other) => {
                    anyhow::bail!("unexpected response to dns status request: {other:?}")
                }
                Err(e) => {
                    return Err(e)
                        .with_context(|| format!("querying dns status at {}", socket.display()));
                }
            };
            service_dns_name_from_arg(&dns, &status, host)?
        }
    };
    // Go: `targetFQDN = strings.TrimSuffix(targetFQDN, ".")`. The peer arm already trims; a Service
    // record's name is whatever control pushed, so it can still carry the root dot.
    let fqdn = fqdn.trim_end_matches('.').to_string();
    // The FQDN lands unquoted in the YAML *and* inside the cluster's `https://…` server URL, both
    // built by string interpolation. Both are only safe because the name is constrained to a DNS
    // charset here; keep this check in front of `update_kubeconfig`, which relies on it.
    validate_kube_fqdn(&fqdn)?;
    let url = format!("{scheme}{fqdn}");

    match output {
        // Go's behaviour, and the default: merge the cluster/context/user triple into the kubeconfig
        // kubectl already reads, leaving every other cluster in it intact.
        None => {
            let path = kubeconfig_path()?;
            set_kubeconfig_for_peer(scheme, &fqdn, &path)?;
            // Go's closing line, verbatim (`kubeconfig configured for %q at URL %q`), plus the file
            // it edited — Go leaves that implicit, but `$KUBECONFIG` can point anywhere.
            println!("kubeconfig configured for {fqdn:?} at URL {url:?} — merged into {path}");
        }
        // `--output` is this fork's own escape hatch, not a Go flag: emit the triple as a fresh
        // standalone document and touch nothing else. Nothing is read, so nothing can be merged.
        Some(dest) => {
            let kubeconfig = update_kubeconfig("", scheme, &fqdn)?;
            if dest == "-" {
                use std::io::Write as _;
                std::io::stdout()
                    .write_all(kubeconfig.as_bytes())
                    .context("writing the kubeconfig to stdout")?;
                eprintln!("kubeconfig configured for {fqdn:?} at URL {url:?} — written to stdout");
            } else {
                write_kubeconfig_file(dest, &kubeconfig, force)?;
                println!("kubeconfig configured for {fqdn:?} at URL {url:?} — written to {dest}");
            }
            // Say plainly what `--output` did NOT do, so nobody assumes `~/.kube/config` was updated.
            eprintln!(
                "note: --output writes a standalone kubeconfig — no existing kubeconfig was read or \
                 modified. Use it with `kubectl --kubeconfig <path>`, or stack it: \
                 `KUBECONFIG=~/.kube/config:<path>`. Drop --output to merge into your kubeconfig."
            );
        }
    }
    Ok(())
}

/// Split the `<hostname-or-fqdn>` argument into the name to resolve and the scheme the cluster URL
/// gets, porting Go's `getInputs` (plus the empty-argument arm of `runConfigureKubeconfig`).
///
/// Go runs the argument through `url.Parse`: an `http`/`https` scheme in the argument wins over
/// `--http` in BOTH directions (`https://host` stays HTTPS even with `--http`, `http://host` is
/// plaintext without it) and the host is what gets resolved; anything else is a bare name and the
/// flag decides. Go's `len(args) != 1 || args[0] == ""` arm returns `flag.ErrHelp`, so an empty
/// argument is a usage refusal, not a peer lookup for the empty name. clap already refuses a missing
/// argument; the empty-string one has to be refused here.
///
/// The authority is taken the way `url.Parse` fills `u.Host`: everything after the scheme, up to the
/// first `/`, `?` or `#`, with any `userinfo@` prefix dropped. Whatever survives still has to match a
/// peer and pass [`validate_kube_fqdn`], so a port or a path in the argument fails loudly rather than
/// being spliced into the server URL.
fn kubeconfig_inputs(arg: &str, http_flag: bool) -> Result<(String, &'static str)> {
    if arg.is_empty() {
        anyhow::bail!(
            "configure kubeconfig: needs a <hostname-or-fqdn> argument — the tailnet peer running \
             the auth proxy in front of the cluster's API server"
        );
    }
    for scheme in ["https://", "http://"] {
        // `get`, not a bare slice: the argument is arbitrary argv, so indexing by a byte length can
        // land inside a multi-byte character and panic.
        if arg
            .get(..scheme.len())
            .is_some_and(|p| p.eq_ignore_ascii_case(scheme))
        {
            let authority = &arg[scheme.len()..];
            let authority = authority.split(['/', '?', '#']).next().unwrap_or(authority);
            let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
            return Ok((host.to_string(), scheme));
        }
    }
    Ok((arg.to_string(), kube_scheme(http_flag)))
}

/// The URL scheme `--http` selects, in Go's `scheme := "https://"` / `"http://"` spelling.
fn kube_scheme(http: bool) -> &'static str {
    if http { "http://" } else { "https://" }
}

/// Resolve a `<hostname-or-fqdn>` argument to a peer's MagicDNS name, mirroring Go's
/// `nodeDNSNameFromArg`: a full DNS name, the leading label of one, or a tailnet IP all match, and
/// name comparison is case-insensitive with a trailing root dot ignored on both sides. Returns the
/// peer's name with the trailing dot stripped (Go's caller does the same `TrimSuffix` before use).
fn peer_dns_name_from_arg(
    status: &tailscaled_rs::localapi::StatusReport,
    arg: &str,
) -> Option<String> {
    // Go parses the argument with `netip.ParseAddr` first: an argument that IS an address matches
    // only against the peer's tailnet IPs and never falls through to a name comparison.
    let arg_ip: Option<std::net::IpAddr> = arg.parse().ok();
    let arg = arg.trim_end_matches('.');
    if arg.is_empty() {
        return None;
    }
    for peer in &status.peers {
        let name = peer.name.trim_end_matches('.');
        if name.is_empty() {
            // A peer with no name can still be addressed by IP, but there is no FQDN to build a
            // kubeconfig from, so it can never be the answer — skip it entirely.
            continue;
        }
        if let Some(want) = arg_ip {
            // Compare PARSED addresses, as Go's `slices.Contains(ps.TailscaleIPs, argIP)` does, so an
            // abbreviated IPv6 literal still matches however the netmap spelled the same address.
            let hit = [Some(peer.ipv4.as_str()), peer.ipv6.as_deref()]
                .into_iter()
                .flatten()
                .filter_map(|ip| ip.parse::<std::net::IpAddr>().ok())
                .any(|ip| ip == want);
            if hit {
                return Some(name.to_string());
            }
            continue;
        }
        if name.eq_ignore_ascii_case(arg) {
            return Some(name.to_string());
        }
        if let Some((base, _)) = name.split_once('.')
            && base.eq_ignore_ascii_case(arg)
        {
            return Some(name.to_string());
        }
    }
    None
}

/// Reject anything that is not a plain DNS name before it is interpolated into the kubeconfig.
///
/// The name comes from the netmap (control-assigned), not from argv — but it is still remote input,
/// and it is spliced unquoted into YAML and into a `https://…` URL. Confining it to the DNS charset
/// makes both splices safe by construction: no quote, newline, `/`, `@`, `:` or leading `-` can
/// reach the output, so the value cannot break out of its YAML scalar or repoint the server URL.
fn validate_kube_fqdn(fqdn: &str) -> Result<()> {
    let bad = |why: &str| {
        anyhow!(
            "configure kubeconfig: refusing peer name {:?} — {why}",
            sanitize_for_terminal(fqdn)
        )
    };
    if fqdn.is_empty() {
        return Err(bad("it is empty"));
    }
    // RFC 1035's 255-octet wire limit is 253 characters in presentation form.
    if fqdn.len() > 253 {
        return Err(bad("it is longer than 253 characters"));
    }
    for label in fqdn.split('.') {
        if label.is_empty() {
            return Err(bad("it has an empty DNS label"));
        }
        if label.len() > 63 {
            return Err(bad("it has a DNS label longer than 63 characters"));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(bad("a DNS label starts or ends with '-'"));
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(bad("it contains characters outside [A-Za-z0-9.-]"));
        }
    }
    Ok(())
}

/// Merge the auth-proxy cluster/context/user triple into an existing kubeconfig, porting Go's
/// `updateKubeconfig` (and the `appendOrSetNamed` it leans on).
///
/// `cfg_yaml` is the current contents of the target file, or `""` when there is none — which is the
/// "render a fresh document" case, and the only one `--output` uses.
///
/// Go's model is `sigs.k8s.io/yaml`, i.e. YAML over `encoding/json`: the document is decoded into a
/// `map[string]any`, mutated, and marshalled back through JSON. The port keeps that model exactly —
/// [`serde_json::Value`] is the document, [`serde_norway`] only parses and emits — so the output
/// matches Go byte for byte, including the alphabetical top-level key order (Go's `encoding/json`
/// sorts map keys; `serde_json::Map` is a `BTreeMap`).
///
/// What the merge preserves, per Go: every cluster, context and user the file already held, in
/// order; a triple already named after this FQDN is REPLACED in place rather than duplicated (that
/// is `appendOrSetNamed`); and the `tailscale-auth` user is one shared entry every Tailscale context
/// points at, carrying Go's placeholder token — the proxy authorizes by tailnet identity and ignores
/// the token, but with no credential at all in the user entry kubectl prompts for a username and
/// password.
///
/// Refuses (Go's `errInvalidKubeconfig`) a document that does not parse, or that is not an
/// `apiVersion: v1` / `kind: Config` mapping. That refusal is what keeps a merge from turning into a
/// silent overwrite of a file this build did not understand.
///
/// `scheme` is Go's `"https://"` / `"http://"` (see [`kube_scheme`] and [`kubeconfig_inputs`]). The
/// caller has already run [`validate_kube_fqdn`], so the name is a plain DNS name.
fn update_kubeconfig(cfg_yaml: &str, scheme: &str, fqdn: &str) -> Result<String> {
    use serde_json::{Map, Value, json};

    let invalid = || {
        anyhow!(
            "configure kubeconfig: invalid kubeconfig — it is not an `apiVersion: v1` / `kind: \
             Config` YAML document. Refusing to touch it (Go refuses the same way): merging into a \
             file this build cannot read would mean overwriting it."
        )
    };
    // Go unmarshals into a `map[string]any` and treats a nil map (empty input, or a document that is
    // only comments / an explicit `null`) as "start a fresh config"; anything that is not a mapping
    // fails to unmarshal at all.
    let parsed: Option<Map<String, Value>> = if cfg_yaml.is_empty() {
        None
    } else {
        match serde_norway::from_str::<Value>(cfg_yaml) {
            Ok(Value::Null) => None,
            Ok(Value::Object(m)) => Some(m),
            Ok(_) | Err(_) => return Err(invalid()),
        }
    };
    let mut cfg = match parsed {
        None => {
            let mut m = Map::new();
            m.insert("apiVersion".to_string(), json!("v1"));
            m.insert("kind".to_string(), json!("Config"));
            m
        }
        Some(m) => {
            // Go: `cfg["apiVersion"] != "v1" || cfg["kind"] != "Config"`. A missing key compares
            // unequal too, so `{}` is invalid — it is a mapping, just not a kubeconfig.
            if m.get("apiVersion") != Some(&json!("v1")) || m.get("kind") != Some(&json!("Config"))
            {
                return Err(invalid());
            }
            m
        }
    };

    // Go: `clusters, _ := cfg["clusters"].([]any)` — a missing key AND a key holding something that
    // is not a list both yield nil, and the key is then overwritten with the rebuilt list.
    let seq = |cfg: &Map<String, Value>, key: &str| match cfg.get(key) {
        Some(Value::Array(a)) => a.clone(),
        _ => Vec::new(),
    };

    let mut clusters = seq(&cfg, "clusters");
    append_or_set_named(
        &mut clusters,
        fqdn,
        json!({"name": fqdn, "cluster": {"server": format!("{scheme}{fqdn}")}}),
    );
    cfg.insert("clusters".to_string(), Value::Array(clusters));

    let mut users = seq(&cfg, "users");
    append_or_set_named(
        &mut users,
        "tailscale-auth",
        json!({"name": "tailscale-auth", "user": {"token": "unused"}}),
    );
    cfg.insert("users".to_string(), Value::Array(users));

    let mut contexts = seq(&cfg, "contexts");
    append_or_set_named(
        &mut contexts,
        fqdn,
        json!({"name": fqdn, "context": {"cluster": fqdn, "user": "tailscale-auth"}}),
    );
    cfg.insert("contexts".to_string(), Value::Array(contexts));

    cfg.insert("current-context".to_string(), json!(fqdn));
    serde_norway::to_string(&Value::Object(cfg)).context("rendering the merged kubeconfig as YAML")
}

/// Go's `appendOrSetNamed`: replace the entry whose `name` key equals `name`, or append if there is
/// none. Anything in the list that is not a mapping with a matching string `name` is left alone,
/// exactly as Go's type assertion skips it.
fn append_or_set_named(dst: &mut Vec<serde_json::Value>, name: &str, val: serde_json::Value) {
    let want = serde_json::Value::String(name.to_string());
    match dst.iter().position(|m| m.get("name") == Some(&want)) {
        Some(i) => dst[i] = val,
        None => dst.push(val),
    }
}

/// The kubeconfig file to merge into, porting Go's `kubeconfigPath()`.
///
/// `$KUBECONFIG` wins when set: it is a `:`-separated list, and the target is the first entry that
/// exists and is not a directory — falling back to the LAST entry when none of them exists, which is
/// how a first run creates the file the list names. Otherwise it is `$HOME/.kube/config`.
///
/// Split out from [`kubeconfig_path`] so the resolution is testable without mutating the process
/// environment. Go's sandboxed-macOS-GUI arms have no analogue here (this daemon has no sandboxed
/// GUI build), and its Windows `;` list separator is out of scope — this CLI is unix-only.
fn kubeconfig_path_from(kubeconfig_env: Option<&str>, home: Option<&str>) -> Result<String> {
    if let Some(list) = kubeconfig_env.filter(|s| !s.is_empty()) {
        let mut out = "";
        for entry in list.split(':') {
            out = entry;
            match std::fs::metadata(entry) {
                // Exists and is a file: this is the one kubectl would read first.
                Ok(md) if !md.is_dir() => break,
                Ok(_) => continue,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                // Exists but cannot be stat'd (a permission error on the parent, say). Go's
                // `!os.IsNotExist(err)` arm takes it too — and then nil-derefs; we just take it and
                // let the open() below produce the real error.
                Err(_) => break,
            }
        }
        if out.is_empty() {
            anyhow::bail!(
                "configure kubeconfig: $KUBECONFIG names no usable file ({:?}) — set it to a path, \
                 or unset it to use ~/.kube/config",
                sanitize_for_terminal(list)
            );
        }
        return Ok(out.to_string());
    }
    let home = home.filter(|h| !h.is_empty()).ok_or_else(|| {
        anyhow!(
            "configure kubeconfig: $HOME is not set, so ~/.kube/config cannot be located — set \
             $KUBECONFIG to the kubeconfig to merge into"
        )
    })?;
    Ok(format!("{home}/.kube/config"))
}

/// [`kubeconfig_path_from`] against the real environment (Go's `os.Getenv("KUBECONFIG")` +
/// `homedir.HomeDir()`).
fn kubeconfig_path() -> Result<String> {
    let kubeconfig = std::env::var("KUBECONFIG").ok();
    let home = std::env::var("HOME").ok();
    kubeconfig_path_from(kubeconfig.as_deref(), home.as_deref())
}

/// Merge the triple into the kubeconfig at `path`, porting Go's `setKubeconfigForPeer`: create the
/// parent directory if it is missing, read whatever is there (a missing file is an empty document),
/// merge, and write the result back at mode `0600`.
///
/// Symlinks are followed, as Go's `os.ReadFile`/`os.WriteFile` do — a `~/.kube/config` symlinked into
/// a dotfiles checkout is a normal setup, and refusing it would break the common case this command
/// exists for. (`--output`, which creates a *new* file, still refuses to follow one; see
/// [`write_kubeconfig_file`].)
fn set_kubeconfig_for_peer(scheme: &str, fqdn: &str, path: &str) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};

    let p = std::path::Path::new(path);
    // Go: `os.Mkdir(dir, 0755)` — one level, not MkdirAll, so a path several directories deep still
    // reports the missing parent rather than conjuring the tree.
    if let Some(dir) = p.parent().filter(|d| !d.as_os_str().is_empty())
        && !dir.exists()
    {
        std::fs::DirBuilder::new()
            .mode(0o755)
            .create(dir)
            .with_context(|| format!("creating {}", dir.display()))?;
    }
    let existing = match std::fs::read(p) {
        Ok(b) => String::from_utf8(b).map_err(|_| {
            anyhow!(
                "configure kubeconfig: {path} is not valid UTF-8, so it is not a kubeconfig this \
                 build can merge into. Refusing to overwrite it."
            )
        })?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e).with_context(|| format!("reading kubeconfig {path}")),
    };
    let merged = update_kubeconfig(&existing, scheme, fqdn)
        .with_context(|| format!("merging the auth-proxy cluster into {path}"))?;
    // Go: `os.WriteFile(filePath, b, 0600)`. The mode applies on creation; an existing file keeps
    // whatever mode it had, so this never loosens a kubeconfig the user tightened.
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(p)
        .with_context(|| format!("opening kubeconfig {path} for writing"))?;
    f.write_all(merged.as_bytes())
        .with_context(|| format!("writing kubeconfig {path}"))?;
    f.sync_all()
        .with_context(|| format!("fsync kubeconfig {path}"))?;
    Ok(())
}

/// Go's `dnsname.ToFQDN`, returning the `WithTrailingDot()` form — the shape Go compares Service
/// record names in — or `None` for a name that is not a valid DNS name.
///
/// Faithful to Go including its edges: an empty string and `"."` are both the root, a leading dot is
/// dropped, the length limit is 254 counting the trailing dot, and only labels *before* the last dot
/// are length-checked (Go's loop fires on `.`, so a trailing label is never measured).
fn to_fqdn(s: &str) -> Option<String> {
    if s.is_empty() || s == "." {
        return Some(".".to_string());
    }
    let s = s.strip_prefix('.').unwrap_or(s);
    let raw = s;
    let mut total = s.len();
    let body = match s.strip_suffix('.') {
        Some(b) => b,
        None => {
            total += 1; // account for the missing dot
            s
        }
    };
    if total > 254 {
        return None;
    }
    let mut st = 0;
    for (i, c) in body.char_indices() {
        if c != '.' {
            continue;
        }
        let label = &body[st..i];
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        st = i + 1;
    }
    Some(if raw.ends_with('.') {
        raw.to_string()
    } else {
        format!("{raw}.")
    })
}

/// Go's `serviceDNSRecordFromDNSConfig`: find the control-pushed DNS record (a Tailscale Service's
/// MagicDNS entry) that the argument names.
///
/// An argument that parses as an IP matches a record by its *value*; otherwise it matches a record's
/// leading label or its full name, case-insensitively and with the trailing root dot normalised on
/// both sides. Returns the `(name, addr)` pair as [`DnsStatusReport::extra_records`] carries it.
fn service_dns_record_from_dns_config<'a>(
    dns: &'a tailscaled_rs::localapi::DnsStatusReport,
    arg: &str,
) -> Option<&'a (String, String)> {
    let arg_ip: Option<std::net::IpAddr> = arg.parse().ok();
    let arg_fqdn = to_fqdn(arg);
    if arg_ip.is_none() && arg_fqdn.is_none() {
        return None;
    }
    for rec in &dns.extra_records {
        if let Some(want) = arg_ip {
            // Compare PARSED addresses, as Go does, so a differently-spelled IPv6 literal still hits.
            if rec.1.parse::<std::net::IpAddr>().ok() == Some(want) {
                return Some(rec);
            }
            continue;
        }
        let Some(argf) = arg_fqdn.as_deref() else {
            continue;
        };
        if arg.eq_ignore_ascii_case(rec.0.split('.').next().unwrap_or("")) {
            return Some(rec);
        }
        let Some(recf) = to_fqdn(&rec.0) else {
            continue;
        };
        if argf.eq_ignore_ascii_case(&recf) {
            return Some(rec);
        }
    }
    None
}

/// The Tailscale Service arm of Go's `nodeOrServiceDNSNameFromArg`, reached only when no peer
/// matched the argument.
///
/// A Service is not a peer: it is a MagicDNS record whose address some peer advertises in its
/// `AllowedIPs`. So finding the record is not enough — Go then requires a peer to actually be
/// advertising that exact host route, and reports the two failures distinctly: an argument that
/// names nothing at all is "no peer found", while a name control publishes that no peer currently
/// carries is "in MagicDNS, but not reachable". Collapsing them would tell an operator to go look at
/// their spelling when the real answer is that the Service's backend is down.
fn service_dns_name_from_arg(
    dns: &tailscaled_rs::localapi::DnsStatusReport,
    status: &tailscaled_rs::localapi::StatusReport,
    arg: &str,
) -> Result<String> {
    let rec = service_dns_record_from_dns_config(dns, arg).ok_or_else(|| {
        anyhow!(
            "configure kubeconfig: no peer found for {:?} (run `tnet status` to list peers, or \
             `tnet dns status` to list the tailnet's Tailscale Service records)",
            sanitize_for_terminal(arg)
        )
    })?;
    let ip: std::net::IpAddr = rec.1.parse().map_err(|e| {
        anyhow!(
            "configure kubeconfig: error parsing ExtraRecord IP address {:?}: {e}",
            sanitize_for_terminal(&rec.1)
        )
    })?;
    // Go builds `netip.PrefixFrom(ip, ip.BitLen())` and looks for that exact prefix in some peer's
    // AllowedIPs: a Service's address is advertised as a single-host route, so a covering subnet
    // route does NOT count as reachability.
    for peer in &status.peers {
        for route in &peer.allowed_routes {
            if let Ok(net) = route.parse::<ipnet::IpNet>()
                && net.addr() == ip
                && net.prefix_len() == net.max_prefix_len()
            {
                return Ok(rec.0.clone());
            }
        }
    }
    Err(anyhow!(
        "configure kubeconfig: {:?} is in MagicDNS, but is not currently reachable on any known \
         peer (no peer advertises {})",
        sanitize_for_terminal(arg),
        sanitize_for_terminal(&rec.1)
    ))
}

/// Write a standalone kubeconfig to `--output PATH` with mode `0600`.
///
/// Without `--force` the file is created `O_EXCL` (`create_new`), so an existing kubeconfig is never
/// touched: `--output` renders a fresh document rather than merging, and overwriting a kubeconfig
/// with it would silently delete every other cluster in that file. (Merging is what the default,
/// `--output`-less path does — see [`set_kubeconfig_for_peer`].) `O_NOFOLLOW` on the final component
/// keeps a pre-planted symlink from redirecting the write (the same residual as elsewhere in this
/// CLI: an attacker-controlled *parent* directory is still traversed).
fn write_kubeconfig_file(path: &str, kubeconfig: &str, force: bool) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).mode(0o600).custom_flags(libc::O_NOFOLLOW);
    if force {
        opts.create(true).truncate(true);
    } else {
        opts.create_new(true);
    }
    let mut f = match opts.open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            anyhow::bail!(
                "configure kubeconfig: {path} already exists and --output writes a standalone \
                 kubeconfig, never a merge. Drop --output to MERGE into your kubeconfig, write it \
                 elsewhere, or pass --force to REPLACE {path} (losing every other cluster it holds)."
            );
        }
        Err(e) => return Err(e).with_context(|| format!("creating kubeconfig file {path}")),
    };
    f.write_all(kubeconfig.as_bytes())
        .with_context(|| format!("writing kubeconfig file {path}"))?;
    f.sync_all()
        .with_context(|| format!("fsync kubeconfig file {path}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tailscaled_rs::localapi::{StatusReport, WhoisReport};

    #[test]
    fn map_via_encodes_like_go() {
        // Go `tailscale debug via 7 10.1.2.0/24` → fd7a:115c:a1e0:b1a:0:7:a01:200/120.
        // (0x0a01_0200 = 10.1.2.0; site id 7 at bytes 8..12; /24 + 96 = /120.)
        let v4: ipnet::Ipv4Net = "10.1.2.0/24".parse().unwrap();
        let route = map_via(7, &v4).unwrap();
        assert_eq!(route.to_string(), "fd7a:115c:a1e0:b1a:0:7:a01:200/120");
    }

    #[test]
    fn unmap_via_decodes_back() {
        let via: ipnet::Ipv6Net = "fd7a:115c:a1e0:b1a:0:7:a01:200/120".parse().unwrap();
        let (site_id, v4) = unmap_via(&via).unwrap();
        assert_eq!(site_id, 7);
        assert_eq!(v4.to_string(), "10.1.2.0/24");
    }

    #[test]
    fn via_round_trips_for_several_sites_and_cidrs() {
        // Encoding then decoding must recover the exact (site_id, CIDR) for a spread of inputs.
        for (site, cidr) in [
            (0u32, "192.168.0.0/16"),
            (1, "10.0.0.0/8"),
            (255, "172.16.5.0/24"),
            (0xffff, "10.1.2.3/32"),
            (42, "0.0.0.0/0"),
        ] {
            let v4: ipnet::Ipv4Net = cidr.parse().unwrap();
            let route = map_via(site, &v4).unwrap();
            let (got_site, got_v4) = unmap_via(&route).unwrap();
            assert_eq!(got_site, site, "site id must round-trip for {cidr}");
            assert_eq!(got_v4, v4, "CIDR must round-trip for site {site}");
        }
    }

    #[test]
    fn unmap_via_rejects_non_via_range() {
        // An IPv6 route outside fd7a:115c:a1e0:b1a::/64 is not a 4via6 route.
        let not_via: ipnet::Ipv6Net = "2001:db8::/120".parse().unwrap();
        assert!(unmap_via(&not_via).is_err());
    }

    #[test]
    fn unmap_via_rejects_too_short_prefix() {
        // Inside the via range but shorter than /96 → cannot carry a site id + IPv4.
        let too_short: ipnet::Ipv6Net = "fd7a:115c:a1e0:b1a::/64".parse().unwrap();
        assert!(unmap_via(&too_short).is_err());
    }

    #[test]
    fn run_debug_via_encode_and_decode_paths() {
        // The two CLI forms (these print; we assert they don't error and the math is wired).
        assert!(run_debug_via("7", Some("10.1.2.0/24")).is_ok());
        assert!(run_debug_via("fd7a:115c:a1e0:b1a:0:7:a01:200/120", None).is_ok());
        // A site id above 0xffff is rejected (Go bounds it).
        assert!(run_debug_via("70000", Some("10.0.0.0/8")).is_err());
        // A bare non-IPv6 single arg (looks like neither a valid route nor a 2-arg form) errors.
        assert!(run_debug_via("not-an-addr", None).is_err());
        // A negative/garbage site id with a cidr errors on the parse.
        assert!(run_debug_via("-1", Some("10.0.0.0/8")).is_err());
    }

    #[test]
    fn render_known_hosts_emits_name_and_ips_per_key() {
        use tailscaled_rs::localapi::PeerReport;
        // Go's genKnownHosts: one `<host> <key>` line per (host-identifier × key), where the host
        // identifiers are the peer's name + each tailnet IP. Two keys × three hosts (name, v4, v6) = 6.
        let peer = PeerReport {
            name: "host.example.ts.net".into(),
            ipv4: "100.64.0.2".into(),
            ipv6: Some("fd7a:115c:a1e0::2".into()),
            ssh_host_keys: vec![
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5key1".into(),
                "ecdsa-sha2-nistp256 AAAAE2VjZHNhkey2".into(),
            ],
            ..Default::default()
        };
        let out = render_known_hosts(&peer);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            lines.len(),
            6,
            "2 keys × 3 host identifiers = 6 lines: {out:?}"
        );
        // Each line is `<host> <key>` and every host identifier is keyed to each key.
        assert!(out.contains("host.example.ts.net ssh-ed25519 AAAAC3NzaC1lZDI1NTE5key1"));
        assert!(out.contains("100.64.0.2 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5key1"));
        assert!(out.contains("fd7a:115c:a1e0::2 ecdsa-sha2-nistp256 AAAAE2VjZHNhkey2"));
        assert!(out.ends_with('\n'));
    }

    #[test]
    fn render_known_hosts_skips_crlf_injected_keys() {
        use tailscaled_rs::localapi::PeerReport;
        // A control-supplied host key with an embedded newline must NOT be able to forge extra
        // known_hosts lines (CR/LF injection guard) — the bad key is skipped entirely.
        let peer = PeerReport {
            name: "h".into(),
            ipv4: "100.64.0.5".into(),
            ssh_host_keys: vec![
                "ssh-ed25519 good".into(),
                "ssh-ed25519 evil\n100.64.0.5 ssh-ed25519 forged".into(),
                "ssh-ed25519 also\rbad".into(),
            ],
            ..Default::default()
        };
        let out = render_known_hosts(&peer);
        // Only the good key survives → 2 hosts (name + v4) × 1 key = 2 lines; no "forged"/"evil"/"bad".
        assert_eq!(
            out.lines().count(),
            2,
            "only the clean key is emitted: {out:?}"
        );
        assert!(!out.contains("forged"));
        assert!(!out.contains("evil"));
        assert!(!out.contains("bad"));
        assert!(out.contains("h ssh-ed25519 good"));
        assert!(out.contains("100.64.0.5 ssh-ed25519 good"));
    }

    #[test]
    fn render_known_hosts_skips_crlf_injected_host_name() {
        use tailscaled_rs::localapi::PeerReport;
        // SECURITY (M1): a control-supplied peer.name with an embedded newline must NOT forge an extra
        // known_hosts line (e.g. a `*` wildcard pinning an attacker key). The unsafe NAME contributes
        // no line; the peer's IP (safe, numeric) still gets its line, so a real connection by IP works.
        let peer = PeerReport {
            name: "victim.ts.net\n* ssh-ed25519 ATTACKERKEY".into(),
            ipv4: "100.64.0.9".into(),
            ssh_host_keys: vec!["ssh-ed25519 realkey".into()],
            ..Default::default()
        };
        let out = render_known_hosts(&peer);
        // The forged `*` wildcard line must NOT appear, and no ATTACKERKEY anywhere.
        assert!(
            !out.contains('*'),
            "must not forge a wildcard host line: {out:?}"
        );
        assert!(!out.contains("ATTACKERKEY"));
        // Only the safe IP host keyed to the real key survives → exactly one line.
        assert_eq!(out, "100.64.0.9 ssh-ed25519 realkey\n", "got: {out:?}");
    }

    #[test]
    fn render_known_hosts_skips_host_with_space_or_leading_hash() {
        use tailscaled_rs::localapi::PeerReport;
        // A name with a space would split into a bogus host token; a leading `#` would comment the
        // line out. Both are rejected as host identifiers (the IP still works).
        let spaced = PeerReport {
            name: "a b".into(),
            ipv4: "100.64.0.3".into(),
            ssh_host_keys: vec!["ssh-ed25519 k".into()],
            ..Default::default()
        };
        assert_eq!(render_known_hosts(&spaced), "100.64.0.3 ssh-ed25519 k\n");
        let hashed = PeerReport {
            name: "#cmt".into(),
            ipv4: "100.64.0.4".into(),
            ssh_host_keys: vec!["ssh-ed25519 k".into()],
            ..Default::default()
        };
        assert_eq!(render_known_hosts(&hashed), "100.64.0.4 ssh-ed25519 k\n");
    }

    #[test]
    fn render_known_hosts_empty_when_no_keys() {
        use tailscaled_rs::localapi::PeerReport;
        // A peer with no advertised SSH host keys produces an empty file (run_ssh refuses BEFORE
        // calling this in that case, but the renderer is still well-defined → empty string).
        let peer = PeerReport {
            name: "h".into(),
            ipv4: "100.64.0.7".into(),
            ..Default::default()
        };
        assert_eq!(render_known_hosts(&peer), "");
    }

    #[test]
    fn ssh_target_without_user_yields_a_bare_destination() {
        // Upstream v1.102.3: no `user@` means no username at all, so `ssh` applies the caller's own
        // ssh_config `User` directive instead of the local account.
        let (user, host) = split_ssh_target("laptop").expect("bare host parses");
        assert_eq!(user, None);
        assert_eq!(host, "laptop");
        assert_eq!(
            ssh_destination(user.as_deref(), "laptop.example.ts.net"),
            "laptop.example.ts.net"
        );
    }

    #[test]
    fn ssh_target_with_user_keeps_user_at_host() {
        let (user, host) = split_ssh_target("alice@laptop").expect("user@host parses");
        assert_eq!(user.as_deref(), Some("alice"));
        assert_eq!(host, "laptop");
        assert_eq!(
            ssh_destination(user.as_deref(), "laptop.example.ts.net"),
            "alice@laptop.example.ts.net"
        );
    }

    #[test]
    fn ssh_target_splits_on_the_first_at() {
        // Go's `strings.Cut`: only the first `@` separates, so the rest stays in the host (which then
        // simply fails to resolve against the netmap).
        let (user, host) = split_ssh_target("alice@bob@laptop").expect("first-@ split parses");
        assert_eq!(user.as_deref(), Some("alice"));
        assert_eq!(host, "bob@laptop");
    }

    #[test]
    fn ssh_target_rejects_unsafe_or_missing_halves() {
        // An explicitly supplied username is still argv the caller controls: a `-`-leading name would
        // be read by ssh as an option, and whitespace would split the destination.
        let err = split_ssh_target("-oProxyCommand=x@laptop")
            .unwrap_err()
            .to_string();
        assert!(err.contains("refusing unsafe username"), "{err}");
        let err = split_ssh_target("bad user@laptop").unwrap_err().to_string();
        assert!(err.contains("refusing unsafe username"), "{err}");
        // An explicit but empty user, and a target with no host, are both unusable.
        let err = split_ssh_target("@laptop").unwrap_err().to_string();
        assert!(err.contains("empty user"), "{err}");
        let err = split_ssh_target("alice@").unwrap_err().to_string();
        assert!(err.contains("empty host"), "{err}");
    }

    #[test]
    fn shell_quote_wraps_and_escapes() {
        // Single-quote wrapping for the ProxyCommand tokens; an embedded quote becomes '\'' .
        assert_eq!(shell_quote("/usr/bin/tnet"), "'/usr/bin/tnet'");
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
    }

    /// Build a minimal `StatusReport` in the given state with no auth_url/error, no peers.
    fn report(state: &str) -> StatusReport {
        StatusReport {
            state: state.to_string(),
            want_running: true,
            ..Default::default()
        }
    }

    #[test]
    fn classify_auth_url() {
        let mut s = report("NeedsLogin");
        s.auth_url = Some("https://login.example.com/a/abc123".to_string());
        match classify_auth(&s) {
            AuthOutcome::Url(url) => assert_eq!(url, "https://login.example.com/a/abc123"),
            _ => panic!("expected Url"),
        }
    }

    #[test]
    fn classify_auth_failed() {
        // Terminal registration failure → Failed, the early-bail case.
        let mut s = report("NeedsLogin");
        s.error = Some("authentication rejected by control: invalid key".to_string());
        match classify_auth(&s) {
            AuthOutcome::Failed(reason) => {
                assert_eq!(reason, "authentication rejected by control: invalid key");
            }
            _ => panic!("expected Failed"),
        }
    }

    #[test]
    fn classify_auth_none() {
        // No URL, no error → nothing to prompt yet.
        match classify_auth(&report("Running")) {
            AuthOutcome::None => {}
            _ => panic!("expected None"),
        }
    }

    #[test]
    fn classify_auth_error_wins_over_url() {
        // If both somehow co-occur, the permanent error must win over a pending URL.
        let mut s = report("NeedsLogin");
        s.auth_url = Some("https://login.example.com/a/stale".to_string());
        s.error = Some("node key expired; re-authentication required".to_string());
        match classify_auth(&s) {
            AuthOutcome::Failed(reason) => {
                assert_eq!(reason, "node key expired; re-authentication required");
            }
            _ => panic!("expected Failed to win over Url"),
        }
    }

    #[test]
    fn resolve_exit_node_set_wins() {
        // A set value maps to Some(Some(_)); it also wins if a clear is somehow also present (clap
        // forbids that via conflicts_with, but the mapping must still be unambiguous).
        assert_eq!(
            resolve_exit_node(Some("100.64.0.9".to_string()), false),
            Some(Some("100.64.0.9".to_string()))
        );
        assert_eq!(
            resolve_exit_node(Some("exit-1".to_string()), true),
            Some(Some("exit-1".to_string())),
            "an explicit selector wins over the clear flag"
        );
    }

    #[test]
    fn resolve_exit_node_clear_and_unchanged() {
        // `--clear-exit-node` → Some(None) (stop using one); neither flag → None (unchanged).
        assert_eq!(resolve_exit_node(None, true), Some(None));
        assert_eq!(resolve_exit_node(None, false), None);
    }

    #[test]
    fn resolve_advertise_exit_node_tristate() {
        // Enable → Some(true); disable → Some(false); neither → None (unchanged).
        assert_eq!(resolve_advertise_exit_node(true, false), Some(true));
        assert_eq!(resolve_advertise_exit_node(false, true), Some(false));
        assert_eq!(resolve_advertise_exit_node(false, false), None);
        // Enable wins if both are somehow set (clap's conflicts_with prevents this in practice).
        assert_eq!(resolve_advertise_exit_node(true, true), Some(true));
    }

    #[test]
    fn resolve_accept_routes_tristate() {
        // Enable → Some(true); disable → Some(false); neither → None (unchanged).
        assert_eq!(resolve_accept_routes(true, false), Some(true));
        assert_eq!(resolve_accept_routes(false, true), Some(false));
        assert_eq!(resolve_accept_routes(false, false), None);
        // Enable wins if both are somehow set (clap's conflicts_with prevents this in practice).
        assert_eq!(resolve_accept_routes(true, true), Some(true));
    }

    #[test]
    fn resolve_ephemeral_tristate() {
        // --ephemeral → Some(true); --no-ephemeral → Some(false); neither → None (unchanged, so a
        // fresh node keeps the persistent default).
        assert_eq!(resolve_ephemeral(true, false), Some(true));
        assert_eq!(resolve_ephemeral(false, true), Some(false));
        assert_eq!(resolve_ephemeral(false, false), None);
        assert_eq!(resolve_ephemeral(true, true), Some(true));
    }

    #[test]
    fn resolve_shields_up_tristate() {
        // Enable → Some(true); disable → Some(false); neither → None (unchanged).
        assert_eq!(resolve_shields_up(true, false), Some(true));
        assert_eq!(resolve_shields_up(false, true), Some(false));
        assert_eq!(resolve_shields_up(false, false), None);
        // Enable wins if both are somehow set (clap's conflicts_with prevents this in practice).
        assert_eq!(resolve_shields_up(true, true), Some(true));
    }

    #[test]
    fn resolve_ssh_tristate() {
        // `--ssh` → Some(true) (run the SSH server); `--no-ssh` → Some(false); neither → None
        // (leave the persisted pref unchanged).
        assert_eq!(resolve_ssh(true, false), Some(true));
        assert_eq!(resolve_ssh(false, true), Some(false));
        assert_eq!(resolve_ssh(false, false), None);
        // Enable wins if both are somehow set (clap's conflicts_with prevents this in practice).
        assert_eq!(resolve_ssh(true, true), Some(true));
    }

    #[test]
    fn is_tailscale_ip_matches_go_tsaddr() {
        use std::net::IpAddr;
        let v = |s: &str| s.parse::<IpAddr>().unwrap();
        // CGNAT 100.64.0.0/10 → Tailscale.
        assert!(is_tailscale_ip(v("100.64.0.1")));
        assert!(is_tailscale_ip(v("100.127.255.255")));
        // ChromeOS-VM 100.115.92.0/23 is EXCLUDED (Go IsTailscaleIPv4 && !ChromeOSVMRange).
        assert!(!is_tailscale_ip(v("100.115.92.1")));
        assert!(!is_tailscale_ip(v("100.115.93.250")));
        // ...but the rest of 100.115/16 (outside the /23) is still CGNAT/Tailscale.
        assert!(is_tailscale_ip(v("100.115.94.1")));
        // Tailscale ULA fd7a:115c:a1e0::/48 → Tailscale.
        assert!(is_tailscale_ip(v("fd7a:115c:a1e0::1")));
        // Outside CGNAT (octet1 top bits 0b10), a /32-not-/48 ULA, loopback, public → NOT Tailscale.
        assert!(!is_tailscale_ip(v("100.128.0.1")));
        assert!(!is_tailscale_ip(v("fd7a:115c:beef::1")));
        assert!(!is_tailscale_ip(v("192.168.1.1")));
        assert!(!is_tailscale_ip(v("::1")));
        assert!(!is_tailscale_ip(v("8.8.8.8")));
    }

    #[test]
    fn ssh_client_is_tailscale_parses_first_token() {
        // SSH_CLIENT = "<client-ip> <client-port> <server-port>"; only the first token matters.
        assert!(ssh_client_is_tailscale("100.64.0.7 12345 22"));
        assert!(ssh_client_is_tailscale("fd7a:115c:a1e0::9 50000 22"));
        assert!(!ssh_client_is_tailscale("8.8.8.8 1 22")); // public client → not over tailnet
        assert!(!ssh_client_is_tailscale("100.115.92.5 1 22")); // ChromeOS-VM excluded
        assert!(!ssh_client_is_tailscale("")); // not an SSH session
        assert!(!ssh_client_is_tailscale("garbage")); // unparseable
    }

    #[test]
    fn risk_accepted_matches_go_isriskaccepted() {
        // Comma list; accept on exact name or the catch-all `all`. Matched RAW (no trim), like Go's
        // isRiskAccepted (strings.SplitSeq members compared verbatim).
        assert!(risk_accepted("lose-ssh", "lose-ssh"));
        assert!(risk_accepted("all", "lose-ssh"));
        assert!(risk_accepted("foo,lose-ssh", "lose-ssh")); // no-space comma list member
        assert!(risk_accepted("foo,all", "lose-ssh")); // `all` anywhere in the list
        // A space-padded member does NOT match (faithful to Go — the token is " lose-ssh").
        assert!(!risk_accepted("foo, lose-ssh", "lose-ssh"));
        assert!(!risk_accepted("", "lose-ssh"));
        assert!(!risk_accepted("other", "lose-ssh"));
    }

    #[test]
    fn force_reauth_over_ssh_refusal_predicate() {
        // The exact gate the Up handler applies: refuse iff force_reauth AND over-tailnet-SSH AND not
        // accepted. Pin all the corners of that 3-way composition (the env read is factored out via
        // `ssh_client_is_tailscale`, so this is fully deterministic).
        let refuse = |force_reauth: bool, ssh_client: &str, accept: &str| {
            force_reauth
                && ssh_client_is_tailscale(ssh_client)
                && !risk_accepted(accept, "lose-ssh")
        };
        // Refuse: force-reauth, over tailnet SSH, not accepted.
        assert!(refuse(true, "100.64.0.7 1 22", ""));
        // Allow: not a force-reauth.
        assert!(!refuse(false, "100.64.0.7 1 22", ""));
        // Allow: not over a tailnet SSH session (public client / no session).
        assert!(!refuse(true, "8.8.8.8 1 22", ""));
        assert!(!refuse(true, "", ""));
        // Allow: the operator pre-accepted the risk (by name or `all`).
        assert!(!refuse(true, "100.64.0.7 1 22", "lose-ssh"));
        assert!(!refuse(true, "100.64.0.7 1 22", "all"));
    }

    #[test]
    fn ssh_toggle_refusal_decision() {
        // The pure ssh-toggle risk decision (Go presentSSHToggleRisk): None = allow, Some(true) =
        // refuse-an-enable, Some(false) = refuse-a-disable. over_ssh + accepted are the modifiers.
        // Allow: toggle not mentioned.
        assert_eq!(ssh_toggle_refusal(None, false, true, ""), None);
        assert_eq!(ssh_toggle_refusal(None, true, true, ""), None);
        // Allow: no-op toggle (want == have).
        assert_eq!(ssh_toggle_refusal(Some(true), true, true, ""), None);
        assert_eq!(ssh_toggle_refusal(Some(false), false, true, ""), None);
        // Allow: not over a Tailscale SSH session.
        assert_eq!(ssh_toggle_refusal(Some(true), false, false, ""), None);
        // Allow: risk pre-accepted (by name or `all`).
        assert_eq!(
            ssh_toggle_refusal(Some(true), false, true, "lose-ssh"),
            None
        );
        assert_eq!(ssh_toggle_refusal(Some(false), true, true, "all"), None);
        // Refuse ENABLE: want SSH on, currently off, over SSH, not accepted → Some(true).
        assert_eq!(ssh_toggle_refusal(Some(true), false, true, ""), Some(true));
        // Refuse DISABLE: want SSH off, currently on, over SSH, not accepted → Some(false).
        assert_eq!(ssh_toggle_refusal(Some(false), true, true, ""), Some(false));
    }

    #[tokio::test]
    async fn ssh_toggle_gate_short_circuits_without_a_round_trip() {
        // The load-bearing guarantee: the gate must NOT hit the daemon on the common path. We point it
        // at a dead socket — a real GetPrefs round-trip would return Err (connect fails) — and assert
        // Ok(()), which proves the short-circuit returned before the round-trip. Cases that must skip:
        let dead = std::path::Path::new("/tmp/tnet-ssh-toggle-nope.sock");
        // (a) toggle not mentioned (want_ssh None) → no round-trip.
        assert!(
            refuse_ssh_toggle_risk_if_needed(dead, None, None)
                .await
                .is_ok(),
            "no --ssh/--no-ssh must skip the round-trip"
        );
        // (b) toggle mentioned + risk pre-accepted → no round-trip (accepted short-circuits).
        assert!(
            refuse_ssh_toggle_risk_if_needed(dead, Some(true), Some("lose-ssh"))
                .await
                .is_ok(),
            "an accepted risk must skip the round-trip"
        );
        // (c) toggle mentioned but NOT over a Tailscale SSH session → no round-trip. In a normal test
        // process SSH_CLIENT is unset (or not a tailnet IP), so is_ssh_over_tailscale() is false; the
        // gate returns Ok before the round-trip. (This relies on the test env not being an actual
        // Tailscale SSH session, which CI/dev shells are not.)
        if !is_ssh_over_tailscale() {
            assert!(
                refuse_ssh_toggle_risk_if_needed(dead, Some(true), None)
                    .await
                    .is_ok(),
                "not over Tailscale SSH must skip the round-trip"
            );
        }
    }

    #[test]
    fn command_set_maps_to_request_set_fields() {
        // A representative invocation: rename + set an exit node + accept routes, leaving the
        // advertise-* prefs untouched. Built from the same resolver helpers the `Command::Set` arm
        // in `main` uses, so the wire mapping is covered without spawning the CLI. The unset prefs
        // must map to `None` (unchanged), not a silent clear.
        let req = Request::Set {
            hostname: Some("laptop".to_string()),
            accept_routes: resolve_accept_routes(true, false),
            accept_dns: resolve_accept_dns(false, false),
            shields_up: resolve_shields_up(false, false),
            exit_node: resolve_exit_node(Some("100.64.0.9".to_string()), false),
            advertise_exit_node: resolve_advertise_exit_node(false, false),
            advertise_routes: resolve_list_or_clear(vec![], false),
            advertise_tags: None,
            ssh: resolve_ssh(false, false),
            advertise_connector: None,
            auto_update: None,
            update_check: None,
            operator: None,
            nickname: None,
            report_posture: None,
            webclient: None,
            exit_node_allow_lan_access: None,
        };
        match req {
            Request::Set {
                hostname,
                accept_routes,
                accept_dns,
                shields_up,
                exit_node,
                advertise_exit_node,
                advertise_routes,
                advertise_tags: _,
                ssh,
                advertise_connector: _,
                auto_update: _,
                update_check: _,
                operator: _,
                nickname: _,
                report_posture: _,
                webclient: _,
                exit_node_allow_lan_access: _,
            } => {
                assert_eq!(hostname, Some("laptop".to_string()));
                assert_eq!(accept_routes, Some(true));
                assert_eq!(accept_dns, None, "unset → unchanged, not flipped");
                assert_eq!(shields_up, None, "unset → unchanged, not flipped");
                assert_eq!(exit_node, Some(Some("100.64.0.9".to_string())));
                assert_eq!(advertise_exit_node, None, "unset → unchanged, not flipped");
                assert_eq!(advertise_routes, None, "unset → unchanged, not cleared");
                assert_eq!(ssh, None, "unset → unchanged, not flipped");
            }
            other => panic!("expected Request::Set, got {other:?}"),
        }
    }

    #[test]
    fn command_up_maps_accept_routes_tristate() {
        // `tnet up` now carries `--accept-routes`/`--no-accept-routes` (Go parity), reusing the same
        // `resolve_accept_routes` tri-state helper as `set`. Pin all three states map into the wire
        // `Request::Up.accept_routes`: enable → Some(true), disable → Some(false), neither → None
        // (leave unchanged). Built from the same resolver the `Command::Up` arm in `main` uses.
        let enabled = Request::Up {
            authkey: None,
            control_url: None,
            hostname: None,
            tun: None,
            tun_name: None,
            tun_mtu: None,
            exit_node: None,
            advertise_exit_node: None,
            advertise_routes: None,
            advertise_tags: None,
            accept_routes: resolve_accept_routes(true, false),
            accept_dns: None,
            shields_up: None,
            ssh: None,
            operator: None,
            exit_node_allow_lan_access: None,
            advertise_connector: None,
            report_posture: None,
            reset: false,
            force_reauth: false,
            ephemeral: None,
            client_id: None,
            client_secret: None,
            id_token: None,
            audience: None,
        };
        match enabled {
            Request::Up { accept_routes, .. } => {
                assert_eq!(accept_routes, Some(true), "--accept-routes → Some(true)")
            }
            other => panic!("expected Request::Up, got {other:?}"),
        }

        let disabled = Request::Up {
            authkey: None,
            control_url: None,
            hostname: None,
            tun: None,
            tun_name: None,
            tun_mtu: None,
            exit_node: None,
            advertise_exit_node: None,
            advertise_routes: None,
            advertise_tags: None,
            accept_routes: resolve_accept_routes(false, true),
            accept_dns: None,
            shields_up: None,
            ssh: None,
            operator: None,
            exit_node_allow_lan_access: None,
            advertise_connector: None,
            report_posture: None,
            reset: false,
            force_reauth: false,
            ephemeral: None,
            client_id: None,
            client_secret: None,
            id_token: None,
            audience: None,
        };
        match disabled {
            Request::Up { accept_routes, .. } => {
                assert_eq!(
                    accept_routes,
                    Some(false),
                    "--no-accept-routes → Some(false)"
                )
            }
            other => panic!("expected Request::Up, got {other:?}"),
        }

        let unchanged = Request::Up {
            authkey: None,
            control_url: None,
            hostname: None,
            tun: None,
            tun_name: None,
            tun_mtu: None,
            exit_node: None,
            advertise_exit_node: None,
            advertise_routes: None,
            advertise_tags: None,
            accept_routes: resolve_accept_routes(false, false),
            accept_dns: None,
            shields_up: None,
            ssh: None,
            operator: None,
            exit_node_allow_lan_access: None,
            advertise_connector: None,
            report_posture: None,
            reset: false,
            force_reauth: false,
            ephemeral: None,
            client_id: None,
            client_secret: None,
            id_token: None,
            audience: None,
        };
        match unchanged {
            Request::Up { accept_routes, .. } => assert_eq!(
                accept_routes, None,
                "neither flag → None (leave the persisted pref unchanged)"
            ),
            other => panic!("expected Request::Up, got {other:?}"),
        }
    }

    #[test]
    fn command_up_maps_shields_up_tristate() {
        // `tnet up` carries `--shields-up`/`--no-shields-up` (Go parity), reusing the same
        // `resolve_shields_up` tri-state helper as `set`. Pin all three states map into the wire
        // `Request::Up.shields_up`: enable → Some(true), disable → Some(false), neither → None
        // (leave unchanged). Built from the same resolver the `Command::Up` arm in `main` uses.
        let enabled = Request::Up {
            authkey: None,
            control_url: None,
            hostname: None,
            tun: None,
            tun_name: None,
            tun_mtu: None,
            exit_node: None,
            advertise_exit_node: None,
            advertise_routes: None,
            advertise_tags: None,
            accept_routes: None,
            accept_dns: None,
            shields_up: resolve_shields_up(true, false),
            ssh: None,
            operator: None,
            exit_node_allow_lan_access: None,
            advertise_connector: None,
            report_posture: None,
            reset: false,
            force_reauth: false,
            ephemeral: None,
            client_id: None,
            client_secret: None,
            id_token: None,
            audience: None,
        };
        match enabled {
            Request::Up { shields_up, .. } => {
                assert_eq!(shields_up, Some(true), "--shields-up → Some(true)")
            }
            other => panic!("expected Request::Up, got {other:?}"),
        }

        let disabled = Request::Up {
            authkey: None,
            control_url: None,
            hostname: None,
            tun: None,
            tun_name: None,
            tun_mtu: None,
            exit_node: None,
            advertise_exit_node: None,
            advertise_routes: None,
            advertise_tags: None,
            accept_routes: None,
            accept_dns: None,
            shields_up: resolve_shields_up(false, true),
            ssh: None,
            operator: None,
            exit_node_allow_lan_access: None,
            advertise_connector: None,
            report_posture: None,
            reset: false,
            force_reauth: false,
            ephemeral: None,
            client_id: None,
            client_secret: None,
            id_token: None,
            audience: None,
        };
        match disabled {
            Request::Up { shields_up, .. } => {
                assert_eq!(shields_up, Some(false), "--no-shields-up → Some(false)")
            }
            other => panic!("expected Request::Up, got {other:?}"),
        }

        let unchanged = Request::Up {
            authkey: None,
            control_url: None,
            hostname: None,
            tun: None,
            tun_name: None,
            tun_mtu: None,
            exit_node: None,
            advertise_exit_node: None,
            advertise_routes: None,
            advertise_tags: None,
            accept_routes: None,
            accept_dns: None,
            shields_up: resolve_shields_up(false, false),
            ssh: None,
            operator: None,
            exit_node_allow_lan_access: None,
            advertise_connector: None,
            report_posture: None,
            reset: false,
            force_reauth: false,
            ephemeral: None,
            client_id: None,
            client_secret: None,
            id_token: None,
            audience: None,
        };
        match unchanged {
            Request::Up { shields_up, .. } => assert_eq!(
                shields_up, None,
                "neither flag → None (leave the persisted pref unchanged)"
            ),
            other => panic!("expected Request::Up, got {other:?}"),
        }
    }

    #[test]
    fn command_set_maps_clears_distinctly_from_unset() {
        // The "clear" flags must produce the present-but-empty sentinels (`Some(None)` /
        // `Some(vec![])`), distinct from the absent (`None`) case above — that's the whole reason
        // the clear flags exist. Built via the same resolvers as `main`'s `Command::Set` arm.
        let req = Request::Set {
            hostname: None,
            accept_routes: resolve_accept_routes(false, true),
            accept_dns: resolve_accept_dns(false, false),
            shields_up: resolve_shields_up(true, false),
            exit_node: resolve_exit_node(None, true),
            advertise_exit_node: resolve_advertise_exit_node(false, true),
            advertise_routes: resolve_list_or_clear(vec![], true),
            advertise_tags: None,
            ssh: resolve_ssh(true, false),
            advertise_connector: None,
            auto_update: None,
            update_check: None,
            operator: None,
            nickname: None,
            report_posture: None,
            webclient: None,
            exit_node_allow_lan_access: None,
        };
        match req {
            Request::Set {
                hostname,
                accept_routes,
                accept_dns,
                shields_up,
                exit_node,
                advertise_exit_node,
                advertise_routes,
                advertise_tags: _,
                ssh,
                advertise_connector: _,
                auto_update: _,
                update_check: _,
                operator: _,
                nickname: _,
                report_posture: _,
                webclient: _,
                exit_node_allow_lan_access: _,
            } => {
                assert_eq!(hostname, None);
                assert_eq!(accept_routes, Some(false));
                assert_eq!(
                    accept_dns, None,
                    "neither --accept-dns flag → None (unchanged)"
                );
                assert_eq!(shields_up, Some(true), "--shields-up → Some(true)");
                assert_eq!(exit_node, Some(None), "--clear-exit-node → Some(None)");
                assert_eq!(advertise_exit_node, Some(false));
                assert_eq!(
                    advertise_routes,
                    Some(vec![]),
                    "--advertise-routes-clear → Some(vec![])"
                );
                assert_eq!(ssh, Some(true), "--ssh → Some(true)");
            }
            other => panic!("expected Request::Set, got {other:?}"),
        }
    }

    #[test]
    fn resolve_list_or_clear_set_clear_unchanged() {
        // A non-empty list replaces the set.
        assert_eq!(
            resolve_list_or_clear(
                vec!["192.168.1.0/24".to_string(), "10.0.0.0/8".to_string()],
                false
            ),
            Some(vec!["192.168.1.0/24".to_string(), "10.0.0.0/8".to_string()])
        );
        // No routes + clear flag → advertise none (empty set).
        assert_eq!(resolve_list_or_clear(vec![], true), Some(vec![]));
        // Neither → leave the persisted set unchanged.
        assert_eq!(resolve_list_or_clear(vec![], false), None);
        // A passed list takes precedence over the clear flag.
        assert_eq!(
            resolve_list_or_clear(vec!["172.16.0.0/12".to_string()], true),
            Some(vec!["172.16.0.0/12".to_string()]),
            "an explicit list wins over the clear flag"
        );
    }

    #[test]
    fn format_ip_renders_addresses_and_placeholder() {
        use tailscaled_rs::localapi::Response;

        // Both addresses → IPv4 then IPv6, one per line.
        assert_eq!(
            format_ip(Some("100.70.22.12"), Some("fd7a:115c:a1e0::1")),
            "100.70.22.12\nfd7a:115c:a1e0::1\n"
        );
        // IPv4 only (the common case — this fork is IPv4-first).
        assert_eq!(format_ip(Some("100.70.22.12"), None), "100.70.22.12\n");
        // No address yet (no netmap received) → a clear placeholder, never empty output.
        assert_eq!(format_ip(None, None), "(no tailnet address yet)\n");

        // The formatter consumes exactly what the `Response::Ip` arm feeds it (`as_deref()` of the
        // wire's `Option<String>` fields), so a populated wire reply renders as above.
        let resp = Response::Ip {
            ipv4: Some("100.70.22.12".to_string()),
            ipv6: None,
        };
        match resp {
            Response::Ip { ipv4, ipv6 } => {
                assert_eq!(
                    format_ip(ipv4.as_deref(), ipv6.as_deref()),
                    "100.70.22.12\n"
                );
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn format_files_empty_prints_placeholder() {
        // An empty Taildrop inbox must print a clear placeholder, never empty output.
        assert_eq!(format_files(&[]), "(no files waiting)\n");
    }

    #[test]
    fn format_files_renders_one_line_per_file() {
        use tailscaled_rs::localapi::{Response, WaitingFileReport};

        let files = vec![
            WaitingFileReport {
                name: "report.pdf".to_string(),
                size: 2048,
            },
            WaitingFileReport {
                name: "notes.txt".to_string(),
                size: 17,
            },
        ];
        assert_eq!(
            format_files(&files),
            "report.pdf  (2048 bytes)\nnotes.txt  (17 bytes)\n"
        );

        // The formatter consumes exactly what the `Response::Files` arm feeds it (`&files`).
        let resp = Response::Files {
            files: vec![WaitingFileReport {
                name: "one.bin".to_string(),
                size: 1,
            }],
        };
        match resp {
            Response::Files { files } => assert_eq!(format_files(&files), "one.bin  (1 bytes)\n"),
            _ => unreachable!(),
        }
    }

    #[test]
    fn format_files_sanitizes_peer_supplied_name() {
        use tailscaled_rs::localapi::WaitingFileReport;

        // The file name arrives from the sending peer (untrusted); a hostile name must not smuggle
        // terminal escapes through `tnet file list`. `format_files` runs it through
        // `sanitize_for_terminal`, so the raw ESC/BEL bytes are stripped.
        let files = vec![WaitingFileReport {
            name: "evil\x1b[2J\x07name.txt".to_string(),
            size: 9,
        }];
        let out = format_files(&files);
        assert!(!out.contains('\x1b'), "ESC must be stripped from file name");
        assert!(!out.contains('\x07'), "BEL must be stripped from file name");
        // The readable parts survive (just the control bytes become the replacement char).
        assert!(out.contains("evil") && out.contains("name.txt"));
        assert!(out.contains("(9 bytes)"));
    }

    #[test]
    fn command_file_subcommands_map_to_requests() {
        // `list`/`get` select the right wire `Request` (built the same way `main`'s `Command::File`
        // arm builds them). `cp` is no longer a simple request-map (it parses the colon target, may
        // `--targets`-list, and sends 1..N files via `run_file_cp`), so its logic is covered by the
        // `parse_cp_target` / `basename` / `format_file_targets` unit tests instead.
        let list = match FileCmd::List {
            FileCmd::List => Request::FileList,
            _ => unreachable!(),
        };
        match list {
            Request::FileList => {}
            other => panic!("expected Request::FileList, got {other:?}"),
        }

        // `get` has two shapes, decided by whether a second positional (DEST) is present — this is the
        // exact branch in `run_file`. Replicate it so both map to the right wire request.
        let build_get = |target: String, dest: Option<String>, conflict: ConflictArg, da: bool| {
            // Mirror run_file's match on `dest`.
            match (FileCmd::Get {
                target,
                dest,
                conflict,
                delete_after: da,
                verbose: false,
            }) {
                FileCmd::Get {
                    target,
                    dest,
                    conflict,
                    delete_after,
                    verbose: _,
                } => match dest {
                    Some(dest) => Request::FileGet {
                        name: target,
                        dest,
                        delete_after,
                    },
                    None => Request::FileGetDir {
                        dir: target,
                        conflict: conflict.into(),
                    },
                },
                _ => unreachable!(),
            }
        };

        // Two positionals (`get <name> <dest> --delete-after`) → single-file FileGet.
        match build_get(
            "report.pdf".to_string(),
            Some("/tmp/out.pdf".to_string()),
            ConflictArg::Skip,
            true,
        ) {
            Request::FileGet {
                name,
                dest,
                delete_after,
            } => {
                assert_eq!(name, "report.pdf");
                assert_eq!(dest, "/tmp/out.pdf");
                assert!(delete_after, "--delete-after → true");
            }
            other => panic!("expected Request::FileGet, got {other:?}"),
        }

        // One positional (`get <dir> --conflict=rename`) → directory-drain FileGetDir.
        match build_get(
            "/tmp/downloads".to_string(),
            None,
            ConflictArg::Rename,
            false,
        ) {
            Request::FileGetDir { dir, conflict } => {
                assert_eq!(dir, "/tmp/downloads");
                assert_eq!(
                    conflict,
                    tailscaled_rs::localapi::ConflictPolicy::Rename,
                    "--conflict=rename maps to the wire policy"
                );
            }
            other => panic!("expected Request::FileGetDir, got {other:?}"),
        }
    }

    #[test]
    fn parse_cp_target_requires_colon_and_strips_it() {
        // A bare name + colon → the name (Go's trailing-colon disambiguator).
        assert_eq!(parse_cp_target("peer-b:").unwrap(), "peer-b");
        assert_eq!(parse_cp_target("100.64.0.9:").unwrap(), "100.64.0.9");
        // Missing colon → error (Go: "must end in colon").
        assert!(
            parse_cp_target("peer-b").is_err(),
            "no colon must be rejected"
        );
        // Empty peer (`:` or `[]:`) → error (can't resolve an empty selector).
        assert!(parse_cp_target(":").is_err(), "empty peer must be rejected");
        assert!(
            parse_cp_target("[]:").is_err(),
            "empty bracketed peer must be rejected"
        );
    }

    #[test]
    fn parse_cp_target_ipv6_bracket_rules_match_go() {
        // A bracketed IPv6 literal → the inner address (brackets + colon stripped).
        assert_eq!(parse_cp_target("[fd7a::1]:").unwrap(), "fd7a::1");
        // A bare (unbracketed) IPv6 literal → error, pointing at the bracketed form.
        let err = parse_cp_target("fd7a::1:").unwrap_err().to_string();
        assert!(err.contains("must be written as ["), "got: {err}");
        // Brackets around a NON-IPv6 (a name or v4) → error (Go rejects unexpected brackets).
        assert!(
            parse_cp_target("[peer-b]:").is_err(),
            "brackets around a non-IPv6 must be rejected"
        );
        assert!(
            parse_cp_target("[1.2.3.4]:").is_err(),
            "brackets around a v4 literal must be rejected"
        );
    }

    #[test]
    fn basename_takes_final_component() {
        assert_eq!(basename("/tmp/a/b.txt"), "b.txt");
        assert_eq!(basename("b.txt"), "b.txt");
        assert_eq!(basename("/trailing/"), "");
    }

    #[test]
    fn format_file_targets_renders_status_columns_like_go() {
        use tailscaled_rs::localapi::FileTargetReport;
        let targets = vec![
            FileTargetReport {
                ip: "100.64.0.2".to_string(),
                name: "laptop".to_string(),
                online: Some(true),
            },
            FileTargetReport {
                ip: "100.64.0.3".to_string(),
                name: "desktop".to_string(),
                online: Some(false),
            },
            FileTargetReport {
                ip: "100.64.0.4".to_string(),
                name: "phone".to_string(),
                online: None,
            },
        ];
        let out = format_file_targets(&targets);
        // Online peer: just ip \t name, no detail column.
        assert!(out.contains("100.64.0.2\tlaptop\n"), "{out}");
        // Offline / unknown peers get the detail column.
        assert!(out.contains("100.64.0.3\tdesktop\toffline\n"), "{out}");
        assert!(out.contains("100.64.0.4\tphone\tunknown-status\n"), "{out}");
        // Empty → placeholder.
        assert_eq!(format_file_targets(&[]), "(no Taildrop targets)\n");
    }

    #[test]
    fn format_file_targets_sanitizes_peer_name() {
        use tailscaled_rs::localapi::FileTargetReport;
        // The peer name is control-supplied; terminal escapes must be stripped.
        let targets = vec![FileTargetReport {
            ip: "100.64.0.2".to_string(),
            name: "evil\x1b[2J\x07".to_string(),
            online: Some(true),
        }];
        let out = format_file_targets(&targets);
        assert!(!out.contains('\x1b') && !out.contains('\x07'), "{out}");
    }

    #[test]
    fn format_file_targets_resists_column_and_row_injection() {
        use tailscaled_rs::localapi::FileTargetReport;
        // `file cp --targets` renders TAB-separated columns, one peer per line. A malicious control
        // server could set a peer's ComputedName to embed a TAB (forging a fake `offline`/IP column)
        // or a newline (forging an entire fake peer row). The name MUST NOT be able to introduce a
        // structural delimiter — only the renderer itself emits `\t`/`\n`.
        let targets = vec![FileTargetReport {
            ip: "100.64.0.2".to_string(),
            name: "real\toffline\n100.64.0.99\tfake-peer".to_string(),
            online: Some(true),
        }];
        let out = format_file_targets(&targets);
        // Exactly ONE row (one trailing newline, no interior newline forged by the name).
        assert_eq!(out.matches('\n').count(), 1, "forged extra row: {out:?}");
        // A single online peer → exactly ONE column separator (ip<TAB>name, no status column, and the
        // name contributed no extra TAB).
        assert_eq!(out.matches('\t').count(), 1, "forged extra column: {out:?}");
        // The forged literals survive as inert visible text (neutralized to U+FFFD), so nothing is
        // silently dropped — the operator still sees the suspicious name.
        assert!(
            out.contains('\u{FFFD}'),
            "delimiters not neutralized: {out:?}"
        );
        assert!(out.contains("fake-peer"), "name text lost: {out:?}");
    }

    #[test]
    fn sanitizers_split_on_structural_whitespace() {
        // The single-line/columnar default neutralizes ALL control chars, INCLUDING `\t`/`\n`/`\r`,
        // so it can never forge a column or row.
        let s = sanitize_for_terminal("a\tb\nc\rd\x1be");
        assert!(
            !s.contains('\t') && !s.contains('\n') && !s.contains('\r') && !s.contains('\x1b'),
            "{s:?}"
        );
        assert_eq!(s, "a\u{FFFD}b\u{FFFD}c\u{FFFD}d\u{FFFD}e");

        // The free-form multiline variant keeps `\t`/`\n`/`\r` (so a multi-line reason stays legible)
        // but still strips other C0/C1 escapes like ESC.
        let m = sanitize_multiline("a\tb\nc\rd\x1be");
        assert!(
            m.contains('\t') && m.contains('\n') && m.contains('\r'),
            "{m:?}"
        );
        assert!(!m.contains('\x1b'), "{m:?}");
        assert_eq!(m, "a\tb\nc\rd\u{FFFD}e");
    }

    #[tokio::test]
    async fn read_secret_arg_handles_literal_file_and_none() {
        use secrecy::ExposeSecret as _;
        // A bare value is taken verbatim.
        let lit = read_secret_arg(Some("tskey-client-literal".into()))
            .await
            .unwrap()
            .expect("some");
        assert_eq!(lit.expose_secret(), "tskey-client-literal");
        // `None` in → `None` out.
        assert!(read_secret_arg(None).await.unwrap().is_none());
        // `file:PATH` reads the file and trims leading/trailing whitespace (`str::trim`, matching Go's
        // `strings.TrimSpace`) — so a plain `echo >` newline AND a CRLF / leading-space file both work.
        let dir = std::env::temp_dir().join(format!("tnet-wif-secret-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let path = dir.join("secret");
        tokio::fs::write(&path, b"tskey-from-file\n").await.unwrap();
        let from_file = read_secret_arg(Some(format!("file:{}", path.display())))
            .await
            .unwrap()
            .expect("some");
        assert_eq!(
            from_file.expose_secret(),
            "tskey-from-file",
            "file: value is read and the trailing newline trimmed"
        );
        // A CRLF file with surrounding whitespace is fully trimmed on both ends (not just one \n).
        let crlf = dir.join("crlf");
        tokio::fs::write(&crlf, b"  tskey-crlf\r\n").await.unwrap();
        let from_crlf = read_secret_arg(Some(format!("file:{}", crlf.display())))
            .await
            .unwrap()
            .expect("some");
        assert_eq!(
            from_crlf.expose_secret(),
            "tskey-crlf",
            "leading spaces and a trailing CRLF are both trimmed"
        );
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn resolve_wif_rejects_id_token_with_audience() {
        // Go's `up.go`: `--id-token` and `--audience` both drive the OIDC-token request, so passing
        // both is ambiguous — reject it CLI-side before any daemon round-trip.
        // NOTE: `WifFlags` holds `SecretString` and is deliberately NOT `Debug` (no accidental secret
        // leak), so we cannot use `expect_err` (it would format the `Ok` value) — match the `Result`.
        match resolve_wif(
            Some("cid".into()),
            None,
            Some("eyJ.token".into()),
            Some("sts.example".into()),
        )
        .await
        {
            Err(e) => assert!(
                e.to_string().contains("mutually exclusive"),
                "error should name the conflict: {e}"
            ),
            Ok(_) => panic!("id-token + audience must be rejected"),
        }
        // The non-conflicting combinations resolve fine and wrap the secret.
        let ok = resolve_wif(Some("cid".into()), Some("sec".into()), None, None)
            .await
            .expect("client-id + client-secret is valid");
        assert!(ok.client_secret.is_some() && ok.client_id.is_some());
    }

    #[test]
    fn format_files_got_renders_success_and_failure_lines() {
        use tailscaled_rs::localapi::FileGotReport;
        // A drain with one success (written elsewhere under rename), one failure (left in inbox).
        // The compact renderer carries only the progress; the failure comes out of the drain's
        // accumulated errors, which `render_files_got` appends after it (Go's order).
        let results = vec![
            FileGotReport {
                name: "a.txt".to_string(),
                size: 12,
                written: Some("/tmp/dl/a (1).txt".to_string()),
                error: None,
            },
            FileGotReport {
                name: "b.txt".to_string(),
                size: 0,
                written: None,
                error: Some("refusing to overwrite /tmp/dl/b.txt: file already exists".to_string()),
            },
        ];
        let out = format_files_got(&results);
        assert!(
            out.contains("wrote a.txt -> /tmp/dl/a (1).txt (12 bytes)"),
            "success line: {out}"
        );
        assert!(
            !out.contains("error:"),
            "failures are not progress lines: {out}"
        );
        // One file did move, so the tally is not an error — the single failure is, and being the
        // last (and only) one it is what the command returns.
        let (stdout, last) = render_files_got(&results, false);
        assert!(
            stdout.contains("wrote a.txt -> /tmp/dl/a (1).txt (12 bytes)"),
            "success line: {stdout}"
        );
        assert_eq!(
            last.as_deref(),
            Some("error: b.txt: refusing to overwrite /tmp/dl/b.txt: file already exists"),
            "the failure is the command's error: {stdout}"
        );
        // Empty drain → placeholder, and no error (an empty inbox is not a stuck one).
        assert_eq!(format_files_got(&[]), "(no files waiting)\n");
        assert_eq!(
            render_files_got(&[], false),
            ("(no files waiting)\n".to_string(), None)
        );
    }

    #[test]
    fn format_files_got_shows_saved_but_not_consumed_as_error() {
        use tailscaled_rs::localapi::FileGotReport;
        // The "not consumed" case: written to disk AND an error (inbox delete failed). Go prints the
        // `wrote` line before it tries to clear the inbox and reports the delete failure separately,
        // so BOTH must surface — where it landed and that it could not be cleared — and it must not
        // read as a clean success. Nothing was cleared, so this drain is also Go's stuck case: the
        // `moved 0/1 files` tally is the error the command returns.
        let results = vec![FileGotReport {
            name: "c.txt".to_string(),
            size: 7,
            written: Some("/tmp/dl/c.txt".to_string()),
            error: Some("saved but could not be removed from the inbox: Io(...)".to_string()),
        }];
        let (out, last) = render_files_got(&results, false);
        assert!(
            out.contains("wrote c.txt -> /tmp/dl/c.txt (7 bytes)"),
            "{out}"
        );
        assert!(
            out.contains("error: c.txt: saved but could not be removed from the inbox"),
            "must name the reason: {out}"
        );
        assert_eq!(
            last.as_deref(),
            Some("moved 0/1 files"),
            "a drain that cleared nothing is Go's stuck-inbox error: {out}"
        );
    }

    #[test]
    fn file_get_stuck_inbox_reports_the_tally_without_verbose() {
        use tailscaled_rs::localapi::FileGotReport;
        // Go: `if deleted == 0 && len(wfs) > 0 { errs = append(errs, fmt.Errorf("moved %d/%d
        // files", ...)) }` — "persistently stuck files are basically an error". That branch is NOT
        // gated on --verbose, so a plain `tnet file get <dir>` that clears nothing must still report
        // the tally and fail. Two files, neither cleared, no --verbose.
        let results = vec![
            FileGotReport {
                name: "a.txt".to_string(),
                size: 0,
                written: None,
                error: Some("refusing to overwrite /tmp/dl/a.txt".to_string()),
            },
            FileGotReport {
                name: "b.txt".to_string(),
                size: 5,
                written: Some("/tmp/dl/b.txt".to_string()),
                error: Some("saved but could not be removed from the inbox".to_string()),
            },
        ];
        let (out, last) = render_files_got(&results, false);
        assert_eq!(
            last.as_deref(),
            Some("moved 0/2 files"),
            "the stuck tally is the command's error (non-zero exit): {out}"
        );
        // Both per-file failures still print, ahead of the returned error.
        assert!(
            out.contains("error: a.txt: refusing to overwrite /tmp/dl/a.txt\n"),
            "{out}"
        );
        assert!(
            out.contains("error: b.txt: saved but could not be removed from the inbox\n"),
            "{out}"
        );
        // A drain that moved something is not stuck: no tally, no error, exit 0.
        let moved = vec![FileGotReport {
            name: "ok.txt".to_string(),
            size: 3,
            written: Some("/tmp/dl/ok.txt".to_string()),
            error: None,
        }];
        let (out, last) = render_files_got(&moved, false);
        assert_eq!(last, None, "a clean drain has no error: {out}");
        assert!(
            !out.contains("moved "),
            "the informational tally stays verbose-only: {out}"
        );
    }

    #[test]
    fn file_get_stuck_inbox_does_not_print_the_tally_twice_under_verbose() {
        use tailscaled_rs::localapi::FileGotReport;
        // Go's tally is an if/else: the stuck case goes to `errs`, everything else to the verbose
        // printf. Under --verbose a stuck drain must therefore report `moved 0/1 files` exactly once
        // — as the error — and not also as the informational line.
        let results = vec![FileGotReport {
            name: "a.txt".to_string(),
            size: 0,
            written: None,
            error: Some("refusing to overwrite /tmp/dl/a.txt".to_string()),
        }];
        let (out, last) = render_files_got(&results, true);
        assert_eq!(last.as_deref(), Some("moved 0/1 files"), "{out}");
        assert!(
            !out.contains("moved "),
            "the tally must not be printed as well as returned: {out}"
        );
    }

    #[test]
    fn file_get_errors_come_after_all_progress_lines() {
        use tailscaled_rs::localapi::FileGotReport;
        // Go prints the batch's progress as it goes and accumulates failures, printing them only
        // once the batch is done. So every `wrote` line precedes every `error:` line, even when the
        // failing file was drained first.
        let results = vec![
            FileGotReport {
                name: "bad.txt".to_string(),
                size: 0,
                written: None,
                error: Some("refusing to overwrite /tmp/dl/bad.txt".to_string()),
            },
            FileGotReport {
                name: "ok.txt".to_string(),
                size: 3,
                written: Some("/tmp/dl/ok.txt".to_string()),
                error: None,
            },
        ];
        // Only the failure is left over, so it is the returned error and the printed body is pure
        // progress; with a second failure the earlier one prints ahead of the `wrote` line's peer.
        let (out, last) = render_files_got(&results, true);
        assert_eq!(
            out, "wrote ok.txt as /tmp/dl/ok.txt (3 bytes)\nmoved 1/2 files\n",
            "progress only"
        );
        assert_eq!(
            last.as_deref(),
            Some("error: bad.txt: refusing to overwrite /tmp/dl/bad.txt")
        );
        let mut two = results.clone();
        two.push(FileGotReport {
            name: "worse.txt".to_string(),
            size: 0,
            written: None,
            error: Some("disk full".to_string()),
        });
        let (out, last) = render_files_got(&two, true);
        let wrote = out.find("wrote ok.txt").expect("progress line present");
        let failed = out.find("error: bad.txt").expect("failure line present");
        assert!(wrote < failed, "failures come after the progress: {out}");
        assert_eq!(
            last.as_deref(),
            Some("error: worse.txt: disk full"),
            "the last accumulated failure is the command's error: {out}"
        );
    }

    #[test]
    fn file_get_errors_flags_a_report_with_neither_outcome() {
        use tailscaled_rs::localapi::FileGotReport;
        // Defensive: the daemon always sets `written` or `error`, but a report with neither must not
        // pass for a clean success — it counts as no move (so the drain is stuck) and says so.
        let results = vec![FileGotReport {
            name: "ghost.txt".to_string(),
            size: 0,
            written: None,
            error: None,
        }];
        assert_eq!(
            file_get_errors(&results),
            vec![
                "error: ghost.txt: unknown outcome".to_string(),
                "moved 0/1 files".to_string()
            ]
        );
        assert_eq!(files_got_moved(&results), 0);
    }

    #[test]
    fn format_files_got_verbose_renders_go_progress_lines() {
        use tailscaled_rs::localapi::FileGotReport;
        // Two received files, one of them landed under a numbered name (`rename`) — Go's verbose line
        // names both the inbox name and the path it actually landed at, plus the size, then closes
        // the batch with the `moved <n>/<total> files` tally.
        let results = vec![
            FileGotReport {
                name: "a.txt".to_string(),
                size: 12,
                written: Some("/tmp/dl/a.txt".to_string()),
                error: None,
            },
            FileGotReport {
                name: "b.bin".to_string(),
                size: 4096,
                written: Some("/tmp/dl/b (1).bin".to_string()),
                error: None,
            },
        ];
        assert_eq!(
            format_files_got_verbose(&results),
            "wrote a.txt as /tmp/dl/a.txt (12 bytes)\n\
             wrote b.bin as /tmp/dl/b (1).bin (4096 bytes)\n\
             moved 2/2 files\n"
        );
    }

    #[test]
    fn format_files_got_verbose_empty_inbox_says_so() {
        // Zero waiting files must say so rather than render as an empty list; the Go tally follows.
        // An empty inbox is not Go's stuck case (`len(wfs) > 0` fails), so the tally stays the
        // informational line and the drain succeeds.
        assert_eq!(
            format_files_got_verbose(&[]),
            "(no files waiting)\nmoved 0/0 files\n"
        );
        assert_eq!(
            render_files_got(&[], true),
            ("(no files waiting)\nmoved 0/0 files\n".to_string(), None)
        );
    }

    #[test]
    fn format_files_got_verbose_tally_counts_only_cleared_files() {
        use tailscaled_rs::localapi::FileGotReport;
        // Three attempted files, one of each end-state. Only the clean success counts toward `moved`
        // (Go's `deleted`): a file written but not cleared from the inbox would be re-fetched on the
        // next drain, and a file that never landed is still waiting — neither one moved.
        let results = vec![
            FileGotReport {
                name: "ok.txt".to_string(),
                size: 3,
                written: Some("/tmp/dl/ok.txt".to_string()),
                error: None,
            },
            FileGotReport {
                name: "stuck.txt".to_string(),
                size: 7,
                written: Some("/tmp/dl/stuck.txt".to_string()),
                error: Some("saved but could not be removed from the inbox".to_string()),
            },
            FileGotReport {
                name: "clash.txt".to_string(),
                size: 0,
                written: None,
                error: Some("refusing to overwrite /tmp/dl/clash.txt".to_string()),
            },
        ];
        assert_eq!(files_got_moved(&results), 1);
        let (out, last) = render_files_got(&results, true);
        assert!(
            out.contains("wrote ok.txt as /tmp/dl/ok.txt (3 bytes)\n"),
            "{out}"
        );
        // Written-but-stuck: the progress line still shows where it landed, and the reason follows
        // with the rest of the batch's failures.
        assert!(
            out.contains("wrote stuck.txt as /tmp/dl/stuck.txt (7 bytes)\n"),
            "{out}"
        );
        assert!(
            out.contains("error: stuck.txt: saved but could not be removed from the inbox\n"),
            "{out}"
        );
        assert_eq!(
            last.as_deref(),
            Some("error: clash.txt: refusing to overwrite /tmp/dl/clash.txt")
        );
        assert!(
            out.contains("moved 1/3 files\n"),
            "only the cleared file counts as moved: {out}"
        );
    }

    #[test]
    fn format_files_got_verbose_sanitizes_peer_supplied_name() {
        use tailscaled_rs::localapi::FileGotReport;
        // Same rule as the compact renderer: the inbox name comes from the sending peer (untrusted),
        // so terminal escapes must never reach the verbose progress line either — nor the failure
        // lines, whose reason text is daemon-supplied.
        let results = vec![
            FileGotReport {
                name: "evil\x1b[2J\x07.txt".to_string(),
                size: 1,
                written: Some("/tmp/evil\x1b[2J.txt".to_string()),
                error: None,
            },
            FileGotReport {
                name: "bad\x1b[2J.txt".to_string(),
                size: 0,
                written: None,
                error: Some("refusing to overwrite /tmp/bad\x07.txt".to_string()),
            },
        ];
        let (out, last) = render_files_got(&results, true);
        assert!(!out.contains('\x1b'), "ESC stripped from verbose line");
        assert!(!out.contains('\x07'), "BEL stripped from verbose line");
        let last = last.expect("the failed file is the command's error");
        assert!(!last.contains('\x1b'), "ESC stripped from the error");
        assert!(!last.contains('\x07'), "BEL stripped from the error");
    }

    #[test]
    fn file_get_verbose_flag_parses_into_file_get() {
        // `tnet file get <dir> --verbose` parses to `FileCmd::Get { verbose: true, .. }`; omitting it
        // leaves the compact default. `run_file` reads exactly this field to pick the renderer.
        let verbose_of = |argv: &[&str]| -> bool {
            match Cli::try_parse_from(argv).expect("parses").command {
                Command::File {
                    cmd: FileCmd::Get { verbose, .. },
                } => verbose,
                _ => panic!("expected `file get` from {argv:?}"),
            }
        };
        assert!(verbose_of(&["tnet", "file", "get", "/tmp/dl", "--verbose"]));
        assert!(
            !verbose_of(&["tnet", "file", "get", "/tmp/dl"]),
            "no --verbose → compact drain output"
        );
    }

    #[test]
    fn format_files_got_sanitizes_peer_supplied_name() {
        use tailscaled_rs::localapi::FileGotReport;
        // The inbox name comes from the sending peer (untrusted); terminal escapes must be stripped.
        let results = vec![FileGotReport {
            name: "evil\x1b[2J\x07.txt".to_string(),
            size: 1,
            written: Some("/tmp/evil\x1b[2J.txt".to_string()),
            error: None,
        }];
        let out = format_files_got(&results);
        assert!(!out.contains('\x1b'), "ESC stripped from drain line");
        assert!(!out.contains('\x07'), "BEL stripped from drain line");
    }

    #[test]
    fn format_whois_not_found_names_the_ip() {
        let w = WhoisReport {
            found: false,
            ..Default::default()
        };
        assert_eq!(
            format_whois(&w, "100.64.0.9"),
            "no tailnet node owns 100.64.0.9\n"
        );
        // Go's `ip[:port]` flow argument is echoed as typed: the operator asked about a flow, and a
        // line naming only the bare IP would hide which query came back empty.
        assert_eq!(
            format_whois(&w, "100.64.0.9:22"),
            "no tailnet node owns 100.64.0.9:22\n"
        );
    }

    #[test]
    fn format_whois_renders_node_user_and_capabilities() {
        let w = WhoisReport {
            found: true,
            node_name: Some("peer-b.example.ts.net".to_string()),
            node_ipv4: Some("100.64.0.2".to_string()),
            user: Some("alice@example.com".to_string()),
            capabilities: vec![
                "https://tailscale.com/cap/is-admin".to_string(),
                "funnel".to_string(),
            ],
            // Flow-scoped peer-cap grants (Go `WhoIsResponse.CapMap`): one cap WITH a raw-JSON value
            // and one value-less cap, to exercise both render shapes.
            cap_map: std::collections::BTreeMap::from([
                (
                    "https://tailscale.com/cap/file-sharing".to_string(),
                    vec!["{\"foo\":1}".to_string()],
                ),
                ("cap/is-admin".to_string(), vec![]),
            ]),
            tags: vec!["tag:server".to_string(), "tag:ci".to_string()],
            node_key_expiry: Some("2026-09-01 12:00:00 UTC".to_string()),
            // Offline + a known last-seen: status convention is to show BOTH the `online: no` line
            // and the `last-seen:` line (an online node's last-seen is "now", so it's only shown
            // when offline).
            online: Some(false),
            last_seen: Some("2026-06-11 05:19:14 UTC".to_string()),
        };
        let out = format_whois(&w, "100.64.0.2");
        assert!(out.contains("peer-b.example.ts.net"), "node name present");
        assert!(out.contains("100.64.0.2"), "node ipv4 present");
        assert!(out.contains("alice@example.com"), "user present when Some");
        assert!(
            out.contains("https://tailscale.com/cap/is-admin") && out.contains("funnel"),
            "every capability present"
        );
        // Flow-scoped grants render under their own `cap-grants:` header (distinct from the
        // node-level `capabilities:` block), with the cap name and — for a cap that has values —
        // each value on its own indented line.
        assert!(
            out.contains("cap-grants:"),
            "cap-grants header present when cap_map non-empty"
        );
        assert!(
            out.contains("https://tailscale.com/cap/file-sharing") && out.contains("cap/is-admin"),
            "every cap-grant name present (value-bearing and value-less)"
        );
        // `cap_map` is a BTreeMap, so the render order is the keys' sorted order (deterministic — the
        // production renderer relies on this for stable output). Within the `cap-grants:` section,
        // `cap/is-admin` < `https://…/cap/file-sharing` lexicographically, so the value-less cap
        // renders before the value-bearing one. (Compare positions WITHIN the cap-grants block: the
        // node-level `capabilities:` block above also contains a `.../cap/is-admin` entry, so anchor
        // the search at the `cap-grants:` header to avoid matching that earlier occurrence.)
        let grants = out.split_once("cap-grants:").unwrap().1;
        assert!(
            grants.find("cap/is-admin").unwrap() < grants.find("cap/file-sharing").unwrap(),
            "cap-grants render in BTreeMap-sorted key order"
        );
        assert!(
            out.contains("{\"foo\":1}"),
            "the cap-grant's raw-JSON value renders on its own line"
        );
        // ACL tags render under a `tags:` header, one bullet each (Go parity).
        assert!(
            out.contains("tags:"),
            "tags header present when tags non-empty"
        );
        assert!(
            out.contains("tag:server") && out.contains("tag:ci"),
            "every tag present"
        );
        // Node-key expiry renders as a single line when present.
        assert!(
            out.contains("key-expiry:") && out.contains("2026-09-01 12:00:00 UTC"),
            "node-key expiry present when Some"
        );
        // Liveness: offline → `online: no` AND the last-seen line (offline-only, status convention).
        assert!(
            out.contains("online:       no"),
            "offline node shows online: no"
        );
        assert!(
            out.contains("last-seen:    2026-06-11 05:19:14 UTC"),
            "offline node with known last_seen shows the last-seen line"
        );
    }

    #[test]
    fn format_whois_online_node_shows_online_yes_without_last_seen() {
        // An ONLINE node shows `online: yes` and NO last-seen line (its last-seen is "now" — status
        // only surfaces last-seen for offline peers, and whois mirrors that).
        let w = WhoisReport {
            found: true,
            node_name: Some("peer-b".to_string()),
            node_ipv4: Some("100.64.0.2".to_string()),
            online: Some(true),
            // Even if a last_seen is present, an online node must NOT render the last-seen line.
            last_seen: Some("2026-06-11 05:19:14 UTC".to_string()),
            ..Default::default()
        };
        let out = format_whois(&w, "100.64.0.2");
        assert!(
            out.contains("online:       yes"),
            "online node shows online: yes"
        );
        assert!(
            !out.contains("last-seen:"),
            "an online node must not render a last-seen line (its last-seen is 'now')"
        );
    }

    #[test]
    fn format_whois_omits_absent_optional_fields() {
        // `user` is `None` in this fork by default and capabilities can be empty; neither should
        // emit a stray line. Only the fields that are present render.
        let w = WhoisReport {
            found: true,
            node_name: Some("peer-b".to_string()),
            node_ipv4: Some("100.64.0.2".to_string()),
            user: None,
            capabilities: vec![],
            cap_map: std::collections::BTreeMap::new(),
            tags: vec![],
            node_key_expiry: None,
            online: None,
            last_seen: None,
        };
        let out = format_whois(&w, "100.64.0.2");
        assert!(out.contains("peer-b"));
        assert!(out.contains("100.64.0.2"));
        assert!(!out.contains("user:"), "no user line when user is None");
        assert!(
            !out.contains("capabilities:"),
            "no capabilities header when the set is empty"
        );
        assert!(
            !out.contains("cap-grants:"),
            "no cap-grants header when the flow-scoped cap_map is empty"
        );
        assert!(
            !out.contains("tags:"),
            "no tags header when the set is empty"
        );
        assert!(
            !out.contains("key-expiry:"),
            "no key-expiry line when expiry is None"
        );
        assert!(
            !out.contains("online:"),
            "no online line when liveness is unknown (None)"
        );
    }

    #[test]
    fn format_whois_sanitizes_control_supplied_node_name() {
        // The node name comes from the control server (semi-trusted); a malicious one must not be
        // able to smuggle terminal escapes through `tnet whois`. `format_whois` runs it through
        // `sanitize_for_terminal`, so the raw ESC/BEL bytes are stripped.
        let w = WhoisReport {
            found: true,
            node_name: Some("evil\x1b[2J\x07name".to_string()),
            node_ipv4: Some("100.64.0.2".to_string()),
            user: None,
            capabilities: vec![],
            // Flow-scoped cap grants are control-supplied too — BOTH the cap NAME and each grant VALUE
            // must be sanitized. Smuggle a terminal escape into a cap name AND into a value.
            cap_map: std::collections::BTreeMap::from([(
                "cap/\x1b]0;pwned\x07evil".to_string(),
                vec!["bad\x1b[2Jvalue".to_string()],
            )]),
            // Tags are also control-supplied — a hostile one must be sanitized just like the name.
            tags: vec!["tag:\x1bevil\x07".to_string()],
            node_key_expiry: None,
            online: None,
            last_seen: None,
        };
        let out = format_whois(&w, "100.64.0.2");
        assert!(
            !out.contains('\x1b'),
            "ESC must be stripped from node name + tags + cap-grant name/value"
        );
        assert!(
            !out.contains('\x07'),
            "BEL must be stripped from node name + tags + cap-grant name/value"
        );
        // The readable parts survive (just the control bytes become the replacement char).
        assert!(out.contains("evil"));
        assert!(out.contains("name"));
        // The cap-grant's readable fragments survive sanitization too (control bytes replaced).
        assert!(
            out.contains("value"),
            "cap-grant value's readable text survives"
        );
    }

    #[test]
    fn sanitize_strips_terminal_escapes_keeps_plain_text() {
        // The registration-failure reason is the one free-form, possibly multi-line field, so it is
        // printed via `sanitize_multiline`: ANSI/terminal escapes must be neutralized so a malicious
        // control server can't drive the operator's terminal, but plain text AND ordinary whitespace
        // (so a multi-line message stays legible) survive unchanged.
        let evil = "auth rejected\x1b[2J\x1b[31mFAKE PROMPT\x07 token=\x00secret";
        let clean = sanitize_multiline(evil);
        assert!(
            !clean.contains('\x1b'),
            "ESC must be stripped, got {clean:?}"
        );
        assert!(!clean.contains('\x07'), "BEL must be stripped");
        assert!(!clean.contains('\x00'), "NUL must be stripped");
        // The readable words are preserved (just the control bytes become the replacement char).
        assert!(clean.contains("auth rejected"));
        assert!(clean.contains("token="));

        // Ordinary text and whitespace pass through verbatim in the multi-line reason path.
        let benign = "authentication rejected by control: key not found\n\tretry later";
        assert_eq!(
            sanitize_multiline(benign),
            benign,
            "plain text + tab/newline must be unchanged in a free-form reason"
        );
    }

    #[test]
    fn sanitize_neutralizes_unicode_line_separators_and_bidi_overrides() {
        // Beyond C0/C1 controls: U+2028/U+2029 (some terminals break a line on these → a forged row)
        // and the bidi overrides/isolates U+202A–202E / U+2066–2069 (reorder displayed text — the
        // "Trojan Source" class) are NOT `char::is_control()`, so they used to pass through. Both
        // sanitizers must now map them to U+FFFD.
        for evil in [
            "node-a\u{2028}fake-row",       // line separator
            "node-a\u{2029}fake-row",       // paragraph separator
            "good\u{202E}evil\u{202C}name", // RLO + PDF (bidi override)
            "iso\u{2066}late\u{2069}",      // LRI + PDI (bidi isolate)
        ] {
            let clean = sanitize_for_terminal(evil);
            for bad in [
                '\u{2028}', '\u{2029}', '\u{202A}', '\u{202E}', '\u{2066}', '\u{2069}',
            ] {
                assert!(
                    !clean.contains(bad),
                    "sanitize_for_terminal must strip {bad:?} (from {evil:?}), got {clean:?}"
                );
            }
            // The multiline path must strip them too (a Unicode line/para separator is NOT the plain
            // \n/\r it preserves — it is still a spoofing vector).
            let clean_ml = sanitize_multiline(evil);
            assert!(
                !clean_ml.contains('\u{2028}')
                    && !clean_ml.contains('\u{2029}')
                    && !clean_ml.contains('\u{202E}')
                    && !clean_ml.contains('\u{2066}'),
                "sanitize_multiline must strip the Unicode separators + bidi from {evil:?}, got {clean_ml:?}"
            );
            // The ASCII letters survive.
            assert!(clean.contains("node") || clean.contains("good") || clean.contains("iso"));
        }
        // A plain ASCII name is untouched (no false positives).
        assert_eq!(
            sanitize_for_terminal("node-a.example.ts.net"),
            "node-a.example.ts.net"
        );
    }

    #[test]
    fn revert_pref_to_flag_maps_keys_to_their_up_flags() {
        // Value prefs render as `--flag=value`; the daemon's `advertise_routes` value is already
        // comma-joined and re-passed verbatim.
        assert_eq!(
            revert_pref_to_flag("advertise_routes", "10.0.0.0/8,192.168.1.0/24"),
            "--advertise-routes=10.0.0.0/8,192.168.1.0/24"
        );
        assert_eq!(
            revert_pref_to_flag("exit_node", "100.64.0.9"),
            "--exit-node=100.64.0.9"
        );
        assert_eq!(
            revert_pref_to_flag("hostname", "node-a"),
            "--hostname=node-a"
        );
        // Boolean prefs: the guard only reports them when non-default (true), so the keep-it token is
        // the bare enabling flag.
        assert_eq!(revert_pref_to_flag("ssh", "true"), "--ssh");
        assert_eq!(
            revert_pref_to_flag("accept_routes", "true"),
            "--accept-routes"
        );
        assert_eq!(revert_pref_to_flag("shields_up", "true"), "--shields-up");
        // The Go pref flags `up` shares with `set`: bools render as the bare enabling flag (the only
        // case the guard reports), and the value-bearing `operator` as `--operator=<user>`.
        assert_eq!(
            revert_pref_to_flag("exit_node_allow_lan_access", "true"),
            "--exit-node-allow-lan-access"
        );
        assert_eq!(
            revert_pref_to_flag("advertise_connector", "true"),
            "--advertise-connector"
        );
        assert_eq!(
            revert_pref_to_flag("report_posture", "true"),
            "--report-posture"
        );
        assert_eq!(revert_pref_to_flag("operator", "alice"), "--operator=alice");
        assert_eq!(revert_pref_to_flag("tun", "true"), "--tun");
        // Defensive: a false bool renders the disabling flag (shouldn't occur from the guard).
        assert_eq!(revert_pref_to_flag("ssh", "false"), "--no-ssh");
        // Unknown key (daemon newer than CLI): still actionable, not dropped.
        assert_eq!(revert_pref_to_flag("future_pref", "x"), "--future_pref=x");
    }

    #[test]
    fn format_licenses_is_fork_true_and_local() {
        let out = format_licenses();
        // Names THIS fork + its license + repo (not Tailscale's hosted URL), and points at the
        // offline cargo dependency-license path. Pure/local — no network or daemon involved.
        assert!(out.contains("tailscaled-rs"), "{out}");
        assert!(out.contains("BSD-3-Clause"), "{out}");
        assert!(
            out.contains("github.com/GeiserX/tailscaled-rs"),
            "must point at this fork's repo, not tailscale.com: {out}"
        );
        assert!(
            !out.contains("tailscale.com/licenses"),
            "must NOT point at Tailscale's hosted licenses page (wrong dep set): {out}"
        );
        assert!(out.contains("cargo about"), "{out}");
    }

    #[test]
    fn format_version_shapes() {
        // Plain, no daemon → bare client version line (Go's first line). `cap` is irrelevant to the
        // human form (a stable even minor here so no unstable marker anyway).
        assert_eq!(format_version("0.10.0", None, 130, false), "0.10.0\n");
        // Plain, with daemon → Client:/Daemon: pair (Go's --daemon form).
        assert_eq!(
            format_version("0.10.0", Some("0.10.0"), 130, false),
            "Client: 0.10.0\nDaemon: 0.10.0\n"
        );
        // JSON, no daemon → Go version.Meta shape. Parse it and assert the keys/values.
        let j: serde_json::Value =
            serde_json::from_str(format_version("0.10.0", None, 130, true).trim()).unwrap();
        assert_eq!(j["majorMinorPatch"], "0.10.0");
        assert_eq!(j["short"], "0.10.0");
        assert_eq!(j["long"], "0.10.0");
        assert_eq!(j["cap"], 130, "cap = the engine capability version");
        assert!(
            j.get("daemonLong").is_none(),
            "no daemonLong without --daemon"
        );
        assert!(
            j.get("unstableBranch").is_none(),
            "even minor (10) is stable → unstableBranch omitted"
        );
        // JSON, with daemon → daemonLong present (the queried daemon version).
        let jd: serde_json::Value =
            serde_json::from_str(format_version("0.10.0", Some("0.8.0"), 130, true).trim())
                .unwrap();
        assert_eq!(jd["majorMinorPatch"], "0.10.0");
        assert_eq!(jd["daemonLong"], "0.8.0");
        // JSON, odd minor → unstableBranch:true (Go IsUnstableBuild).
        let ju: serde_json::Value =
            serde_json::from_str(format_version("0.11.0", None, 130, true).trim()).unwrap();
        assert_eq!(ju["unstableBranch"], true, "odd minor (11) is unstable");
    }

    #[test]
    fn version_unstable_minor_and_parse() {
        // Go IsUnstableBuild: odd minor = unstable, even = stable.
        assert!(is_unstable_minor(11));
        assert!(is_unstable_minor(1));
        assert!(!is_unstable_minor(10));
        assert!(!is_unstable_minor(0));
        // minor_of parses the middle field, tolerating a (currently-unused) pre-release suffix.
        assert_eq!(minor_of("0.32.0"), Some(32));
        assert_eq!(minor_of("1.2.3"), Some(2));
        assert_eq!(minor_of("0.31.0-dev"), Some(31));
        assert_eq!(minor_of("garbage"), None);
    }

    #[test]
    fn format_get_set_flags_emits_reappliable_line() {
        use tailscaled_rs::localapi::PrefsView;
        let view = PrefsView {
            hostname: Some("node-a".into()),
            exit_node: None,
            advertise_exit_node: false,
            advertise_routes: vec!["10.0.0.0/8".into()],
            advertise_tags: vec![],
            accept_routes: true,
            accept_dns: false,
            shields_up: true,
            ssh: false,
            ssh_running: false,
            tun: false,
            advertise_connector: false,
            auto_update: None,
            update_check: true,
            operator: None,
            nickname: None,
            report_posture: false,
            webclient: false,
            exit_node_allow_lan_access: false,
        };
        let line = format_get_set_flags(&view);
        // Every setting is `--name=value`, space-joined (Go getOutputSetFlags / fmtFlagValueArg).
        assert!(line.contains("--hostname=node-a"), "{line}");
        assert!(line.contains("--accept-routes=true"), "{line}");
        assert!(line.contains("--accept-dns=false"), "{line}");
        assert!(line.contains("--shields-up=true"), "{line}");
        assert!(line.contains("--advertise-routes=10.0.0.0/8"), "{line}");
        // Unset/empty values render as a bare `--name=` (Go's explicit empty form), not omitted.
        assert!(
            line.contains("--exit-node= "),
            "unset exit-node → empty: {line}"
        );
        assert!(
            line.contains("--advertise-tags= "),
            "empty tags → empty: {line}"
        );
        // It's a single space-joined line (no newlines), re-pasteable into `tnet set`.
        assert!(!line.contains('\n'), "must be one line: {line}");
    }

    #[test]
    fn format_get_shapes() {
        use tailscaled_rs::localapi::PrefsView;
        let view = PrefsView {
            hostname: Some("node-a".into()),
            exit_node: Some("100.64.0.9".into()),
            advertise_exit_node: false,
            advertise_routes: vec!["10.0.0.0/8".into(), "192.168.1.0/24".into()],
            advertise_tags: vec![],
            accept_routes: true,
            accept_dns: true,
            shields_up: true,
            ssh: true,
            ssh_running: true,
            tun: false,
            advertise_connector: true,
            auto_update: Some(true),
            update_check: true,
            operator: Some("alice".into()),
            nickname: Some("laptop".into()),
            report_posture: true,
            webclient: false,
            exit_node_allow_lan_access: true,
        };

        // Default table: a `NAME  VALUE` header line (Go `getOutputTable`) then one line per setting.
        let table = format_get(&view, None, false).unwrap();
        // First line is the header.
        assert!(
            table.starts_with("NAME") && table.lines().next().unwrap().contains("VALUE"),
            "the table must lead with a NAME/VALUE header, like Go: {table}"
        );
        assert!(table.contains("accept-routes"), "{table}");
        assert!(table.contains("shields-up"), "{table}");
        assert!(table.contains("true"), "{table}");
        assert!(
            table.contains("advertise-routes") && table.contains("10.0.0.0/8,192.168.1.0/24"),
            "{table}"
        );
        assert!(table.contains("advertise-tags"), "{table}");
        assert!(table.contains("accept-dns"), "{table}");
        assert!(
            table.contains("hostname") && table.contains("node-a"),
            "hostname must be listed with its value: {table}"
        );
        // 1 header + 18 settings (hostname, exit-node, advertise-exit-node, advertise-routes,
        // advertise-tags, accept-routes, accept-dns, shields-up, ssh, tun, advertise-connector,
        // auto-update, update-check, operator, nickname, report-posture, webclient,
        // exit-node-allow-lan-access) → 19 lines.
        assert_eq!(table.lines().count(), 19, "{table}");
        // The Go pref flags added alongside their engine `Config` fields are listed too, keyed by the
        // same `tnet set` flag name Go's `get` uses.
        for name in [
            "advertise-connector",
            "auto-update",
            "update-check",
            "operator",
            "nickname",
            "report-posture",
            "webclient",
            "exit-node-allow-lan-access",
        ] {
            assert!(
                table.contains(name),
                "{name} missing from the table: {table}"
            );
        }

        // --json: flattened name→value map keyed by set-flag name, with GO-FAITHFUL TYPED values —
        // booleans are bare JSON `true`/`false` (NOT quoted strings), strings are strings. Parse it
        // and assert on the typed values (more robust than string-matching, and proves the shape).
        let j = format_get(&view, None, true).unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(&j).expect("get --json must be valid JSON");
        assert_eq!(
            parsed["accept-routes"],
            serde_json::json!(true),
            "bare bool: {j}"
        );
        assert_eq!(
            parsed["shields-up"],
            serde_json::json!(true),
            "bare bool: {j}"
        );
        assert_eq!(parsed["ssh"], serde_json::json!(true), "{j}");
        assert_eq!(
            parsed["advertise-exit-node"],
            serde_json::json!(false),
            "{j}"
        );
        assert_eq!(parsed["exit-node"], serde_json::json!("100.64.0.9"), "{j}");
        assert_eq!(
            parsed["advertise-routes"],
            serde_json::json!("10.0.0.0/8,192.168.1.0/24"),
            "{j}"
        );
        assert_eq!(
            parsed["advertise-connector"],
            serde_json::json!(true),
            "{j}"
        );
        assert_eq!(parsed["operator"], serde_json::json!("alice"), "{j}");
        assert_eq!(parsed["nickname"], serde_json::json!("laptop"), "{j}");
        assert_eq!(parsed["report-posture"], serde_json::json!(true), "{j}");
        assert_eq!(parsed["webclient"], serde_json::json!(false), "{j}");
        assert_eq!(
            parsed["exit-node-allow-lan-access"],
            serde_json::json!(true),
            "{j}"
        );
        // `auto-update` is Go's tri-state `opt.Bool`: an explicit opt-in is a bare `true`, and a
        // never-stated value is `null` — NOT `false` (which would claim an explicit opt-OUT).
        assert_eq!(parsed["auto-update"], serde_json::json!(true), "{j}");
        let unstated = format_get(
            &PrefsView {
                auto_update: None,
                ..view.clone()
            },
            Some("auto-update"),
            true,
        )
        .unwrap();
        assert_eq!(
            unstated, "null\n",
            "an unstated auto-update must render as null, not false"
        );

        // Single named setting → just its value (plain).
        assert_eq!(
            format_get(&view, Some("accept-routes"), false).unwrap(),
            "true\n"
        );
        assert_eq!(
            format_get(&view, Some("advertise-routes"), false).unwrap(),
            "10.0.0.0/8,192.168.1.0/24\n"
        );
        // Single setting --json → the typed JSON value (bare bool for a boolean setting).
        assert_eq!(format_get(&view, Some("ssh"), true).unwrap(), "true\n");
        assert_eq!(
            format_get(&view, Some("exit-node"), true).unwrap(),
            "\"100.64.0.9\"\n"
        );

        // "all" behaves like None (all settings).
        assert_eq!(format_get(&view, Some("all"), false).unwrap(), table);

        // Unknown setting → error (Go errors too).
        assert!(format_get(&view, Some("no-such-setting"), false).is_err());
    }

    /// A 64-hex tailnet-lock public key for the argument tests. Not a real key — the parse only
    /// cares about the prefix, the length and the alphabet.
    const TEST_LOCK_KEY: &str =
        "tlpub:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

    /// Arguments for `plan_lock_init` with everything at its default, so each test names only what
    /// it is exercising.
    fn init_args<'a>(positionals: &'a [String]) -> LockInitArgs<'a> {
        LockInitArgs {
            positionals,
            gen_disablements: None,
            gen_disablement_for_support: false,
            confirm: false,
            supplied_secret: None,
        }
    }

    /// A deterministic stand-in for the OS CSPRNG so the minted secret is pinnable.
    fn fixed_mint() -> impl FnMut() -> Result<[u8; 32]> {
        || Ok([0xab; 32])
    }

    #[test]
    fn parse_lock_args_ports_gos_positional_grammar() {
        // A bare key: votes default to 1 (Go `tka.Key{..., Votes: 1}`), and both the CLI prefix and
        // the wire prefix decode, as Go's `NLPublic.UnmarshalText` accepts either.
        let args = vec![
            TEST_LOCK_KEY.to_string(),
            TEST_LOCK_KEY.replace("tlpub:", "nlpub:"),
        ];
        let (keys, disablements) = parse_lock_args(&args, true, true).unwrap();
        assert_eq!(keys.len(), 2, "both prefixes must parse: {keys:?}");
        assert_eq!(keys[0].public[0], 0x01);
        assert_eq!(keys[0].public[31], 0x20);
        assert_eq!(keys[0].votes, 1);
        assert_eq!(keys[0].public, keys[1].public);
        assert!(disablements.is_empty());

        // `<key>?<votes>` weights a key (Go `strings.SplitN(a, "?", 2)` + `strconv.Atoi`).
        let args = vec![format!("{TEST_LOCK_KEY}?3")];
        let (keys, _) = parse_lock_args(&args, true, true).unwrap();
        assert_eq!(keys[0].votes, 3);

        // Both disablement prefixes are values, hex-decoded, in argument order.
        let args = vec![
            "disablement:00ff".to_string(),
            "disablement-secret:1020".to_string(),
        ];
        let (keys, disablements) = parse_lock_args(&args, true, true).unwrap();
        assert!(keys.is_empty());
        assert_eq!(disablements, vec![vec![0x00, 0xff], vec![0x10, 0x20]]);

        // Go's error messages, which are the only feedback a mistyped argument gets.
        let err = |a: &str| {
            parse_lock_args(&[a.to_string()], true, true)
                .unwrap_err()
                .to_string()
        };
        assert!(
            err("deadbeef")
                .contains("parsing key 1: key hex string doesn't have expected type prefix tlpub:"),
            "{}",
            err("deadbeef")
        );
        assert!(
            err("tlpub:00").contains("key hex has the wrong size, got 2 want 64"),
            "{}",
            err("tlpub:00")
        );
        assert!(
            err(&TEST_LOCK_KEY.replace("0102", "zz02")).contains("invalid hex character in key"),
            "{}",
            err(&TEST_LOCK_KEY.replace("0102", "zz02"))
        );
        assert!(
            err(&format!("{TEST_LOCK_KEY}?x")).contains("parsing key 1 votes"),
            "{}",
            err(&format!("{TEST_LOCK_KEY}?x"))
        );
        assert!(
            err("disablement:0f0").contains("parsing disablement 1"),
            "{}",
            err("disablement:0f0")
        );
        // `parseKeys=false` (Go's `lock add`/`remove` shape) rejects a key with the message naming
        // the two prefixes it does accept.
        let e = parse_lock_args(&[TEST_LOCK_KEY.to_string()], false, true)
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("expected value with \"disablement:\" or \"disablement-secret:\" prefix"),
            "{e}"
        );
    }

    #[test]
    fn lock_hex_arguments_reject_non_ascii_instead_of_panicking() {
        // Every length check on this path counts BYTES, like Go's, so a multibyte argument can pass
        // it and still not be splittable at byte 2. `str` indexing panicked there, killing the
        // process on nothing worse than a mistyped key. 21 × `€` (3 bytes each) + `a` is 64 bytes.
        let multibyte = "€".repeat(21) + "a";
        assert_eq!(
            multibyte.len(),
            64,
            "the fixture has to pass the byte-length check"
        );

        let e = parse_lock_public_key(&format!("tlpub:{multibyte}"))
            .expect_err("non-ASCII must be an error, not a panic")
            .to_string();
        assert_eq!(e, "invalid hex character in key", "{e}");

        // And through the argument parser an operator actually reaches, for both kinds of value.
        let err = |a: &str| {
            parse_lock_args(&[a.to_string()], true, true)
                .expect_err("non-ASCII must be an error, not a panic")
                .to_string()
        };
        let e = err(&format!("tlpub:{multibyte}"));
        assert!(
            e.contains("parsing key 1: invalid hex character in key"),
            "{e}"
        );
        let e = err(&format!("disablement:{}", "€".repeat(2)));
        assert!(e.contains("parsing disablement 1: invalid hex byte"), "{e}");

        // `hex_decode_lower` takes the same operator input via `--disablement-secret`.
        assert!(hex_decode_lower("€€").is_err(), "multibyte hex rejected");
        assert_eq!(
            hex_decode_lower("00FF").unwrap(),
            vec![0x00, 0xff],
            "upper-hex still decodes"
        );

        // `u8::from_str_radix` also accepted a leading sign, so `+f` decoded as 0x0f — one more
        // string Go's `fromHexChar` refuses and this used to take.
        assert!(
            hex_decode_lower("+f").is_err(),
            "leading sign is not a hex byte"
        );
        let e = parse_lock_public_key(&format!("tlpub:+f{}", "0".repeat(62)))
            .expect_err("leading sign is not a hex byte")
            .to_string();
        assert_eq!(e, "invalid hex character in key", "{e}");
    }

    #[test]
    fn lock_init_never_reads_a_trusted_key_as_a_disablement_secret() {
        // The regression this command's grammar change is for. Both spellings an operator could
        // plausibly type used to be swallowed as a "disablement secret":
        //   * a tailnet lock public key — Go's actual positional — which would have gated the lock
        //     with a value that is, by construction, public;
        //   * a bare hex secret, this fork's old positional, which quietly meant something else
        //     than the same command line does upstream.
        // Both must now fail, saying what is wrong.
        let key = vec![TEST_LOCK_KEY.to_string()];
        let e = plan_lock_init("tnet", &init_args(&key), false, &mut fixed_mint())
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("cannot initialize tailnet lock with a chosen trusted-key set")
                && e.contains(
                    "the tailnet lock key of the current node must be one of the trusted keys \
                     during initialization"
                ),
            "{e}"
        );

        let old_positional = vec!["00112233445566778899aabbccddeeff".to_string()];
        let e = plan_lock_init(
            "tnet",
            &init_args(&old_positional),
            false,
            &mut fixed_mint(),
        )
        .unwrap_err()
        .to_string();
        assert!(
            e.contains("parsing key 1: key hex string doesn't have expected type prefix tlpub:"),
            "a bare hex secret must now be read as Go reads it — a malformed key: {e}"
        );
    }

    #[test]
    fn lock_init_refuses_an_already_enabled_lock_before_anything_else() {
        // Go checks the status first, so this wins even over an unparseable argument list.
        let junk = vec!["not-a-key".to_string()];
        let e = plan_lock_init("tnet", &init_args(&junk), true, &mut fixed_mint())
            .unwrap_err()
            .to_string();
        assert_eq!(e, "tailnet lock is already enabled");
    }

    #[test]
    fn lock_init_without_confirm_changes_nothing_and_prints_the_rerun_command() {
        let none: Vec<String> = Vec::new();
        let plan = plan_lock_init("tnet", &init_args(&none), false, &mut fixed_mint()).unwrap();
        let LockInitPlan::Confirm(text) = plan else {
            panic!("without --confirm the plan must be the two-step, not an init");
        };
        assert!(
            text.starts_with(
                "You are initializing tailnet lock with the following trusted signing keys:\n"
            ),
            "{text}"
        );
        assert!(
            text.contains("1 disablement secrets will be generated."),
            "{text}"
        );
        assert!(
            text.contains(
                "If this is correct, please re-run this command with the --confirm flag:"
            ),
            "{text}"
        );
        assert!(
            text.contains("\ttnet lock init --confirm --gen-disablements 1\n"),
            "the printed command must be runnable as-is: {text}"
        );
        // The operator learns about the support disablement BEFORE committing, not after.
        assert!(
            text.contains("transmits the disablement secret to the coordination server"),
            "{text}"
        );
        // Nothing was minted: no secret may appear in the preview.
        assert!(!text.contains("disablement-secret:"), "{text}");
    }

    #[test]
    fn lock_init_with_confirm_mints_the_secret_and_prints_it_once() {
        let none: Vec<String> = Vec::new();
        let mut args = init_args(&none);
        args.confirm = true;
        let plan = plan_lock_init("tnet", &args, false, &mut fixed_mint()).unwrap();
        let LockInitPlan::Init {
            secret_hex,
            preamble,
            notice,
        } = plan
        else {
            panic!("--confirm must produce an init");
        };
        // Go prints the trusted keys on the confirmed path too, not only in the preview.
        assert!(
            preamble.starts_with(
                "You are initializing tailnet lock with the following trusted signing keys:\n"
            ),
            "{preamble}"
        );
        // 32 bytes of entropy, rendered the way Go renders it (`%X`), and the value handed to the
        // daemon is the very value printed.
        assert_eq!(secret_hex, "AB".repeat(32));
        assert!(
            notice.contains(
                "1 disablement secrets have been generated and are printed below. Take note of \
                 them now, they WILL NOT be shown again."
            ),
            "{notice}"
        );
        assert!(
            notice.contains(&format!("\tdisablement-secret:{secret_hex}\n")),
            "{notice}"
        );
        assert!(
            notice.contains("transmits the disablement secret to the coordination server"),
            "{notice}"
        );
    }

    #[test]
    fn lock_init_refuses_the_arguments_this_engine_cannot_honour() {
        let none: Vec<String> = Vec::new();

        // A second disablement value cannot be stored.
        let mut args = init_args(&none);
        args.gen_disablements = Some(2);
        let e = plan_lock_init("tnet", &args, false, &mut fixed_mint())
            .unwrap_err()
            .to_string();
        assert!(e.contains("cannot honour --gen-disablements 2"), "{e}");

        // Nor may there be none: a lock with no disablement value could never be turned off.
        let mut args = init_args(&none);
        args.gen_disablements = Some(0);
        let e = plan_lock_init("tnet", &args, false, &mut fixed_mint())
            .unwrap_err()
            .to_string();
        assert!(e.contains("requires at least one disablement"), "{e}");

        // Nor can a separate one for the coordination server's operator.
        let mut args = init_args(&none);
        args.gen_disablement_for_support = true;
        let e = plan_lock_init("tnet", &args, false, &mut fixed_mint())
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("cannot honour --gen-disablement-for-support"),
            "{e}"
        );

        // Nor a pre-computed disablement value, whichever prefix it carries.
        let value = vec!["disablement:00ff".to_string()];
        let e = plan_lock_init("tnet", &init_args(&value), false, &mut fixed_mint())
            .unwrap_err()
            .to_string();
        assert!(e.contains("pre-computed disablement value"), "{e}");

        // Minting and supplying the secret are alternatives, not a combination.
        let mut args = init_args(&none);
        args.gen_disablements = Some(1);
        args.supplied_secret = Some("00ff");
        let e = plan_lock_init("tnet", &args, false, &mut fixed_mint())
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("--gen-disablements can only be used without --disablement-secret"),
            "{e}"
        );
    }

    #[test]
    fn lock_init_can_still_be_given_the_operators_own_secret() {
        // The capability the old positional had, under a name that cannot be mistaken for Go's.
        let none: Vec<String> = Vec::new();
        let mut args = init_args(&none);
        args.confirm = true;
        args.supplied_secret = Some("00ff10");
        let plan = plan_lock_init("tnet", &args, false, &mut fixed_mint()).unwrap();
        let LockInitPlan::Init {
            secret_hex, notice, ..
        } = plan
        else {
            panic!("--confirm must produce an init");
        };
        assert_eq!(
            secret_hex, "00ff10",
            "the supplied secret must be used verbatim"
        );
        assert!(
            !notice.contains("disablement-secret:"),
            "a supplied secret is not reprinted: {notice}"
        );

        // A malformed secret fails before the confirmation step, not after it.
        let mut args = init_args(&none);
        args.supplied_secret = Some("nothex");
        let e = plan_lock_init("tnet", &args, false, &mut fixed_mint())
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("--disablement-secret must be hex-encoded"),
            "{e}"
        );
    }

    #[test]
    fn format_lock_status_human_and_json() {
        use tailscaled_rs::localapi::LockReport;
        // Not enabled: Go's exact wording (no "on this tailnet" suffix) + the trailing blank line Go
        // prints unconditionally after the status line.
        let off = LockReport::default();
        assert_eq!(
            format_lock_status(&off, false),
            "Tailnet Lock is NOT enabled.\n\n",
            "must byte-match Go's `Tailnet Lock is NOT enabled.` + blank line"
        );
        // Enabled with a head + pending disablement.
        let on = LockReport {
            enabled: true,
            head: "tka-aumhash-abc".into(),
            disabled: true,
        };
        let h = format_lock_status(&on, false);
        // Status line is byte-exact Go wording, followed by the blank line.
        assert!(h.starts_with("Tailnet Lock is ENABLED.\n\n"), "{h}");
        assert!(h.contains("tka-aumhash-abc"), "{h}");
        assert!(h.contains("disablement is pending"), "{h}");
        // JSON shape (typed bools).
        let j = format_lock_status(&on, true);
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        assert_eq!(v["enabled"], serde_json::json!(true));
        assert_eq!(v["head"], serde_json::json!("tka-aumhash-abc"));
        assert_eq!(v["disabled"], serde_json::json!(true));
    }

    /// `lock log` (Go `tailscale lock log`) over a synthesised daemon report: the stanza shape,
    /// newest-first order, the unsigned (genesis) row, and the JSON object.
    #[test]
    fn format_lock_log_human_and_json() {
        use tailscaled_rs::localapi::{LockLogEntry, LockLogReport};
        let report = LockLogReport {
            enabled: true,
            entries: vec![
                LockLogEntry {
                    hash: "AAAAQ".into(),
                    change: "add-key".into(),
                    signer_key_ids: vec!["tlpub:aabb".into(), "tlpub:ccdd".into()],
                    raw: "a1626b76".into(),
                },
                LockLogEntry {
                    hash: "BBBBQ".into(),
                    change: "checkpoint".into(),
                    signer_key_ids: vec![],
                    raw: "a1626370".into(),
                },
            ],
        };
        let h = format_lock_log(&report, false);
        assert_eq!(
            h,
            "update AAAAQ (add-key)\n  signed by: tlpub:aabb, tlpub:ccdd\n\n\
             update BBBBQ (checkpoint)\n  signed by: (unsigned)\n\n",
            "one stanza per update, head-first, blank line between them"
        );
        // Head-first: the engine returns newest → oldest and the renderer must not re-order.
        assert!(
            h.find("AAAAQ") < h.find("BBBBQ"),
            "newest update must print first: {h}"
        );
        // The raw CBOR is deliberately NOT in the human output (Go prints decoded detail, which this
        // build cannot produce; the bytes are `--json`-only).
        assert!(!h.contains("a1626b76"), "{h}");

        let j = format_lock_log(&report, true);
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        assert_eq!(v["enabled"], serde_json::json!(true));
        assert_eq!(v["entries"].as_array().unwrap().len(), 2);
        assert_eq!(v["entries"][0]["hash"], serde_json::json!("AAAAQ"));
        assert_eq!(v["entries"][0]["change"], serde_json::json!("add-key"));
        assert_eq!(
            v["entries"][0]["signer_key_ids"],
            serde_json::json!(["tlpub:aabb", "tlpub:ccdd"])
        );
        // Raw CBOR IS carried in JSON, so the full AUM can be decoded out-of-band.
        assert_eq!(v["entries"][0]["raw"], serde_json::json!("a1626b76"));
    }

    /// The two empty histories must be distinguishable in words, not an empty table: lock off vs.
    /// lock on with nothing synced to this node yet.
    #[test]
    fn format_lock_log_empty_says_which_empty_it_is() {
        use tailscaled_rs::localapi::LockLogReport;
        // Lock not in use: the same sentence `lock status` prints, so the two verbs agree.
        let off = LockLogReport::default();
        assert_eq!(
            format_lock_log(&off, false),
            "Tailnet Lock is NOT enabled.\n\n"
        );
        // Lock in use, but this node has synced no chain yet.
        let on_but_empty = LockLogReport {
            enabled: true,
            entries: vec![],
        };
        let h = format_lock_log(&on_but_empty, false);
        assert!(h.starts_with("Tailnet Lock is ENABLED,"), "{h}");
        assert!(h.contains("no update-chain history has synced"), "{h}");
        // JSON stays a well-formed object with an empty list in both cases (no null, no bare array).
        let v: serde_json::Value = serde_json::from_str(&format_lock_log(&off, true)).unwrap();
        assert_eq!(v["enabled"], serde_json::json!(false));
        assert_eq!(v["entries"], serde_json::json!([]));
    }

    #[test]
    fn format_dns_status_populated_human_and_json() {
        use tailscaled_rs::localapi::DnsStatusReport;
        let report = DnsStatusReport {
            magic_dns: true,
            search_domains: vec!["user.ts.net".into()],
            resolvers: vec!["100.100.100.100:53".into(), "8.8.8.8:53".into()],
            routes: std::collections::BTreeMap::from([(
                "corp.example.com".to_string(),
                vec!["10.0.0.53:53".to_string()],
            )]),
            fallback_resolvers: vec!["1.1.1.1:53".into()],
            cert_domains: vec!["host.user.ts.net".into()],
            extra_records: vec![("printer.user.ts.net".into(), "100.64.0.7".into())],
            exit_node_filtered_set: vec![".internal".into()],
        };
        // Human form: the populated resolver/route/search lines appear, MagicDNS reads enabled, and
        // the honest omission note is present.
        let h = format_dns_status(&report, false);
        assert!(h.contains("MagicDNS: enabled tailnet-wide"), "{h}");
        assert!(h.contains("  - 100.100.100.100:53"), "{h}");
        assert!(h.contains("  - 8.8.8.8:53"), "{h}");
        assert!(h.contains("corp.example.com"), "{h}");
        assert!(h.contains("-> 10.0.0.53:53"), "{h}");
        assert!(h.contains("  - user.ts.net"), "{h}");
        assert!(h.contains("  - 1.1.1.1:53"), "{h}");
        assert!(h.contains("host.user.ts.net"), "{h}");
        assert!(h.contains("printer.user.ts.net -> 100.64.0.7"), "{h}");
        assert!(h.contains(".internal"), "{h}");
        assert!(
            h.contains("not surfaced by this build"),
            "the honest omission note must be present: {h}"
        );
        // JSON form: Go-shaped keys + a bare MagicDNS bool, escape-safe via serde.
        let j = format_dns_status(&report, true);
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        assert_eq!(v["MagicDNS"], serde_json::json!(true));
        assert_eq!(
            v["Resolvers"],
            serde_json::json!(["100.100.100.100:53", "8.8.8.8:53"])
        );
        assert_eq!(
            v["SplitDNSRoutes"]["corp.example.com"],
            serde_json::json!(["10.0.0.53:53"])
        );
        assert_eq!(v["SearchDomains"], serde_json::json!(["user.ts.net"]));
        assert_eq!(v["FallbackResolvers"], serde_json::json!(["1.1.1.1:53"]));
        assert_eq!(v["CertDomains"], serde_json::json!(["host.user.ts.net"]));
        assert_eq!(
            v["ExtraRecords"]["printer.user.ts.net"],
            serde_json::json!("100.64.0.7")
        );
        assert_eq!(v["ExitNodeFilteredSet"], serde_json::json!([".internal"]));
    }

    #[test]
    fn format_dns_status_empty_renders_none_lines() {
        use tailscaled_rs::localapi::DnsStatusReport;
        // The no-netmap / default report: MagicDNS disabled + every section a parenthetical none-line.
        let empty = DnsStatusReport::default();
        let h = format_dns_status(&empty, false);
        assert!(h.contains("MagicDNS: disabled tailnet-wide"), "{h}");
        assert!(
            h.contains("Resolvers (in preference order):\n  (none configured)"),
            "{h}"
        );
        assert!(h.contains("Split DNS Routes:\n  (none)"), "{h}");
        assert!(h.contains("Search Domains:\n  (none)"), "{h}");
        assert!(h.contains("Fallback Resolvers:\n  (none)"), "{h}");
        assert!(h.contains("Certificate Domains:\n  (none)"), "{h}");
        assert!(h.contains("Additional DNS Records:\n  (none)"), "{h}");
        assert!(
            h.contains("Filtered suffixes (exit-node):\n  (none)"),
            "{h}"
        );
        assert!(h.contains("not surfaced by this build"), "{h}");
        // JSON: a default report still carries a bare MagicDNS:false + empty collections.
        let v: serde_json::Value = serde_json::from_str(&format_dns_status(&empty, true)).unwrap();
        assert_eq!(v["MagicDNS"], serde_json::json!(false));
        assert_eq!(v["Resolvers"], serde_json::json!([]));
    }

    #[test]
    fn parse_and_name_qtype_round_trip_plus_numeric_and_rcode() {
        // Mnemonics (case-insensitive) → numbers, and back.
        for (name, num) in [
            ("A", 1u16),
            ("aaaa", 28),
            ("CNAME", 5),
            ("ptr", 12),
            ("TXT", 16),
            ("caa", 257),
        ] {
            assert_eq!(parse_qtype(name), Some(num), "parse {name}");
            assert_eq!(qtype_name(num), name.to_ascii_uppercase(), "name {num}");
        }
        // A bare decimal TYPE is accepted (so uncommon types stay reachable) and an unknown number
        // renders RFC-3597-style.
        assert_eq!(parse_qtype("65"), Some(65));
        assert_eq!(qtype_name(65), "TYPE65");
        // Garbage → None.
        assert_eq!(parse_qtype("nope"), None);
        assert_eq!(parse_qtype(""), None);
        // RCODE mnemonics + unknown.
        assert_eq!(rcode_name(0), "NoError");
        assert_eq!(rcode_name(3), "NXDomain");
        assert_eq!(rcode_name(5), "Refused");
        assert_eq!(rcode_name(11), "RCODE11");
    }

    #[test]
    fn decode_dns_header_reads_fixed_fields_and_rejects_short() {
        // A hand-built 12-byte header: id=0x1234, flags=0x8180, QD=1, AN=2, NS=0, AR=1.
        let hex = "12348180000100020000000100";
        let h = decode_dns_header(hex).expect("12+ bytes decodes");
        assert_eq!(h.id, 0x1234);
        assert_eq!((h.qd, h.an, h.ns, h.ar), (1, 2, 0, 1));
        // Too short (< 24 hex chars = < 12 bytes) → None (not a panic / garbage).
        assert!(decode_dns_header("1234").is_none());
        assert!(decode_dns_header("").is_none());
    }

    #[test]
    fn format_dns_query_human_and_json() {
        use tailscaled_rs::localapi::DnsQueryReport;
        // A forwarded NoError answer: id=0x1234 flags=0x8180 QD=1 AN=1, one resolver consulted.
        let r = DnsQueryReport {
            name: "example.com".into(),
            qtype: 1,
            rcode: 0,
            resolvers_consulted: vec!["8.8.8.8:53".into()],
            response_hex: "12348180000100010000000000".into(),
        };
        let h = format_dns_query(&r, false);
        assert!(h.contains("query:    example.com A"), "{h}");
        assert!(h.contains("rcode:    NoError (0)"), "{h}");
        assert!(h.contains("- 8.8.8.8:53"), "{h}");
        assert!(h.contains("questions=1 answers=1"), "{h}");
        assert!(h.contains("answer records are not decoded"), "{h}");

        // A locally-answered query (no resolver egressed) → the explicit local note.
        let local = DnsQueryReport {
            name: "host.tailnet.ts.net".into(),
            qtype: 1,
            rcode: 0,
            resolvers_consulted: vec![],
            response_hex: "abcd8180000100010000000000".into(),
        };
        assert!(
            format_dns_query(&local, false).contains("answered locally"),
            "local query must say so"
        );

        // JSON shape: mnemonic + numeric for both qtype and rcode, plus the decoded header.
        let v: serde_json::Value = serde_json::from_str(&format_dns_query(&r, true)).unwrap();
        assert_eq!(v["Name"], serde_json::json!("example.com"));
        assert_eq!(v["QType"], serde_json::json!("A"));
        assert_eq!(v["RCode"], serde_json::json!("NoError"));
        assert_eq!(v["Header"]["ANCount"], serde_json::json!(1));
        assert_eq!(v["ResolversConsulted"], serde_json::json!(["8.8.8.8:53"]));
    }

    #[test]
    fn format_netcheck_populated_human_and_json() {
        use tailscaled_rs::localapi::{NetcheckReport, RegionLatencyView};
        // Region 10 included DELIBERATELY: it distinguishes serde's lexicographic key order
        // ("1" < "10" < "7") from numeric order (1 < 7 < 10), so the ordering assertion below is not
        // vacuous. A duplicate region_id (7) is included to pin the BTreeMap's dedup (last write wins).
        let report = NetcheckReport {
            preferred_derp: Some(1),
            region_latencies: vec![
                RegionLatencyView {
                    region_id: 1,
                    latency_ms: 23.42,
                },
                RegionLatencyView {
                    region_id: 7,
                    latency_ms: 99.9, // superseded by the dedup entry below
                },
                RegionLatencyView {
                    region_id: 10,
                    latency_ms: 5.0,
                },
                RegionLatencyView {
                    region_id: 7,
                    latency_ms: 41.7, // last write for region 7 wins
                },
            ],
        };
        // Human form: the preferred region, per-region latency lines (formatted to 0.1ms), and the
        // honest omission note.
        let h = format_netcheck(&report, NetcheckFormat::Human);
        assert!(h.contains("Report:"), "{h}");
        assert!(h.contains("* Nearest DERP: region 1"), "{h}");
        assert!(h.contains("- region 1: 23.4ms"), "{h}");
        assert!(h.contains("- region 10: 5.0ms"), "{h}");
        assert!(
            h.contains("DERP-region latency only"),
            "the honest reduced-scope note must be present: {h}"
        );
        // JSON form: Go's field names + value encoding — a bare numeric PreferredDERP and a
        // RegionLatency map keyed by stringified region id with integer-NANOSECOND values
        // (`map[int]time.Duration` marshalled as ns). 23.42ms = 23_420_000ns; 41.7ms = 41_700_000ns.
        let j = format_netcheck(&report, NetcheckFormat::Json);
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        assert_eq!(v["PreferredDERP"], serde_json::json!(1));
        assert_eq!(v["RegionLatency"]["1"], serde_json::json!(23_420_000_i64));
        // Dedup: region 7's LAST entry (41.7ms) wins over the earlier 99.9ms.
        assert_eq!(v["RegionLatency"]["7"], serde_json::json!(41_700_000_i64));
        assert_eq!(v["RegionLatency"]["10"], serde_json::json!(5_000_000_i64));
        // Exactly 3 distinct keys (the duplicate 7 was deduped).
        assert_eq!(v["RegionLatency"].as_object().unwrap().len(), 3, "{j}");
        // Key order is serde_json's LEXICOGRAPHIC string order ("1" < "10" < "7"), NOT numeric — and
        // that is fine (JSON object key order is non-semantic). Pin the real behavior so the claim and
        // the test agree: "10" precedes "7" in the emitted bytes.
        assert!(
            j.find("\"10\":").unwrap() < j.find("\"7\":").unwrap(),
            "RegionLatency keys are serde lexicographic order (\"10\" before \"7\"): {j}"
        );
        // Indent is a TAB, matching Go's `json.MarshalIndent(report, "", \"\\t\")`.
        assert!(
            j.contains("\n\t\"PreferredDERP\""),
            "netcheck JSON must use tab indent like Go: {j:?}"
        );
    }

    #[test]
    fn format_netcheck_empty_renders_none_lines() {
        use tailscaled_rs::localapi::NetcheckReport;
        // The pre-measurement / default report: no preferred region + no measured latency → the two
        // none-lines, plus the honest note.
        let empty = NetcheckReport::default();
        let h = format_netcheck(&empty, NetcheckFormat::Human);
        assert!(h.contains("Report:"), "{h}");
        assert!(
            h.contains("* Nearest DERP: (none — not measured yet)"),
            "{h}"
        );
        assert!(h.contains("(no DERP latency measured)"), "{h}");
        assert!(h.contains("DERP-region latency only"), "{h}");
        // JSON: a default report carries PreferredDERP 0 (Go's "0 for unknown", NOT null) + an empty
        // RegionLatency object (Go's `map[int]time.Duration`, empty → `{}`, not `[]`).
        let v: serde_json::Value =
            serde_json::from_str(&format_netcheck(&empty, NetcheckFormat::Json)).unwrap();
        assert_eq!(v["PreferredDERP"], serde_json::json!(0));
        assert_eq!(v["RegionLatency"], serde_json::json!({}));
    }

    #[test]
    fn format_netcheck_json_line_is_one_compact_line() {
        use tailscaled_rs::localapi::{NetcheckReport, RegionLatencyView};
        // `--format json-line`: a single compact JSON object per report (no tabs/newlines inside), so
        // `--every` produces a clean line-per-report stream. Same fields as `json`, just compact.
        let report = NetcheckReport {
            preferred_derp: Some(2),
            region_latencies: vec![RegionLatencyView {
                region_id: 2,
                latency_ms: 23.4,
            }],
        };
        let line = format_netcheck(&report, NetcheckFormat::JsonLine);
        // Exactly one trailing newline, none embedded, no tab indentation.
        assert_eq!(
            line.matches('\n').count(),
            1,
            "json-line is one line + trailing \\n: {line:?}"
        );
        assert!(
            !line.trim_end().contains('\n') && !line.contains('\t'),
            "compact: {line:?}"
        );
        // Still valid JSON with the Go-cased fields + ns-encoded latency (23.4ms → 23_400_000 ns).
        let v: serde_json::Value = serde_json::from_str(line.trim_end()).expect("valid JSON line");
        assert_eq!(v["PreferredDERP"], serde_json::json!(2));
        assert_eq!(v["RegionLatency"]["2"], serde_json::json!(23_400_000_i64));
    }

    #[test]
    fn format_policy_empty_is_no_policy_settings() {
        use tailscaled_rs::localapi::PolicyReport;
        // The normal Linux/Unix result: no registered store → empty snapshot → Go's exact string.
        let empty = PolicyReport {
            scope: "Device".into(),
            settings: vec![],
        };
        assert_eq!(format_policy(&empty, false), "No policy settings\n");
        // JSON form still emits a valid object carrying the scope (settings omitted when empty).
        let v: serde_json::Value = serde_json::from_str(&format_policy(&empty, true)).unwrap();
        assert_eq!(v["scope"], serde_json::json!("Device"));
        // Tab indent like Go's MarshalIndent.
        assert!(
            format_policy(&empty, true).contains("\n\t\"scope\""),
            "policy JSON must use tab indent"
        );
    }

    #[test]
    fn format_policy_populated_table_and_error_row() {
        use tailscaled_rs::localapi::{PolicyReport, PolicySetting};
        // Two value rows + one error row; supplied OUT of key order to prove the sort.
        let r = PolicyReport {
            scope: "Device".into(),
            settings: vec![
                PolicySetting {
                    key: "ExitNodeID".into(),
                    origin: "Platform (Device)".into(),
                    value: Some("n123".into()),
                    error: None,
                },
                PolicySetting {
                    key: "AuthKey".into(),
                    origin: "Platform (Device)".into(),
                    value: None,
                    error: Some("decrypt failed".into()),
                },
                PolicySetting {
                    key: "LoginURL".into(),
                    origin: "Platform (Device)".into(),
                    value: Some("https://controlplane.example".into()),
                    error: None,
                },
            ],
        };
        let h = format_policy(&r, false);
        // Header + dashed separator present.
        assert!(h.contains("Name"), "{h}");
        assert!(h.contains("Origin"), "{h}");
        assert!(h.contains("Value"), "{h}");
        assert!(h.contains("Error"), "{h}");
        assert!(h.contains("----"), "{h}");
        // Rows sorted by key: AuthKey < ExitNodeID < LoginURL.
        let a = h.find("AuthKey").unwrap();
        let e = h.find("ExitNodeID").unwrap();
        let l = h.find("LoginURL").unwrap();
        assert!(a < e && e < l, "rows must be sorted by key: {h}");
        // The error row wraps the error in {...} and shows no value.
        assert!(h.contains("{decrypt failed}"), "{h}");
        // A value row shows its value.
        assert!(h.contains("https://controlplane.example"), "{h}");
        // Trailing blank line (Go's fmt.Println()).
        assert!(
            h.ends_with("\n\n"),
            "policy table ends with a blank line: {h:?}"
        );

        // JSON: settings round-trip with all four logical fields.
        let v: serde_json::Value = serde_json::from_str(&format_policy(&r, true)).unwrap();
        assert_eq!(v["scope"], serde_json::json!("Device"));
        assert_eq!(v["settings"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn format_policy_table_is_byte_faithful_to_go_tabwriter() {
        use tailscaled_rs::localapi::{PolicyReport, PolicySetting};
        // GOLDEN test: the populated table must be byte-for-byte what Go's `printPolicySettings`
        // emits through `text/tabwriter` (minwidth 0, padding 2, padchar ' ', flags 0). The expected
        // literal below was generated by reproducing tabwriter's algorithm for this exact input.
        // KEY POINT (the one all three reviewers flagged): value rows END IN TRAILING WHITESPACE —
        // Go's value-row format `"%s\t%s\t%v\t\n"` tab-terminates the Value cell, so tabwriter pads it
        // to the column width and the empty trailing Error cell leaves that padding at end of line.
        // We must NOT trim it, or we diverge from Go. Error rows (`"%s\t%s\t\t{%v}\n"`) end on the
        // non-empty trailing Error text, so they are not padded. Widths here: Name=10 (ExitNodeID),
        // Origin=17 (Platform (Device)), Value=28 (the URL).
        let r = PolicyReport {
            scope: "Device".into(),
            settings: vec![
                PolicySetting {
                    key: "ExitNodeID".into(),
                    origin: "Platform (Device)".into(),
                    value: Some("n123".into()),
                    error: None,
                },
                PolicySetting {
                    key: "AuthKey".into(),
                    origin: "Platform (Device)".into(),
                    value: None,
                    error: Some("decrypt failed".into()),
                },
                PolicySetting {
                    key: "LoginURL".into(),
                    origin: "Platform (Device)".into(),
                    value: Some("https://controlplane.example".into()),
                    error: None,
                },
            ],
        };
        // Build the expected bytes with an explicit tab-terminated-cell padder. Source-literal lines
        // can't carry trailing whitespace (editors/`cargo fmt` strip it, and it's invisible), so the
        // value rows' trailing padding is injected here — this is exactly what must NOT be trimmed.
        // `pad` left-aligns a cell to `width` + 2 spaces, matching tabwriter (padding 2). The widths
        // (Name=10, Origin=17, Value=28) are hand-derived from the inputs above.
        let pad =
            |s: &str, width: usize| format!("{s}{}", " ".repeat(width - s.chars().count() + 2));
        let mut expected = String::new();
        // Header + dashed separator (Value/Origin/Name are tab-terminated → padded; Error trailing).
        expected.push_str(&pad("Name", 10));
        expected.push_str(&pad("Origin", 17));
        expected.push_str(&pad("Value", 28));
        expected.push_str("Error\n");
        expected.push_str(&pad("----", 10));
        expected.push_str(&pad("------", 17));
        expected.push_str(&pad("-----", 28));
        expected.push_str("-----\n");
        // AuthKey: error row — empty Value cell (still padded to width), error trailing, unpadded.
        expected.push_str(&pad("AuthKey", 10));
        expected.push_str(&pad("Platform (Device)", 17));
        expected.push_str(&pad("", 28));
        expected.push_str("{decrypt failed}\n");
        // ExitNodeID + LoginURL: value rows — the Value cell is padded (so the line ENDS in spaces),
        // and the empty trailing Error cell contributes nothing. This is Go's behavior we must match.
        expected.push_str(&pad("ExitNodeID", 10));
        expected.push_str(&pad("Platform (Device)", 17));
        expected.push_str(&pad("n123", 28));
        expected.push('\n');
        expected.push_str(&pad("LoginURL", 10));
        expected.push_str(&pad("Platform (Device)", 17));
        expected.push_str(&pad("https://controlplane.example", 28));
        expected.push('\n');
        expected.push('\n'); // trailing blank line (Go's `fmt.Println()` after `w.Flush()`)

        assert_eq!(
            format_policy(&r, false),
            expected,
            "policy table must be byte-identical to Go's tabwriter output (incl. value-row trailing \
             whitespace)"
        );
        // Independently pin the no-trim fix with concrete counts (so this can't silently pass if the
        // padder and the renderer ever shared the same off-by-one): the `n123` value (4 chars) is
        // padded to width 28 + 2 → 26 trailing spaces; the 28-char URL → exactly 2 trailing spaces.
        assert!(
            format_policy(&r, false).contains(&format!("n123{}\n", " ".repeat(26))),
            "value row must keep Go's trailing padding (26 spaces after n123)"
        );
        assert!(
            format_policy(&r, false).contains("https://controlplane.example  \n"),
            "the widest value gets exactly 2 trailing spaces, like tabwriter"
        );
    }

    #[test]
    fn format_policy_sanitizes_terminal_escapes() {
        use tailscaled_rs::localapi::{PolicyReport, PolicySetting};
        // A malicious/managed store could smuggle an ANSI escape or a newline into a key/value; the
        // renderer must NEUTRALIZE controls (each → U+FFFD) so it can't forge a row or hijack the
        // terminal (defense in depth, matching the DNS/whois hardening).
        let r = PolicyReport {
            scope: "Device".into(),
            settings: vec![PolicySetting {
                key: "Evil\u{1b}[31m".into(),
                origin: "Platform (Device)".into(),
                value: Some("bad\nFakeKey  forged".into()),
                error: None,
            }],
        };
        let h = format_policy(&r, false);
        assert!(!h.contains('\u{1b}'), "escape byte must be stripped: {h:?}");
        // The embedded newline must not survive to forge a second row.
        assert!(
            !h.contains("bad\nFakeKey"),
            "embedded newline must be neutralized: {h:?}"
        );
    }

    #[test]
    fn format_exit_node_list_filters_and_placeholder() {
        use tailscaled_rs::localapi::PeerReport;
        // None offering → placeholder.
        let none = vec![PeerReport {
            name: "plain".into(),
            ipv4: "100.64.0.2".into(),
            is_exit_node: false,
            ..Default::default()
        }];
        assert!(format_exit_node_list(&none).contains("no exit nodes"));
        // Mixed → only exit-node peers listed, with online state.
        let peers = vec![
            PeerReport {
                name: "exit-a".into(),
                ipv4: "100.64.0.9".into(),
                is_exit_node: true,
                online: Some(true),
                ..Default::default()
            },
            PeerReport {
                name: "plain-b".into(),
                ipv4: "100.64.0.3".into(),
                is_exit_node: false,
                ..Default::default()
            },
            PeerReport {
                name: "exit-c".into(),
                ipv4: "100.64.0.10".into(),
                is_exit_node: true,
                online: Some(false),
                ..Default::default()
            },
        ];
        let out = format_exit_node_list(&peers);
        assert!(out.contains("exit-a") && out.contains("(online)"), "{out}");
        assert!(out.contains("exit-c") && out.contains("(offline)"), "{out}");
        assert!(
            !out.contains("plain-b"),
            "non-exit peer must not appear: {out}"
        );
    }

    #[test]
    fn format_exit_node_list_resists_row_injection() {
        use tailscaled_rs::localapi::PeerReport;
        // The hostname is control-supplied (netmap); a name with an embedded newline must not be able
        // to forge a second exit-node row (header line + one row per real exit, nothing more).
        let peers = vec![PeerReport {
            name: "real\n100.64.0.99  fake-exit".into(),
            ipv4: "100.64.0.9".into(),
            is_exit_node: true,
            online: Some(true),
            ..Default::default()
        }];
        let out = format_exit_node_list(&peers);
        // Header line + exactly one peer row = two newlines, no forged third line.
        assert_eq!(out.matches('\n').count(), 2, "forged extra row: {out:?}");
        assert!(out.contains('\u{FFFD}'), "newline not neutralized: {out:?}");
    }

    #[test]
    fn format_status_sanitizes_control_supplied_names() {
        use tailscaled_rs::localapi::{PeerReport, StatusReport};
        // `self_name`, `active_exit_node`, and each peer `name` are control-supplied (netmap display
        // names). A `\n` in any of them must not be able to forge a fake status line / peer row, and
        // terminal escapes must be stripped — `format_status` runs each through `sanitize_for_terminal`.
        let s = StatusReport {
            state: "Running".into(),
            want_running: true,
            self_name: Some("me\x1b[2J\n injected: yes".into()),
            self_ipv4: Some("100.64.0.1".into()),
            active_exit_node: Some("exit\nfake-line: spoofed".into()),
            peers: vec![PeerReport {
                name: "peer\n  - 100.64.0.99  forged".into(),
                ipv4: "100.64.0.2".into(),
                is_exit_node: false,
                online: Some(true),
                ..Default::default()
            }],
            ..Default::default()
        };
        let out = format_status(&s);
        // No escape survives.
        assert!(!out.contains('\x1b'), "ESC must be stripped: {out:?}");
        // None of the injected newlines created a real line: every line must start with one of the
        // known fixed labels or the `  - ` peer-row prefix. A forged `injected:`/`fake-line:`/`forged`
        // line would NOT, so this catches row/line injection structurally.
        for line in out.lines() {
            let ok = line.is_empty()
                || line.starts_with("  - ")
                || ["state:", "want_running:", "self:", "exit-node:", "peers:"]
                    .iter()
                    .any(|lbl| line.starts_with(lbl));
            assert!(ok, "forged/unexpected status line: {line:?}\nfull:\n{out}");
        }
        // The neutralized text is still visibly present (nothing silently dropped).
        assert!(
            out.contains('\u{FFFD}'),
            "delimiters not neutralized: {out:?}"
        );
    }

    #[test]
    fn switch_usage_refusal_matches_gos_order_and_messages() {
        // Ported from Go's `switchProfile` (`cmd/tailscale/cli/switch.go`), whose three checks run in
        // this order. Each case below is one of Go's branches.

        // `--list` is handled first, so every flag/arg combination under it is usable: plain list,
        // JSON list, and a stray target next to `--list` (Go ignores the args entirely once listing).
        assert_eq!(switch_usage_refusal(true, false, None, false), None);
        assert_eq!(switch_usage_refusal(true, true, None, false), None);
        assert_eq!(switch_usage_refusal(true, true, Some("work"), false), None);

        // `--json` WITHOUT `--list` is refused — with or without a target, because `--json` only ever
        // formats the listing. Go: `--json argument cannot be used with tailscale switch NAME`.
        assert_eq!(
            switch_usage_refusal(false, true, Some("work"), false),
            Some("--json argument cannot be used with tnet switch NAME")
        );
        assert_eq!(
            switch_usage_refusal(false, true, None, false),
            Some("--json argument cannot be used with tnet switch NAME"),
            "the --json refusal precedes the usage line, as in Go"
        );

        // No target, no `--list`, no `--json` → the usage line.
        assert_eq!(
            switch_usage_refusal(false, false, None, false),
            Some("usage: tnet switch NAME")
        );

        // A plain target is usable.
        assert_eq!(
            switch_usage_refusal(false, false, Some("work"), false),
            None
        );

        // The `remove` subcommand is exempt from all of it: Go's ffcli dispatches the subcommand
        // before `switch`'s own Exec runs, so `switch`'s flag rules never apply to it.
        assert_eq!(switch_usage_refusal(false, false, None, true), None);
        assert_eq!(switch_usage_refusal(false, true, None, true), None);
    }

    #[test]
    fn format_profiles_marks_current() {
        use tailscaled_rs::localapi::ProfileEntry;
        let out = format_profiles(&[
            ProfileEntry {
                id: "default".into(),
                name: "default".into(),
                current: false,
            },
            ProfileEntry {
                id: "work".into(),
                name: "Work tailnet".into(),
                current: true,
            },
        ]);
        // Current profile marked with `*`; name shown only when it differs from the id.
        assert!(out.contains("* work  (Work tailnet)"), "{out}");
        assert!(out.contains("  default\n"), "{out}");
        assert!(!out.contains("* default"), "{out}");
        // Empty → placeholder.
        assert_eq!(format_profiles(&[]), "(no profiles)\n");
    }

    #[test]
    fn format_profiles_json_shape_matches_go() {
        use tailscaled_rs::localapi::ProfileEntry;
        let json = format_profiles_json(&[
            ProfileEntry {
                id: "default".into(),
                name: "default".into(),
                current: false,
            },
            ProfileEntry {
                id: "work".into(),
                name: "Work tailnet".into(),
                current: true,
            },
        ]);
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid JSON array");
        let arr = v.as_array().expect("top-level array");
        assert_eq!(arr.len(), 2);
        // Profile 0: name == id → nickname null; not selected.
        assert_eq!(arr[0]["id"], "default");
        assert!(
            arr[0]["nickname"].is_null(),
            "nickname null when == id: {json}"
        );
        assert_eq!(arr[0]["selected"], false);
        // Profile 1: distinct name → nickname carries it; selected true.
        assert_eq!(arr[1]["id"], "work");
        assert_eq!(arr[1]["nickname"], "Work tailnet");
        assert_eq!(arr[1]["selected"], true);
        // Engine-gated fields present as null (shape parity with Go, honestly empty).
        assert!(arr[1]["tailnet"].is_null());
        assert!(arr[1]["account"].is_null());
        // Empty → "[]".
        assert_eq!(format_profiles_json(&[]), "[]");
    }

    #[test]
    fn normalize_serve_target_expands_bare_port() {
        assert_eq!(normalize_serve_target("5000"), "127.0.0.1:5000");
        assert_eq!(normalize_serve_target("10.0.0.5:22"), "10.0.0.5:22");
        assert_eq!(normalize_serve_target("localhost:8080"), "localhost:8080");
    }

    #[test]
    fn unexpanded_redirect_var_refuses_the_placeholders_the_doc_promised() {
        // Neither placeholder is expanded anywhere in the stack, so `serve redirect` refuses both
        // rather than sending them to the client as literal characters in `Location:`.
        assert_eq!(
            unexpanded_redirect_var("https://${HOST}/new"),
            Some("${HOST}")
        );
        assert_eq!(
            unexpanded_redirect_var("https://dest.ts.net${REQUEST_URI}"),
            Some("${REQUEST_URI}")
        );
        // Reported placeholder-first, so the message names one the caller can actually find.
        assert_eq!(
            unexpanded_redirect_var("https://${HOST}${REQUEST_URI}"),
            Some("${HOST}")
        );

        // A literal URL passes, including one carrying a `$` that is not one of the two
        // placeholders — `$` is a legal URL sub-delimiter and must not be refused on sight.
        assert_eq!(unexpanded_redirect_var("https://dest.ts.net/new"), None);
        assert_eq!(unexpanded_redirect_var("https://dest.ts.net/a$b"), None);
        assert_eq!(
            unexpanded_redirect_var("https://dest.ts.net/${OTHER}"),
            None
        );
        assert_eq!(unexpanded_redirect_var("https://dest.ts.net/$HOST"), None);
    }

    #[test]
    fn format_serve_status_lists_and_flags() {
        use tailscaled_rs::localapi::{ServeConfig, TcpPortHandler};
        // Empty → placeholder, with Go's exact wording (no trailing period).
        let empty = format_serve_status(&ServeConfig::default(), false);
        assert_eq!(
            empty, "No serve config\n",
            "must match Go's exact empty message"
        );

        // A funnel-only config (AllowFunnel set, no TCP handler) is NOT empty in Go's
        // `isServeConfigEmpty`, so it must NOT print the placeholder.
        let mut funnel_only = ServeConfig::default();
        funnel_only
            .allow_funnel
            .insert("node:443".to_string(), true);
        assert!(
            !format_serve_status(&funnel_only, false).contains("No serve config"),
            "a funnel-only config is not empty (Go isServeConfigEmpty), must not show the placeholder"
        );

        let mut cfg = ServeConfig::default();
        // Plain TCP forward (daemon's own accept loop) — served.
        cfg.tcp.insert(
            "8443".to_string(),
            TcpPortHandler {
                tcp_forward: "127.0.0.1:5000".into(),
                ..Default::default()
            },
        );
        // HTTPS web with a backend (engine delegation) — served.
        cfg.tcp.insert(
            "443".to_string(),
            TcpPortHandler {
                https: true,
                tcp_forward: "127.0.0.1:3000".into(),
                ..Default::default()
            },
        );
        // HTTP web with a backend — served.
        cfg.tcp.insert(
            "80".to_string(),
            TcpPortHandler {
                http: true,
                tcp_forward: "127.0.0.1:8080".into(),
                ..Default::default()
            },
        );
        // HTTPS flag with NO backend — can't be served.
        cfg.tcp.insert(
            "8444".to_string(),
            TcpPortHandler {
                https: true,
                ..Default::default()
            },
        );
        // TLS-terminated raw TCP with a backend (no proxy-protocol) — SERVED via engine delegation.
        cfg.tcp.insert(
            "9000".to_string(),
            TcpPortHandler {
                tcp_forward: "127.0.0.1:9".into(),
                terminate_tls: "host.ts.net".into(),
                ..Default::default()
            },
        );
        // TLS-terminated requesting PROXY-protocol — NOT served (engine `Proxy` can't write the header).
        cfg.tcp.insert(
            "9001".to_string(),
            TcpPortHandler {
                tcp_forward: "127.0.0.1:10".into(),
                terminate_tls: "host.ts.net".into(),
                proxy_protocol: 1,
                ..Default::default()
            },
        );
        let out = format_serve_status(&cfg, false);
        // Plain forward is served.
        assert!(out.contains("tcp :8443 -> 127.0.0.1:5000"), "{out}");
        // HTTPS/HTTP web entries with a backend are served (engine delegation).
        assert!(
            out.contains("https://<node>:443 -> 127.0.0.1:3000"),
            "{out}"
        );
        assert!(out.contains("http://<node>:80 -> 127.0.0.1:8080"), "{out}");
        // HTTPS flag with no proxy target can't be served.
        assert!(
            out.contains("8444") && out.contains("no proxy target"),
            "{out}"
        );
        // TLS-terminated raw TCP with a backend IS served now (engine TLS-terminate + splice).
        assert!(
            out.contains("tls+tcp :9000 -> 127.0.0.1:9 (TLS-terminated)"),
            "{out}"
        );
        // The proxy-protocol terminate-tls entry is NOT served (with the reason).
        assert!(
            out.contains("9001") && out.contains("NOT served") && out.contains("proxy-protocol"),
            "{out}"
        );
    }

    #[test]
    fn clean_url_path_matches_go() {
        assert_eq!(clean_url_path("").unwrap(), "/");
        assert_eq!(clean_url_path("/").unwrap(), "/");
        assert_eq!(clean_url_path("foo").unwrap(), "/foo"); // leading slash added
        assert_eq!(clean_url_path("/foo").unwrap(), "/foo");
        assert_eq!(clean_url_path("/foo/").unwrap(), "/foo/"); // trailing slash allowed
        assert_eq!(clean_url_path("/foo/bar").unwrap(), "/foo/bar");
        // Uncleaned forms are rejected.
        assert!(clean_url_path("/foo/../bar").is_err());
        assert!(clean_url_path("//foo").is_err());
    }

    #[test]
    fn elliptically_truncate_matches_go() {
        assert_eq!(elliptically_truncate("short", 20), "short");
        // Exactly 20 bytes is unchanged.
        let twenty = "12345678901234567890";
        assert_eq!(elliptically_truncate(twenty, 20), twenty);
        // Longer → s[..17] + "..." (total 20).
        let long = "this is a long greeting message";
        let t = elliptically_truncate(long, 20);
        assert_eq!(t, "this is a long gr...");
        assert_eq!(t.len(), 20);
    }

    // The build_web_serve tests now author Go's `Web` map: TCP[port]={HTTPS flag} (no body) + the
    // handler under web["{host}:{port}"].handlers[mount]. `H` is the host the CLI resolves from status.
    const H: &str = "host.ts.net";

    #[test]
    fn build_web_serve_text_and_proxy_root() {
        use tailscaled_rs::localapi::ServeConfig;
        // text: target → a text handler at "/" in the Web map; the TCP handler is the bare HTTPS flag.
        let cfg =
            build_web_serve(ServeConfig::default(), H, 443, "text:hi there", None, true).unwrap();
        let th = cfg.tcp.get("443").unwrap();
        assert!(
            th.https && th.tcp_forward.is_empty(),
            "TCP handler is the flag, no body"
        );
        let wh = &cfg.web["host.ts.net:443"].handlers["/"];
        assert_eq!(wh.text, "hi there");
        assert!(wh.proxy.is_empty());

        // proxy target (bare port normalized) at root → proxy handler.
        let cfg = build_web_serve(ServeConfig::default(), H, 443, "3000", None, true).unwrap();
        assert_eq!(
            cfg.web["host.ts.net:443"].handlers["/"].proxy,
            "127.0.0.1:3000"
        );

        // empty text body is rejected (Go parity).
        assert!(build_web_serve(ServeConfig::default(), H, 443, "text:", None, true).is_err());
    }

    #[test]
    fn build_web_serve_set_path_mounts_accumulate() {
        use tailscaled_rs::localapi::ServeConfig;
        // First mount at /api, then /web on the same port — must accumulate in the Web map, not clobber.
        let cfg =
            build_web_serve(ServeConfig::default(), H, 443, "3000", Some("/api"), true).unwrap();
        let cfg = build_web_serve(cfg, H, 443, "text:hello", Some("/web"), true).unwrap();
        let h = &cfg.web["host.ts.net:443"].handlers;
        assert_eq!(h.len(), 2, "mounts should accumulate");
        assert_eq!(h["/api"].proxy, "127.0.0.1:3000");
        assert_eq!(h["/web"].text, "hello");
    }

    #[test]
    fn build_web_serve_bare_root_then_mount_accretes() {
        use tailscaled_rs::localapi::ServeConfig;
        // A bare root proxy, then a --set-path mount on the SAME port: the root must survive as the
        // "/" handler (Go SetWebHandler accretes — must NOT be clobbered).
        let cfg = build_web_serve(ServeConfig::default(), H, 443, "3000", None, true).unwrap();
        let cfg = build_web_serve(cfg, H, 443, "text:hi", Some("/api"), true).unwrap();
        let h = &cfg.web["host.ts.net:443"].handlers;
        assert_eq!(h.len(), 2, "root + /api should coexist");
        assert_eq!(
            h["/"].proxy, "127.0.0.1:3000",
            "the bare root proxy stayed as /"
        );
        assert_eq!(h["/api"].text, "hi");
    }

    #[test]
    fn build_web_serve_mount_then_bare_root_accretes() {
        use tailscaled_rs::localapi::ServeConfig;
        // The reverse: a --set-path mount, then a bare root serve on the same port. The root folds in
        // as the "/" handler rather than wiping the existing mount.
        let cfg =
            build_web_serve(ServeConfig::default(), H, 443, "3000", Some("/api"), true).unwrap();
        let cfg = build_web_serve(cfg, H, 443, "9000", None, true).unwrap();
        let h = &cfg.web["host.ts.net:443"].handlers;
        assert_eq!(h.len(), 2, "/api + new root should coexist");
        assert_eq!(h["/api"].proxy, "127.0.0.1:3000");
        assert_eq!(h["/"].proxy, "127.0.0.1:9000");
    }

    #[test]
    fn build_web_serve_migrates_legacy_handler_to_web_map() {
        use tailscaled_rs::localapi::{ServeConfig, TcpPortHandler};
        // A legacy on-disk config (body on the TCP handler). A new serve on that port must MIGRATE the
        // legacy body into the Web map (accrete), not silently drop it.
        let mut cfg = ServeConfig::default();
        cfg.tcp.insert(
            "443".into(),
            TcpPortHandler {
                https: true,
                tcp_forward: "127.0.0.1:3000".into(),
                ..Default::default()
            },
        );
        let cfg = build_web_serve(cfg, H, 443, "text:hi", Some("/api"), true).unwrap();
        let h = &cfg.web["host.ts.net:443"].handlers;
        assert_eq!(
            h["/"].proxy, "127.0.0.1:3000",
            "legacy root proxy migrated to /"
        );
        assert_eq!(h["/api"].text, "hi");
    }

    #[test]
    fn format_serve_status_renders_text_redirect_mux() {
        use tailscaled_rs::localapi::{RedirectSpec, ServeConfig, TcpPortHandler, WebMount};
        let mut cfg = ServeConfig::default();
        // Text handler.
        cfg.tcp.insert(
            "443".into(),
            TcpPortHandler {
                https: true,
                text: Some("hello".into()),
                ..Default::default()
            },
        );
        // Redirect handler.
        cfg.tcp.insert(
            "8443".into(),
            TcpPortHandler {
                https: true,
                redirect: Some(RedirectSpec {
                    to: "https://dest.ts.net/".into(),
                    status: 301,
                }),
                ..Default::default()
            },
        );
        // Path mux.
        let mut mounts = std::collections::BTreeMap::new();
        mounts.insert(
            "/api".to_string(),
            WebMount::Proxy {
                to: "127.0.0.1:3000".into(),
            },
        );
        cfg.tcp.insert(
            "9443".into(),
            TcpPortHandler {
                https: true,
                mounts,
                ..Default::default()
            },
        );
        let out = format_serve_status(&cfg, false);
        assert!(
            out.contains("https://<node>:443 -> text \"hello\""),
            "{out}"
        );
        assert!(
            out.contains("redirect 301 -> https://dest.ts.net/"),
            "{out}"
        );
        assert!(out.contains("9443 (path mux)"), "{out}");
        assert!(out.contains("/api -> proxy -> 127.0.0.1:3000"), "{out}");
    }

    #[test]
    fn format_serve_status_renders_go_web_map() {
        // A Go-shaped config (target in the top-level Web map) must render as served, using the real
        // host from the Web key — and a Web-only config must NOT print "No serve config".
        let cfg: tailscaled_rs::localapi::ServeConfig = serde_json::from_str(
            r#"{"TCP":{"443":{"HTTPS":true}},"Web":{"host.ts.net:443":{"Handlers":{"/":{"Proxy":"127.0.0.1:3000"}}}}}"#,
        )
        .unwrap();
        let out = format_serve_status(&cfg, false);
        assert!(
            !out.contains("No serve config"),
            "Web-only config is not empty: {out}"
        );
        assert!(
            out.contains("https://host.ts.net:443 -> proxy -> 127.0.0.1:3000"),
            "the Web-map proxy must render with its real host: {out}"
        );

        // Multi-mount Web entry → path mux, rendered from the Web map.
        let mux: tailscaled_rs::localapi::ServeConfig = serde_json::from_str(
            r#"{"TCP":{"443":{"HTTPS":true}},"Web":{"h:443":{"Handlers":{"/":{"Proxy":"127.0.0.1:3000"},"/old":{"Redirect":"301:https://h/new"}}}}}"#,
        )
        .unwrap();
        let out = format_serve_status(&mux, false);
        assert!(out.contains("https://h:443 (path mux)"), "{out}");
        assert!(out.contains("/ -> proxy -> 127.0.0.1:3000"), "{out}");
        assert!(
            out.contains("/old -> redirect -> 301:https://h/new"),
            "{out}"
        );
    }

    #[test]
    fn format_serve_status_annotates_funnel_ports() {
        use tailscaled_rs::ipn::serve;
        use tailscaled_rs::localapi::{ServeConfig, TcpPortHandler};
        let mut cfg = ServeConfig::default();
        cfg.tcp.insert(
            "443".into(),
            TcpPortHandler {
                https: true,
                tcp_forward: "127.0.0.1:3000".into(),
                ..Default::default()
            },
        );
        // No funnel yet → no funnel section.
        assert!(!format_serve_status(&cfg, false).contains("Funnel"));
        // Enable funnel on 443 → the funnel section appears.
        serve::set_funnel(&mut cfg, "host.example.ts.net", 443, true);
        let out = format_serve_status(&cfg, false);
        assert!(out.contains("Funnel (on the public internet):"), "{out}");
        assert!(out.contains("https://<node>:443"), "{out}");
    }

    /// Parse helper for the flag-grammar tests: run the real clap parser over a `tnet serve …`
    /// command line and hand back the `Serve` variant's parts.
    fn parse_serve(argv: &[&str]) -> (Option<ServeCmd>, ServeFlags) {
        let mut args = vec!["tnet", "serve"];
        args.extend_from_slice(argv);
        match Cli::try_parse_from(args).expect("serve command line must parse") {
            Cli {
                command: Command::Serve { cmd, flags },
                ..
            } => (cmd, flags),
            _ => panic!("expected a serve command for {argv:?}"),
        }
    }

    /// Same, for `tnet funnel …`.
    fn parse_funnel(argv: &[&str]) -> (Option<FunnelCmd>, ServeFlags) {
        let mut args = vec!["tnet", "funnel"];
        args.extend_from_slice(argv);
        match Cli::try_parse_from(args).expect("funnel command line must parse") {
            Cli {
                command: Command::Funnel { cmd, flags },
                ..
            } => (cmd, flags),
            _ => panic!("expected a funnel command for {argv:?}"),
        }
    }

    #[test]
    fn serve_accepts_the_go_flag_grammar_and_the_fork_sub_verbs() {
        // Go v1.100.0: `tailscale serve --https=443 localhost:3000`.
        let (cmd, flags) = parse_serve(&["--https=443", "localhost:3000"]);
        assert!(
            cmd.is_none(),
            "the flag grammar must not consume a sub-verb"
        );
        assert_eq!(flags.https, Some(443));
        assert_eq!(flags.target.as_deref(), Some("localhost:3000"));
        assert_eq!(flags.bg, None, "unset; Go's default is the foreground");
        assert!(!serve_background(&flags), "Go's default is the foreground");

        // Go's every-flag form, including the ones this build refuses at runtime.
        let (_, flags) = parse_serve(&[
            "--bg",
            "--tls-terminated-tcp=8443",
            "--proxy-protocol=2",
            "--service=svc:web",
            "--tun",
            "--accept-app-caps=example.com/cap-a,example.com/cap-b",
            "--yes",
            "tcp://127.0.0.1:5432",
        ]);
        assert_eq!(flags.bg, Some(true));
        assert_eq!(flags.tls_terminated_tcp, Some(8443));
        assert_eq!(flags.proxy_protocol, Some(2));
        assert_eq!(flags.service.as_deref(), Some("svc:web"));
        assert_eq!(
            flags.accept_app_caps,
            vec!["example.com/cap-a,example.com/cap-b".to_string()],
            "--accept-app-caps takes Go's comma-separated VALUE, not a bare bool"
        );
        assert!(flags.tun && flags.yes);

        // Go's `bgBoolFlag` accepts an explicit `--bg=false`; a bare `--bg` still means true, and a
        // following bare `false` stays a target, exactly as Go's flag package leaves it.
        let (_, flags) = parse_serve(&["--bg=false", "localhost:3000"]);
        assert_eq!(flags.bg, Some(false));
        assert!(!serve_background(&flags));
        let (_, flags) = parse_serve(&["--bg", "false"]);
        assert_eq!(flags.bg, Some(true));
        assert_eq!(flags.target.as_deref(), Some("false"));

        // The subcommands still win over the positional target when the word matches one.
        assert!(matches!(
            parse_serve(&["status", "--json"]).0,
            Some(ServeCmd::Status { json: true })
        ));
        assert!(matches!(parse_serve(&["reset"]).0, Some(ServeCmd::Reset)));
        assert!(matches!(
            parse_serve(&["https", "8443", "localhost:3000"]).0,
            Some(ServeCmd::Https { port: 8443, .. })
        ));
        // …and the fork-only `redirect` verb is untouched by the new grammar.
        assert!(matches!(
            parse_serve(&["redirect", "443", "https://example.com"]).0,
            Some(ServeCmd::Redirect { port: 443, .. })
        ));

        // Two port flags name one listener. Go decides that at runtime rather than at parse time
        // (its zero value is "unset", so it cannot), and so does this.
        let (_, flags) = parse_serve(&["--https=443", "--tcp=22", "x"]);
        let err = serve_kind_and_port(&flags)
            .expect_err("--https and --tcp name one listener")
            .to_string();
        assert!(err.contains("cannot serve multiple types"), "{err}");
    }

    #[test]
    fn serve_defaults_to_https_443_like_go() {
        // serve_v2.go: with no port flag the listener is HTTPS on 443.
        let (_, flags) = parse_serve(&["localhost:3000"]);
        assert_eq!(
            serve_kind_and_port(&flags).unwrap(),
            (ServeKind::Https, 443)
        );

        for (argv, want) in [
            (vec!["--http=80", "x"], (ServeKind::Http, 80u16)),
            (vec!["--tcp=2222", "x"], (ServeKind::Tcp, 2222)),
            (
                vec!["--tls-terminated-tcp=8443", "x"],
                (ServeKind::TlsTerminatedTcp, 8443),
            ),
        ] {
            let (_, flags) = parse_serve(&argv);
            assert_eq!(serve_kind_and_port(&flags).unwrap(), want, "{argv:?}");
        }
    }

    #[test]
    fn a_zero_port_flag_is_unset_like_go() {
        // srvTypeAndPortFromFlags counts a port flag only `if v != 0`, because Go's flags are plain
        // uints whose zero value IS "unset". So `serve --https=0 3000` names no listener, the count
        // stays at zero, and the default HTTPS/443 listener wins — it is not an error.
        for flag in ["--https=0", "--http=0", "--tcp=0", "--tls-terminated-tcp=0"] {
            let (_, flags) = parse_serve(&[flag, "3000"]);
            assert_eq!(
                serve_kind_and_port(&flags).unwrap(),
                (ServeKind::Https, 443),
                "{flag} is unset, so the default listener stands"
            );
            assert_eq!(
                check_serve_flags(&flags, false).unwrap(),
                (ServeKind::Https, 443),
                "{flag}"
            );
        }

        // A zero flag alongside a real one leaves exactly one listener named, so it is not the
        // multiple-types error either.
        let (_, flags) = parse_serve(&["--https=0", "--tcp=22", "3000"]);
        assert_eq!(serve_kind_and_port(&flags).unwrap(), (ServeKind::Tcp, 22));
    }

    #[test]
    fn tun_is_gos_fifth_serve_type() {
        // serve_v2.go: --tun sets serveTypeTUN and counts toward the exclusivity check…
        let (_, flags) = parse_serve(&["--tun", "3000"]);
        assert_eq!(serve_kind_and_port(&flags).unwrap(), (ServeKind::Tun, 0));
        let (_, flags) = parse_serve(&["--tun", "--https=443", "3000"]);
        let err = serve_kind_and_port(&flags)
            .expect_err("--tun and --https name one listener")
            .to_string();
        assert!(err.contains("cannot serve multiple types"), "{err}");

        // …and Go refuses it outright without a service, which is the only shape this build can
        // express: `--service` is refused before `--tun` is ever looked at.
        let (_, flags) = parse_serve(&["--tun", "3000"]);
        let err = check_serve_flags(&flags, false)
            .expect_err("--tun without a service is refused by Go too")
            .to_string();
        assert_eq!(err, "tun mode is only supported for services");
    }

    #[test]
    fn gos_own_proxy_protocol_refusals_come_first() {
        // serve_v2.go refuses --proxy-protocol on a web serve, whether the HTTP(S) listener was
        // named or defaulted to HTTPS/443.
        for argv in [
            vec!["--proxy-protocol=1", "3000"],
            vec!["--https=8443", "--proxy-protocol=1", "3000"],
            vec!["--http=80", "--proxy-protocol=2", "3000"],
        ] {
            let (_, flags) = parse_serve(&argv);
            let err = check_serve_flags(&flags, false)
                .expect_err("PROXY protocol is a TCP-only option")
                .to_string();
            assert_eq!(
                err, "PROXY protocol is only supported for TCP forwarding, not HTTP/HTTPS",
                "{argv:?}"
            );
        }

        // Then Go's version validation, for a TCP forward. Typed as Go types it, so a version well
        // past a u8 still gets Go's message rather than clap's integer-range one.
        for (argv, want) in [
            (
                vec!["--tcp=2222", "--proxy-protocol=3", "3000"],
                "invalid PROXY protocol version 3; must be 1 or 2",
            ),
            (
                vec!["--tls-terminated-tcp=8443", "--proxy-protocol=300", "3000"],
                "invalid PROXY protocol version 300; must be 1 or 2",
            ),
        ] {
            let (_, flags) = parse_serve(&argv);
            let err = check_serve_flags(&flags, false)
                .expect_err("only versions 1 and 2 exist")
                .to_string();
            assert_eq!(err, want, "{argv:?}");
        }

        // Go's zero value means unset: --proxy-protocol=0 asks for nothing and refuses nothing.
        let (_, flags) = parse_serve(&["--proxy-protocol=0", "3000"]);
        assert_eq!(
            check_serve_flags(&flags, false).unwrap(),
            (ServeKind::Https, 443)
        );

        // A version Go would have ACCEPTED is where this build's own refusal lands.
        let (_, flags) = parse_serve(&["--tcp=2222", "--proxy-protocol=2", "3000"]);
        let err = check_serve_flags(&flags, false)
            .expect_err("this build cannot emit a PROXY header")
            .to_string();
        assert!(err.contains("--proxy-protocol=2"), "{err}");
        assert!(err.contains("not supported by this build"), "{err}");
    }

    #[test]
    fn gos_own_service_refusals_come_first() {
        // `--service` with funnel, and `--service` with an explicit foreground: both are Go's.
        let (_, flags) = parse_funnel(&["--service=svc:web", "3000"]);
        let err = check_serve_flags(&flags, true)
            .expect_err("Go does not serve a service over funnel")
            .to_string();
        assert_eq!(err, "--service flag is not supported with funnel");

        let (_, flags) = parse_serve(&["--service=svc:web", "--bg=false", "3000"]);
        let err = check_serve_flags(&flags, false)
            .expect_err("a service serve must be a background one")
            .to_string();
        assert_eq!(
            err,
            "--service flag is only compatible with background mode"
        );

        // Without --bg, Go flips the default to the background for a service serve, so that refusal
        // does NOT fire and the build gap is what is reported.
        let (_, flags) = parse_serve(&["--service=svc:web", "3000"]);
        assert!(serve_background(&flags), "--service defaults to --bg in Go");
        let err = check_serve_flags(&flags, false)
            .expect_err("this build has no Services")
            .to_string();
        assert!(err.contains("--service=svc:web"), "{err}");
        assert!(err.contains("not supported by this build"), "{err}");
    }

    #[test]
    fn accept_app_caps_takes_gos_value_and_gos_validation() {
        // acceptAppCapsFlag.Set: comma-separated, trimmed, {domain}/{name}, repeats append.
        assert_eq!(
            parse_accept_app_caps(&[
                "example.com/cap-a, example.com/deep/cap".to_string(),
                "sub.example.com/cap-b".to_string(),
            ])
            .unwrap(),
            vec![
                "example.com/cap-a".to_string(),
                "example.com/deep/cap".to_string(),
                "sub.example.com/cap-b".to_string(),
            ]
        );
        // Go returns early on an empty value, so it asks for no capabilities at all.
        assert!(parse_accept_app_caps(&[String::new()]).unwrap().is_empty());

        for bad in [
            "nodomain/cap",
            "example.com",
            "example.com/",
            "/cap",
            "exa mple.com/cap",
        ] {
            let err = parse_accept_app_caps(&[bad.to_string()])
                .expect_err("not a {domain}/{name} capability")
                .to_string();
            assert!(
                err.contains("does not match the form {domain}/{name}"),
                "{bad}: {err}"
            );
        }

        // A Go command line has to PARSE before it can be told what is missing here.
        let (_, flags) = parse_serve(&["--accept-app-caps=example.com/cap-a", "3000"]);
        let err = check_serve_flags(&flags, false)
            .expect_err("this build forwards no capability headers")
            .to_string();
        assert!(err.contains("--accept-app-caps=example.com/cap-a"), "{err}");
        assert!(err.contains("not supported by this build"), "{err}");

        // An empty list asks for nothing, so it is not refused.
        let (_, flags) = parse_serve(&["--accept-app-caps=", "3000"]);
        assert_eq!(
            check_serve_flags(&flags, false).unwrap(),
            (ServeKind::Https, 443)
        );
    }

    #[test]
    fn unsupported_serve_flags_are_refused_by_name() {
        // Each flag, in the shape Go itself would have accepted, so the refusal that lands is this
        // build's own and names the missing capability rather than a syntax error.
        for (argv, needle) in [
            (vec!["--service=svc:web", "x"], "--service=svc:web"),
            (
                vec!["--tcp=2222", "--proxy-protocol=1", "x"],
                "--proxy-protocol=1",
            ),
            (
                vec!["--accept-app-caps=example.com/cap", "x"],
                "--accept-app-caps=example.com/cap",
            ),
        ] {
            let (_, flags) = parse_serve(&argv);
            let err = check_serve_flags(&flags, false)
                .expect_err("this build cannot honor this flag")
                .to_string();
            assert!(err.contains(needle), "{err}");
            assert!(
                err.contains("not supported by this build"),
                "the message must say it is a build gap, not a syntax error: {err}"
            );
        }
        // Everything this build DOES honor passes, `--yes` (an accepted no-op) included.
        let (_, flags) = parse_serve(&["--bg", "--yes", "--set-path=/api", "3000"]);
        assert_eq!(
            check_serve_flags(&flags, false).unwrap(),
            (ServeKind::Https, 443)
        );
    }

    #[test]
    fn tcp_serve_target_accepts_gos_tcp_scheme() {
        // Go's ExpandProxyTargetValue takes `tcp://host:port` for --tcp/--tls-terminated-tcp; the
        // stored TCPForward is always the bare host:port.
        assert_eq!(
            normalize_tcp_serve_target("tcp://192.0.2.10:5432"),
            "192.0.2.10:5432"
        );
        assert_eq!(normalize_tcp_serve_target("5432"), "127.0.0.1:5432");
        assert_eq!(
            normalize_tcp_serve_target("192.0.2.10:5432"),
            "192.0.2.10:5432"
        );
    }

    #[test]
    fn serve_off_clears_the_handler_the_web_body_and_the_funnel_key() {
        use tailscaled_rs::ipn::serve;
        use tailscaled_rs::localapi::{HttpHandler, ServeConfig, TcpPortHandler, WebServerConfig};
        let mut cfg = ServeConfig::default();
        cfg.tcp.insert(
            "443".into(),
            TcpPortHandler {
                https: true,
                ..Default::default()
            },
        );
        cfg.web.insert(
            "host.example.ts.net:443".into(),
            WebServerConfig {
                handlers: [(
                    "/".to_string(),
                    HttpHandler {
                        proxy: "127.0.0.1:3000".into(),
                        ..Default::default()
                    },
                )]
                .into_iter()
                .collect(),
            },
        );
        serve::set_funnel(&mut cfg, "host.example.ts.net", 443, true);
        // An untouched port on the side must survive the removal.
        cfg.tcp.insert(
            "8443".into(),
            TcpPortHandler {
                tcp_forward: "127.0.0.1:9000".into(),
                ..Default::default()
            },
        );

        assert!(remove_serve_port(&mut cfg, 443));
        assert!(!cfg.tcp.contains_key("443"));
        assert!(cfg.web.is_empty(), "the Web body must go with the handler");
        assert!(
            cfg.allow_funnel.is_empty(),
            "a funnel with no serve behind it exposes nothing"
        );
        assert!(cfg.tcp.contains_key("8443"), "other ports are untouched");

        // Removing a port that was never served changes nothing and says so.
        assert!(!remove_serve_port(&mut cfg, 443));
    }

    #[test]
    fn funnel_keeps_the_legacy_toggle_and_adds_the_flag_grammar() {
        // Legacy: `tnet funnel <port> on|off`.
        let (cmd, flags) = parse_funnel(&["8443", "on"]);
        assert!(cmd.is_none());
        assert_eq!(legacy_funnel_toggle(&flags), Some((8443, true)));
        let (_, flags) = parse_funnel(&["8443", "off"]);
        assert_eq!(legacy_funnel_toggle(&flags), Some((8443, false)));

        // Go grammar: a target that is not a bare port, or any explicit port flag, is NOT the
        // legacy toggle.
        let (_, flags) = parse_funnel(&["--https=443", "localhost:3000"]);
        assert_eq!(legacy_funnel_toggle(&flags), None);
        let (_, flags) = parse_funnel(&["--https=443", "off"]);
        assert_eq!(legacy_funnel_toggle(&flags), None);
        let (_, flags) = parse_funnel(&["localhost:3000"]);
        assert_eq!(legacy_funnel_toggle(&flags), None);

        // Go's `funnel status` / `funnel reset` aliases.
        assert!(matches!(
            parse_funnel(&["status", "--json"]).0,
            Some(FunnelCmd::Status { json: true })
        ));
        assert!(matches!(parse_funnel(&["reset"]).0, Some(FunnelCmd::Reset)));
    }

    #[test]
    fn format_ping_summary_counts_and_loss() {
        assert_eq!(
            format_ping_summary(3, 3),
            "--- 3 sent, 3 received, 0% loss ---"
        );
        assert_eq!(
            format_ping_summary(4, 1),
            "--- 4 sent, 1 received, 75% loss ---"
        );
        assert_eq!(
            format_ping_summary(2, 0),
            "--- 2 sent, 0 received, 100% loss ---"
        );
    }

    #[test]
    fn resolve_until_direct_defaults_true_like_go() {
        // Go's `--until-direct` is a bool flag defaulting to true: neither flag → on.
        assert!(
            resolve_until_direct(false, false),
            "default must be on (Go)"
        );
        // The bare flag → on (redundant with the default, but a user may pass it).
        assert!(resolve_until_direct(true, false));
        // `--no-until-direct` is the only way to turn it off.
        assert!(!resolve_until_direct(false, true));
    }

    #[test]
    fn ping_verdict_matches_go_end_of_loop() {
        // No reply at all → "no reply" (regardless of until_direct).
        assert_eq!(ping_verdict(0, false, true), PingVerdict::NoReply);
        assert_eq!(ping_verdict(0, false, false), PingVerdict::NoReply);
        // Replies but never went direct, and --until-direct was asked → "direct not established".
        assert_eq!(ping_verdict(3, false, true), PingVerdict::NoDirect);
        // Replies and went direct → ok, even with --until-direct.
        assert_eq!(ping_verdict(2, true, true), PingVerdict::Ok);
        // Replies, no direct, but --until-direct OFF → ok (we weren't waiting for direct).
        assert_eq!(ping_verdict(5, false, false), PingVerdict::Ok);
    }

    #[test]
    fn ping_via_distinguishes_direct_and_derp() {
        // A direct endpoint → `via <ip:port>`; no endpoint → `via DERP` (relayed).
        assert_eq!(ping_via(Some("100.64.0.2:41641")), "via 100.64.0.2:41641");
        assert_eq!(ping_via(None), "via DERP");
    }

    #[test]
    fn ping_seq_label_omits_denominator_when_infinite() {
        // Finite run shows N/M; infinite (`-c 0`) shows just the attempt number.
        assert_eq!(ping_seq_label(2, 10), "2/10");
        assert_eq!(ping_seq_label(7, 0), "7");
    }

    #[test]
    fn format_ping_line_reports_path_and_rtt() {
        // Direct path.
        assert_eq!(
            format_ping_line("100.64.0.2", 12.34, Some("100.64.0.2:41641"), 1, 10),
            "pong from 100.64.0.2 via 100.64.0.2:41641 in 12.3 ms  (seq 1/10)"
        );
        // DERP-relayed path, infinite count (no denominator).
        assert_eq!(
            format_ping_line("100.64.0.2", 50.0, None, 3, 0),
            "pong from 100.64.0.2 via DERP in 50.0 ms  (seq 3)"
        );
    }

    #[test]
    fn format_ping_miss_labels_attempt() {
        // The daemon returns a bare cause (no `ping <ip> failed:` prefix), so the CLI line carries
        // the IP + attempt label exactly once — no doubled `ping … failed: ping … failed:`.
        assert_eq!(
            format_ping_miss("100.64.0.2", "timed out", 2, 10),
            "ping 100.64.0.2 (2/10) failed: timed out"
        );
        // Infinite run: attempt label has no denominator.
        assert_eq!(
            format_ping_miss("100.64.0.2", "unreachable", 3, 0),
            "ping 100.64.0.2 (3) failed: unreachable"
        );
    }

    #[test]
    fn format_ip_filtered_selects_family_and_first() {
        let v4 = Some("100.64.0.1");
        let v6 = Some("fd7a::1");

        // No flags → both, v4 then v6.
        assert_eq!(
            format_ip_filtered(v4, v6, IpSelect::default()),
            "100.64.0.1\nfd7a::1\n"
        );
        // -4 → only v4.
        assert_eq!(
            format_ip_filtered(
                v4,
                v6,
                IpSelect {
                    v4: true,
                    ..Default::default()
                }
            ),
            "100.64.0.1\n"
        );
        // -6 → only v6.
        assert_eq!(
            format_ip_filtered(
                v4,
                v6,
                IpSelect {
                    v6: true,
                    ..Default::default()
                }
            ),
            "fd7a::1\n"
        );
        // -1 → only the first (v4, since both present).
        assert_eq!(
            format_ip_filtered(
                v4,
                v6,
                IpSelect {
                    first: true,
                    ..Default::default()
                }
            ),
            "100.64.0.1\n"
        );
        // -6 -1 → Go truncates to the first address (the v4 one) and only then filters for v6, so
        // the combination selects NOTHING on a dual-stack node. That empty answer is exactly why Go
        // refuses the combination up front rather than serving it; `ip_usage_refusal` ports the
        // refusal, so no `tnet ip` invocation can reach this state. Asserted here so the ported
        // evaluation order stays pinned even though the CLI no longer exposes it.
        assert_eq!(
            format_ip_filtered(
                v4,
                v6,
                IpSelect {
                    v6: true,
                    first: true,
                    ..Default::default()
                }
            ),
            "(no matching tailnet address)\n"
        );
        assert_eq!(
            ip_usage_refusal(false, true, true),
            Some("tnet ip -1, -4, and -6 are mutually exclusive"),
            "and the CLI refuses it before the formatter ever sees it"
        );
        // -4 with only v6 available → nothing matches.
        assert_eq!(
            format_ip_filtered(
                None,
                v6,
                IpSelect {
                    v4: true,
                    ..Default::default()
                }
            ),
            "(no matching tailnet address)\n"
        );
    }

    #[test]
    fn ip_refuses_gos_mutually_exclusive_selectors() {
        // Ported from Go's `runIP` (`cmd/tailscale/cli/ip.go`), which counts `-1`, `-4` and `-6` and
        // refuses as soon as two are set: `tailscale ip -1, -4, and -6 are mutually exclusive`.
        const MESSAGE: &str = "tnet ip -1, -4, and -6 are mutually exclusive";

        // Each flag alone is a usable invocation, as is none of them.
        assert_eq!(ip_usage_refusal(false, false, false), None);
        assert_eq!(ip_usage_refusal(true, false, false), None, "-4 alone");
        assert_eq!(ip_usage_refusal(false, true, false), None, "-6 alone");
        assert_eq!(ip_usage_refusal(false, false, true), None, "-1 alone");

        // Every pair is refused — including `-4 -6`, which used to be clap's `conflicts_with` and so
        // answered one third of Go's single check with a different message and a different exit code.
        assert_eq!(ip_usage_refusal(true, true, false), Some(MESSAGE), "-4 -6");
        assert_eq!(ip_usage_refusal(true, false, true), Some(MESSAGE), "-4 -1");
        assert_eq!(ip_usage_refusal(false, true, true), Some(MESSAGE), "-6 -1");
        assert_eq!(
            ip_usage_refusal(true, true, true),
            Some(MESSAGE),
            "-4 -6 -1"
        );
    }

    #[test]
    fn ip_refusal_covers_the_service_arm_that_would_answer_emptily() {
        // The refusal matters most on `tnet ip <service-VIP>`: a Service carries a LIST of addresses,
        // so `-6 -1` reads like "the Service's IPv6 address". It is not — Go truncates to the first
        // address before filtering, so on a dual-stack Service the pair selects nothing. Without the
        // ported refusal the command would answer that empty set instead of refusing the flags.
        let addrs = vec!["100.64.0.10".to_string(), "fd7a:115c:a1e0::a".to_string()];
        assert_eq!(
            format_service_ips(
                &addrs,
                IpSelect {
                    v6: true,
                    first: true,
                    ..Default::default()
                }
            ),
            "(no matching tailnet address)\n",
            "Go's order: -1 truncates to the v4 address, then -6 filters it away"
        );
        assert_eq!(
            ip_usage_refusal(false, true, true),
            Some("tnet ip -1, -4, and -6 are mutually exclusive"),
            "so the CLI never gets to print that"
        );
        // `-1` on its own still means what it means: the Service's first address, both families
        // wanted, which is the answer Go gives and the one this arm keeps giving.
        assert_eq!(
            format_service_ips(
                &addrs,
                IpSelect {
                    first: true,
                    ..Default::default()
                }
            ),
            "100.64.0.10\n"
        );
    }

    #[test]
    fn status_filter_active_self_peers() {
        use tailscaled_rs::localapi::{PeerReport, PrefsView, StatusReport};
        let base = || StatusReport {
            state: "Running".to_string(),
            want_running: true,
            self_ipv4: Some("100.70.22.12".to_string()),
            self_name: Some("node-a".to_string()),
            auth_url: None,
            error: None,
            prefs: PrefsView::default(),
            self_ipv6: None,
            active_exit_node: None,
            active_exit_node_id: None,
            magic_dns_suffix: None,
            peers: vec![
                PeerReport {
                    name: "online-peer".to_string(),
                    ipv4: "100.64.0.2".to_string(),
                    is_exit_node: false,
                    stable_id: "n1".to_string(),
                    online: Some(true),
                    ..Default::default()
                },
                PeerReport {
                    name: "offline-peer".to_string(),
                    ipv4: "100.64.0.3".to_string(),
                    is_exit_node: false,
                    stable_id: "n2".to_string(),
                    online: Some(false),
                    ..Default::default()
                },
                PeerReport {
                    name: "unknown-peer".to_string(),
                    ipv4: "100.64.0.4".to_string(),
                    is_exit_node: false,
                    stable_id: "n3".to_string(),
                    online: None,
                    ..Default::default()
                },
            ],
            version: None,
            have_node_key: true,
            health: Vec::new(),
        };

        // No filter → everything.
        let all = StatusFilter::default().apply(base());
        assert_eq!(all.peers.len(), 3);
        assert!(all.self_name.is_some());

        // --no-peers → peer list emptied, self kept.
        let np = StatusFilter {
            hide_peers: true,
            ..Default::default()
        }
        .apply(base());
        assert!(np.peers.is_empty());
        assert!(np.self_name.is_some());

        // --no-self → self blanked, peers kept.
        let ns = StatusFilter {
            hide_self: true,
            ..Default::default()
        }
        .apply(base());
        assert!(ns.self_name.is_none() && ns.self_ipv4.is_none());
        assert_eq!(ns.peers.len(), 3);

        // --active → only online==Some(true) peers (offline + unknown hidden).
        let act = StatusFilter {
            active_only: true,
            ..Default::default()
        }
        .apply(base());
        assert_eq!(act.peers.len(), 1);
        assert_eq!(act.peers[0].name, "online-peer");

        // --no-peers wins over --active (no peers at all).
        let both = StatusFilter {
            active_only: true,
            hide_peers: true,
            ..Default::default()
        }
        .apply(base());
        assert!(both.peers.is_empty());
    }

    #[test]
    fn format_status_json_is_go_shaped() {
        use tailscaled_rs::localapi::{PeerReport, PrefsView, StatusReport};
        let report = StatusReport {
            state: "Running".to_string(),
            want_running: true,
            self_ipv4: Some("100.70.22.12".to_string()),
            self_name: Some("node-a".to_string()),
            auth_url: None,
            error: None,
            prefs: PrefsView::default(),
            self_ipv6: Some("fd7a:115c:a1e0::1".to_string()),
            active_exit_node: Some("peer-b".to_string()),
            active_exit_node_id: Some("nABC123".to_string()),
            magic_dns_suffix: Some("tail0123.ts.net".to_string()),
            peers: vec![
                PeerReport {
                    name: "peer-b".to_string(),
                    ipv4: "100.64.0.2".to_string(),
                    is_exit_node: true,
                    stable_id: "nABC123".to_string(),
                    online: Some(true),
                    ipv6: Some("fd7a:115c:a1e0::2".to_string()),
                    allowed_routes: vec!["100.64.0.2/32".to_string(), "0.0.0.0/0".to_string()],
                    cur_addr: Some("192.0.2.5:41641".to_string()),
                    ..Default::default()
                },
                PeerReport {
                    name: "peer-c".to_string(),
                    ipv4: "100.64.0.3".to_string(),
                    is_exit_node: false,
                    stable_id: String::new(), // missing id → keyed by name (fallback)
                    online: Some(false),
                    relay: Some("nyc".to_string()),
                    // RFC3339, the form the daemon actually emits (`to_rfc3339()`), NOT the chrono
                    // Display form (`2026-06-11 05:19:14 UTC`) which is not RFC3339.
                    last_seen: Some("2026-06-11T05:19:14+00:00".to_string()),
                    ..Default::default()
                },
            ],
            version: Some("0.36.0".to_string()),
            have_node_key: true,
            health: Vec::new(),
        };
        let out = format_status_json(&report).unwrap();
        let v: serde_json::Value =
            serde_json::from_str(&out).expect("status --json must be valid JSON");

        // Go key names + the exact BackendState string.
        assert_eq!(v["BackendState"], serde_json::json!("Running"));
        assert_eq!(v["AuthURL"], serde_json::json!("")); // always present, empty when none
        // TailscaleIPs now carries IPv4 then IPv6.
        assert_eq!(
            v["TailscaleIPs"],
            serde_json::json!(["100.70.22.12", "fd7a:115c:a1e0::1"])
        );
        assert_eq!(v["MagicDNSSuffix"], serde_json::json!("tail0123.ts.net"));
        // ExitNodeStatus.ID is the StableNodeID (Go's `tailcfg.StableNodeID` that keys the Peer map),
        // NOT the display name — so it matches the `Peer` key `nABC123` (asserted below). The resolved
        // name rides the non-Go `Name` field.
        assert_eq!(v["ExitNodeStatus"]["ID"], serde_json::json!("nABC123"));
        assert_eq!(v["ExitNodeStatus"]["Name"], serde_json::json!("peer-b"));
        assert!(
            v["Peer"].get("nABC123").is_some(),
            "ExitNodeStatus.ID must be a key in the Peer map (Go-tooling compatibility)"
        );
        // Version (Go `Status.Version`) + TUN (Go `Status.TUN`) now surfaced; HaveNodeKey true once
        // past the pre-login states (this report is Running). All Go-cased field names.
        assert_eq!(v["Version"], serde_json::json!("0.36.0"));
        assert_eq!(v["TUN"], serde_json::json!(false)); // PrefsView::default() → netstack
        assert_eq!(v["HaveNodeKey"], serde_json::json!(true));
        // Self subset.
        assert_eq!(v["Self"]["HostName"], serde_json::json!("node-a"));
        assert_eq!(
            v["Self"]["TailscaleIPs"],
            serde_json::json!(["100.70.22.12", "fd7a:115c:a1e0::1"])
        );
        // Peer map keyed by stable_id (with name-fallback for the id-less peer).
        assert_eq!(
            v["Peer"]["nABC123"]["HostName"],
            serde_json::json!("peer-b")
        );
        assert_eq!(
            v["Peer"]["nABC123"]["ExitNodeOption"],
            serde_json::json!(true)
        );
        assert_eq!(v["Peer"]["nABC123"]["Online"], serde_json::json!(true));
        assert_eq!(
            v["Peer"]["nABC123"]["TailscaleIPs"],
            serde_json::json!(["100.64.0.2", "fd7a:115c:a1e0::2"])
        );
        assert_eq!(
            v["Peer"]["nABC123"]["AllowedIPs"],
            serde_json::json!(["100.64.0.2/32", "0.0.0.0/0"])
        );
        assert_eq!(
            v["Peer"]["nABC123"]["CurAddr"],
            serde_json::json!("192.0.2.5:41641")
        );
        assert_eq!(v["Peer"]["peer-c"]["HostName"], serde_json::json!("peer-c"));
        assert_eq!(v["Peer"]["peer-c"]["Online"], serde_json::json!(false));
        assert_eq!(v["Peer"]["peer-c"]["Relay"], serde_json::json!("nyc"));
        assert_eq!(
            v["Peer"]["peer-c"]["LastSeen"],
            serde_json::json!("2026-06-11T05:19:14+00:00")
        );
    }

    #[test]
    fn format_status_prints_the_health_block_only_when_something_is_wrong() {
        use tailscaled_rs::localapi::StatusReport;
        // Go `cmd/tailscale/cli/status.go`'s `printHealth`: a `# Health check:` header followed by
        // one `#     - <text>` line per problem, and nothing at all on a healthy node.
        let healthy = StatusReport {
            state: "Running".to_string(),
            want_running: true,
            ..Default::default()
        };
        let out = format_status(&healthy);
        assert!(
            !out.contains("# Health check:"),
            "a healthy node's status block must be unchanged: {out}"
        );

        let warned = StatusReport {
            state: "Starting".to_string(),
            want_running: true,
            health: vec!["This network requires you to log in using your web browser.".to_string()],
            ..Default::default()
        };
        let out = format_status(&warned);
        assert!(
            out.contains(
                "# Health check:\n#     - This network requires you to log in using your web \
                 browser.\n"
            ),
            "the health block must match Go's printHealth shape: {out}"
        );
    }

    #[test]
    fn format_status_json_carries_health() {
        use tailscaled_rs::localapi::StatusReport;
        // Go `ipnstate.Status.Health` is a `[]string`; `status --json` must expose it under that key
        // so a script can act on it.
        let report = StatusReport {
            state: "Starting".to_string(),
            health: vec!["This network requires you to log in using your web browser.".to_string()],
            ..Default::default()
        };
        let v: serde_json::Value =
            serde_json::from_str(&format_status_json(&report).unwrap()).unwrap();
        assert_eq!(
            v["Health"],
            serde_json::json!(["This network requires you to log in using your web browser."])
        );

        // Healthy: an empty ARRAY, never a missing key or a null (the documented deviation from Go,
        // which emits null for its nil slice) — so `jq '.Health | length'` needs no null guard.
        let healthy = StatusReport {
            state: "Running".to_string(),
            ..Default::default()
        };
        let v: serde_json::Value =
            serde_json::from_str(&format_status_json(&healthy).unwrap()).unwrap();
        assert_eq!(v["Health"], serde_json::json!([]));
    }

    #[test]
    fn format_status_json_omits_have_node_key_when_false() {
        use tailscaled_rs::localapi::StatusReport;
        // The omitempty half of Go-fidelity: HaveNodeKey is OMITTED when the node holds no key (Go's
        // `json:",omitempty"`), while TUN is ALWAYS present (Go's bare bool) — even on a keyless node.
        let report = StatusReport {
            state: "NeedsLogin".to_string(),
            have_node_key: false,
            version: Some("0.36.0".to_string()),
            ..Default::default()
        };
        let out = format_status_json(&report).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert!(
            v.get("HaveNodeKey").is_none(),
            "HaveNodeKey must be omitted when false (Go omitempty): {out}"
        );
        assert_eq!(
            v["TUN"],
            serde_json::json!(false),
            "TUN is always present even when HaveNodeKey is omitted (Go bare bool)"
        );
    }

    #[test]
    fn html_escape_neutralizes_markup() {
        assert_eq!(
            html_escape("a&b<c>d\"e'f"),
            "a&amp;b&lt;c&gt;d&quot;e&#39;f"
        );
        assert_eq!(html_escape("plain"), "plain");
    }

    #[test]
    fn render_status_html_includes_fields_and_escapes_peers() {
        use tailscaled_rs::localapi::{PeerReport, StatusReport};
        let report = StatusReport {
            state: "Running".to_string(),
            self_name: Some("node-a".to_string()),
            self_ipv4: Some("100.64.0.1".to_string()),
            magic_dns_suffix: Some("tail0123.ts.net".to_string()),
            version: Some("0.37.0".to_string()),
            peers: vec![PeerReport {
                // A hostile, control-supplied peer name must render inert (no raw <script>).
                name: "<script>alert(1)</script>".to_string(),
                ipv4: "100.64.0.2".to_string(),
                online: Some(true),
                ..Default::default()
            }],
            have_node_key: true,
            ..Default::default()
        };
        let html = render_status_html(&report, None);
        assert!(html.starts_with("<!DOCTYPE html>"), "well-formed page");
        assert!(html.contains("Running") && html.contains("0.37.0") && html.contains("node-a"));
        assert!(html.contains("tail0123.ts.net") && html.contains("100.64.0.1"));
        // The peer is listed, but its hostile name is escaped — no raw <script> tag.
        assert!(html.contains("100.64.0.2"), "peer ip present");
        assert!(
            !html.contains("<script>"),
            "a hostile peer name must be HTML-escaped, not rendered as markup: {html}"
        );
        assert!(html.contains("&lt;script&gt;"), "escaped form present");

        // An empty / not-yet-running report still renders a valid page (no panic).
        let empty = StatusReport {
            state: "NeedsLogin".to_string(),
            ..Default::default()
        };
        let empty_html = render_status_html(&empty, None);
        assert!(empty_html.starts_with("<!DOCTYPE html>"));
        assert!(empty_html.contains("NeedsLogin") && empty_html.contains("no peers"));
    }

    #[test]
    fn render_status_html_login_affordance() {
        use tailscaled_rs::localapi::StatusReport;
        // NeedsLogin + an auth_url → the page surfaces a clickable login LINK (the one action Go's
        // LoginServerMode exposes), display-only (no form/POST — no mutating surface). A
        // control-supplied auth_url is escaped into the href attribute (can't inject markup).
        let needs_login = StatusReport {
            state: "NeedsLogin".to_string(),
            auth_url: Some("https://login.example.com/a/\"><script>x".to_string()),
            ..Default::default()
        };
        let html = render_status_html(&needs_login, None);
        assert!(
            html.contains("needs to be authenticated") && html.contains("Log in to authenticate"),
            "the login affordance must render when auth_url is set"
        );
        assert!(
            html.contains("href=\"https://login.example.com/a/&quot;&gt;&lt;script&gt;x\""),
            "the control-supplied auth_url must be HTML-attribute-escaped (no markup break-out): {html}"
        );
        assert!(
            !html.contains("<script>x"),
            "a hostile auth_url must not inject raw markup: {html}"
        );
        // No mutating form anywhere — this is the read+login face, not a control surface.
        assert!(
            !html.to_lowercase().contains("<form"),
            "the loopback web UI must expose NO mutating form (mutation is the over-Tailscale manage \
             UI, engine-gated): {html}"
        );

        // A terminal registration failure renders distinctly (NOT a pending-login link), escaped.
        let failed = StatusReport {
            state: "NeedsLogin".to_string(),
            error: Some("bad key <x>".to_string()),
            ..Default::default()
        };
        let fhtml = render_status_html(&failed, None);
        assert!(fhtml.contains("Registration failed") && fhtml.contains("bad key &lt;x&gt;"));
        assert!(
            !fhtml.contains("Log in to authenticate"),
            "a terminal failure must not offer a login link (re-running won't help)"
        );
    }

    #[test]
    fn parse_request_target_extracts_method_and_path() {
        assert_eq!(parse_request_target("GET / HTTP/1.1"), Some(("GET", "/")));
        assert_eq!(
            parse_request_target("GET /foo HTTP/1.1"),
            Some(("GET", "/foo"))
        );
        assert_eq!(parse_request_target("POST / HTTP/1.0"), Some(("POST", "/")));
        // Malformed (no path token) → None; the serve loop treats that as 404.
        assert_eq!(parse_request_target("GET"), None);
        assert_eq!(parse_request_target(""), None);
    }

    #[test]
    fn normalize_served_path_handles_prefix_forms() {
        // Empty / "/" → root.
        assert_eq!(normalize_served_path(""), "/");
        assert_eq!(normalize_served_path("/"), "/");
        assert_eq!(normalize_served_path("   "), "/");
        // A prefix is normalized to exactly one leading slash, no trailing slash, regardless of input.
        assert_eq!(normalize_served_path("tailscale"), "/tailscale");
        assert_eq!(normalize_served_path("/tailscale"), "/tailscale");
        assert_eq!(normalize_served_path("/tailscale/"), "/tailscale");
        assert_eq!(normalize_served_path("  /web/ui/  "), "/web/ui");
    }

    #[test]
    fn web_usage_refusal_refuses_a_listen_address_that_is_never_bound() {
        // `--cgi` serves one request out of the CGI environment and binds nothing, so a `--listen`
        // next to it names an address that will never exist. Refused, in the same shape this CLI
        // already uses for `cert --listen` without `--serve-demo`.
        assert_eq!(
            web_usage_refusal(true, true),
            Some("--listen can only be used without --cgi (a CGI script binds no listener)")
        );
        // Every usable combination stays usable: a listener with an address, a listener with the
        // default address, and CGI with no address at all.
        assert_eq!(web_usage_refusal(false, true), None);
        assert_eq!(web_usage_refusal(false, false), None);
        assert_eq!(web_usage_refusal(true, false), None);
    }

    #[test]
    fn parse_web_origin_normalizes_a_base_url_and_refuses_anything_else() {
        // The reverse-proxy case Go's `--origin` exists for: scheme + host + the path the proxy
        // publishes. A trailing slash is not a different origin.
        assert_eq!(
            parse_web_origin("https://ts.example.com/tailscale"),
            Ok("https://ts.example.com/tailscale".to_string())
        );
        assert_eq!(
            parse_web_origin("  https://ts.example.com/tailscale/  "),
            Ok("https://ts.example.com/tailscale".to_string())
        );
        // Scheme + host alone is the pass-through proxy case; an explicit non-default port is kept,
        // a default one is not (both name the same origin).
        assert_eq!(
            parse_web_origin("http://192.0.2.10:8088"),
            Ok("http://192.0.2.10:8088".to_string())
        );
        assert_eq!(
            parse_web_origin("https://ts.example.com:443/"),
            Ok("https://ts.example.com".to_string())
        );
        // An IPv6 literal keeps its brackets, so the result is still a usable URL.
        assert_eq!(
            parse_web_origin("http://[2001:db8::1]:8088/ui"),
            Ok("http://[2001:db8::1]:8088/ui".to_string())
        );

        // The refusals. A bare host is the mistake to expect — it is what `--prefix` habits produce
        // — and it is precisely the input that carries no scheme, the thing `--origin` is for.
        for bad in ["", "   ", "ts.example.com", "/tailscale"] {
            assert!(
                parse_web_origin(bad).is_err(),
                "{bad:?} is not an absolute URL and must be refused"
            );
        }
        assert!(
            parse_web_origin("ftp://ts.example.com")
                .unwrap_err()
                .contains("http or https"),
            "a non-http(s) scheme must be named in the refusal"
        );
        assert!(
            parse_web_origin("https://ts.example.com/ui?a=1")
                .unwrap_err()
                .contains("query or fragment"),
            "a query names one request, not the base URL the UI is served at"
        );
        assert!(
            parse_web_origin("https://ts.example.com/ui#top")
                .unwrap_err()
                .contains("query or fragment")
        );
        assert!(
            parse_web_origin("https://user:pw@ts.example.com")
                .unwrap_err()
                .contains("credentials")
        );
    }

    #[test]
    fn web_ui_url_prefers_the_origin_over_the_address_that_was_bound() {
        // The defect: behind a reverse proxy the bound address is not the address anyone reaches,
        // and `--prefix` fixes only the path. With an origin, the origin wins outright.
        let origin = parse_web_origin("https://ts.example.com/tailscale").unwrap();
        assert_eq!(
            web_ui_url(Some(&origin), Some("127.0.0.1:8088"), "/tailscale").as_deref(),
            Some("https://ts.example.com/tailscale")
        );
        // An origin that already names the outside path is used verbatim — the proxy is free to map
        // it onto a different inside path, so appending `--prefix` would invent a URL nobody serves.
        assert_eq!(
            web_ui_url(Some(&origin), Some("127.0.0.1:8088"), "/inside").as_deref(),
            Some("https://ts.example.com/tailscale")
        );
        // An origin that names only scheme + host is the pass-through case: the served path applies.
        let host_only = parse_web_origin("https://ts.example.com").unwrap();
        assert_eq!(
            web_ui_url(Some(&host_only), None, "/tailscale").as_deref(),
            Some("https://ts.example.com/tailscale")
        );
        assert_eq!(
            web_ui_url(Some(&host_only), None, "/").as_deref(),
            Some("https://ts.example.com")
        );

        // Without an origin, nothing changes from the previous behaviour: the bound address, plus
        // the served path.
        assert_eq!(
            web_ui_url(None, Some("127.0.0.1:8088"), "/").as_deref(),
            Some("http://127.0.0.1:8088")
        );
        assert_eq!(
            web_ui_url(None, Some("127.0.0.1:8088"), "/tailscale").as_deref(),
            Some("http://127.0.0.1:8088/tailscale")
        );
        // `--cgi` without `--origin`: nothing was bound and the proxy's scheme/host is not in the
        // CGI environment, so the URL is unknown rather than guessed.
        assert_eq!(web_ui_url(None, None, "/"), None);
    }

    #[test]
    fn route_web_request_answers_only_get_at_the_served_path() {
        // The one route the read-only page has — shared by the listener and `--cgi`.
        assert_eq!(route_web_request("GET", "/", "/"), WebRoute::Page);
        assert_eq!(
            route_web_request("GET", "/tailscale", "/tailscale"),
            WebRoute::Page
        );
        // A different path, a path that only looks right, and a non-GET method are all 404.
        assert_eq!(route_web_request("GET", "/other", "/"), WebRoute::NotFound);
        assert_eq!(
            route_web_request("GET", "/tailscale", "/"),
            WebRoute::NotFound
        );
        assert_eq!(route_web_request("POST", "/", "/"), WebRoute::NotFound);
        assert_eq!(route_web_request("", "/", "/"), WebRoute::NotFound);
    }

    #[test]
    fn cgi_request_path_follows_the_cgi_environment_precedence() {
        // `REQUEST_URI` wins when the server supplied it (Go's `net/http/cgi` reads it first), and
        // the query string is dropped — the read-only page takes no parameters.
        assert_eq!(
            cgi_request_path(Some("/tailscale?x=1"), Some("/tailscale"), None),
            "/tailscale"
        );
        assert_eq!(cgi_request_path(Some("/"), Some("/ignored"), None), "/");
        // Without it, the path is the script's own mount point plus whatever followed it.
        assert_eq!(
            cgi_request_path(None, Some("/tailscale"), Some("/extra")),
            "/tailscale/extra"
        );
        assert_eq!(
            cgi_request_path(None, Some("/tailscale"), None),
            "/tailscale"
        );
        // An empty or absent environment is the root request, not an empty path (which would 404
        // against every served path).
        assert_eq!(cgi_request_path(None, None, None), "/");
        assert_eq!(cgi_request_path(Some("   "), None, None), "/");
    }

    #[test]
    fn cgi_response_is_headers_then_a_blank_line_then_the_body() {
        let body = "<!DOCTYPE html><html><body>hi</body></html>";
        let response = cgi_response("200 OK", body);
        // Go's CGI child writer always emits a `Status:` line; the invoking web server turns these
        // headers into the HTTP response.
        assert!(response.starts_with("Status: 200 OK\r\n"), "{response}");
        assert!(response.contains("Content-Type: text/html; charset=utf-8\r\n"));
        assert!(response.contains(&format!("Content-Length: {}\r\n", body.len())));
        // Exactly one blank line separates the headers from the body, and the body is last.
        let (headers, rest) = response
            .split_once("\r\n\r\n")
            .expect("a CGI response ends its headers with a blank line");
        assert!(!headers.contains("\r\n\r\n"));
        assert_eq!(rest, body);
        // The error routes reuse the same serializer, so their status reaches the server too.
        assert!(
            cgi_response("404 Not Found", WEB_NOT_FOUND_BODY).starts_with("Status: 404 Not Found")
        );
    }

    #[test]
    fn render_status_html_states_the_url_it_is_served_at() {
        use tailscaled_rs::localapi::StatusReport;
        let report = StatusReport {
            state: "Running".to_string(),
            ..Default::default()
        };
        // With a known absolute URL (from `--origin`, or the bound address), the page says so — the
        // reverse-proxy case where the address this process bound is not the address anyone reached.
        let origin = parse_web_origin("https://ts.example.com/tailscale").unwrap();
        let url = web_ui_url(Some(&origin), None, "/").expect("an origin always yields a URL");
        let html = render_status_html(&report, Some(&url));
        assert!(
            html.contains("<link rel=\"canonical\" href=\"https://ts.example.com/tailscale\">"),
            "the page must state the absolute URL it is served at: {html}"
        );
        // Operator-supplied, but it still lands in markup: escaped like every other value.
        let hostile = render_status_html(&report, Some("https://x/\"><script>y"));
        assert!(
            !hostile.contains("<script>y"),
            "a canonical URL must not inject raw markup: {hostile}"
        );
        assert!(hostile.contains("&quot;&gt;&lt;script&gt;y"));
        // `--cgi` without `--origin`: no URL is known, so the page claims none.
        let unknown = render_status_html(&report, None);
        assert!(
            !unknown.contains("rel=\"canonical\""),
            "an unknown URL must not be guessed at: {unknown}"
        );
    }

    #[test]
    fn peer_status_cell_renders_path_and_offline() {
        use tailscaled_rs::localapi::PeerReport;
        // Direct path → "direct <addr>".
        let direct = PeerReport {
            cur_addr: Some("192.0.2.5:41641".to_string()),
            online: Some(true),
            ..Default::default()
        };
        assert_eq!(peer_status_cell(&direct), "  (direct 192.0.2.5:41641)");
        // No direct path, DERP relay → relay "region" (quoted, like Go).
        let relayed = PeerReport {
            relay: Some("nyc".to_string()),
            online: Some(true),
            ..Default::default()
        };
        assert_eq!(peer_status_cell(&relayed), r#"  (relay "nyc")"#);
        // Offline with last-seen → appended suffix; relay still shown.
        let offline = PeerReport {
            relay: Some("fra".to_string()),
            online: Some(false),
            last_seen: Some("2026-06-11 05:19:14 UTC".to_string()),
            ..Default::default()
        };
        assert_eq!(
            peer_status_cell(&offline),
            r#"  (relay "fra"; offline, last seen 2026-06-11 05:19:14 UTC)"#
        );
        // Online peer with no known path → empty cell.
        let plain = PeerReport {
            online: Some(true),
            ..Default::default()
        };
        assert_eq!(peer_status_cell(&plain), "");
    }

    #[tokio::test]
    async fn wait_times_out_against_a_dead_socket() {
        // With a short timeout and no daemon listening, `wait` must give up and return Err (→ the
        // CLI's non-zero exit), not hang forever. A non-existent socket path makes every poll's
        // round-trip fail (which `wait` tolerates), so only the timeout ends the loop.
        let dead = std::path::Path::new("/tmp/tnet-wait-nope-does-not-exist.sock");
        let start = tokio::time::Instant::now();
        let r = wait_for_running(dead, Some(1)).await;
        assert!(
            r.is_err(),
            "wait against a dead socket must time out to Err"
        );
        assert!(
            r.unwrap_err().to_string().contains("timed out"),
            "the error should say it timed out"
        );
        // It should give up promptly after ~1s, not run away.
        assert!(
            start.elapsed() < std::time::Duration::from_secs(5),
            "wait should honor the ~1s timeout, took {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn up_timeout_flag_parses_into_command_up() {
        // `tnet up --timeout 30` parses to `Command::Up { timeout: Some(30), .. }`; omitting the flag
        // leaves it `None` (the fire-and-return default — no wait). This is the CLI-side contract the
        // post-`up` path keys on (`up_timeout = timeout`), so pin it at the parse boundary.
        // `Command` doesn't derive Debug, so extract the field with a helper closure rather than a
        // `match … => panic!("{other:?}")` arm (which would need Debug).
        let up_timeout_of = |argv: &[&str]| -> Option<u64> {
            match Cli::try_parse_from(argv).expect("parses").command {
                Command::Up { timeout, .. } => timeout,
                _ => panic!("expected Command::Up from {argv:?}"),
            }
        };
        assert_eq!(up_timeout_of(&["tnet", "up", "--timeout", "30"]), Some(30));
        assert_eq!(
            up_timeout_of(&["tnet", "up"]),
            None,
            "no --timeout → None (don't wait)"
        );
        // `--timeout 0` is the explicit "wait forever" value (Go's 0 = wait indefinitely); it must
        // parse as Some(0), distinct from absent (None) — `wait_for_running` maps both to no deadline.
        assert_eq!(up_timeout_of(&["tnet", "up", "--timeout", "0"]), Some(0));
    }

    #[test]
    fn up_json_flag_parses_into_command_up() {
        // `tnet up --json` parses to `Command::Up { json: true, .. }` (Go `tailscale up --json`);
        // omitting it leaves `json` false (the human-output default). Pin both at the parse boundary
        // since `run_up` keys its output mode on this exact field.
        let up_json_of = |argv: &[&str]| -> bool {
            match Cli::try_parse_from(argv).expect("parses").command {
                Command::Up { json, .. } => json,
                _ => panic!("expected Command::Up from {argv:?}"),
            }
        };
        assert!(up_json_of(&["tnet", "up", "--json"]), "--json → json: true");
        assert!(
            !up_json_of(&["tnet", "up"]),
            "no --json → json: false (human output)"
        );
    }

    #[test]
    fn up_json_string_matches_go_up_output_shape() {
        // Pin the `up --json` object shape (Go `upOutputJSON`: `{AuthURL, BackendState, Error}`),
        // including the `,omitempty` behavior on every field. The helper is pure, so assert on the
        // returned string (parsed back) rather than capturing stdout.
        let parse = |s: &str| -> serde_json::Value {
            serde_json::from_str(s).expect("up_json_string must emit valid JSON")
        };

        // Auth-URL path: `{AuthURL, BackendState}`, no `Error` key (it was empty → omitted).
        let v = parse(&up_json_string(
            Some("https://controlplane.example/a/abc123"),
            Some("NeedsLogin"),
            None,
        ));
        assert_eq!(v["AuthURL"], "https://controlplane.example/a/abc123");
        assert_eq!(v["BackendState"], "NeedsLogin");
        assert!(
            v.get("Error").is_none(),
            "empty Error must be omitted (Go `,omitempty`)"
        );
        // No `QR` field in this fork (Go gates it behind HasQRCodes; we carry no QR encoder).
        assert!(v.get("QR").is_none(), "this fork emits no QR field");

        // Done path: `{BackendState}` only.
        let v = parse(&up_json_string(None, Some("Running"), None));
        assert_eq!(v["BackendState"], "Running");
        assert!(v.get("AuthURL").is_none() && v.get("Error").is_none());

        // Failure path: `{BackendState, Error}`.
        let v = parse(&up_json_string(
            None,
            Some("NeedsLogin"),
            Some("invalid key"),
        ));
        assert_eq!(v["BackendState"], "NeedsLogin");
        assert_eq!(v["Error"], "invalid key");
        assert!(v.get("AuthURL").is_none());

        // All-empty (and explicit empty strings) → `{}`: every field omitted, valid empty object.
        assert_eq!(up_json_string(None, None, None), "{}");
        assert_eq!(
            up_json_string(Some(""), Some(""), Some("")),
            "{}",
            "empty strings are omitted exactly like absent fields"
        );

        // Error-only path (Response::Error / RevertGuard in JSON mode): `{Error}` alone.
        let v = parse(&up_json_string(None, None, Some("daemon refused")));
        assert_eq!(v["Error"], "daemon refused");
        assert!(v.get("AuthURL").is_none() && v.get("BackendState").is_none());
    }

    #[test]
    fn id_token_command_parses_audience() {
        // `tnet id-token <aud>` parses to Command::IdToken { audience } (the subcommand spelling is
        // the hyphenated `id-token`, matching Go); the audience positional is required.
        match Cli::try_parse_from(["tnet", "id-token", "https://example.com"])
            .expect("parses")
            .command
        {
            Command::IdToken { audience } => assert_eq!(audience, "https://example.com"),
            _ => panic!("expected Command::IdToken"),
        }
        // Missing the required audience is a parse error (not a panic / empty token).
        assert!(
            Cli::try_parse_from(["tnet", "id-token"]).is_err(),
            "audience is required"
        );
    }

    #[test]
    fn disablement_kdf_matches_go_goldens() {
        // The disablement KDF is a security primitive: a wrong digest means a lock initialized with
        // these values could never be disabled (the operator's secret would hash to something not in
        // the authority's set). Pin it byte-for-byte against Go `tka.DisablementKDF` v1.100.0 goldens.
        // Re-derive the value the same way the command does (the command only adds the
        // `disablement:`-prefix + print), so this proves the Argon2**i** selection + params + salt.
        use argon2::{Algorithm, Argon2, Params, Version};
        let kdf = |secret: &[u8]| -> String {
            let params = Params::new(16 * 1024, 4, 4, Some(32)).unwrap();
            let argon = Argon2::new(Algorithm::Argon2i, Version::V0x13, params);
            let mut out = [0u8; 32];
            argon
                .hash_password_into(secret, b"tailscale network-lock disablement salt", &mut out)
                .unwrap();
            out.iter().map(|b| format!("{b:02x}")).collect()
        };
        // Goldens straight from Go `tka.DisablementKDF` (v1.100.0).
        assert_eq!(
            kdf(&[0u8; 32]),
            "f56df7e85d257a51c0aa17d2600502182359a1224b892ff4667002a7bc71aa56",
            "all-zero 32B"
        );
        assert_eq!(
            kdf(&[0xFFu8; 32]),
            "fe74d82e0971202e69143984381f1834f0f3364e61e239a7d935c218e321811f",
            "all-0xFF 32B"
        );
        assert_eq!(
            kdf(&[0xA5u8; 32]),
            "c3fea8a0d70ede2555990ca60d70a8a03cbe627d2c9f3cb0e2ba7093d0884e2f",
            "all-0xA5 32B (proves Argon2i, not Argon2id)"
        );
        // The hex decoder round-trips an odd/invalid input as an error, not a panic.
        assert!(hex_decode_lower("abc").is_err(), "odd-length hex rejected");
        assert!(hex_decode_lower("zz").is_err(), "non-hex rejected");
        assert_eq!(hex_decode_lower("00ff").unwrap(), vec![0x00, 0xff]);
    }

    #[test]
    fn ip_assert_and_whois_json_flags_parse() {
        // `tnet ip --assert <ip>` parses into Command::Ip { assert: Some(..) }; and --assert conflicts
        // with a peer positional (Go: --assert is self-only).
        match Cli::try_parse_from(["tnet", "ip", "--assert", "100.64.0.1"])
            .expect("parses")
            .command
        {
            Command::Ip { assert, peer, .. } => {
                assert_eq!(assert.as_deref(), Some("100.64.0.1"));
                assert!(peer.is_none());
            }
            _ => panic!("expected Command::Ip"),
        }
        assert!(
            Cli::try_parse_from(["tnet", "ip", "--assert", "100.64.0.1", "peer-b"]).is_err(),
            "--assert must conflict with a peer argument"
        );
        // `tnet whois <ip> --json` parses into Command::Whois { json: true }.
        match Cli::try_parse_from(["tnet", "whois", "100.64.0.9", "--json"])
            .expect("parses")
            .command
        {
            Command::Whois {
                target,
                proto,
                json,
            } => {
                assert_eq!(target, vec!["100.64.0.9".to_string()]);
                assert!(proto.is_none(), "no --proto means Go's empty value: both");
                assert!(json);
            }
            _ => panic!("expected Command::Whois"),
        }
    }

    #[test]
    fn whois_accepts_gos_proto_flag_and_ip_port_argument() {
        // The whole point of the bead: `tailscale whois --proto=tcp 100.64.0.9:22` copied from Go
        // must reach the lookup instead of dying at argument parsing.
        match Cli::try_parse_from(["tnet", "whois", "--proto=tcp", "100.64.0.9:22"])
            .expect("Go's flag + ip:port argument must parse")
            .command
        {
            Command::Whois {
                target,
                proto,
                json,
            } => {
                assert_eq!(target, vec!["100.64.0.9:22".to_string()]);
                assert_eq!(proto.as_deref(), Some("tcp"));
                assert!(!json);
            }
            _ => panic!("expected Command::Whois"),
        }
        // Go's separated spelling (`--proto udp`) is the same flag.
        match Cli::try_parse_from(["tnet", "whois", "--proto", "udp", "100.64.0.9"])
            .expect("parses")
            .command
        {
            Command::Whois { proto, .. } => assert_eq!(proto.as_deref(), Some("udp")),
            _ => panic!("expected Command::Whois"),
        }
        // The positional is a list at the clap layer so the arity refusals can be Go's own words
        // (see `whois_target`) — clap itself must accept zero and two arguments.
        for argv in [
            vec!["tnet", "whois"],
            vec!["tnet", "whois", "100.64.0.9", "100.64.0.10"],
        ] {
            assert!(
                Cli::try_parse_from(&argv).is_ok(),
                "clap must defer the arity verdict to whois_target: {argv:?}"
            );
        }
    }

    #[test]
    fn whois_target_ports_gos_two_argument_refusals() {
        // Go `runWhoIs`: `len(args) > 1` → "too many arguments, expected at most one peer";
        // `len(args) == 0` → "missing argument, expected one peer". Both verbatim.
        let one = ["100.64.0.9".to_string()];
        assert_eq!(
            whois_target(&one).expect("one argument is the peer"),
            "100.64.0.9"
        );
        let none: [String; 0] = [];
        assert_eq!(
            whois_target(&none).unwrap_err().to_string(),
            "missing argument, expected one peer"
        );
        let two = ["100.64.0.9".to_string(), "100.64.0.10".to_string()];
        assert_eq!(
            whois_target(&two).unwrap_err().to_string(),
            "too many arguments, expected at most one peer"
        );
    }

    #[test]
    fn parse_whois_target_splits_gos_ip_port_form() {
        // A bare IP keeps Go's port 0, which the wire spells `None`.
        assert_eq!(
            parse_whois_target("100.64.0.9").expect("a bare IP parses"),
            ("100.64.0.9".to_string(), None)
        );
        // `ip:port` — the form the bead's copied command uses.
        assert_eq!(
            parse_whois_target("100.64.0.9:22").expect("ip:port parses"),
            ("100.64.0.9".to_string(), Some(22))
        );
        // IPv6, bare and bracketed-with-port (Go's `whois` is documented for v4 or v6).
        assert_eq!(
            parse_whois_target("fd7a:115c:a1e0::1").expect("a bare IPv6 parses"),
            ("fd7a:115c:a1e0::1".to_string(), None)
        );
        assert_eq!(
            parse_whois_target("[fd7a:115c:a1e0::1]:22").expect("[v6]:port parses"),
            ("fd7a:115c:a1e0::1".to_string(), Some(22))
        );
        // Anything else is refused here, before any daemon round trip, naming what was passed.
        for bad in ["peer-b", "100.64.0.9:", "100.64.0.9:notaport", ""] {
            let err = parse_whois_target(bad)
                .expect_err("only an IP or ip:port is accepted")
                .to_string();
            assert!(
                err.contains("expected an IP or Go's ip[:port] form"),
                "the refusal should name the accepted forms: {err}"
            );
        }
    }

    #[test]
    fn parse_whois_proto_maps_gos_three_values() {
        use tailscaled_rs::localapi::WhoisProto;
        // Go: `protocol; one of "tcp" or "udp"; empty means both`. Absent and explicitly-empty are
        // the same "both", which the wire spells `None`.
        assert_eq!(parse_whois_proto(None).expect("absent is both"), None);
        assert_eq!(parse_whois_proto(Some("")).expect("empty is both"), None);
        assert_eq!(
            parse_whois_proto(Some("tcp")).expect("tcp parses"),
            Some(WhoisProto::Tcp)
        );
        assert_eq!(
            parse_whois_proto(Some("udp")).expect("udp parses"),
            Some(WhoisProto::Udp)
        );
        // A value outside Go's documented pair is refused rather than silently ignored: it could
        // never select anything on this build, so a typo would otherwise look like it worked.
        for bad in ["TCP", "sctp", "tcp6"] {
            let err = parse_whois_proto(Some(bad))
                .expect_err("only tcp/udp are accepted")
                .to_string();
            assert!(
                err.contains("expected \"tcp\" or \"udp\""),
                "the refusal should name the accepted values: {err}"
            );
        }
    }

    #[test]
    fn resolve_tristate_maps_the_flag_pair() {
        // The shared `--x`/`--no-x` → `Option<bool>` mapping every pref flag added since the
        // per-flag resolvers uses. Neither flag must leave the persisted pref UNCHANGED, never
        // flipped to the flag's zero value — the bug this sentinel exists to prevent.
        assert_eq!(resolve_tristate(true, false), Some(true));
        assert_eq!(resolve_tristate(false, true), Some(false));
        assert_eq!(resolve_tristate(false, false), None);
        // clap's `conflicts_with` makes both-set unreachable; enable wins defensively.
        assert_eq!(resolve_tristate(true, true), Some(true));
    }

    #[test]
    fn resolve_clearable_string_distinguishes_absent_from_empty() {
        // Go clears `--operator`/`--nickname` by passing an EMPTY value (its own `fmtFlagValueArg`
        // renders exactly `--operator=`). Absent → unchanged; empty → clear; value → set. Collapsing
        // "empty" into "absent" would make the clear command a silent no-op.
        assert_eq!(resolve_clearable_string(None), None);
        assert_eq!(resolve_clearable_string(Some(String::new())), Some(None));
        assert_eq!(
            resolve_clearable_string(Some("alice".to_string())),
            Some(Some("alice".to_string()))
        );
    }

    #[test]
    fn up_carries_the_four_go_up_pref_flags() {
        // Go registers `--operator`, `--exit-node-allow-lan-access`, `--advertise-connector` and
        // `--report-posture` on BOTH `up` and `set` (up.go `newUpFlagSet`). Parse them off `tnet up`
        // and pin the resolved wire sentinels — including that omitting a flag leaves the pref
        // unchanged (`None`) rather than defaulting it off.
        match Cli::try_parse_from([
            "tnet",
            "up",
            "--operator",
            "alice",
            "--exit-node-allow-lan-access",
            "--advertise-connector",
            "--no-report-posture",
        ])
        .expect("parses")
        .command
        {
            Command::Up {
                operator,
                exit_node_allow_lan_access,
                no_exit_node_allow_lan_access,
                advertise_connector,
                no_advertise_connector,
                report_posture,
                no_report_posture,
                ..
            } => {
                assert_eq!(
                    resolve_clearable_string(operator),
                    Some(Some("alice".to_string()))
                );
                assert_eq!(
                    resolve_tristate(exit_node_allow_lan_access, no_exit_node_allow_lan_access),
                    Some(true)
                );
                assert_eq!(
                    resolve_tristate(advertise_connector, no_advertise_connector),
                    Some(true)
                );
                assert_eq!(
                    resolve_tristate(report_posture, no_report_posture),
                    Some(false)
                );
            }
            _ => panic!("expected Command::Up"),
        }
        // A bare `up` mentions none of them → every sentinel is "unchanged".
        match Cli::try_parse_from(["tnet", "up"]).expect("parses").command {
            Command::Up {
                operator,
                exit_node_allow_lan_access,
                no_exit_node_allow_lan_access,
                advertise_connector,
                no_advertise_connector,
                report_posture,
                no_report_posture,
                ..
            } => {
                assert_eq!(resolve_clearable_string(operator), None);
                assert_eq!(
                    resolve_tristate(exit_node_allow_lan_access, no_exit_node_allow_lan_access),
                    None
                );
                assert_eq!(
                    resolve_tristate(advertise_connector, no_advertise_connector),
                    None
                );
                assert_eq!(resolve_tristate(report_posture, no_report_posture), None);
            }
            _ => panic!("expected Command::Up"),
        }
        // `--operator=` (empty) is Go's "remove the operator" form → the CLEAR sentinel.
        match Cli::try_parse_from(["tnet", "up", "--operator="])
            .expect("parses")
            .command
        {
            Command::Up { operator, .. } => {
                assert_eq!(resolve_clearable_string(operator), Some(None))
            }
            _ => panic!("expected Command::Up"),
        }
        // Go does NOT register `--webclient`/`--auto-update`/`--update-check` on `up` (only on
        // `set`), so neither do we — an `up` that names them is a usage error, not a
        // silently-ignored flag.
        for flag in ["--webclient", "--auto-update", "--update-check"] {
            assert!(
                Cli::try_parse_from(["tnet", "up", flag]).is_err(),
                "{flag} must not be an `up` flag (Go registers it on `set` only)"
            );
        }
        // `--nickname` is not an `up` pref either — Go registers it on `set` and `login` — but it is
        // carried on the parser so a command line that names it is answered by name rather than by
        // clap; see `up_nickname_is_answered_by_name_and_sent_to_set`.
        assert!(
            check_ported_up_flags(&parse_ported_up(&["--nickname=x"])).is_err(),
            "`up --nickname` must not set a pref: it is refused"
        );
    }

    #[test]
    fn set_carries_all_eight_go_set_pref_flags() {
        // Go's `set` flag set (set.go `newSetFlagSet`) carries four more than `up`: `--nickname`,
        // `--webclient`, `--auto-update`, `--update-check`. Parse all eight off `tnet set` and pin
        // the resolved wire sentinels.
        match Cli::try_parse_from([
            "tnet",
            "set",
            "--advertise-connector",
            "--auto-update",
            "--no-update-check",
            "--operator",
            "alice",
            "--nickname",
            "laptop",
            "--report-posture",
            "--webclient",
            "--exit-node-allow-lan-access",
        ])
        .expect("parses")
        .command
        {
            Command::Set {
                advertise_connector,
                no_advertise_connector,
                auto_update,
                no_auto_update,
                update_check,
                no_update_check,
                operator,
                nickname,
                report_posture,
                no_report_posture,
                webclient,
                no_webclient,
                exit_node_allow_lan_access,
                no_exit_node_allow_lan_access,
                ..
            } => {
                assert_eq!(
                    resolve_tristate(advertise_connector, no_advertise_connector),
                    Some(true)
                );
                assert_eq!(resolve_tristate(auto_update, no_auto_update), Some(true));
                assert_eq!(resolve_tristate(update_check, no_update_check), Some(false));
                assert_eq!(
                    resolve_clearable_string(operator),
                    Some(Some("alice".to_string()))
                );
                assert_eq!(
                    resolve_clearable_string(nickname),
                    Some(Some("laptop".to_string()))
                );
                assert_eq!(
                    resolve_tristate(report_posture, no_report_posture),
                    Some(true)
                );
                assert_eq!(resolve_tristate(webclient, no_webclient), Some(true));
                assert_eq!(
                    resolve_tristate(exit_node_allow_lan_access, no_exit_node_allow_lan_access),
                    Some(true)
                );
            }
            _ => panic!("expected Command::Set"),
        }
        // Each `--x` is mutually exclusive with its `--no-x` (clap `conflicts_with`), so a
        // contradictory invocation is refused rather than silently resolved.
        for (on, off) in [
            ("--advertise-connector", "--no-advertise-connector"),
            ("--auto-update", "--no-auto-update"),
            ("--update-check", "--no-update-check"),
            ("--report-posture", "--no-report-posture"),
            ("--webclient", "--no-webclient"),
            (
                "--exit-node-allow-lan-access",
                "--no-exit-node-allow-lan-access",
            ),
        ] {
            assert!(
                Cli::try_parse_from(["tnet", "set", on, off]).is_err(),
                "{on} and {off} must conflict"
            );
        }
    }

    /// Parse a `tnet set` command line and project it onto the four unmodelled Go `set` pref flags,
    /// exactly as `main`'s `Command::Set` arm builds the value it hands to `run_set`.
    fn parse_unmodelled_set(argv: &[&str]) -> UnmodelledSetFlags {
        let mut full = vec!["tnet", "set"];
        full.extend_from_slice(argv);
        match Cli::try_parse_from(full)
            .unwrap_or_else(|e| panic!("{argv:?} should parse: {e}"))
            .command
        {
            Command::Set {
                relay_server_port,
                relay_server_static_endpoints,
                remote_config,
                no_remote_config,
                sync,
                no_sync,
                ..
            } => UnmodelledSetFlags {
                relay_server_port,
                relay_server_static_endpoints,
                remote_config: resolve_tristate(remote_config, no_remote_config),
                sync: resolve_tristate(sync, no_sync),
            },
            _ => panic!("expected Command::Set"),
        }
    }

    #[test]
    fn the_four_unmodelled_set_flags_parse_instead_of_dying_at_the_parser() {
        // The whole point of carrying them: a command line ported from Go reaches a refusal that
        // names the gap, not clap's "unexpected argument". All four are `set`-only in Go
        // (`set.go` `newSetFlagSet`; `up.go` registers none of them), so `tnet up` must still
        // reject them.
        let flags = parse_unmodelled_set(&[
            "--relay-server-port=41641",
            "--relay-server-static-endpoints=192.0.2.1:40000",
            "--remote-config",
            "--no-sync",
        ]);
        assert_eq!(
            flags,
            UnmodelledSetFlags {
                relay_server_port: Some("41641".to_string()),
                relay_server_static_endpoints: Some("192.0.2.1:40000".to_string()),
                remote_config: Some(true),
                sync: Some(false),
            }
        );

        // Absent flags stay absent — an unmentioned flag must not look like a mentioned one.
        assert_eq!(parse_unmodelled_set(&[]), UnmodelledSetFlags::default());
        assert!(check_unmodelled_set_flags(&UnmodelledSetFlags::default()).is_ok());

        // Go's bool flags become this build's `--x`/`--no-x` pairs, which must conflict.
        for (on, off) in [
            ("--remote-config", "--no-remote-config"),
            ("--sync", "--no-sync"),
        ] {
            assert!(
                Cli::try_parse_from(["tnet", "set", on, off]).is_err(),
                "{on} and {off} must conflict"
            );
        }

        // `up` does not carry them (Go registers them on `set` only).
        for flag in [
            "--relay-server-port=41641",
            "--relay-server-static-endpoints=192.0.2.1:40000",
            "--remote-config",
            "--sync",
        ] {
            assert!(
                Cli::try_parse_from(["tnet", "up", flag]).is_err(),
                "{flag} is a set-only flag in Go"
            );
        }
    }

    #[test]
    fn gos_own_relay_flag_parse_errors_come_first() {
        // Go parses `--relay-server-port` with `strconv.ParseUint(s, 10, 16)`, so a non-number, a
        // negative, a sign prefix and anything past 65535 all fail before any refusal — with Go's
        // `failed to set relay server port:` prefix.
        for value in ["notanumber", "-1", "+80", "65536", "1e5"] {
            let err = check_unmodelled_set_flags(&parse_unmodelled_set(&[&format!(
                "--relay-server-port={value}"
            )]))
            .expect_err("Go rejects this value")
            .to_string();
            assert!(
                err.starts_with("failed to set relay server port: "),
                "{value}: {err}"
            );
        }

        // `netip.ParseAddrPort` needs brackets around an IPv6 literal and a port on every entry;
        // Go names the offending entry with %q and stops at the first bad one.
        for (value, bad) in [
            ("192.0.2.1", "192.0.2.1"),
            ("192.0.2.1:40000,2001:db8::1:40000", "2001:db8::1:40000"),
            ("192.0.2.1:40000,,198.51.100.7:40000", ""),
            ("192.0.2.1:99999", "192.0.2.1:99999"),
        ] {
            let err = check_unmodelled_set_flags(&parse_unmodelled_set(&[&format!(
                "--relay-server-static-endpoints={value}"
            )]))
            .expect_err("Go rejects this list")
            .to_string();
            assert_eq!(
                err,
                format!(
                    "failed to set relay server static endpoints: {bad:?} is not a valid IP:port"
                ),
                "{value}"
            );
        }

        // A malformed port is rejected before the endpoints are even looked at (Go parses the port
        // first), and before this build's own refusals fire — so nothing reaches the daemon.
        let err = check_unmodelled_set_flags(&parse_unmodelled_set(&[
            "--relay-server-port=nope",
            "--relay-server-static-endpoints=alsonope",
            "--remote-config",
        ]))
        .expect_err("the port parse runs first")
        .to_string();
        assert!(
            err.starts_with("failed to set relay server port: "),
            "{err}"
        );
    }

    #[test]
    fn relay_endpoints_are_deduped_and_ordered_like_go() {
        // Go collects into a `set.Set[netip.AddrPort]` then sorts with `netip.AddrPort.Compare`:
        // every IPv4 endpoint before every IPv6 one, then by address, then by port. The refusal
        // message names that normalized list, so this pins the normalization the parser produces.
        let endpoints = parse_relay_static_endpoints(
            "[2001:db8::1]:40000,198.51.100.7:40001,192.0.2.1:40000,198.51.100.7:40000,192.0.2.1:40000",
        )
        .expect("every entry is a valid IP:port");
        assert_eq!(
            endpoints
                .iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join(","),
            "192.0.2.1:40000,198.51.100.7:40000,198.51.100.7:40001,[2001:db8::1]:40000"
        );

        // Go's zero port is legal on the port flag ("pick a random unused port"), so it must reach
        // the refusal rather than the parse error.
        assert_eq!(parse_relay_server_port("0").unwrap(), 0);
        assert_eq!(parse_relay_server_port("65535").unwrap(), 65535);
    }

    #[test]
    fn the_value_this_build_already_guarantees_is_accepted() {
        // Go types the two relay flags as STRINGS so the empty value means "disable" /
        // "advertise none" — which is the state this daemon is permanently in, so those command
        // lines keep working instead of being refused for asking for the status quo. Likewise
        // `--no-remote-config` (never delegate) and `--sync` (do sync from control).
        for argv in [
            vec!["--relay-server-port="],
            vec!["--relay-server-static-endpoints="],
            vec!["--no-remote-config"],
            vec!["--sync"],
            vec![
                "--relay-server-port=",
                "--relay-server-static-endpoints=",
                "--no-remote-config",
                "--sync",
            ],
        ] {
            check_unmodelled_set_flags(&parse_unmodelled_set(&argv))
                .unwrap_or_else(|e| panic!("{argv:?} asks for the status quo: {e}"));
        }
    }

    #[test]
    fn the_value_that_needs_missing_behaviour_is_refused_by_name() {
        // Each refusal must NAME the flag (and its value, where there is one) so a ported command
        // line says what is missing, and must say plainly that this build does not support it.
        for (argv, needle) in [
            (
                vec!["--relay-server-port=41641"],
                "--relay-server-port=41641",
            ),
            (vec!["--relay-server-port=0"], "--relay-server-port=0"),
            (
                vec!["--relay-server-static-endpoints=198.51.100.7:40000,192.0.2.1:40000"],
                // The normalized (deduped, Go-ordered) list, not the raw argument.
                "--relay-server-static-endpoints=192.0.2.1:40000,198.51.100.7:40000",
            ),
            (vec!["--remote-config"], "--remote-config"),
            (vec!["--no-sync"], "--no-sync"),
        ] {
            let err = check_unmodelled_set_flags(&parse_unmodelled_set(&argv))
                .expect_err("this build cannot do this")
                .to_string();
            assert!(err.contains(needle), "{argv:?}: {err}");
            assert!(
                err.contains("not supported by this build"),
                "{argv:?}: {err}"
            );
        }

        // `--remote-config` is refused as a product decision, not as an engine gap: the message has
        // to say so, or a reader will file it as another pin-bump wait.
        let err = check_unmodelled_set_flags(&parse_unmodelled_set(&["--remote-config"]))
            .expect_err("declined by design")
            .to_string();
        assert!(
            err.contains("not a gap this fork intends to close"),
            "{err}"
        );
        assert!(err.contains("double opt-in"), "{err}");

        // The three that ARE engine-gated point at the filed ask instead.
        for argv in [
            vec!["--relay-server-port=41641"],
            vec!["--relay-server-static-endpoints=192.0.2.1:40000"],
            vec!["--no-sync"],
        ] {
            let err = check_unmodelled_set_flags(&parse_unmodelled_set(&argv))
                .expect_err("engine-gated")
                .to_string();
            assert!(err.contains("engine ask #34"), "{argv:?}: {err}");
        }
    }

    /// Parse a `tnet up` command line and project it onto the Go `up` spellings that carry no pref,
    /// exactly as `main`'s `Command::Up` arm builds the value it hands to `run_up`.
    fn parse_ported_up(argv: &[&str]) -> PortedUpFlags {
        let mut full = vec!["tnet", "up"];
        full.extend_from_slice(argv);
        match Cli::try_parse_from(&full)
            .unwrap_or_else(|e| panic!("`tnet up {argv:?}` should parse: {e}"))
            .command
        {
            Command::Up {
                host_routes,
                nickname,
                ..
            } => PortedUpFlags {
                host_routes,
                nickname,
            },
            _ => panic!("expected Command::Up"),
        }
    }

    #[test]
    fn gos_up_spellings_land_on_this_forks_own_up_flags() {
        // `--auth-key` and `--login-server` are Go's names for two flags this fork already had, so
        // they are ALIASES: one flag, two spellings, identical behaviour. A ported command line that
        // uses Go's names must set exactly what the fork's names set.
        let Command::Up {
            authkey,
            control_url,
            ..
        } = Cli::try_parse_from([
            "tnet",
            "up",
            "--auth-key",
            "tskey-auth-example",
            "--login-server",
            "https://headscale.example.com",
        ])
        .expect("Go's spellings should parse")
        .command
        else {
            panic!("expected Command::Up")
        };
        assert_eq!(authkey.as_deref(), Some("tskey-auth-example"));
        assert_eq!(
            control_url.as_deref(),
            Some("https://headscale.example.com")
        );

        // Being one flag under two names is the point: naming it twice is naming one flag twice, and
        // Go's own `--auth-key` still cannot be combined with this fork's `--authkey-file`.
        for argv in [
            vec!["--authkey", "a", "--auth-key", "b"],
            vec![
                "--control-url",
                "http://a.example",
                "--login-server",
                "http://b.example",
            ],
            vec!["--auth-key", "a", "--authkey-file", "/dev/null"],
        ] {
            let mut full = vec!["tnet", "up"];
            full.extend_from_slice(&argv);
            assert!(
                Cli::try_parse_from(&full).is_err(),
                "{argv:?} names one flag twice (or a flag it conflicts with)"
            );
        }
    }

    #[test]
    fn host_routes_accepts_only_the_value_go_allows() {
        // Go registers `--host-routes` as a `notFalseVar`: a bool flag whose `Set` takes "true" and
        // nothing else, hidden, and inert since Tailscale 1.67. Presence and `=true` are accepted
        // and do nothing; every other value is Go's refusal, wrapped the way Go's flag package
        // wraps it.
        for argv in [vec!["--host-routes"], vec!["--host-routes=true"]] {
            let flags = parse_ported_up(&argv);
            assert_eq!(flags.host_routes.as_deref(), Some("true"), "{argv:?}");
            check_ported_up_flags(&flags)
                .unwrap_or_else(|e| panic!("{argv:?} is the one value Go allows: {e}"));
        }
        for value in ["false", "0", "1", "True", ""] {
            let err = check_ported_up_flags(&parse_ported_up(&[&format!("--host-routes={value}")]))
                .expect_err("Go allows only 'true'")
                .to_string();
            assert_eq!(
                err,
                format!(
                    "invalid boolean value {value:?} for --host-routes: unsupported value; only \
                     'true' is allowed"
                ),
                "--host-routes={value}"
            );
        }
        // Go's `IsBoolFlag` means the flag never consumes the following argument, so a
        // space-separated value is not a value at all — `up` takes no positionals, so it is refused.
        assert!(
            Cli::try_parse_from(["tnet", "up", "--host-routes", "false"]).is_err(),
            "`--host-routes false` passes `false` as a non-flag argument, as it does in Go"
        );
        // An absent flag asks for nothing.
        assert_eq!(parse_ported_up(&[]), PortedUpFlags::default());
        assert!(check_ported_up_flags(&PortedUpFlags::default()).is_ok());
    }

    #[test]
    fn up_nickname_is_answered_by_name_and_sent_to_set() {
        // `--nickname` is the one of the four that is NOT a rename of something `up` has: no `up`
        // carries a profile name, here or upstream (`up.go` registers it only when the command is
        // `login`). So it parses — no "unexpected argument" — and is refused with the command that
        // does the job.
        let flags = parse_ported_up(&["--nickname", "work-laptop"]);
        assert_eq!(flags.nickname.as_deref(), Some("work-laptop"));
        let err = check_ported_up_flags(&flags)
            .expect_err("`up` names no profile")
            .to_string();
        assert!(err.contains("tnet set --nickname"), "{err}");
        assert!(err.contains("`login`"), "{err}");

        // Go decides both of these in its flag parser, and `--host-routes` is the one that can be
        // wrong on its own line — so it is answered first, whatever else the command line carries.
        let err = check_ported_up_flags(&parse_ported_up(&[
            "--host-routes=false",
            "--nickname",
            "work-laptop",
        ]))
        .expect_err("both are refused")
        .to_string();
        assert!(err.contains("only 'true' is allowed"), "{err}");
    }

    #[tokio::test]
    async fn auth_key_reads_the_file_a_file_prefix_names() {
        use secrecy::ExposeSecret as _;
        // Go's `--auth-key`/`--authkey` value may be `file:<path>` (`up.go` `resolveValueFromFile`,
        // via `getAuthKey`), which is how a ported command line keeps the key out of argv without
        // this fork's own `--authkey-file`. The contents are trimmed, as Go trims them.
        let dir = std::env::temp_dir().join(format!("tnet-authkey-file-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let path = dir.join("key");
        tokio::fs::write(&path, b"  tskey-auth-from-file\r\n")
            .await
            .unwrap();

        let from_prefix = resolve_authkey(Some(format!("file:{}", path.display())), None)
            .await
            .unwrap()
            .expect("a key was supplied");
        assert_eq!(from_prefix.expose_secret(), "tskey-auth-from-file");

        // The fork's own `--authkey-file` reads the same file the same way, and still wins over a
        // value given to `--authkey` (the documented precedence).
        let from_flag = resolve_authkey(Some("tskey-inline".into()), Some(path.clone()))
            .await
            .unwrap()
            .expect("a key was supplied");
        assert_eq!(from_flag.expose_secret(), "tskey-auth-from-file");

        // A bare value is still taken verbatim — only the `file:` prefix means a path.
        let literal = resolve_authkey(Some("tskey-inline".into()), None)
            .await
            .unwrap()
            .expect("a key was supplied");
        assert_eq!(literal.expose_secret(), "tskey-inline");

        // A `file:` path that does not exist is an error naming what it failed to read, not a key
        // whose literal value is the path.
        let missing = dir.join("absent");
        let err = resolve_authkey(Some(format!("file:{}", missing.display())), None)
            .await
            .expect_err("the file is not there");
        assert!(
            format!("{err:#}").contains("reading auth key from"),
            "{err:#}"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[test]
    fn get_reports_no_row_for_the_unmodelled_set_flags() {
        // `tnet get` keys its output by set-flag name, and these four store no pref — so they must
        // NOT appear with a fabricated value. `format_get` errors on an unknown name, which is the
        // honest answer here.
        let view = tailscaled_rs::localapi::PrefsView::default();
        for name in [
            "relay-server-port",
            "relay-server-static-endpoints",
            "remote-config",
            "sync",
        ] {
            assert!(
                !get_settings(&view).iter().any(|(n, _)| *n == name),
                "{name} has no persisted value to report"
            );
            let err = format_get(&view, Some(name), false)
                .expect_err("no such setting")
                .to_string();
            assert!(err.contains(name), "{err}");
        }
    }

    #[test]
    fn new_pref_flags_reach_the_wire_requests() {
        // The wire mapping, built from the same `UpPrefFlags`/`SetPrefFlags` groups `main` hands to
        // `run_up`/`run_set`. Proves each flag lands on its OWN wire field (a mis-wired pair would
        // otherwise only show up against a live daemon).
        let up_prefs = UpPrefFlags {
            operator: Some(Some("alice".to_string())),
            exit_node_allow_lan_access: Some(true),
            advertise_connector: Some(false),
            report_posture: Some(true),
        };
        let up = Request::Up {
            authkey: None,
            control_url: None,
            hostname: None,
            tun: None,
            tun_name: None,
            tun_mtu: None,
            exit_node: None,
            advertise_exit_node: None,
            advertise_routes: None,
            advertise_tags: None,
            accept_routes: None,
            accept_dns: None,
            shields_up: None,
            ssh: None,
            operator: up_prefs.operator,
            exit_node_allow_lan_access: up_prefs.exit_node_allow_lan_access,
            advertise_connector: up_prefs.advertise_connector,
            report_posture: up_prefs.report_posture,
            reset: false,
            force_reauth: false,
            ephemeral: None,
            client_id: None,
            client_secret: None,
            id_token: None,
            audience: None,
        };
        match up {
            Request::Up {
                operator,
                exit_node_allow_lan_access,
                advertise_connector,
                report_posture,
                ..
            } => {
                assert_eq!(operator, Some(Some("alice".to_string())));
                assert_eq!(exit_node_allow_lan_access, Some(true));
                assert_eq!(advertise_connector, Some(false));
                assert_eq!(report_posture, Some(true));
            }
            other => panic!("expected Request::Up, got {other:?}"),
        }

        let set_prefs = SetPrefFlags {
            advertise_connector: Some(true),
            auto_update: Some(false),
            update_check: Some(false),
            operator: Some(None),
            nickname: Some(Some("laptop".to_string())),
            report_posture: Some(true),
            webclient: Some(true),
            exit_node_allow_lan_access: Some(false),
        };
        let set = Request::Set {
            hostname: None,
            accept_routes: None,
            accept_dns: None,
            shields_up: None,
            exit_node: None,
            advertise_exit_node: None,
            advertise_routes: None,
            advertise_tags: None,
            ssh: None,
            advertise_connector: set_prefs.advertise_connector,
            auto_update: set_prefs.auto_update,
            update_check: set_prefs.update_check,
            operator: set_prefs.operator,
            nickname: set_prefs.nickname,
            report_posture: set_prefs.report_posture,
            webclient: set_prefs.webclient,
            exit_node_allow_lan_access: set_prefs.exit_node_allow_lan_access,
        };
        match set {
            Request::Set {
                advertise_connector,
                auto_update,
                update_check,
                operator,
                nickname,
                report_posture,
                webclient,
                exit_node_allow_lan_access,
                ..
            } => {
                assert_eq!(advertise_connector, Some(true));
                assert_eq!(
                    auto_update,
                    Some(false),
                    "--no-auto-update is an explicit OFF"
                );
                assert_eq!(update_check, Some(false));
                assert_eq!(operator, Some(None), "--operator= clears");
                assert_eq!(nickname, Some(Some("laptop".to_string())));
                assert_eq!(report_posture, Some(true));
                assert_eq!(webclient, Some(true));
                assert_eq!(exit_node_allow_lan_access, Some(false));
            }
            other => panic!("expected Request::Set, got {other:?}"),
        }
    }

    #[test]
    fn accept_risk_flag_parses_on_up_and_set() {
        // `--accept-risk <risk>` parses on both `up` and `set` (Go --accept-risk); omitted → None.
        match Cli::try_parse_from(["tnet", "up", "--accept-risk", "lose-ssh"])
            .expect("parses")
            .command
        {
            Command::Up { accept_risk, .. } => assert_eq!(accept_risk.as_deref(), Some("lose-ssh")),
            _ => panic!("expected Command::Up"),
        }
        match Cli::try_parse_from(["tnet", "up"]).expect("parses").command {
            Command::Up { accept_risk, .. } => assert_eq!(accept_risk, None),
            _ => panic!("expected Command::Up"),
        }
        match Cli::try_parse_from(["tnet", "set", "--accept-risk", "all"])
            .expect("parses")
            .command
        {
            Command::Set { accept_risk, .. } => assert_eq!(accept_risk.as_deref(), Some("all")),
            _ => panic!("expected Command::Set"),
        }
    }

    #[tokio::test]
    async fn wait_forever_does_not_return_promptly_against_a_dead_socket() {
        // `--timeout 0` (and `None`) = wait forever: `wait_for_running` must NOT compute a deadline,
        // so against a never-Running dead socket it keeps polling rather than erroring out. We can't
        // wait forever in a test, so assert it is STILL running after a short bound (i.e. it did not
        // immediately return an Err the way a finite timeout would). Complements
        // `wait_times_out_against_a_dead_socket`, which covers the finite-timeout Err path.
        let dead = std::path::Path::new("/tmp/tnet-wait-forever-nope.sock");
        let res = tokio::time::timeout(
            std::time::Duration::from_millis(300),
            wait_for_running(dead, Some(0)),
        )
        .await;
        assert!(
            res.is_err(),
            "timeout:0 means wait forever — wait_for_running must still be polling (not returned) \
             after 300ms against a dead socket, so the outer tokio timeout should elapse"
        );
    }

    #[test]
    fn wait_decision_precedence_running_error_authurl_keep() {
        use tailscaled_rs::localapi::StatusReport;

        // (a) Running + a tailnet IP, NETSTACK mode (default, prefs.tun=false) → Done immediately
        // (no kernel interface to observe — Go also returns early on `!st.TUN`).
        let running = StatusReport {
            state: "Running".to_string(),
            self_ipv4: Some("100.64.0.1".to_string()),
            ..Default::default()
        };
        assert_eq!(wait_decision(&running), WaitStep::Done);

        // (a') Running + a tailnet IP, TUN mode → AwaitInterfaceIp (Go `wait` additionally confirms the
        // kernel interface carries the IP; the impure caller does that check). Carries the IP to find.
        let running_tun = StatusReport {
            state: "Running".to_string(),
            self_ipv4: Some("100.64.0.1".to_string()),
            prefs: tailscaled_rs::localapi::PrefsView {
                tun: true,
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(
            wait_decision(&running_tun),
            WaitStep::AwaitInterfaceIp("100.64.0.1".to_string()),
            "a TUN-mode Running node must await the kernel interface IP (Go checkForInterfaceIP)"
        );

        // Running short-circuits even if (impossibly) an error were also set — Running wins.
        let running_with_stale_error = StatusReport {
            state: "Running".to_string(),
            self_ipv4: Some("100.64.0.1".to_string()),
            error: Some("stale".to_string()),
            ..Default::default()
        };
        assert_eq!(wait_decision(&running_with_stale_error), WaitStep::Done);

        // (b) A terminal error (and not yet Running) → Failed, carrying the reason.
        let failed = StatusReport {
            state: "NeedsLogin".to_string(),
            error: Some("authkey expired".to_string()),
            ..Default::default()
        };
        assert_eq!(
            wait_decision(&failed),
            WaitStep::Failed("authkey expired".to_string()),
            "a terminal registration error must fail fast with the reason"
        );

        // (c) auth_url present but NO error → Keep (interactive login is pending = transient, NOT a
        // failure — failing here would break every interactive `up --timeout`).
        let pending_login = StatusReport {
            state: "NeedsLogin".to_string(),
            auth_url: Some("https://login.example/a/abc123".to_string()),
            error: None,
            ..Default::default()
        };
        assert_eq!(
            wait_decision(&pending_login),
            WaitStep::Keep,
            "a pending auth_url is transient — keep waiting, do not fail"
        );

        // (d) A bare not-yet-Running status (no error, no auth_url) → Keep.
        let starting = StatusReport {
            state: "Starting".to_string(),
            ..Default::default()
        };
        assert_eq!(wait_decision(&starting), WaitStep::Keep);

        // (e) A hostile error string (control-influenced): `wait_decision` carries the RAW reason
        // (it's a pure classifier — the caller sanitizes at the bail site, like `classify_auth`).
        // Assert the raw reason round-trips here, AND that the caller's sanitize step — the registration
        // `reason` is free-form text, so `wait_for_running` applies `sanitize_multiline` — strips the
        // ESC/BEL while preserving the legible newline. The full two-step contract, not just one half.
        let hostile = StatusReport {
            state: "NeedsLogin".to_string(),
            error: Some("evil\x1b[2J\x07reason\nsecond line".to_string()),
            ..Default::default()
        };
        match wait_decision(&hostile) {
            WaitStep::Failed(reason) => {
                assert_eq!(
                    reason, "evil\x1b[2J\x07reason\nsecond line",
                    "wait_decision carries the RAW reason (caller sanitizes)"
                );
                // The caller's sanitize step (mirrors wait_for_running's bail site) neutralizes the
                // escapes but, because a registration reason is free-form, keeps the newline so a
                // multi-line server message still renders across lines (matching Go's raw print).
                let shown = sanitize_multiline(&reason);
                assert!(!shown.contains('\x1b'), "ESC stripped at the bail site");
                assert!(!shown.contains('\x07'), "BEL stripped at the bail site");
                assert!(
                    shown.contains('\n'),
                    "multiline reason keeps its newline: {shown:?}"
                );
                assert!(shown.contains("evil") && shown.contains("second line"));
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn tun_interface_has_ip_rejects_unparseable_loopback_and_absent() {
        // An unparseable "IP" is never present (keep waiting, never a spurious success).
        assert!(!tun_interface_has_ip("not-an-ip"));
        assert!(!tun_interface_has_ip(""));
        // A loopback address is explicitly excluded (it's on lo on every host, but it is NOT the
        // tailnet interface carrying the overlay IP — counting it would let the wait return on a node
        // whose TUN iface never came up).
        assert!(
            !tun_interface_has_ip("127.0.0.1"),
            "loopback must not satisfy the kernel-interface-IP check"
        );
        // A CGNAT tailnet IP that is (essentially certainly) not assigned on this test host → absent.
        // This asserts the negative path deterministically without depending on host interfaces; the
        // positive path (the IP IS present) is covered by the gated TUN e2e, which has a real iface.
        assert!(
            !tun_interface_has_ip("100.127.255.254"),
            "an unassigned tailnet IP must read as not-yet-present"
        );
    }

    #[test]
    fn version_command_client_matches_crate_version() {
        // The client version `tnet version` prints is the crate version — guards against drift if the
        // print path ever stops using CARGO_PKG_VERSION.
        assert_eq!(
            format_version(env!("CARGO_PKG_VERSION"), None, 130, false),
            format!("{}\n", env!("CARGO_PKG_VERSION"))
        );
    }

    #[test]
    fn semver_parse_and_order() {
        // `v`-prefix optional; pre-release/build suffix ignored; ordering is numeric per-field.
        assert_eq!(SemVer::parse("v0.43.0"), SemVer::parse("0.43.0"));
        assert_eq!(SemVer::parse("0.43.0").unwrap().to_string(), "0.43.0");
        assert_eq!(
            SemVer::parse("v1.2.3-rc1"),
            Some(SemVer {
                major: 1,
                minor: 2,
                patch: 3
            })
        );
        assert!(SemVer::parse("v0.42.0") < SemVer::parse("v0.43.0"));
        assert!(SemVer::parse("v0.43.0") < SemVer::parse("v0.43.1"));
        assert!(SemVer::parse("v1.0.0") > SemVer::parse("v0.99.99"));
        // The crate's own version must parse (the updater reads it as the baseline).
        assert!(SemVer::parse(env!("CARGO_PKG_VERSION")).is_some());
        // Garbage / wrong arity → None.
        assert_eq!(SemVer::parse("nope"), None);
        assert_eq!(SemVer::parse("1.2"), None);
        assert_eq!(SemVer::parse("1.2.3.4"), None);
    }

    #[test]
    fn verify_sha256_matches_and_rejects() {
        use sha2::{Digest as _, Sha256};
        let data = b"the release tarball bytes";
        let hex: String = Sha256::digest(data)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        // GNU sha256sum format: "<hex>  <filename>" (two spaces). A good sidecar verifies.
        let good = format!("{hex}  tailscaled-rs-v0.43.0-x86_64-unknown-linux-gnu.tar.gz\n");
        assert!(verify_sha256(data, good.as_bytes(), "tarball").is_ok());
        // Filename column is ignored — only the digest matters.
        assert!(verify_sha256(data, format!("{hex}  whatever\n").as_bytes(), "x").is_ok());
        // A wrong digest is rejected (corruption / tamper).
        let bad = format!("{}  f\n", "0".repeat(64));
        assert!(verify_sha256(data, bad.as_bytes(), "tarball").is_err());
        // Malformed sidecars are rejected, not silently accepted.
        assert!(verify_sha256(data, b"", "x").is_err());
        assert!(verify_sha256(data, b"not-hex  f\n", "x").is_err());
        assert!(verify_sha256(data, b"abc  short\n", "x").is_err());
    }

    #[test]
    fn host_release_triple_is_linux_or_none() {
        // On a published-asset platform it's a Linux glibc triple; elsewhere (e.g. macOS) it's None
        // so `update --yes` can report "no artifact for this platform" instead of 404-ing.
        match (std::env::consts::OS, std::env::consts::ARCH) {
            ("linux", "x86_64") => {
                assert_eq!(host_release_triple(), Some("x86_64-unknown-linux-gnu"))
            }
            ("linux", "aarch64") => {
                assert_eq!(host_release_triple(), Some("aarch64-unknown-linux-gnu"))
            }
            _ => assert_eq!(host_release_triple(), None),
        }
    }

    #[test]
    fn homebrew_formula_owning_recognises_every_cellar_prefix() {
        // The three prefixes Homebrew ships with, plus a custom one: the formula is the component
        // after `Cellar`, whatever the prefix is.
        for prefix in [
            "/usr/local",
            "/opt/homebrew",
            "/home/linuxbrew/.linuxbrew",
            "/srv/brew",
        ] {
            let exe =
                std::path::PathBuf::from(format!("{prefix}/Cellar/tailscaled-rs/0.52.2/bin/tnet"));
            assert_eq!(
                homebrew_formula_owning(&exe).as_deref(),
                Some("tailscaled-rs"),
                "{} should be recognised as a Homebrew-owned file",
                exe.display()
            );
        }
    }

    #[test]
    fn homebrew_formula_owning_ignores_non_homebrew_paths() {
        // The paths a release tarball / `cargo install` / a distro package put the binary at — none
        // of them are Homebrew's, so `update --yes` must NOT refuse for them.
        for path in [
            "/usr/local/bin/tnet",
            "/usr/bin/tnet",
            "/home/alice/.cargo/bin/tnet",
            "/opt/tailscaled-rs/bin/tnet",
            // A directory literally named Cellar but with nothing installed under it: `Cellar/x`
            // alone names no file, so it is not evidence of a Homebrew install.
            "/usr/local/Cellar/tailscaled-rs",
        ] {
            assert_eq!(
                homebrew_formula_owning(std::path::Path::new(path)),
                None,
                "{path} is not a Homebrew-owned file"
            );
        }
    }

    #[test]
    fn homebrew_update_refusal_names_the_formula_and_the_brew_command() {
        // The refusal has to be actionable: it must say Homebrew owns the binary and give the exact
        // command that updates it (Go's package-manager refusals do the same — see
        // `clientupdate.updateFreeBSD`'s `pkg upgrade tailscale` hint).
        let msg = homebrew_update_refusal("tailscaled-rs");
        assert!(msg.contains("Homebrew"), "{msg}");
        assert!(
            msg.contains("brew update && brew upgrade tailscaled-rs"),
            "the refusal must name the command that does work: {msg}"
        );
        // The formula name is carried through rather than hard-coded, so a renamed/forked formula
        // still gets a command that works.
        assert!(
            homebrew_update_refusal("tailscaled-rs-git").contains("brew upgrade tailscaled-rs-git"),
            "the formula name must be interpolated, not assumed"
        );
    }

    #[test]
    fn format_revert_guard_renders_sorted_copy_pasteable_command() {
        // The canonical case: `tnet up --ssh` on a node that already advertises routes + accepts
        // routes. The daemon reports the two reverts; the message must list a `tnet up` line that
        // re-mentions both, in a deterministic (sorted) order, and offer `--reset`.
        let reverts = vec![
            RevertedPref {
                key: "advertise_routes".to_string(),
                value: "10.0.0.0/8".to_string(),
            },
            RevertedPref {
                key: "accept_routes".to_string(),
                value: "true".to_string(),
            },
        ];
        let out = format_revert_guard(&reverts);
        // Both keep-flags present, sorted: "--accept-routes" < "--advertise-routes=...".
        assert!(
            out.contains("tnet up --accept-routes --advertise-routes=10.0.0.0/8"),
            "expected a sorted copy-pasteable command, got:\n{out}"
        );
        assert!(
            out.contains("--reset"),
            "must mention the --reset escape hatch"
        );
        // It is framed as an error (non-zero exit at the call site) and explains the revert.
        assert!(out.starts_with("error:"));
        assert!(out.contains("revert"));
    }

    #[test]
    #[cfg(unix)]
    fn reset_sigpipe_sets_default_disposition() {
        // The fix for the broken-pipe panic: `reset_sigpipe()` must actually restore SIGPIPE to
        // SIG_DFL (Rust's runtime installs SIG_IGN, which is what makes `print!` to a closed pipe
        // panic). Prove it by reading the handler back via sigaction after calling the helper — so a
        // refactor that drops or breaks the reset is caught. (Pure libc introspection; no piping.)
        super::reset_sigpipe();
        // SAFETY: sigaction with a null `act` only READS the current handler into `oldact`; no
        // preconditions, no mutation. `MaybeUninit` is fully written by the call on success.
        let mut oldact = std::mem::MaybeUninit::<libc::sigaction>::uninit();
        let rc = unsafe { libc::sigaction(libc::SIGPIPE, std::ptr::null(), oldact.as_mut_ptr()) };
        assert_eq!(rc, 0, "sigaction read must succeed");
        let handler = unsafe { oldact.assume_init() }.sa_sigaction;
        assert_eq!(
            handler,
            libc::SIG_DFL,
            "reset_sigpipe must leave SIGPIPE at SIG_DFL (so a broken pipe terminates cleanly, \
             not a print panic); got {handler:?} (SIG_IGN={:?})",
            libc::SIG_IGN
        );
    }

    #[test]
    fn stat_report_regular_file_has_mode_and_size() {
        // A regular file → one line "<path>: mode <octal>, size <n> bytes\n", no entry list.
        let dir = std::env::temp_dir().join(format!("tnet-stat-file-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("hello.txt");
        std::fs::write(&f, b"12345").unwrap(); // 5 bytes
        let report = super::stat_report(&f);
        assert!(
            report.contains("mode ") && report.contains("size 5 bytes"),
            "expected mode+size for a 5-byte file, got: {report:?}"
        );
        // A plain file produces exactly one line (no directory-entry lines).
        assert_eq!(
            report.lines().count(),
            1,
            "file report must be one line: {report:?}"
        );
        assert!(report.ends_with('\n'), "report must end in a newline");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stat_report_missing_path_reports_error_inline() {
        // A path that cannot be stat-ed → an inline "<path>: <err>" line (never a panic), so a batch
        // continues past it.
        let missing = std::env::temp_dir().join(format!(
            "tnet-stat-nope-{}-does-not-exist",
            std::process::id()
        ));
        let report = super::stat_report(&missing);
        assert!(
            report.contains(&missing.display().to_string()) && !report.contains("mode "),
            "missing path must report an error (no mode line), got: {report:?}"
        );
        assert!(report.ends_with('\n'));
    }

    #[test]
    fn stat_report_directory_lists_entries_capped_at_25() {
        // A directory → the mode/size line PLUS one "  - <name>" per entry, capped at 25 then "  ...".
        let dir = std::env::temp_dir().join(format!("tnet-stat-dir-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for i in 0..30 {
            std::fs::write(dir.join(format!("f{i:02}")), b"").unwrap();
        }
        let report = super::stat_report(&dir);
        let entry_lines = report.lines().filter(|l| l.starts_with("  - ")).count();
        assert_eq!(
            entry_lines, 25,
            "must cap directory entries at 25, got {entry_lines}"
        );
        assert!(
            report.lines().any(|l| l.trim() == "..."),
            "must print a trailing `  ...` when entries exceed the cap: {report:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- `debug resolve` ------------------------------------------------------------------------

    #[test]
    fn parse_resolve_net_accepts_gos_three_networks() {
        assert_eq!(super::parse_resolve_net("ip").unwrap(), ResolveNet::Ip);
        assert_eq!(super::parse_resolve_net("ip4").unwrap(), ResolveNet::Ip4);
        assert_eq!(super::parse_resolve_net("ip6").unwrap(), ResolveNet::Ip6);
    }

    #[test]
    fn parse_resolve_net_refuses_anything_else_like_go() {
        // Go's `LookupIP` rejects every other network with `UnknownNetworkError` — including the
        // ones that are perfectly valid networks elsewhere (`tcp`, `udp`), which is exactly the
        // mistake a user makes when reaching for this flag.
        for bad in ["tcp", "udp4", "ip5", "IP4", ""] {
            let err = super::parse_resolve_net(bad).unwrap_err().to_string();
            assert_eq!(err, format!("unknown network {bad}"), "for {bad:?}");
        }
    }

    #[test]
    fn filter_resolve_addrs_keeps_only_the_selected_family() {
        let mixed = || {
            vec![
                "192.0.2.1".parse().unwrap(),
                "2001:db8::1".parse().unwrap(),
                "198.51.100.7".parse().unwrap(),
            ]
        };
        // `ip` keeps everything, in resolver order.
        let all = super::filter_resolve_addrs(mixed(), ResolveNet::Ip, "host.test").unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].to_string(), "192.0.2.1");
        assert_eq!(all[1].to_string(), "2001:db8::1");

        let v4 = super::filter_resolve_addrs(mixed(), ResolveNet::Ip4, "host.test").unwrap();
        assert!(v4.iter().all(std::net::IpAddr::is_ipv4), "{v4:?}");
        assert_eq!(v4.len(), 2);

        let v6 = super::filter_resolve_addrs(mixed(), ResolveNet::Ip6, "host.test").unwrap();
        assert_eq!(v6.len(), 1);
        assert_eq!(v6[0].to_string(), "2001:db8::1");
    }

    #[test]
    fn filter_resolve_addrs_errors_when_the_family_filter_empties_the_list() {
        // Go's `filterAddrList` turns an empty filtered list into an `AddrError`, so `--net ip6`
        // against an IPv4-only name FAILS rather than silently printing nothing.
        let v4_only = vec!["192.0.2.1".parse().unwrap()];
        let err = super::filter_resolve_addrs(v4_only, ResolveNet::Ip6, "host.test")
            .unwrap_err()
            .to_string();
        assert_eq!(err, "address host.test: no suitable address found");
    }

    #[test]
    fn resolve_report_prints_one_address_per_line() {
        let addrs: Vec<std::net::IpAddr> =
            vec!["192.0.2.1".parse().unwrap(), "2001:db8::1".parse().unwrap()];
        // Go prints the bare address per line — no brackets on IPv6, no trailing blank line.
        assert_eq!(super::resolve_report(&addrs), "192.0.2.1\n2001:db8::1\n");
        assert_eq!(super::resolve_report(&[]), "");
    }

    #[tokio::test]
    async fn resolve_lookup_short_circuits_an_ip_literal() {
        // Go's resolver parses a literal before querying anything — so this must not need a resolver
        // (and this test must not need a network).
        let got = super::resolve_lookup("192.0.2.1", ResolveNet::Ip)
            .await
            .unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].to_string(), "192.0.2.1");

        let got = super::resolve_lookup("2001:db8::1", ResolveNet::Ip6)
            .await
            .unwrap();
        assert_eq!(got[0].to_string(), "2001:db8::1");
    }

    #[tokio::test]
    async fn resolve_lookup_applies_the_family_filter_to_a_literal_too() {
        // The short-circuit does not skip the filter: Go runs the literal through `filterAddrList`
        // like any resolved address.
        let err = super::resolve_lookup("192.0.2.1", ResolveNet::Ip6)
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(err, "address 192.0.2.1: no suitable address found");
    }

    #[tokio::test]
    async fn resolve_lookup_refuses_an_empty_host_before_querying() {
        // Go's `LookupIP` guards `host == ""` ahead of the resolver, so an empty argument is a
        // command error, not a DNS round-trip.
        let err = super::resolve_lookup("", ResolveNet::Ip)
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(err, "lookup : no suitable address found");
    }

    #[tokio::test]
    async fn run_debug_resolve_refuses_the_wrong_argument_count() {
        // Go: `if len(args) != 1 { return errors.New("usage: …") }` — zero and two are both wrong.
        for args in [vec![], vec!["a.test".to_string(), "b.test".to_string()]] {
            let err = super::run_debug_resolve(&args, "ip")
                .await
                .unwrap_err()
                .to_string();
            assert_eq!(err, "usage: tnet debug resolve <hostname>", "for {args:?}");
        }
    }

    #[tokio::test]
    async fn run_debug_resolve_checks_the_argument_count_before_the_network() {
        // Go checks arity FIRST, so a call that is wrong twice over reports the usage line — not
        // the network complaint.
        let args = vec!["a.test".to_string(), "b.test".to_string()];
        let err = super::run_debug_resolve(&args, "tcp")
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(err, "usage: tnet debug resolve <hostname>");
    }

    #[tokio::test]
    async fn run_debug_resolve_refuses_an_unknown_network() {
        let args = vec!["192.0.2.1".to_string()];
        let err = super::run_debug_resolve(&args, "tcp")
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(err, "unknown network tcp");
    }

    #[tokio::test]
    async fn run_debug_resolve_prints_a_resolvable_host() {
        // The happy path through the real entry point, with a literal so no resolver (and no
        // network) is involved: one argument, default network, no error.
        let args = vec!["192.0.2.1".to_string()];
        super::run_debug_resolve(&args, "ip").await.unwrap();
    }

    // --- `debug statedir` / `debug build-info` --------------------------------------------------

    #[test]
    fn statedir_report_names_the_rule_that_won() {
        // The whole point of the command: the path alone cannot tell you WHY it was chosen, so the
        // rule has to be on the page next to it.
        let dir = std::env::temp_dir().join(format!("tnet-statedir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("tailnetd.sock");

        let report = super::statedir_report(&dir, tailscaled_rs::StateDirSource::SystemRoot, &sock);
        assert!(
            report.contains(&dir.display().to_string())
                && report.contains(&sock.display().to_string()),
            "must print both resolved paths: {report:?}"
        );
        assert!(
            report.contains(tailscaled_rs::StateDirSource::SystemRoot.describe()),
            "must name the winning cascade rule: {report:?}"
        );
        assert_eq!(report.lines().count(), 3, "expected 3 lines: {report:?}");
        assert!(report.ends_with('\n'));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn statedir_report_distinguishes_present_from_absent() {
        // A present dir reports its permission bits (a non-0700 state dir is itself a finding); a
        // missing socket reports `absent` rather than erroring out — this command must stay useful
        // precisely when the daemon is NOT running.
        let dir = std::env::temp_dir().join(format!("tnet-statedir-abs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let sock = dir.join("not-there.sock");

        let report = super::statedir_report(&dir, tailscaled_rs::StateDirSource::Env, &sock);
        assert!(
            report.contains("present, mode 700"),
            "an existing state dir must report its mode: {report:?}"
        );
        assert!(
            report.contains("(absent)"),
            "a missing socket must report `absent`: {report:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn build_info_json_splits_the_dirty_suffix_into_vcs_fields() {
        // build.rs stamps `<sha>-dirty` for an uncommitted tree; the JSON must split that back into
        // Go's `vcs.revision` / `vcs.modified` pair rather than leaking the suffix into the sha.
        let v = super::build_info_json(
            "tailscaled-rs",
            "0.52.2",
            "x86_64-unknown-linux-gnu",
            "release",
            "rustc 1.95.0",
            "abc123def-dirty",
            &["ssh"],
        );
        assert_eq!(v["vcs"]["revision"], "abc123def");
        assert_eq!(v["vcs"]["modified"], true);
        assert_eq!(v["package"], "tailscaled-rs");
        assert_eq!(v["version"], "0.52.2");
        assert_eq!(v["target"], "x86_64-unknown-linux-gnu");
        assert_eq!(v["features"][0], "ssh");

        // A clean tree: same sha, `modified` false.
        let clean = super::build_info_json(
            "tailscaled-rs",
            "0.52.2",
            "x86_64-unknown-linux-gnu",
            "release",
            "rustc 1.95.0",
            "abc123def",
            &[],
        );
        assert_eq!(clean["vcs"]["revision"], "abc123def");
        assert_eq!(clean["vcs"]["modified"], false);
        assert!(
            clean["features"].as_array().is_some_and(|a| a.is_empty()),
            "a default build reports an empty feature list, not null"
        );
    }

    #[test]
    fn build_info_json_reports_undetermined_fields_as_null() {
        // Built from a tarball with no `.git` and no rustc on PATH: build.rs stamps the literal
        // `unknown`. That must surface as JSON `null` — a bug report is better served by an honest
        // gap than by the string "unknown" masquerading as a value.
        let v = super::build_info_json(
            "tailscaled-rs",
            "0.52.2",
            "unknown",
            "unknown",
            "unknown",
            "unknown",
            &[],
        );
        assert!(v["vcs"].is_null(), "no revision → no vcs object: {v}");
        assert!(v["target"].is_null());
        assert!(v["profile"].is_null());
        assert!(v["rustcVersion"].is_null());
        // The facts cargo always knows are still present.
        assert_eq!(v["binary"], "tnet");
        assert_eq!(v["version"], "0.52.2");
    }

    /// The real, compiled-in stamps must produce a well-formed object — this is what catches a
    /// `build.rs` that stopped emitting one of the `env!` values.
    #[test]
    fn build_info_json_from_the_real_build_stamps_is_well_formed() {
        let v = super::build_info_json(
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION"),
            env!("TAILNETD_TARGET"),
            env!("TAILNETD_PROFILE"),
            env!("TAILNETD_RUSTC_VERSION"),
            env!("TAILNETD_GIT_COMMIT"),
            &[],
        );
        assert_eq!(v["package"], env!("CARGO_PKG_NAME"));
        assert_eq!(v["version"], env!("CARGO_PKG_VERSION"));
        // Under cargo test the triple + profile are always known, so they must not be null.
        assert!(v["target"].is_string(), "target must be stamped: {v}");
        assert!(v["profile"].is_string(), "profile must be stamped: {v}");
    }

    // --- `configure kubeconfig` (Go `tailscale configure kubeconfig`) ---------------------------

    /// A netmap with the shapes the resolver has to tell apart: a normal MagicDNS peer, a peer whose
    /// leading label collides with nothing, one carrying a trailing root dot, and a nameless peer.
    fn kube_status() -> StatusReport {
        use tailscaled_rs::localapi::PeerReport;
        StatusReport {
            state: "Running".to_string(),
            want_running: true,
            peers: vec![
                PeerReport {
                    name: "k8s-proxy.tail0123.ts.net".to_string(),
                    ipv4: "100.64.0.7".to_string(),
                    ipv6: Some("fd7a:115c:a1e0::7".to_string()),
                    stable_id: "n1".to_string(),
                    ..Default::default()
                },
                PeerReport {
                    name: "other.tail0123.ts.net.".to_string(),
                    ipv4: "100.64.0.8".to_string(),
                    stable_id: "n2".to_string(),
                    ..Default::default()
                },
                PeerReport {
                    name: String::new(),
                    ipv4: "100.64.0.9".to_string(),
                    stable_id: "n3".to_string(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        }
    }

    #[test]
    fn kubeconfig_peer_resolves_by_name_label_and_ip() {
        // Go's `nodeDNSNameFromArg`: full DNS name, leading label, or a tailnet IP all resolve to the
        // peer's DNS name; matching is case-insensitive and a trailing root dot is ignored on BOTH
        // sides. The returned name always comes back without that trailing dot (Go trims it before
        // building the server URL, and an `https://host./` URL would not match the cert anyway).
        let st = kube_status();
        let want = Some("k8s-proxy.tail0123.ts.net".to_string());
        assert_eq!(peer_dns_name_from_arg(&st, "k8s-proxy"), want, "bare label");
        assert_eq!(
            peer_dns_name_from_arg(&st, "k8s-proxy.tail0123.ts.net"),
            want,
            "full FQDN"
        );
        assert_eq!(
            peer_dns_name_from_arg(&st, "k8s-proxy.tail0123.ts.net."),
            want,
            "FQDN with a trailing root dot"
        );
        assert_eq!(
            peer_dns_name_from_arg(&st, "K8S-Proxy"),
            want,
            "case-folded"
        );
        assert_eq!(peer_dns_name_from_arg(&st, "100.64.0.7"), want, "IPv4");
        assert_eq!(
            peer_dns_name_from_arg(&st, "fd7a:115c:a1e0::7"),
            want,
            "IPv6"
        );
        // The peer whose stored name carries the root dot resolves too, dot stripped.
        assert_eq!(
            peer_dns_name_from_arg(&st, "other"),
            Some("other.tail0123.ts.net".to_string())
        );
    }

    #[test]
    fn kubeconfig_peer_resolution_misses_are_none() {
        let st = kube_status();
        // No such peer, and the empty/dot-only argument (which must not match the nameless peer or
        // trivially match anything after trimming).
        assert_eq!(peer_dns_name_from_arg(&st, "nope"), None);
        assert_eq!(peer_dns_name_from_arg(&st, ""), None);
        assert_eq!(peer_dns_name_from_arg(&st, "."), None);
        // A nameless peer is addressable by IP but yields no FQDN to build a kubeconfig from, so it
        // must NOT resolve (returning an empty name would render `server: https://`).
        assert_eq!(peer_dns_name_from_arg(&st, "100.64.0.9"), None);
        // A non-leading label must not match — Go cuts at the FIRST dot only.
        assert_eq!(peer_dns_name_from_arg(&st, "tail0123"), None);
        // Go parses the argument as an address FIRST: an IP that matches no peer is a miss, never a
        // name comparison that could match a peer literally named after an address.
        assert_eq!(peer_dns_name_from_arg(&st, "100.64.0.99"), None);
    }

    /// A tailnet whose MagicDNS carries one Tailscale Service record, advertised by a peer that is
    /// NOT the one the record is named after — which is the point: a Service is a DNS record plus a
    /// host route in some peer's AllowedIPs, not a peer of its own.
    /// The two Services the `service list` tests render: one bare (no display name, no explicit
    /// action — its type is inferred from a well-known TCP port) and one fully populated.
    fn service_fixtures() -> Vec<tailscaled_rs::localapi::ServiceReport> {
        use tailscaled_rs::localapi::{ServiceActionReport, ServicePortRange, ServiceReport};
        vec![
            ServiceReport {
                name: "svc:api".into(),
                display_name: String::new(),
                addrs: vec!["100.64.0.11".into()],
                ports: vec![ServicePortRange {
                    proto: 6,
                    first: 443,
                    last: 443,
                }],
                actions: Vec::new(),
            },
            ServiceReport {
                name: "svc:db".into(),
                display_name: "Production database".into(),
                addrs: vec!["100.64.0.10".into(), "fd7a:115c:a1e0::a".into()],
                ports: vec![ServicePortRange {
                    proto: 6,
                    first: 5432,
                    last: 5432,
                }],
                actions: vec![ServiceActionReport {
                    action_type: "postgresql".into(),
                    port: 5432,
                    display_name: "Postgres".into(),
                    attributes: std::collections::BTreeMap::new(),
                }],
            },
        ]
    }

    #[test]
    fn service_list_renders_gos_tabwriter_table() {
        // Go's table: a leading blank line, the five headers, one row per Service, every column
        // padded to `max(10, widest cell + 5)` (its `tabwriter.NewWriter(Stdout, 10, 5, 5, ' ', 0)`)
        // including the last, which is why the rows end in trailing spaces. IP is `Addrs[0]`; the
        // absent display name becomes Go's `-`; `svc:api` carries no explicit action, so its type is
        // inferred from the well-known TCP port 443.
        let out = format_service_list(&service_fixtures(), Some("tail0123.ts.net"), false);
        assert_eq!(
            out,
            "\n IP              HOSTNAME                DISPLAY NAME            ENDPOINTS     TYPE           \n \
             100.64.0.11     api.tail0123.ts.net     -                       tcp:443       http           \n \
             100.64.0.10     db.tail0123.ts.net      Production database     tcp:5432      postgresql     \n"
        );
    }

    #[test]
    fn service_list_empty_prints_gos_sentence() {
        // A node whose tailnet ACLs grant it no Service is an ordinary answer, not an error or an
        // empty table — Go prints one sentence and exits 0.
        assert_eq!(
            format_service_list(&[], Some("tail0123.ts.net"), false),
            "No Tailscale Services are available to this node.\n"
        );
        // And in JSON, an empty array (Go encodes the empty `entries` slice).
        assert_eq!(
            format_service_list(&[], Some("tail0123.ts.net"), true),
            "[]\n"
        );
    }

    #[test]
    fn service_list_json_matches_gos_entry_shape() {
        // Go emits `serviceListEntry`: the `ServiceDetails` fields in Go's own order, then the
        // `Hostname` the CLI decorates each entry with. `omitzero`/`omitempty` fields are dropped
        // when empty (svc:api has no DisplayName and no Actions), `Ports` are Go's text form, and
        // `Hostname` is always present.
        let out = format_service_list(&service_fixtures(), Some("tail0123.ts.net"), true);
        assert_eq!(
            out,
            r#"[
  {
    "Name": "svc:api",
    "Addrs": [
      "100.64.0.11"
    ],
    "Ports": [
      "tcp:443"
    ],
    "Hostname": "api.tail0123.ts.net"
  },
  {
    "Name": "svc:db",
    "DisplayName": "Production database",
    "Addrs": [
      "100.64.0.10",
      "fd7a:115c:a1e0::a"
    ],
    "Ports": [
      "tcp:5432"
    ],
    "Actions": [
      {
        "Type": "postgresql",
        "Port": 5432,
        "DisplayName": "Postgres"
      }
    ],
    "Hostname": "db.tail0123.ts.net"
  }
]
"#
        );
    }

    #[test]
    fn service_hostname_needs_both_the_prefix_and_a_suffix() {
        // Go's `serviceHostname`: `<name-without-svc:>.<magicDNSSuffix>`, with the suffix's dots
        // trimmed, and "" whenever either half is missing — a name that carries no `svc:` prefix is
        // not a valid service name, and a node with no netmap suffix has no domain to build in.
        assert_eq!(
            service_hostname("svc:db", Some("tail0123.ts.net")),
            "db.tail0123.ts.net"
        );
        assert_eq!(
            service_hostname("svc:db", Some(".tail0123.ts.net.")),
            "db.tail0123.ts.net"
        );
        assert_eq!(service_hostname("svc:db", None), "");
        assert_eq!(service_hostname("svc:db", Some("")), "");
        assert_eq!(service_hostname("db", Some("tail0123.ts.net")), "");
        assert_eq!(service_hostname("svc:", Some("tail0123.ts.net")), "");
        // An empty hostname reaches the table as Go's `-`, never as a blank cell.
        let mut svc = service_fixtures();
        svc.truncate(1);
        let out = format_service_list(&svc, None, false);
        assert!(
            out.lines().nth(2).is_some_and(|l| l.contains(" -")),
            "a Service with no resolvable hostname must print `-`:\n{out}"
        );
    }

    #[test]
    fn service_action_types_names_two_and_summarizes_the_rest() {
        use tailscaled_rs::localapi::{ServiceActionReport, ServicePortRange, ServiceReport};
        let action = |t: &str, port: u16| ServiceActionReport {
            action_type: t.into(),
            port,
            display_name: String::new(),
            attributes: std::collections::BTreeMap::new(),
        };
        let with_actions = |actions: Vec<ServiceActionReport>| ServiceReport {
            name: "svc:x".into(),
            actions,
            ..Default::default()
        };
        // None → "-", one → the type, two → both, more → the first two plus a count. The noun is
        // singular for exactly one extra (Go's `1 other`).
        assert_eq!(service_action_types(&with_actions(vec![])), "-");
        assert_eq!(
            service_action_types(&with_actions(vec![action("http", 80)])),
            "http"
        );
        assert_eq!(
            service_action_types(&with_actions(vec![action("http", 80), action("ssh", 22)])),
            "http, ssh"
        );
        assert_eq!(
            service_action_types(&with_actions(vec![
                action("http", 80),
                action("ssh", 22),
                action("vnc", 5900),
            ])),
            "http, ssh, 1 other"
        );
        assert_eq!(
            service_action_types(&with_actions(vec![
                action("http", 80),
                action("ssh", 22),
                action("vnc", 5900),
                action("rdp", 3389),
            ])),
            "http, ssh, 2 others"
        );
        // Duplicates collapse in first-seen order (Go's `seen` map).
        assert_eq!(
            service_action_types(&with_actions(vec![
                action("http", 80),
                action("http", 443),
                action("ssh", 22),
            ])),
            "http, ssh"
        );
        // With no explicit actions, types are inferred from well-known SINGLE TCP ports only: 443
        // and 80 both mean http (and collapse), 6443 means kubernetes, a UDP port and a port range
        // infer nothing, and an unknown port infers nothing.
        let with_ports = |ports: Vec<&str>| ServiceReport {
            name: "svc:x".into(),
            ports: ports
                .iter()
                .map(|p| p.parse::<ServicePortRange>().unwrap())
                .collect(),
            ..Default::default()
        };
        assert_eq!(
            service_action_types(&with_ports(vec!["tcp:443", "80", "6443"])),
            "http, kubernetes"
        );
        assert_eq!(
            service_action_types(&with_ports(vec!["udp:443", "tcp:80-90", "tcp:9999"])),
            "-"
        );
        // An explicit action wins over the port inference entirely (Go only infers when Actions is
        // empty), so a Service whose ports would infer `http` still reports only what it declares.
        assert_eq!(
            service_action_types(&ServiceReport {
                name: "svc:x".into(),
                ports: vec!["tcp:443".parse().unwrap()],
                actions: vec![action("aws-s3", 443)],
                ..Default::default()
            }),
            "aws-s3"
        );
    }

    #[test]
    fn ip_falls_back_to_a_service_vip() {
        // Go `ip.go`: a peer miss is retried against the Service VIPs, and a hit prints THAT
        // Service's addresses. The lookup compares parsed addresses, so an abbreviated IPv6 literal
        // matches however the netmap spelled it.
        let services = service_fixtures();
        let hit: std::net::IpAddr = "fd7a:115c:a1e0:0::a".parse().unwrap();
        assert_eq!(
            service_addrs_matching_ip(&services, hit),
            Some(["100.64.0.10".to_string(), "fd7a:115c:a1e0::a".to_string()].as_slice())
        );
        assert_eq!(
            service_addrs_matching_ip(&services, "100.64.0.11".parse().unwrap()),
            Some(["100.64.0.11".to_string()].as_slice())
        );
        // An address no Service carries is a miss — the caller then reports Go's "no peer or
        // service found with IP".
        assert_eq!(
            service_addrs_matching_ip(&services, "100.64.0.99".parse().unwrap()),
            None
        );
        assert_eq!(service_addrs_matching_ip(&[], hit), None);
    }

    #[test]
    fn service_ips_honor_the_family_and_first_filters() {
        // Go prints every address of the resolved Service, filtered by `-4`/`-6`, after `-1` has
        // truncated the list to the first.
        let addrs = vec!["100.64.0.10".to_string(), "fd7a:115c:a1e0::a".to_string()];
        assert_eq!(
            format_service_ips(&addrs, IpSelect::default()),
            "100.64.0.10\nfd7a:115c:a1e0::a\n"
        );
        assert_eq!(
            format_service_ips(
                &addrs,
                IpSelect {
                    v4: true,
                    ..Default::default()
                }
            ),
            "100.64.0.10\n"
        );
        assert_eq!(
            format_service_ips(
                &addrs,
                IpSelect {
                    v6: true,
                    ..Default::default()
                }
            ),
            "fd7a:115c:a1e0::a\n"
        );
        assert_eq!(
            format_service_ips(
                &addrs,
                IpSelect {
                    first: true,
                    ..Default::default()
                }
            ),
            "100.64.0.10\n"
        );
        // A Service with only a v6 address (an IPv4-disabled tailnet) and `-4` selects nothing —
        // reported as such, never as a fabricated address.
        assert_eq!(
            format_service_ips(
                &["fd7a:115c:a1e0::a".to_string()],
                IpSelect {
                    v4: true,
                    ..Default::default()
                }
            ),
            "(no matching tailnet address)\n"
        );
    }

    fn kube_dns() -> tailscaled_rs::localapi::DnsStatusReport {
        tailscaled_rs::localapi::DnsStatusReport {
            magic_dns: true,
            extra_records: vec![
                (
                    "k8s-svc.tail0123.ts.net".to_string(),
                    "100.80.0.5".to_string(),
                ),
                (
                    "offline-svc.tail0123.ts.net".to_string(),
                    "100.80.0.6".to_string(),
                ),
            ],
            ..Default::default()
        }
    }

    /// `kube_status()` plus the AllowedIPs that make the first Service reachable.
    fn kube_status_with_service_route() -> StatusReport {
        let mut st = kube_status();
        st.peers[0].allowed_routes = vec![
            "100.64.0.7/32".to_string(),
            "100.80.0.5/32".to_string(),
            // A covering subnet route must NOT count as reachability for the second Service: Go
            // looks for the single-host prefix and nothing else.
            "100.80.0.0/24".to_string(),
        ];
        st
    }

    #[test]
    fn kubeconfig_falls_back_to_a_tailscale_service() {
        // Go's `nodeOrServiceDNSNameFromArg` second arm: an argument matching no peer is looked up
        // as a Tailscale Service DNS record, and resolves to the record's name once a peer is seen
        // advertising the record's address as a host route.
        let st = kube_status_with_service_route();
        let dns = kube_dns();
        let want = "k8s-svc.tail0123.ts.net".to_string();
        assert_eq!(peer_dns_name_from_arg(&st, "k8s-svc"), None, "not a peer");
        assert_eq!(
            service_dns_name_from_arg(&dns, &st, "k8s-svc").unwrap(),
            want,
            "the record's leading label"
        );
        assert_eq!(
            service_dns_name_from_arg(&dns, &st, "K8S-SVC.tail0123.ts.net.").unwrap(),
            want,
            "the full name, case-folded, trailing root dot ignored"
        );
        assert_eq!(
            service_dns_name_from_arg(&dns, &st, "100.80.0.5").unwrap(),
            want,
            "an argument that is the record's address"
        );
    }

    #[test]
    fn kubeconfig_service_misses_keep_gos_two_distinct_errors() {
        // Go reports these differently on purpose, and the distinction is the whole diagnostic: a
        // name nothing publishes is the operator's spelling, while a published name no peer carries
        // is the Service's backend being down.
        let st = kube_status_with_service_route();
        let dns = kube_dns();

        let err = service_dns_name_from_arg(&dns, &st, "nope").expect_err("names nothing");
        assert!(
            err.to_string().contains("no peer found for"),
            "an unknown name is Go's `no peer found for %q`: {err}"
        );

        let err = service_dns_name_from_arg(&dns, &st, "offline-svc")
            .expect_err("published, but no peer advertises its /32");
        assert!(
            err.to_string()
                .contains("is in MagicDNS, but is not currently reachable"),
            "a MagicDNS-known but unreachable Service has its own error: {err}"
        );
        assert!(
            !err.to_string().contains("no peer found for"),
            "the two failures must not collapse into one message: {err}"
        );

        // A record whose value control did not spell as an IP is its own failure, not a silent miss.
        let broken = tailscaled_rs::localapi::DnsStatusReport {
            extra_records: vec![("weird.tail0123.ts.net".to_string(), "not-an-ip".to_string())],
            ..Default::default()
        };
        let err = service_dns_name_from_arg(&broken, &st, "weird").expect_err("unparseable value");
        assert!(
            err.to_string()
                .contains("error parsing ExtraRecord IP address"),
            "{err}"
        );
    }

    #[test]
    fn kubeconfig_service_record_lookup_ports_go() {
        // `serviceDNSRecordFromDNSConfig` in isolation: what matches a record and what does not.
        let dns = kube_dns();
        assert_eq!(
            service_dns_record_from_dns_config(&dns, "k8s-svc").map(|r| r.0.as_str()),
            Some("k8s-svc.tail0123.ts.net")
        );
        // An IP argument matches by VALUE only — never by name, and never a different record.
        assert_eq!(
            service_dns_record_from_dns_config(&dns, "100.80.0.6").map(|r| r.0.as_str()),
            Some("offline-svc.tail0123.ts.net")
        );
        assert!(service_dns_record_from_dns_config(&dns, "100.80.0.9").is_none());
        // A non-leading label must not match; Go cuts at the first dot.
        assert!(service_dns_record_from_dns_config(&dns, "tail0123").is_none());
        assert!(service_dns_record_from_dns_config(&dns, "").is_none());

        // Go's `dnsname.ToFQDN` gate: a name with an over-long or empty label is not a DNS name, so
        // it can never name a Service.
        assert_eq!(
            to_fqdn("foo.example.com"),
            Some("foo.example.com.".to_string())
        );
        assert_eq!(
            to_fqdn("foo.example.com."),
            Some("foo.example.com.".to_string())
        );
        assert_eq!(
            to_fqdn(".foo.example.com"),
            Some("foo.example.com.".to_string())
        );
        assert_eq!(to_fqdn(""), Some(".".to_string()));
        assert_eq!(to_fqdn("."), Some(".".to_string()));
        assert_eq!(to_fqdn("a..b.example.com"), None, "empty label");
        assert_eq!(to_fqdn(&format!("{}.example.com", "a".repeat(64))), None);
        assert_eq!(to_fqdn(&"a.".repeat(200)), None, "longer than 254");
    }

    #[test]
    fn kubeconfig_peer_ip_match_is_by_address_not_by_spelling() {
        // Go compares parsed `netip.Addr`s, so an argument that spells the same IPv6 address
        // differently than the netmap did still resolves.
        let st = kube_status();
        let want = Some("k8s-proxy.tail0123.ts.net".to_string());
        assert_eq!(
            peer_dns_name_from_arg(&st, "fd7a:115c:a1e0:0:0:0:0:7"),
            want,
            "an unabbreviated IPv6 literal is the same address"
        );
        assert_eq!(
            peer_dns_name_from_arg(&st, "FD7A:115C:A1E0::7"),
            want,
            "IPv6 literals are hex, so case must not matter"
        );
    }

    /// Go's `TestKubeconfig` table (cmd/tailscale/cli/configure-kube_test.go, v1.100.0), verbatim:
    /// input document, scheme, and expected output, for the same `foo.tail-scale.ts.net` peer.
    ///
    /// Go trims surrounding whitespace before comparing, so the goldens carry no trailing newline;
    /// the comparison below trims the same way and nothing else, so the bytes in between are Go's.
    const GO_KUBECONFIG_CASES: &[(&str, bool, &str)] = &[
        (
            "empty",
            false,
            "apiVersion: v1
clusters:
- cluster:
    server: https://foo.tail-scale.ts.net
  name: foo.tail-scale.ts.net
contexts:
- context:
    cluster: foo.tail-scale.ts.net
    user: tailscale-auth
  name: foo.tail-scale.ts.net
current-context: foo.tail-scale.ts.net
kind: Config
users:
- name: tailscale-auth
  user:
    token: unused",
        ),
        (
            "empty_http",
            true,
            "apiVersion: v1
clusters:
- cluster:
    server: http://foo.tail-scale.ts.net
  name: foo.tail-scale.ts.net
contexts:
- context:
    cluster: foo.tail-scale.ts.net
    user: tailscale-auth
  name: foo.tail-scale.ts.net
current-context: foo.tail-scale.ts.net
kind: Config
users:
- name: tailscale-auth
  user:
    token: unused",
        ),
    ];

    #[test]
    fn kubeconfig_merge_matches_the_go_goldens() {
        // The whole of Go's `TestKubeconfig`: a fresh document, `--http`, a config whose lists were
        // emptied to `null`, an already-configured one (must not duplicate), an unrelated cluster
        // (must survive), and a second Tailscale cluster (shares the `tailscale-auth` user).
        const FQDN: &str = "foo.tail-scale.ts.net";
        for (name, http, want) in GO_KUBECONFIG_CASES {
            let scheme = kube_scheme(*http);
            let got = update_kubeconfig("", scheme, FQDN)
                .unwrap_or_else(|e| panic!("{name}: update_kubeconfig failed: {e}"));
            assert_eq!(got.trim_end(), *want, "{name}: drifted from the Go golden");
        }

        // "all-configs-clusters-users-deleted": explicit `null` lists rebuild cleanly, and the stale
        // `current-context` is replaced.
        let got = update_kubeconfig(
            "apiVersion: v1
clusters: null
contexts: null
kind: Config
current-context: some-non-existent-cluster
users: null
",
            "https://",
            FQDN,
        )
        .expect("null lists are a valid kubeconfig");
        assert_eq!(
            got.trim_end(),
            GO_KUBECONFIG_CASES[0].2,
            "all-configs-clusters-users-deleted"
        );

        // "already-configured": re-running must REPLACE the existing triple, not append a second one.
        let already = format!("{}\n", GO_KUBECONFIG_CASES[0].2);
        let got = update_kubeconfig(&already, "https://", FQDN).expect("re-running is idempotent");
        assert_eq!(
            got.trim_end(),
            GO_KUBECONFIG_CASES[0].2,
            "already-configured must be idempotent, not duplicated"
        );

        // "other-cluster": an unrelated cluster/context/user must all survive, in place, with the
        // Tailscale triple appended after them and the context switched.
        let got = update_kubeconfig(
            "apiVersion: v1
clusters:
- cluster:
    server: https://192.168.1.1:8443
  name: some-cluster
contexts:
- context:
    cluster: some-cluster
    user: some-auth
  name: some-cluster
kind: Config
current-context: some-cluster
users:
- name: some-auth
  user:
    token: asdfasdf
",
            "https://",
            FQDN,
        )
        .expect("an unrelated cluster is a valid kubeconfig");
        assert_eq!(
            got.trim_end(),
            "apiVersion: v1
clusters:
- cluster:
    server: https://192.168.1.1:8443
  name: some-cluster
- cluster:
    server: https://foo.tail-scale.ts.net
  name: foo.tail-scale.ts.net
contexts:
- context:
    cluster: some-cluster
    user: some-auth
  name: some-cluster
- context:
    cluster: foo.tail-scale.ts.net
    user: tailscale-auth
  name: foo.tail-scale.ts.net
current-context: foo.tail-scale.ts.net
kind: Config
users:
- name: some-auth
  user:
    token: asdfasdf
- name: tailscale-auth
  user:
    token: unused",
            "other-cluster: the pre-existing cluster/context/user must survive untouched"
        );

        // "already-using-tailscale": a second Tailscale cluster is appended and reuses the single
        // shared `tailscale-auth` user rather than adding a second copy of it.
        let got = update_kubeconfig(
            "apiVersion: v1
clusters:
- cluster:
    server: https://bar.tail-scale.ts.net
  name: bar.tail-scale.ts.net
contexts:
- context:
    cluster: bar.tail-scale.ts.net
    user: tailscale-auth
  name: bar.tail-scale.ts.net
kind: Config
current-context: bar.tail-scale.ts.net
users:
- name: tailscale-auth
  user:
    token: unused
",
            "https://",
            FQDN,
        )
        .expect("a config that already uses tailscale is valid");
        assert_eq!(
            got.trim_end(),
            "apiVersion: v1
clusters:
- cluster:
    server: https://bar.tail-scale.ts.net
  name: bar.tail-scale.ts.net
- cluster:
    server: https://foo.tail-scale.ts.net
  name: foo.tail-scale.ts.net
contexts:
- context:
    cluster: bar.tail-scale.ts.net
    user: tailscale-auth
  name: bar.tail-scale.ts.net
- context:
    cluster: foo.tail-scale.ts.net
    user: tailscale-auth
  name: foo.tail-scale.ts.net
current-context: foo.tail-scale.ts.net
kind: Config
users:
- name: tailscale-auth
  user:
    token: unused",
            "already-using-tailscale: one shared tailscale-auth user, both clusters"
        );
    }

    #[test]
    fn kubeconfig_merge_refuses_a_document_it_cannot_read() {
        // Go's `errInvalidKubeconfig` cases. Both matter because the alternative to refusing is
        // overwriting: a merge that cannot read the file would replace it and lose every cluster.
        let err = update_kubeconfig("apiVersion: v1\nkind: ,asdf", "https://", "foo.example.com")
            .expect_err("invalid YAML must not be merged into");
        assert!(
            err.to_string().contains("invalid kubeconfig"),
            "unhelpful refusal: {err}"
        );
        let err = update_kubeconfig("apiVersion: v1\nkind: Pod", "https://", "foo.example.com")
            .expect_err("a non-kubeconfig document must not be merged into");
        assert!(
            err.to_string().contains("invalid kubeconfig"),
            "unhelpful refusal: {err}"
        );
        // A YAML mapping that is not a kubeconfig at all (no apiVersion/kind) is refused too — Go
        // compares the missing keys against "v1"/"Config" and they are unequal.
        assert!(
            update_kubeconfig("{}", "https://", "foo.example.com").is_err(),
            "an empty mapping is a document we did not write; refuse it"
        );
        // …but a file holding nothing (or only comments) IS the "no kubeconfig yet" case.
        assert!(update_kubeconfig("# nothing here\n", "https://", "foo.example.com").is_ok());
    }

    #[test]
    fn kubeconfig_merge_writes_the_file_preserving_other_clusters() {
        // The end-to-end of the default path: `set_kubeconfig_for_peer` creates the ~/.kube dir,
        // merges into whatever is there, and writes 0600 — the state Go leaves the machine in.
        let dir = std::env::temp_dir().join(format!("tnet-kubemerge-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let kube = dir.join(".kube");
        let path = kube.join("config");
        let path_str = path.to_str().unwrap().to_string();
        std::fs::create_dir_all(&dir).unwrap();

        // No ~/.kube yet: Go creates it, so a first run on a fresh machine works.
        set_kubeconfig_for_peer("https://", "foo.tail-scale.ts.net", &path_str)
            .expect("a missing parent directory is created");
        assert_eq!(
            std::fs::read_to_string(&path).unwrap().trim_end(),
            GO_KUBECONFIG_CASES[0].2
        );
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "kubeconfig must be written 0600, got {mode:o}");
        }

        // Now the case the whole finding is about: a second peer must not erase the first.
        set_kubeconfig_for_peer("http://", "bar.tail-scale.ts.net", &path_str)
            .expect("merging a second cluster");
        let merged = std::fs::read_to_string(&path).unwrap();
        assert!(
            merged.contains("server: https://foo.tail-scale.ts.net"),
            "the first cluster was dropped by the second run:\n{merged}"
        );
        assert!(
            merged.contains("server: http://bar.tail-scale.ts.net"),
            "the second cluster was not added:\n{merged}"
        );
        assert_eq!(
            merged.matches("- name: tailscale-auth").count(),
            1,
            "the tailscale-auth user is ONE shared entry, not one per cluster:\n{merged}"
        );
        assert_eq!(
            merged.matches("user: tailscale-auth").count(),
            2,
            "both contexts must point at that one shared user:\n{merged}"
        );
        assert!(
            merged.contains("current-context: bar.tail-scale.ts.net"),
            "the newest cluster must become current:\n{merged}"
        );

        // A file that is not a kubeconfig is refused, and left byte-identical.
        std::fs::write(&path, "not: a kubeconfig\n").unwrap();
        let err = set_kubeconfig_for_peer("https://", "foo.tail-scale.ts.net", &path_str)
            .expect_err("an unreadable kubeconfig must not be overwritten");
        assert!(
            format!("{err:#}").contains("invalid kubeconfig"),
            "unhelpful refusal: {err:#}"
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "not: a kubeconfig\n",
            "a refused merge must not have touched the file"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn kubeconfig_path_ports_go_kubeconfigpath() {
        // Go's `kubeconfigPath()`: $KUBECONFIG is a `:`-separated list and the target is the first
        // entry that exists and is not a directory; with no $KUBECONFIG it is $HOME/.kube/config.
        let dir = std::env::temp_dir().join(format!("tnet-kubepath-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let real = dir.join("real");
        std::fs::write(&real, "apiVersion: v1\nkind: Config\n").unwrap();
        let real = real.to_str().unwrap();
        let subdir = dir.join("subdir");
        std::fs::create_dir(&subdir).unwrap();
        let subdir = subdir.to_str().unwrap();
        let missing = dir.join("missing").to_str().unwrap().to_string();

        assert_eq!(
            kubeconfig_path_from(None, Some("/home/someone")).unwrap(),
            "/home/someone/.kube/config",
            "no $KUBECONFIG => ~/.kube/config"
        );
        assert_eq!(
            kubeconfig_path_from(Some(""), Some("/home/someone")).unwrap(),
            "/home/someone/.kube/config",
            "an empty $KUBECONFIG is unset"
        );
        assert_eq!(
            kubeconfig_path_from(Some(real), None).unwrap(),
            real,
            "$KUBECONFIG wins over ~/.kube/config, and $HOME is not needed"
        );
        assert_eq!(
            kubeconfig_path_from(Some(&format!("{missing}:{real}")), None).unwrap(),
            real,
            "the first entry that exists is the one kubectl reads"
        );
        assert_eq!(
            kubeconfig_path_from(Some(&format!("{subdir}:{real}")), None).unwrap(),
            real,
            "a directory is never the kubeconfig"
        );
        assert_eq!(
            kubeconfig_path_from(Some(&format!("{missing}:{missing}2")), None).unwrap(),
            format!("{missing}2"),
            "when nothing exists yet, the LAST entry is what gets created"
        );
        assert!(
            kubeconfig_path_from(None, None).is_err(),
            "no $KUBECONFIG and no $HOME has no answer; say so instead of writing to /.kube/config"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn kubeconfig_inputs_port_go_getinputs() {
        // Go's `TestGetInputs` matrix: for every argument shape × every scheme prefix × `--http`,
        // the host to resolve is the argument with the scheme stripped, and a scheme in the argument
        // decides http-vs-https in BOTH directions, overriding the flag.
        for arg in ["foo.tail-scale.ts.net", "foo", "127.0.0.1"] {
            for prefix in ["", "https://", "http://"] {
                for http_flag in [false, true] {
                    let want_http = (http_flag && prefix != "https://") || prefix == "http://";
                    let want_scheme = if want_http { "http://" } else { "https://" };
                    let (host, scheme) =
                        kubeconfig_inputs(&format!("{prefix}{arg}"), http_flag).unwrap();
                    assert_eq!(host, arg, "host for {prefix}{arg} (--http={http_flag})");
                    assert_eq!(
                        scheme, want_scheme,
                        "scheme for {prefix}{arg} (--http={http_flag})"
                    );
                }
            }
        }
        // `url.Parse` lowercases the scheme, and fills `u.Host` from the authority only — a path,
        // query or fragment is not part of the name to resolve, and neither is any `userinfo@`.
        assert_eq!(
            kubeconfig_inputs("HTTPS://foo.tail-scale.ts.net/api?x=1#f", true).unwrap(),
            ("foo.tail-scale.ts.net".to_string(), "https://")
        );
        assert_eq!(
            kubeconfig_inputs("http://someone@foo.tail-scale.ts.net", false).unwrap(),
            ("foo.tail-scale.ts.net".to_string(), "http://")
        );
        // A non-ASCII argument is still just argv: it must be handled as a bare name, never sliced
        // through a multi-byte character.
        assert_eq!(
            kubeconfig_inputs("https:/\u{e9}", false).unwrap(),
            ("https:/\u{e9}".to_string(), "https://"),
            "a near-miss on the scheme prefix is a bare name"
        );
        // Go's `args[0] == ""` arm is `flag.ErrHelp` — a usage refusal, not a lookup of the empty
        // name against the netmap (which would report "no peer" and hide the real mistake).
        let err = kubeconfig_inputs("", false).expect_err("an empty argument is a usage error");
        assert!(
            err.to_string()
                .contains("needs a <hostname-or-fqdn> argument"),
            "the refusal should name the missing argument: {err}"
        );
    }

    #[test]
    fn kubeconfig_fqdn_validation_rejects_yaml_and_url_breakouts() {
        // The FQDN is spliced unquoted into YAML and into `https://…`; the validator is what makes
        // that safe, so pin the hostile shapes it must refuse.
        assert!(validate_kube_fqdn("k8s-proxy.tail0123.ts.net").is_ok());
        assert!(validate_kube_fqdn("host").is_ok(), "a bare label is a name");
        for bad in [
            "",                     // nothing to name
            "a\nb.example.com",     // newline: injects sibling YAML keys
            "\"evil\".example.com", // quote: breaks out of a scalar
            "evil.com/../path",     // slash: repoints the server URL path
            "evil.com:8443",        // colon: repoints the port (and is YAML-significant)
            "user@evil.com",        // '@': repoints the URL authority
            "-lead.example.com",    // a label may not lead with '-'
            "trail-.example.com",   // …nor end with one
            "a..example.com",       // empty label
            ".example.com",         // leading dot => empty first label
            "exam ple.com",         // space
        ] {
            assert!(
                validate_kube_fqdn(bad).is_err(),
                "must reject peer name {bad:?}"
            );
        }
        // Length limits: 253 characters total, 63 per label.
        let long_label = "a".repeat(64);
        assert!(validate_kube_fqdn(&long_label).is_err(), "label > 63");
        let long_name = std::iter::repeat_n("abcdefgh", 32)
            .collect::<Vec<_>>()
            .join(".");
        assert!(
            long_name.len() > 253 && validate_kube_fqdn(&long_name).is_err(),
            "name > 253"
        );
    }

    #[test]
    fn kubeconfig_file_write_refuses_to_clobber_without_force() {
        // `--output` writes a standalone document, so writing over an existing kubeconfig would
        // silently drop every other cluster in it. Default: refuse (and leave the file
        // byte-identical). `--force`: replace. (Merging is the `--output`-less path.)
        let dir = std::env::temp_dir().join(format!("tnet-kubeconfig-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config");
        let path_str = path.to_str().unwrap();

        let rendered = update_kubeconfig("", "https://", "k8s-proxy.tail0123.ts.net")
            .expect("rendering a standalone kubeconfig");
        write_kubeconfig_file(path_str, &rendered, false).expect("first write creates the file");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), rendered);
        // Mode 0600: a kubeconfig names the clusters you can reach; don't publish that.
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "kubeconfig must be written 0600, got {mode:o}");
        }

        let err = write_kubeconfig_file(path_str, "REPLACED\n", false)
            .expect_err("a second write without --force must refuse");
        assert!(
            err.to_string().contains("already exists"),
            "the refusal should say the file exists: {err}"
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            rendered,
            "a refused write must not have touched the file"
        );

        write_kubeconfig_file(path_str, "REPLACED\n", true).expect("--force replaces");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "REPLACED\n");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn configure_kubeconfig_flags_parse() {
        // `tnet configure kubeconfig <host> --http -o <path> --force` reaches the ConfigureCmd arm
        // with all four fields; `--output` defaults to None (stdout), `--http`/`--force` to false.
        let parsed = Cli::try_parse_from([
            "tnet",
            "configure",
            "kubeconfig",
            "k8s-proxy",
            "--http",
            "-o",
            "/tmp/kc.yaml",
            "--force",
        ])
        .expect("flags should parse");
        match parsed.command {
            Command::Configure {
                cmd:
                    ConfigureCmd::Kubeconfig {
                        host,
                        http,
                        output,
                        force,
                    },
            } => {
                assert_eq!(host, "k8s-proxy");
                assert!(http);
                assert_eq!(output.as_deref(), Some("/tmp/kc.yaml"));
                assert!(force);
            }
            // `Command` derives no Debug (it can hold an auth key), so name the miss without `{:?}`.
            _ => panic!("expected a Command::Configure/ConfigureCmd::Kubeconfig pair"),
        }
        let bare = Cli::try_parse_from(["tnet", "configure", "kubeconfig", "k8s-proxy"])
            .expect("the host argument alone should parse");
        match bare.command {
            Command::Configure {
                cmd:
                    ConfigureCmd::Kubeconfig {
                        http,
                        output,
                        force,
                        ..
                    },
            } => {
                assert!(!http, "HTTPS is the default, as in Go");
                assert_eq!(output, None, "no --output means stdout");
                assert!(!force);
            }
            _ => panic!("expected a Command::Configure/ConfigureCmd::Kubeconfig pair"),
        }
        // The host argument is required.
        assert!(Cli::try_parse_from(["tnet", "configure", "kubeconfig"]).is_err());
    }

    #[test]
    fn configure_sysext_and_mac_vpn_grammar_parse() {
        // Go's macOS `configure` pair: `sysext [activate|deactivate|status]` and
        // `mac-vpn [install|uninstall]`, both of which Go also accepts BARE (the parent command has
        // its own Exec, which refuses identically). Reaching a `ConfigureCmd` arm rather than a
        // parse error is the point: it is what lets the CLI answer with a reason instead of clap's
        // "unrecognized subcommand".
        let cases: &[(&[&str], Option<SysextCmd>)] = &[
            (&["tnet", "configure", "sysext"], None),
            (
                &["tnet", "configure", "sysext", "activate"],
                Some(SysextCmd::Activate),
            ),
            (
                &["tnet", "configure", "sysext", "deactivate"],
                Some(SysextCmd::Deactivate),
            ),
            (
                &["tnet", "configure", "sysext", "status"],
                Some(SysextCmd::Status),
            ),
        ];
        for (argv, want) in cases {
            let parsed = Cli::try_parse_from(argv.iter().copied())
                .unwrap_or_else(|e| panic!("{argv:?} should parse: {e}"));
            match parsed.command {
                Command::Configure {
                    cmd: ConfigureCmd::Sysext { cmd },
                } => assert_eq!(cmd, *want, "{argv:?}"),
                // `Command` derives no Debug (it can hold an auth key), so name the miss directly.
                _ => panic!("expected a ConfigureCmd::Sysext arm for {argv:?}"),
            }
        }

        let vpn: &[(&[&str], Option<MacVpnCmd>)] = &[
            (&["tnet", "configure", "mac-vpn"], None),
            (
                &["tnet", "configure", "mac-vpn", "install"],
                Some(MacVpnCmd::Install),
            ),
            (
                &["tnet", "configure", "mac-vpn", "uninstall"],
                Some(MacVpnCmd::Uninstall),
            ),
        ];
        for (argv, want) in vpn {
            let parsed = Cli::try_parse_from(argv.iter().copied())
                .unwrap_or_else(|e| panic!("{argv:?} should parse: {e}"));
            match parsed.command {
                Command::Configure {
                    cmd: ConfigureCmd::MacVpn { cmd },
                } => assert_eq!(cmd, *want, "{argv:?}"),
                _ => panic!("expected a ConfigureCmd::MacVpn arm for {argv:?}"),
            }
        }

        // Only Go's verbs exist under each: a typo is still a parse error, not a refusal that
        // pretends the verb was understood.
        assert!(Cli::try_parse_from(["tnet", "configure", "sysext", "enable"]).is_err());
        assert!(Cli::try_parse_from(["tnet", "configure", "mac-vpn", "reinstall"]).is_err());
        // And the out-of-scope host-integration commands stay absent, as ruled in
        // docs/CONFIGURE_SCOPE.md — recognising them would claim work this fork does not do.
        for name in [
            "synology",
            "synology-cert",
            "jetkvm",
            "flash-appliance",
            "pve-appliance",
        ] {
            assert!(
                Cli::try_parse_from(["tnet", "configure", name]).is_err(),
                "`configure {name}` is out of scope and must not be registered"
            );
        }
    }

    #[test]
    fn configure_sysext_refuses_like_go() {
        // Go's `requiresStandalone` refuses every `sysext` verb, and the bare command too, with one
        // message. Ours names the verb that was refused, keeps Go's "unsupported command:" opening
        // and its Standalone-GUI reason, and then says what this fork offers instead.
        for cmd in [
            None,
            Some(SysextCmd::Activate),
            Some(SysextCmd::Deactivate),
            Some(SysextCmd::Status),
        ] {
            let mac = sysext_refusal(cmd, true);
            assert!(
                mac.starts_with(sysext_verb_path(cmd)),
                "the refusal must name the verb: {mac}"
            );
            assert!(mac.contains("unsupported command:"), "{mac}");
            assert!(
                mac.contains("Standalone (.pkg installer) GUI build"),
                "Go's reason must survive the port: {mac}"
            );
            assert!(mac.contains("tnet install"), "{mac}");

            // Off darwin Go does not register the command at all, so the reason is the platform.
            let other = sysext_refusal(cmd, false);
            assert!(other.contains("darwin only"), "{other}");
            assert!(
                !other.contains("Standalone"),
                "off macOS the GUI build is not the reason: {other}"
            );
        }

        // The production path is an error (exit 1), carrying exactly that message for this host.
        let err = run_configure_sysext(Some(SysextCmd::Status))
            .expect_err("every sysext verb refuses, on every platform");
        assert_eq!(
            err.to_string(),
            sysext_refusal(Some(SysextCmd::Status), cfg!(target_os = "macos"))
        );
    }

    #[test]
    fn configure_mac_vpn_refuses_like_go() {
        // Go's `requiresGUI`, same shape as `requiresStandalone` above.
        for cmd in [None, Some(MacVpnCmd::Install), Some(MacVpnCmd::Uninstall)] {
            let mac = mac_vpn_refusal(cmd, true);
            assert!(
                mac.starts_with(mac_vpn_verb_path(cmd)),
                "the refusal must name the verb: {mac}"
            );
            assert!(mac.contains("unsupported command:"), "{mac}");
            assert!(
                mac.contains("requires a GUI build of the macOS client"),
                "Go's reason must survive the port: {mac}"
            );
            assert!(mac.contains("tnet install"), "{mac}");

            let other = mac_vpn_refusal(cmd, false);
            assert!(other.contains("darwin only"), "{other}");
            assert!(
                !other.contains("GUI build"),
                "off macOS the GUI build is not the reason: {other}"
            );
        }

        let err = run_configure_mac_vpn(None)
            .expect_err("mac-vpn refuses on every platform, bare or with a verb");
        assert_eq!(
            err.to_string(),
            mac_vpn_refusal(None, cfg!(target_os = "macos"))
        );
    }

    #[test]
    fn configure_help_records_the_out_of_scope_commands() {
        // The ruling has to reach the user who goes looking for `tailscale configure synology`, or
        // the absence just reads as unfinished work. `tnet configure --help` names each out-of-scope
        // command and points at the document that explains why.
        let mut cli = <Cli as clap::CommandFactory>::command();
        let help = cli
            .find_subcommand_mut("configure")
            .expect("configure is a subcommand")
            .render_long_help()
            .to_string();
        for name in [
            "synology",
            "synology-cert",
            "configure-host",
            "jetkvm",
            "flash-appliance",
            "pve-appliance",
        ] {
            assert!(
                help.contains(name),
                "`configure --help` must account for {name}"
            );
        }
        assert!(help.contains("OUT OF SCOPE"), "{help}");
        assert!(help.contains("docs/CONFIGURE_SCOPE.md"), "{help}");
    }
    #[test]
    fn go_duration_grammar_is_ported() {
        // `cert --min-validity` takes a Go duration, so the parser has to be Go's — a script that
        // says `720h` must mean 30 days here too. Cases from the Go standard library's
        // `TestParseDuration` (`src/time/format_test.go`).
        let ns = 1i64;
        let us = 1_000 * ns;
        let ms = 1_000 * us;
        let sec = 1_000 * ms;
        let min = 60 * sec;
        let hour = 60 * min;

        assert_eq!(parse_go_duration("0"), Ok(0));
        assert_eq!(parse_go_duration("5s"), Ok(5 * sec));
        assert_eq!(parse_go_duration("30s"), Ok(30 * sec));
        assert_eq!(parse_go_duration("1478s"), Ok(1478 * sec));
        // Signs.
        assert_eq!(parse_go_duration("-5s"), Ok(-5 * sec));
        assert_eq!(parse_go_duration("+5s"), Ok(5 * sec));
        assert_eq!(parse_go_duration("-0"), Ok(0));
        assert_eq!(parse_go_duration("+0"), Ok(0));
        // Decimal points.
        assert_eq!(parse_go_duration("5.0s"), Ok(5 * sec));
        assert_eq!(parse_go_duration("5.6s"), Ok(5 * sec + 600 * ms));
        assert_eq!(parse_go_duration("5.s"), Ok(5 * sec));
        assert_eq!(parse_go_duration(".5s"), Ok(500 * ms));
        assert_eq!(parse_go_duration("1.0s"), Ok(sec));
        assert_eq!(parse_go_duration("1.00s"), Ok(sec));
        assert_eq!(parse_go_duration("1.004s"), Ok(sec + 4 * ms));
        assert_eq!(parse_go_duration("1.0040s"), Ok(sec + 4 * ms));
        assert_eq!(parse_go_duration("100.00100s"), Ok(100 * sec + ms));
        // Every unit, including the two spellings of micro.
        assert_eq!(parse_go_duration("10ns"), Ok(10 * ns));
        assert_eq!(parse_go_duration("11us"), Ok(11 * us));
        assert_eq!(parse_go_duration("12\u{b5}s"), Ok(12 * us));
        assert_eq!(parse_go_duration("12\u{3bc}s"), Ok(12 * us));
        assert_eq!(parse_go_duration("13ms"), Ok(13 * ms));
        assert_eq!(parse_go_duration("14s"), Ok(14 * sec));
        assert_eq!(parse_go_duration("15m"), Ok(15 * min));
        assert_eq!(parse_go_duration("16h"), Ok(16 * hour));
        // Composite durations — the shape `--min-validity 720h`/`1h30m` actually gets typed as.
        assert_eq!(parse_go_duration("3h30m"), Ok(3 * hour + 30 * min));
        assert_eq!(parse_go_duration("720h"), Ok(720 * hour));
        assert_eq!(
            parse_go_duration("10.5s4m"),
            Ok(4 * min + 10 * sec + 500 * ms)
        );
        assert_eq!(
            parse_go_duration("-2m3.4s"),
            Ok(-(2 * min + 3 * sec + 400 * ms))
        );
        assert_eq!(
            parse_go_duration("1h2m3s4ms5us6ns"),
            Ok(hour + 2 * min + 3 * sec + 4 * ms + 5 * us + 6 * ns)
        );
        // Largest and smallest representable durations (Go's boundary cases).
        assert_eq!(parse_go_duration("9223372036854775807ns"), Ok(i64::MAX));
        assert_eq!(parse_go_duration("-9223372036854775808ns"), Ok(i64::MIN));

        // Go's error paths, with Go's error text.
        assert_eq!(
            parse_go_duration(""),
            Err(r#"time: invalid duration """#.to_string())
        );
        assert_eq!(
            parse_go_duration("3"),
            Err(r#"time: missing unit in duration "3""#.to_string())
        );
        assert_eq!(
            parse_go_duration("1d"),
            Err(r#"time: unknown unit "d" in duration "1d""#.to_string()),
            "days are not a Go duration unit — the message has to say which unit was rejected"
        );
        for bad in ["-", "s", ".", "-.", ".s", "+.s", "\u{b5}s", "3000000h"] {
            assert!(
                parse_go_duration(bad).is_err(),
                "{bad:?} must be refused, as Go refuses it"
            );
        }
    }

    #[test]
    fn min_validity_flag_refuses_a_negative_duration() {
        // The wire field is an unsigned second count, so a negative minimum cannot be carried
        // honestly. Go accepts one (where it has no effect); this says so instead of dropping it.
        assert_eq!(
            parse_min_validity("720h"),
            Ok(std::time::Duration::from_secs(720 * 3600))
        );
        assert_eq!(parse_min_validity("0"), Ok(std::time::Duration::ZERO));
        let err = parse_min_validity("-1h").expect_err("a negative minimum must be refused");
        assert!(err.contains("already expired"), "{err}");
        // A grammar error still comes back in Go's words, not ours.
        assert_eq!(
            parse_min_validity("1d"),
            Err(r#"time: unknown unit "d" in duration "1d""#.to_string())
        );
    }

    #[test]
    fn up_refuses_exit_node_allow_lan_access_without_an_exit_node() {
        // Go's `prefsFromUpArgs` refuses this pair outright, before any LocalAPI call:
        // `--exit-node-allow-lan-access` exempts LAN traffic from exit-node routing, so with no exit
        // node it asks for an exemption from routing that is not happening. The message is Go's,
        // verbatim.
        assert_eq!(
            up_usage_refusal(None, false, Some(true)),
            Some("--exit-node-allow-lan-access can only be used with --exit-node")
        );
        // `--clear-exit-node` is this fork's `--exit-node=""`: it names no exit node either.
        assert_eq!(
            up_usage_refusal(None, true, Some(true)),
            Some("--exit-node-allow-lan-access can only be used with --exit-node")
        );
        // An explicitly EMPTY selector is Go's empty `exitNodeIP` — refused for the same reason, and
        // whitespace is not a selector.
        assert_eq!(
            up_usage_refusal(Some(""), false, Some(true)),
            Some("--exit-node-allow-lan-access can only be used with --exit-node")
        );
        assert_eq!(
            up_usage_refusal(Some("  "), false, Some(true)),
            Some("--exit-node-allow-lan-access can only be used with --exit-node")
        );
        // A named selector — IP or MagicDNS name — is exactly Go's non-empty `exitNodeIP`: usable.
        assert_eq!(
            up_usage_refusal(Some("100.64.0.9"), false, Some(true)),
            None
        );
        assert_eq!(up_usage_refusal(Some("exit-1"), false, Some(true)), None);
        // The negative form turns the setting OFF (Go's `--exit-node-allow-lan-access=false`), which
        // is meaningful with no exit node — Go only refuses the true case.
        assert_eq!(up_usage_refusal(None, false, Some(false)), None);
        assert_eq!(up_usage_refusal(None, true, Some(false)), None);
        // Not mentioning the flag at all is always usable, exit node or not.
        assert_eq!(up_usage_refusal(None, false, None), None);
        assert_eq!(up_usage_refusal(Some("100.64.0.9"), false, None), None);
        assert_eq!(up_usage_refusal(None, true, None), None);
    }

    #[test]
    fn cert_refuses_listen_without_serve_demo() {
        // `--listen` only names the address `--serve-demo` binds; on its own it asks for a listener
        // that is never created, so it is refused before the daemon round-trip rather than silently
        // ignored.
        assert_eq!(
            cert_usage_refusal(false, true),
            Some("--listen can only be used with --serve-demo")
        );
        // Every usable combination stays usable.
        assert_eq!(cert_usage_refusal(true, true), None);
        assert_eq!(cert_usage_refusal(true, false), None);
        assert_eq!(cert_usage_refusal(false, false), None);
    }

    #[test]
    fn demo_listen_address_accepts_gos_bare_port() {
        // Go's `net.Listen` takes `:443`; Rust's resolver does not, so the bare form is expanded.
        assert_eq!(normalize_demo_listen(":443"), "0.0.0.0:443");
        assert_eq!(
            normalize_demo_listen(DEFAULT_CERT_DEMO_LISTEN),
            "0.0.0.0:443"
        );
        assert_eq!(normalize_demo_listen(":0"), "0.0.0.0:0");
        // Anything already explicit is passed through untouched.
        assert_eq!(normalize_demo_listen("127.0.0.1:8443"), "127.0.0.1:8443");
        assert_eq!(normalize_demo_listen("[::]:443"), "[::]:443");
        assert_eq!(normalize_demo_listen("192.0.2.10:443"), "192.0.2.10:443");
    }

    #[test]
    fn cert_demo_serves_one_page_to_every_request() {
        // Go's demo handler answers every request with the same short page; the only thing that has
        // to be right is that the response is well-formed HTTP whose length header matches the body,
        // or a browser hangs waiting for bytes that never come.
        let resp = cert_demo_response();
        let (head, body) = resp
            .split_once("\r\n\r\n")
            .expect("response must separate headers from body with a blank line");
        assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{head:?}");
        assert!(
            head.contains(&format!("Content-Length: {}", body.len())),
            "the declared length must match the body ({} bytes): {head:?}",
            body.len()
        );
        assert!(head.contains("Content-Type: text/html; charset=utf-8"));
        assert!(head.contains("Connection: close"));
        assert!(body.contains("It works."), "{body:?}");
    }

    #[test]
    fn cert_command_parses_the_demo_and_validity_flags() {
        match Cli::try_parse_from([
            "tnet",
            "cert",
            "--serve-demo",
            "--listen",
            "127.0.0.1:8443",
            "--min-validity",
            "720h",
            "host.user.ts.net",
        ])
        .expect("parses")
        .command
        {
            Command::Cert {
                domain,
                min_validity,
                serve_demo,
                listen,
                ..
            } => {
                assert_eq!(domain, "host.user.ts.net");
                assert!(serve_demo);
                assert_eq!(listen.as_deref(), Some("127.0.0.1:8443"));
                assert_eq!(
                    min_validity,
                    Some(std::time::Duration::from_secs(720 * 3600))
                );
            }
            _ => panic!("expected Command::Cert"),
        }
        // The defaults: no demo server, no minimum validity.
        match Cli::try_parse_from(["tnet", "cert", "host.user.ts.net"])
            .expect("parses")
            .command
        {
            Command::Cert {
                min_validity,
                serve_demo,
                listen,
                ..
            } => {
                assert!(!serve_demo);
                assert_eq!(listen, None);
                assert_eq!(min_validity, None);
            }
            _ => panic!("expected Command::Cert"),
        }
        // A duration Go's parser rejects is rejected at parse time, before anything is issued.
        assert!(
            Cli::try_parse_from(["tnet", "cert", "--min-validity", "1d", "host.user.ts.net"])
                .is_err()
        );
    }

    #[test]
    fn logout_parses_an_optional_reason() {
        // Go `tailscale logout --reason "<text>"`. Bare `logout` keeps working (no reason).
        match Cli::try_parse_from(["tnet", "logout", "--reason", "laptop returned to IT"])
            .expect("parses")
            .command
        {
            Command::Logout { reason } => {
                assert_eq!(reason.as_deref(), Some("laptop returned to IT"));
            }
            _ => panic!("expected Command::Logout"),
        }
        match Cli::try_parse_from(["tnet", "logout"])
            .expect("parses")
            .command
        {
            Command::Logout { reason } => assert_eq!(reason, None),
            _ => panic!("expected Command::Logout"),
        }
    }

    #[test]
    fn version_accepts_gos_track_flag() {
        // `--track` selects the release track `--upstream` would query. This build has no upstream
        // fetcher, so the flag parses and changes nothing — which is exactly what Go's does in a
        // build without its clientupdate hook.
        match Cli::try_parse_from(["tnet", "version", "--track", "unstable"])
            .expect("parses")
            .command
        {
            Command::Version {
                track,
                upstream,
                daemon,
                json,
            } => {
                assert_eq!(track.as_deref(), Some("unstable"));
                assert!(!upstream && !daemon && !json);
            }
            _ => panic!("expected Command::Version"),
        }
    }

    #[test]
    fn netcheck_verbose_reports_how_long_the_report_took() {
        // Go's netcheck client logs `GetReport took <d>; err=<nil>` after each report; this is the
        // same line, timed around the daemon round-trip that does the measuring here.
        assert_eq!(
            netcheck_verbose_line(std::time::Duration::from_millis(57)),
            "netcheck: GetReport took 57ms; err=<nil>"
        );
        assert_eq!(
            netcheck_verbose_line(std::time::Duration::from_millis(1_234)),
            "netcheck: GetReport took 1234ms; err=<nil>"
        );
        // `--verbose` is off by default, and pairs with the other netcheck flags.
        match Cli::try_parse_from(["tnet", "netcheck", "--verbose", "--every", "5"])
            .expect("parses")
            .command
        {
            Command::Netcheck {
                verbose,
                every,
                json,
                format,
            } => {
                assert!(verbose);
                assert_eq!(every, Some(5));
                assert!(!json && format.is_none());
            }
            _ => panic!("expected Command::Netcheck"),
        }
        match Cli::try_parse_from(["tnet", "netcheck"])
            .expect("parses")
            .command
        {
            Command::Netcheck { verbose, .. } => assert!(!verbose),
            _ => panic!("expected Command::Netcheck"),
        }
    }

    #[test]
    fn status_browser_flag_matches_gos_spelling() {
        // Go writes `--browser=false` to keep the browser closed; this fork's own spelling is
        // `--no-browser`. Both must reach the same decision, and the default must stay "open it".
        assert!(resolve_browser(None, false), "Go's default is to open one");
        assert!(!resolve_browser(Some(false), false), "--browser=false");
        assert!(resolve_browser(Some(true), false), "--browser=true");
        assert!(!resolve_browser(None, true), "--no-browser");

        match Cli::try_parse_from(["tnet", "status", "--web", "--browser=false"])
            .expect("parses")
            .command
        {
            Command::Status {
                browser,
                no_browser,
                ..
            } => {
                assert_eq!(browser, Some(false));
                assert!(!no_browser);
                assert!(!resolve_browser(browser, no_browser));
            }
            _ => panic!("expected Command::Status"),
        }
        // A bare `--browser` is Go's `--browser=true`.
        match Cli::try_parse_from(["tnet", "status", "--web", "--browser"])
            .expect("parses")
            .command
        {
            Command::Status { browser, .. } => assert_eq!(browser, Some(true)),
            _ => panic!("expected Command::Status"),
        }
        // The two spellings of the same switch cannot be combined.
        assert!(
            Cli::try_parse_from(["tnet", "status", "--web", "--browser", "--no-browser"]).is_err(),
            "--browser and --no-browser are the same knob; asking for both is a usage error"
        );
    }

    /// `docs/ENGINE_ASKS.md` §21 is an ask filed against an OLD engine pin, and eight of the flags
    /// it asks for have since shipped. A reader who lands on the ask list decides what is still
    /// missing from it, so a bullet left unmarked — or a rationale still asserting in the present
    /// tense that the engine has no field for the flags below it — sends someone to re-ask for a
    /// pref this build already holds, or to re-implement it.
    ///
    /// The oracle is [`get_settings`], the production projection `tnet get` prints: it is keyed by
    /// the very `set`-flag names the ask list uses, and it has a row exactly for the settings this
    /// build actually models. So the doc is checked against the code rather than against a second
    /// copy of the list — adding a ninth flag to `get_settings` without marking its bullet fails
    /// here, and so does marking a bullet the daemon does not model.
    mod engine_asks_21 {
        use super::*;

        const ASKS: &str = include_str!("../../docs/ENGINE_ASKS.md");

        const HEADING: &str = "## 21.";
        const LIST_INTRO: &str = "**Ask — add the engine `Config` fields";

        /// Ask #21's body, from its heading to the next top-level ask.
        fn section() -> &'static str {
            let start = ASKS
                .find(HEADING)
                .unwrap_or_else(|| panic!("docs/ENGINE_ASKS.md should still contain `{HEADING}`"));
            let body = &ASKS[start..];
            match body[HEADING.len()..].find("\n## ") {
                Some(end) => &body[..HEADING.len() + end],
                None => body,
            }
        }

        /// The bullets of §21's ask list — the `- …` items between the `**Ask — …**` intro and the
        /// next paragraph. Continuation lines are folded into their bullet so a flag named on the
        /// second line still belongs to it.
        fn ask_bullets() -> Vec<String> {
            let section = section();
            let start = section
                .find(LIST_INTRO)
                .unwrap_or_else(|| panic!("§21 should still open its list with `{LIST_INTRO}`"));
            let mut bullets: Vec<String> = Vec::new();
            for line in section[start..].lines().skip(1) {
                if let Some(item) = line.strip_prefix("- ") {
                    bullets.push(item.to_string());
                } else if line.starts_with("  ") {
                    if let Some(last) = bullets.last_mut() {
                        last.push(' ');
                        last.push_str(line.trim());
                    }
                } else if line.starts_with("**") {
                    break; // the next paragraph (workload-identity flags) ends the list
                }
            }
            bullets
        }

        /// Every `--flag` named in a bullet's HEAD — the part before the `→` that points at the
        /// suggested engine field. The tail is prose about the field and can mention anything.
        fn flags_asked_for(bullet: &str) -> Vec<String> {
            let head = bullet.split('→').next().unwrap_or(bullet);
            head.split('`')
                .filter(|token| token.starts_with("--"))
                // A bullet writes the flag with its value placeholder (`--operator <user>`); the
                // name is the first word.
                .filter_map(|token| token.split_whitespace().next())
                .map(|token| token.trim_start_matches('-').to_string())
                .collect()
        }

        #[test]
        fn every_ask_bullet_is_marked_by_whether_this_build_models_the_flag() {
            // The settings this build really has, straight from the projection `tnet get` prints.
            let view = tailscaled_rs::localapi::PrefsView::default();
            let modelled: Vec<&str> = get_settings(&view)
                .into_iter()
                .map(|(name, _)| name)
                .collect();

            let bullets = ask_bullets();
            let (mut shipped_seen, mut open_seen) = (0usize, 0usize);
            for bullet in &bullets {
                let flags = flags_asked_for(bullet);
                assert!(
                    !flags.is_empty(),
                    "§21 ask bullet names no flag before its `→`: {bullet}"
                );
                let carried: Vec<&String> = flags
                    .iter()
                    .filter(|f| modelled.contains(&f.as_str()))
                    .collect();
                if carried.is_empty() {
                    open_seen += 1;
                    assert!(
                        bullet.starts_with("⬜ STILL OPEN"),
                        "§21 asks for {flags:?}, which this build does not model, so the bullet \
                         must stay marked `⬜ STILL OPEN`: {bullet}"
                    );
                } else {
                    shipped_seen += 1;
                    assert!(
                        bullet.starts_with("✅ SHIPPED"),
                        "`tnet get` already reports {carried:?}, so §21's bullet is a shipped flag \
                         and must say so rather than read as an open ask: {bullet}"
                    );
                }
            }

            // Guard the two branches above: if the list ever became all-shipped or all-open, the
            // half that no longer runs would pass vacuously.
            assert!(
                shipped_seen > 0 && open_seen > 0,
                "§21's list should still mix shipped and open asks (saw {shipped_seen} shipped, \
                 {open_seen} open across {} bullets)",
                bullets.len()
            );
        }

        #[test]
        fn the_filed_rationale_is_dated_rather_than_read_as_current() {
            // The trap this catches: the "no field to carry them" paragraph left in the present
            // tense under a banner that says eight of the flags shipped. Whichever half a reader
            // believes, the other one misleads them.
            let section = section();
            assert!(
                !section.contains("has **no field** to carry them"),
                "§21 still asserts in the present tense that the engine has no field for the flags \
                 below it; eight of them ship at the current pin"
            );
            assert!(
                section.contains("the rationale AS FILED"),
                "§21's superseded rationale should stay, labelled as the record of what was asked \
                 for rather than as a description of the engine today"
            );
        }
    }
}
