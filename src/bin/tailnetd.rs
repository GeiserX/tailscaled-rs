//! `tailnetd` — the daemon binary.
//!
//! Loads persisted prefs, optionally auto-starts the node if the last intent was "up", then serves
//! the LocalAPI socket until SIGINT/SIGTERM, shutting the engine down cleanly on exit. A SIGHUP is
//! handled separately — as a *reload*, not a shutdown (see [`sighup_reload_loop`]).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use tailscaled_rs::conffile;
use tailscaled_rs::ipn::{self, Backend};
use tailscaled_rs::prefs::Prefs;
use tokio::sync::Mutex;
use tracing_subscriber::EnvFilter;

/// Env var the underlying engine reads to confirm the operator opted into experimental software.
const EXPERIMENT_VAR: &str = "TS_RS_EXPERIMENT";
/// The exact value the engine requires; anything else (or unset) is a refusal.
const REQUIRED_EXPERIMENT_VALUE: &str = "this_is_unstable_software";

/// Multi-line `--version` block, mirroring the *shape* of Go `tailscaled`'s `version.String()`: the
/// semver on line 1, then two-space-indented detail lines. Go prints `tailscale commit: <sha>` and
/// `go version: <...>`; the faithful analogues here are `commit:` (our git SHA, `-dirty`-suffixed
/// when the tree was dirty at build time) and `rustc version:` (the toolchain that built us). Both
/// values are stamped at compile time by `build.rs`, each falling back to `unknown` when git/rustc
/// were unavailable. clap prints this for `--version`; `-V` still prints the bare semver.
const LONG_VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    "\n  commit: ",
    env!("TAILNETD_GIT_COMMIT"),
    "\n  rustc version: ",
    env!("TAILNETD_RUSTC_VERSION"),
);

/// `tailnetd` command-line flags (the analogue of Go `tailscaled`'s flag set).
///
/// The daemon was historically env-only (`TAILNETD_STATE_DIR` / `TAILNETD_SOCKET` / `TAILNETD_LOG`);
/// these flags are the Go-faithful CLI surface over the same knobs. **A flag, when given, OVERRIDES
/// the corresponding env var** (Go resolves flags first); when omitted, the existing env/default
/// resolution (`tailscaled_rs::state_dir` / `socket_path`) is unchanged, so existing env-driven
/// deployments behave exactly as before.
///
/// The data path is the one knob that is BOTH: `--tun` is a launch flag here as it is in Go, and it
/// is also a pref (`tnet up --tun`/`--tun-name`/`--tun-mtu`), because the pref is what reaches the
/// engine. The flag resolves onto that pref at startup — see the `--tun` field below and
/// [`tailscaled_rs::tunflag`] — so a Go-shaped command line and a `tnet up` end at the same place
/// instead of at two competing answers. `--port` (the WireGuard/disco UDP listen port) is a plain
/// startup flag (see below) — the engine gained a configurable listen port in v0.40.0.
#[derive(Parser, Debug)]
#[command(
    name = "tailnetd",
    about = "The tailscaled-rs daemon (experimental WireGuard mesh node)",
    version,
    long_version = LONG_VERSION
)]
struct Args {
    /// Directory for daemon state (node key, prefs). Overrides `TAILNETD_STATE_DIR`. When omitted,
    /// resolves as before: `TAILNETD_STATE_DIR`, else the system path when root, else an XDG/HOME
    /// path. Go `tailscaled --statedir`. NOTE: relocating the state dir also moves the default socket
    /// to `<DIR>/tailnetd.sock` (unless `TAILNETD_SOCKET`/`--socket` is set), so the `tnet` client
    /// must be pointed at it — `tnet --socket <DIR>/tailnetd.sock …` (or export `TAILNETD_SOCKET`) —
    /// since `tnet` has no `--statedir` of its own.
    #[arg(long, value_name = "DIR")]
    statedir: Option<PathBuf>,
    /// Encrypt the daemon's state file on disk (Go `tailscaled --encrypt-state`). **Accepted by the
    /// parser, then refused at startup when it is on** — see `can_encrypt_state`. Go seals the
    /// state file to the device's TPM (Linux and Windows only) by prefixing the state path with
    /// `tpm:`, and when the flag is *unset* enables that by itself wherever the platform supports it
    /// or the syspolicy key `EncryptState` asks for it.
    ///
    /// This fork has no state-store provider layer and no TPM/keystore integration: prefs and the
    /// node key are written as plain JSON under a `0700` state dir, which `docs/THREAT_MODEL.md`
    /// records as a trust boundary. At-rest encryption is therefore **out of scope for now**, and
    /// the flag says so rather than being an unknown argument or a silent no-op that would claim
    /// protection this build does not provide.
    ///
    /// Tri-state, like Go's `boolFlag` (`cmd/tailscaled/flag.go`), which tracks whether it was ever
    /// set: absent, `--encrypt-state` (= on), or `--encrypt-state=false` (explicitly off, and inert
    /// — Go validates only the "on" case). Go's `flag` package accepts a value for a bool flag only
    /// in the `=` form, hence `require_equals`; the value spellings are Go's `strconv.ParseBool`
    /// set, see `parse_go_bool`.
    #[arg(
        long,
        value_name = "BOOL",
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "true",
        value_parser = parse_go_bool
    )]
    encrypt_state: Option<bool>,
    /// Path of the LocalAPI control socket. Overrides `TAILNETD_SOCKET`. When omitted, resolves to
    /// `TAILNETD_SOCKET` else `<statedir>/tailnetd.sock`. Go `tailscaled --socket`.
    #[arg(long, value_name = "PATH")]
    socket: Option<PathBuf>,
    /// Path of the BIRD control socket, for a subnet router that hands its advertised routes to a
    /// BIRD BGP daemon (Go `tailscaled --bird-socket`). **Accepted by the parser, then refused at
    /// startup** — see `bird_socket_refusal`. Go passes the path to its engine
    /// (`wgengine.Config.BIRDSocket`, constructed via `wgengine.HookNewBird`), which enables BIRD's
    /// `tailscale` protocol while this node is a *primary* subnet router and disables it otherwise.
    /// That toggle lives inside the engine's reconfigure cycle, which this daemon does not own, and
    /// the `tailscale-rs` engine exposes no BIRD hook — so there is nothing here to hand the socket
    /// to. Declaring the flag anyway is the whole point: a Go-shaped command line gets a startup
    /// error that NAMES the missing integration instead of clap's generic "unexpected argument",
    /// and — unlike silently ignoring it — a subnet router is never left believing its BGP
    /// announcements are being driven when nothing is connected to BIRD. Go refuses the same way
    /// (`--bird-socket is not supported on %s`) on a build whose BIRD hook is not linked in.
    #[arg(long, value_name = "PATH")]
    bird_socket: Option<String>,
    /// Log verbosity: `0` (default, info), `1` (debug), `2+` (trace). Overrides the `TAILNETD_LOG`
    /// env filter when given. Go `tailscaled --verbose`.
    #[arg(long, short = 'v', value_name = "LEVEL")]
    verbose: Option<u8>,
    /// Tunnel interface name; use `userspace-networking` to not use TUN (Go `tailscaled --tun`).
    /// This is the single most-copied flag on a `tailscaled` command line — packaged systemd units,
    /// container entrypoints and cloud images all pass `--tun=userspace-networking` or
    /// `--tun=tailscale0` — so it is accepted in Go's full grammar: a device name (`tailscale0`),
    /// `userspace-networking`, `tap:TAPNAME[:BRIDGENAME]`, or a comma-separated fallback list of
    /// those tried left to right (Go's `createEngine` loop; `tailscale0,userspace-networking` is
    /// Go's own Synology default). [`tailscaled_rs::tunflag`] resolves the value and owns every
    /// refusal — a name this build cannot provide is a startup error that says which and why.
    ///
    /// **The resolved data path lands in the TUN prefs** (`tun_enabled`/`tun_name` — the same prefs
    /// `tnet up --tun`/`--tun-name` write), because in this fork the pref is what reaches the
    /// engine. Go instead threads `args.tunname` straight into `wgengine.Config`; it has no pref to
    /// collide with. Mapping the flag onto the pref keeps a single answer to "what data path is this
    /// node on" — see `Backend::apply_tun_flag`, which also explains why it persists.
    ///
    /// **Deliberate deviation: omitting the flag does not mean `tailscale0`.** Go's flag carries a
    /// per-platform device default, so a bare `tailscaled` runs in TUN mode; an absent `--tun` here
    /// leaves the persisted pref alone, and that pref defaults to the userspace netstack. A daemon
    /// that started capturing OS-wide traffic because a flag was left OFF would be a far worse
    /// surprise than a copied command line having to name the mode it wants.
    #[arg(long, value_name = "NAME")]
    tun: Option<String>,
    /// Fixed UDP port for WireGuard + disco (Go `tailscaled --port`). When omitted, falls back to the
    /// `PORT` env var (Go's `EnvironmentFile` convention; the explicit flag wins), and if neither is
    /// set the OS picks an ephemeral port (Go's port `0`, the default) — fine for the common
    /// NAT-traversal case. Pin it (`--port 41641`, Go's default) when behind a firewall that only
    /// forwards/pinholes a fixed UDP port, so the node's endpoint is stable across restarts. If the
    /// chosen port is already taken at startup the engine falls back to an ephemeral port rather than
    /// failing bring-up (a collision never takes the node down). `0` means "pick any" (= omitting it).
    #[arg(long, value_name = "PORT")]
    port: Option<u16>,
    /// Declarative config SOURCE (Go `tailscaled --config`, the `ipn.ConfigVAlpha` JSON). Loaded at
    /// startup and merged over the persisted prefs — the headless/automated path for setting prefs
    /// without an interactive `tnet up`. An `AuthKey` (or `file:<path>`) in the config registers the
    /// node. Fails fast on a malformed/unsupported-version config.
    ///
    /// The value is a *source*, not merely a path (Go's flag doc: "path to config file, or
    /// 'vm:user-data' to use the VM's user-data (EC2); prefix with 'optional:' to boot unconfigured
    /// when the source is absent instead of failing"):
    ///
    /// * `<path>` — a JSON config file on disk;
    /// * `vm:user-data` — the VM's user-data from the cloud instance metadata service. Recognized,
    ///   but this build has no cloud-metadata client, so it reports the source as absent (the same
    ///   branch a Go build without its `HasAWS` feature takes) — see `tailscaled_rs::conffile::load`;
    /// * `optional:<source>` — an ABSENT source is not fatal: the node boots unconfigured and can be
    ///   enrolled interactively instead of refusing to start. A source that is present but INVALID
    ///   still fails. This is what makes the `--config optional:vm:user-data` line in a cloud-init
    ///   template safe to paste onto a host that is not the cloud it was written for.
    ///
    /// (SIGHUP re-read is a follow-up: it shares the same blocker as the existing prefs reload —
    /// adopting changed config fields into a *running* engine needs an `ipn` `reload_prefs` primitive
    /// this crate does not yet own. The `reload-config` LocalAPI verb re-reads this same source.)
    #[arg(long, value_name = "SOURCE")]
    config: Option<String>,
    /// Bind this node's identity to a hardware-backed key (Go `tailscaled --hardware-attestation`).
    /// **Accepted by the parser, then refused at startup when it is on** — see
    /// `can_use_hardware_attestation`. Go uses TPM 2.0 on Linux and Windows, the Secure Enclave on
    /// macOS and iOS and Keystore on Android, then marks the node hardware-attested to its backend;
    /// when the flag is unset it defaults from the syspolicy key `HardwareAttestation`.
    ///
    /// There is no hardware key store anywhere in this fork — the node key is generated and held by
    /// the `tailscale-rs` engine and persisted as an ordinary file — so there is no attestation key
    /// to bind an identity to. **Out of scope for now**, and refused rather than ignored: a silently
    /// accepted flag would leave an operator believing the identity is sealed to this machine.
    ///
    /// Tri-state like `--encrypt-state` above; `--hardware-attestation=false` is accepted and inert.
    #[arg(
        long,
        value_name = "BOOL",
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "true",
        value_parser = parse_go_bool
    )]
    hardware_attestation: Option<bool>,
    /// Run a SOCKS5 proxy on `[host:]port` that dials **over the tailnet** (Go `tailscaled
    /// --socks5-server`). A bare port (`1055`) binds `127.0.0.1:<port>`; pass an explicit address to
    /// bind elsewhere (the proxy is UNAUTHENTICATED — the bind address is the security boundary, so it
    /// defaults to loopback). CONNECT requests resolve a MagicDNS name or IP to a tailnet node and
    /// splice over the overlay (the engine's dialer), so a netstack/no-TUN daemon can route an app's
    /// traffic through the tailnet without root or a TUN device. Off unless given.
    #[arg(long, value_name = "[HOST:]PORT")]
    socks5_server: Option<String>,
    /// Run an outbound HTTP proxy on `[host:]port` that dials **over the tailnet** (Go `tailscaled
    /// --outbound-http-proxy-listen`). The HTTP-proxy sibling of `--socks5-server` for clients that
    /// speak the HTTP-proxy protocol (`https_proxy=...`, `curl -x`). Supports the `CONNECT` method
    /// (HTTPS tunneling — the common case); a bare port binds `127.0.0.1`. Unauthenticated, so the
    /// bind address is the security boundary. Off unless given.
    #[arg(long, value_name = "[HOST:]PORT")]
    outbound_http_proxy_listen: Option<String>,
    /// Clean up any OS-level network state left by a previous run, then exit (Go `tailscaled
    /// --cleanup`). Go uses this to undo DNS config, firewall/netfilter rules, and routes after a
    /// crash or reboot. This fork runs in userspace/netstack mode by default and programs **no** OS
    /// DNS/firewall/route/TUN state, so — exactly like Go's `userspace-networking` path, which skips
    /// the teardown entirely — there is almost nothing to undo. The one piece of system state the
    /// daemon owns is the LocalAPI socket, so cleanup removes a *stale* socket (one with no live
    /// daemon listening) and exits 0. It NEVER deletes the node key or prefs — that is `logout`/state
    /// reset, a different operation Go's `--cleanup` likewise never performs. Refuses (exit 1) if a
    /// daemon is currently listening on the socket, rather than yanking it from under a live process.
    #[arg(long)]
    cleanup: bool,
    /// Accept `--no-logs-no-support` for `tailscaled` CLI compatibility (Go disables log uploads and
    /// forgoes technical support). This fork never uploads logs or telemetry anywhere, so the flag is
    /// an honest no-op: it only prints a one-line notice at startup. There is no posture/status field
    /// to set — Go surfaces it only as a printed warning + an internal logpolicy switch, neither of
    /// which has anything to gate here.
    #[arg(long)]
    no_logs_no_support: bool,
    /// JSON file registered as a **device-scope system-policy source** (Go `tailscaled
    /// --syspolicy-file`, new in v1.102.3). This is the only way an admin on a non-Windows host can
    /// supply MDM-style policy at all — without it `tnet syspolicy list` reports an empty policy set
    /// on every platform, because Go's only other store is the Windows registry. The file is a JSON
    /// object mapping policy keys to values (`{"Hostname": "kiosk-3", "CheckUpdates": "always"}`);
    /// unknown keys and values of the wrong type are refused at startup rather than at first use.
    /// Defaults to `/etc/tailscale/syspolicy.json` (`%ProgramData%\Tailscale\syspolicy.json` on
    /// Windows) — an absent file is simply no policy, not an error — and **an empty value disables
    /// the source**. A file that fails to load is logged and the daemon carries on: a broken policy
    /// file must not keep the node off the tailnet. NOTE: the settings are *reported* today
    /// (`tnet syspolicy list`/`reload`), not yet applied to prefs — Go applies them in
    /// `ipnlocal.applySysPolicy`, a surface this fork does not have yet.
    #[arg(long, value_name = "PATH", default_value_t = default_syspolicy_file())]
    syspolicy_file: String,
    /// Run a debug HTTP server on `[host:]port` exposing `GET /debug/metrics` (Go `tailscaled
    /// --debug`). Serves the daemon's Prometheus metrics (the same text `tnet metrics` returns) over
    /// plain HTTP so a scraper can pull them without the unix LocalAPI socket. A bare port binds
    /// `127.0.0.1` (the endpoint is UNAUTHENTICATED — metrics can carry operational detail, so the
    /// bind address is the security boundary); pass a full address to bind elsewhere. Read-only.
    /// Go's `/debug/pprof/*` is Go-runtime-specific and not served (a request gets a clear 404). Off
    /// unless given.
    #[arg(long, value_name = "[HOST:]PORT")]
    debug: Option<String>,
    /// The daemon's subcommands. `None` is the ordinary case: run the daemon.
    #[command(subcommand)]
    command: Option<Command>,
}

/// `tailnetd`'s subcommands — the analogue of Go `tailscaled`'s `subCommands` map, which `main`
/// dispatches on `os.Args[1]` **before** parsing the daemon's own flag set, so a subcommand runs
/// standalone and never starts a daemon.
///
/// Go's map holds four entries; only `debug` is ported here. `install-system-daemon` /
/// `uninstall-system-daemon` are already reachable in this fork as `tnet install`/`uninstall`
/// (`ipn::install`), and `be-child` is Go's Windows subprocess plumbing, which has nothing to be
/// the child of here.
#[derive(clap::Subcommand, Debug)]
enum Command {
    /// Daemon-less network diagnostics: dump the host network state, follow link changes, or fetch a
    /// URL — none of which need a running daemon or its socket (Go `tailscaled debug`).
    ///
    /// This is NOT the `--debug` flag above, which is the listen address of the metrics HTTP server.
    Debug(tailscaled_rs::debugmode::DebugArgs),
}

/// Restore the default `SIGPIPE` disposition (terminate) before any output. The Rust runtime sets
/// `SIG_IGN`, which turns a write to a closed pipe into `EPIPE` → a `print!` panic; resetting to
/// `SIG_DFL` makes a broken output pipe (e.g. `tailnetd --version | head`) terminate cleanly instead,
/// the Unix-idiomatic behavior (same as the `tnet` CLI; see its `reset_sigpipe`). Output-only — does
/// not affect the LocalAPI socket I/O.
fn reset_sigpipe() {
    // SAFETY: `signal(SIGPIPE, SIG_DFL)` is async-signal-safe, no preconditions; called once at the
    // very start of `main` before any threads/output. The `unsafe` is only the `libc::signal` FFI.
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Restore default SIGPIPE before any output (a broken `--version`/`--help` pipe should terminate
    // cleanly, not panic the print). Must run before clap, which prints help/version.
    reset_sigpipe();
    // Parse flags FIRST: clap handles `--help`/`--version` (print + exit 0) and rejects unknown
    // flags before we touch the experiment gate or any state, matching how Go `tailscaled` parses its
    // flag set up front. The parsed values then override the env-derived defaults below.
    let args = Args::parse();

    // `tailnetd debug …` (Go `tailscaled debug`): a SUBCOMMAND, dispatched first — before the
    // `--bird-socket` refusal, before `--cleanup`, and before the experiment gate. All three of
    // those orderings are deliberate and all three are Go's: Go dispatches its `subCommands` map on
    // `os.Args[1]` at the top of `main`, ahead of its own flag parsing and every startup
    // precondition, because the subcommand never starts a daemon. Here the experiment gate is the
    // one that matters most — the gate exists because the ENGINE is unaudited, and `debug` never
    // constructs one: it enumerates interfaces and speaks plain HTTP. Making an operator opt into
    // experimental software before they may look at their own network state would defeat the point
    // of the tool, which is diagnosing a node that will not come up.
    //
    // Bare message + exit 1 on failure mirrors Go's `log.SetFlags(0)` + `log.Fatal(err)`.
    if let Some(Command::Debug(debug_args)) = &args.command {
        if let Err(e) = tailscaled_rs::debugmode::run(debug_args) {
            eprintln!("{e}");
            std::process::exit(1);
        }
        return Ok(());
    }

    // `--bird-socket <path>` (Go `tailscaled --bird-socket`): parsed so a Go-shaped command line
    // reaches a refusal that names the missing integration, then refused HERE — before the
    // `--cleanup` handling below, which is where Go puts the same check (top of `main`, above its
    // own cleanup exit), so `--cleanup --bird-socket <path>` refuses instead of quietly cleaning up.
    // Bare message + exit 1 mirrors Go's `log.SetFlags(0)` + `log.Fatalf`. See `bird_socket_refusal`
    // for the reasoning and for the empty-path carve-out.
    if let Some(message) = bird_socket_refusal(args.bird_socket.as_deref()) {
        eprintln!("{message}");
        std::process::exit(1);
    }

    // `--encrypt-state` / `--hardware-attestation` (Go `tailscaled --encrypt-state` /
    // `--hardware-attestation`): the explicit-flag half of Go's `handleTPMFlags`. Refused HERE, next
    // to the `--bird-socket` refusal and for the same reasons — an operator who asked for a feature
    // this build does not have should be told about the FLAG rather than about `--cleanup`'s result
    // or an unrelated environment variable, and Go likewise validates these flags before it reaches
    // its own cleanup path. Bare message + exit 1 mirrors Go's `log.SetFlags(0)` + `log.Fatal(err)`.
    // The policy-driven half runs further down, once the syspolicy file is loaded.
    if let Some(message) =
        explicit_tpm_flag_refusal(args.encrypt_state, args.hardware_attestation, goos())
    {
        eprintln!("{message}");
        std::process::exit(1);
    }

    // `--tun <name>` (Go `tailscaled --tun`): resolve the requested data path from the command line.
    // Refused HERE — with the neighbouring flag refusals, before the experiment gate — for the same
    // reason they are: an operator who named an interface this build cannot provide should be told
    // about the FLAG, not about an unrelated environment variable. Bare message + exit 1 mirrors Go's
    // `log.SetFlags(0)` + `log.Fatal(err)`.
    //
    // Skipped entirely under `--cleanup`: Go validates `--tun` inside `createEngine`, which a cleanup
    // run never reaches, and the one check Go does make earlier (its macOS root refusal) carves
    // cleanup out by hand — so reclaiming a stale socket keeps working with whatever `--tun` the unit
    // file happens to carry. The resolved transport is applied to prefs further down, once the
    // backend has loaded them.
    let tun_transport = match args.tun.as_deref().filter(|_| !args.cleanup) {
        Some(value) => match tailscaled_rs::tunflag::resolve(value, goos()) {
            Ok(transport) => Some(transport),
            Err(e) => {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        },
        None => None,
    };

    // `--cleanup` (Go `tailscaled --cleanup`): reclaim OS-level network state from a previous run,
    // then exit — WITHOUT running the engine, so it deliberately runs BEFORE the experiment gate
    // below (Go likewise drops cleanup's normal prerequisites, e.g. the macOS root check). In
    // userspace/netstack mode this fork programs no OS DNS/firewall/route/TUN state, so the only
    // system state to reclaim is the LocalAPI socket (Go skips its DNS/router teardown entirely on
    // the `userspace-networking` path for the same reason). It never touches the node key or prefs.
    if args.cleanup {
        let state_dir = args
            .statedir
            .clone()
            .unwrap_or_else(tailscaled_rs::state_dir);
        let socket_path = args
            .socket
            .clone()
            .unwrap_or_else(|| tailscaled_rs::socket_path_in(&state_dir));
        std::process::exit(run_cleanup(&socket_path).await);
    }

    // Gate, before any logging is set up: the engine refuses to run unless
    // `TS_RS_EXPERIMENT=this_is_unstable_software` is set, so mirror that gate here and surface it
    // early with an actionable message instead of a deep engine error. We deliberately do NOT set
    // the var ourselves — auto-defeating the experimental gate would hide that this is unaudited
    // software. The packaged systemd/launchd units set it for the operator. On refusal we emit a
    // single stderr line and exit(1) (matching `tnet`'s error path) rather than logging + returning
    // an Err, which would otherwise print the same refusal across stdout and stderr.
    if !experiment_gate_ok(std::env::var(EXPERIMENT_VAR).ok().as_deref()) {
        eprintln!(
            "error: {EXPERIMENT_VAR} is not set to `{REQUIRED_EXPERIMENT_VALUE}`.\n\
             The underlying engine is experimental and unaudited; it refuses to run without an \
             explicit opt-in.\n\
             To run tailnetd, set `{EXPERIMENT_VAR}={REQUIRED_EXPERIMENT_VALUE}` in the environment \
             (the packaged systemd/launchd units already do this for you)."
        );
        std::process::exit(1);
    }

    // Log filter: `--verbose <n>` (when given) wins and maps to a level (Go's numeric verbosity);
    // otherwise fall back to the `TAILNETD_LOG` env filter, else `info`. `--verbose` overriding the
    // env mirrors the flags-first resolution Go uses.
    tracing_subscriber::fmt()
        .with_env_filter(match args.verbose {
            Some(level) => EnvFilter::new(verbose_to_level(level)),
            None => {
                EnvFilter::try_from_env("TAILNETD_LOG").unwrap_or_else(|_| EnvFilter::new("info"))
            }
        })
        .init();

    // `--no-logs-no-support` (Go `tailscaled --no-logs-no-support`): Go flips an envknob that swaps
    // the logtail uploader for a no-op transport and prints a warning. This fork never uploads logs
    // or telemetry anywhere, so the flag is an honest no-op — emit the one-line notice (now that
    // logging is initialized) and carry on. There is nothing to disable and no posture field to set.
    if args.no_logs_no_support {
        tracing::info!(
            "--no-logs-no-support: tailnetd never uploads logs or telemetry; this flag is a no-op"
        );
    }

    // `--syspolicy-file <path>` (Go `tailscaled --syspolicy-file`): register the JSON policy file as
    // a device-scope system-policy source. Done HERE — right after logging is initialized, so a load
    // failure has somewhere to be reported, and before anything that could consult a policy setting
    // (Go calls its `loadSyspolicy` hook at the same point, after flag parsing and before the engine
    // exists). Never fatal: see `load_syspolicy_file`.
    load_syspolicy_file(&args.syspolicy_file);

    // The system-policy half of Go's `handleTPMFlags`, run at Go's own position: immediately after
    // the syspolicy file is registered, because these two arms are the only place the daemon reads a
    // policy key at startup. Neither feature can be turned on here, so all this produces is the
    // reporting Go does on the way past — see `tpm_policy_notices`.
    for notice in tpm_policy_notices(
        args.encrypt_state,
        args.hardware_attestation,
        |key| ipn::syspolicy::get_boolean(key, false),
        goos(),
    ) {
        tracing::warn!("{notice}");
    }

    // Best-effort OS-level hardening (no-coredump / no-ptrace / no-swap) for the secrets the engine
    // will hold in memory. Done here — after the experiment gate and logging init (so its outcome is
    // logged), but BEFORE `Backend::load` reads any key material — so the protection is in place
    // before the first secret lands in a page. Non-fatal by design: a denied step is a warning, not
    // a refusal to start (see `tailscaled_rs::hardening`). Skippable with `TAILNETD_NO_HARDEN=1`.
    let _ = tailscaled_rs::hardening::harden_process();

    // Install the SIGHUP handler NOW, before the (potentially multi-second) `Backend::load` +
    // `auto_start` handshake. `tokio::signal::unix::signal` overrides the OS default (terminate) the
    // moment it is created and queues any signal until `recv().await`, so a SIGHUP that arrives
    // during startup is reloaded later rather than killing the daemon mid-boot. (Creating it here vs.
    // inside `sighup_reload_loop` only changes *when the default is overridden* — the consuming loop
    // still starts in the `select!` below.)
    let sighup = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
        Ok(s) => Some(s),
        Err(e) => {
            tracing::warn!(error = %e, "failed to install SIGHUP handler; reload disabled");
            None
        }
    };

    // Resolve the state dir + socket: a flag wins; otherwise the existing env/default resolution.
    // The socket default is derived from the *resolved* state dir (matching `socket_path()`'s own
    // `<state_dir>/tailnetd.sock` fallback), so `--statedir` alone also relocates the socket.
    let state_dir = args.statedir.unwrap_or_else(tailscaled_rs::state_dir);
    let socket_path = args
        .socket
        .unwrap_or_else(|| tailscaled_rs::socket_path_in(&state_dir));
    tracing::info!(state_dir = %state_dir.display(), "starting tailnetd");

    // The state dir holds unencrypted key material; lock it to 0700 before any key file is written.
    if let Err(e) = tailscaled_rs::ensure_state_dir_secure(&state_dir).await {
        tracing::error!(error = %e, state_dir = %state_dir.display(), "failed to secure state dir");
        return Err(e.into());
    }

    // Validate `--socks5-server` / `--outbound-http-proxy-listen` NOW (fail-fast, before any state
    // work) so a bad listen address is a clear startup error rather than a deep bind failure later.
    // `None` when the flag is absent.
    let socks5_listen = match &args.socks5_server {
        Some(addr) => Some(
            tailscaled_rs::socks5::normalize_listen_addr(addr)
                .context("invalid --socks5-server address")?,
        ),
        None => None,
    };
    let http_proxy_listen = match &args.outbound_http_proxy_listen {
        Some(addr) => Some(
            tailscaled_rs::httpproxy::normalize_listen_addr(addr)
                .context("invalid --outbound-http-proxy-listen address")?,
        ),
        None => None,
    };
    let debug_listen = match &args.debug {
        Some(addr) => Some(
            tailscaled_rs::debugserver::normalize_listen_addr(addr)
                .context("invalid --debug address")?,
        ),
        None => None,
    };

    // The prefs path the backend persists to / loads from; SIGHUP re-reads it to re-evaluate intent.
    let prefs_path = state_dir.join("prefs.json");

    let mut backend = Backend::load(&state_dir).await?;

    // `--port <PORT>` / `PORT=` (Go `tailscaled --port`): pin the WireGuard/disco UDP listen port.
    // A daemon-startup setting, not a pref — threaded onto the engine config by `build_config`. The
    // explicit `--port` flag wins; absent that, fall back to the `PORT` env var (Go's `EnvironmentFile`
    // convention — the packaged systemd unit's `EnvironmentFile=-/etc/default/tailnetd` can set it). A
    // malformed `PORT` (non-numeric / out of range) fails the daemon HARD rather than silently using an
    // ephemeral port — a misconfigured fixed-pinhole deploy must not start with the wrong endpoint.
    // Neither given ⇒ the backend's default `None` ⇒ an OS-chosen ephemeral port (untouched path).
    let listen_port = match args.port {
        Some(p) => Some(p),
        None => match std::env::var("PORT") {
            Ok(s) => Some(
                s.parse::<u16>()
                    .with_context(|| format!("invalid PORT env value {s:?}: expected a u16"))?,
            ),
            Err(_) => None,
        },
    };
    if let Some(port) = listen_port {
        backend.set_listen_port(port);
        tracing::info!(port, "pinning WireGuard/disco listen port (--port/PORT)");
    }

    // `--config <source>`: load the declarative config and merge it over the just-loaded prefs (Go
    // `tailscaled --config`). The merge is layered + persisted by `apply_config`, so the config
    // refines the stored prefs and the merged intent survives a later restart. A malformed or
    // unsupported-version config fails the daemon HARD (a misconfigured headless deploy must not start
    // half-configured) — propagate the error rather than logging + continuing. The config's auth key
    // (if any) is threaded into auto-start as a registration credential (never persisted into prefs).
    //
    // The flag's value is a config SOURCE (`ConfigFlag::parse`): a path, the `vm:user-data` sentinel,
    // or either behind `optional:`. `ConfigFlag::load` applies Go's optional contract — `Ok(None)`
    // means "the source is absent and that was declared acceptable", so the node boots unconfigured
    // and can be enrolled interactively, while a present-but-invalid config still fails even then.
    // An absent optional source deliberately leaves the backend's config source UNSET: there is
    // nothing to re-read, so `reload-config` says so plainly (Go leaves `sys.InitialConfig` nil the
    // same way).
    let config_authkey = match args.config.as_deref().and_then(conffile::ConfigFlag::parse) {
        Some(flag) => {
            match flag
                .load()
                .with_context(|| format!("loading --config {}", flag.source))?
            {
                Some(config) => {
                    tracing::info!(source = %flag.source, version = %config.version, "applying --config");
                    let authkey = backend.apply_config(&config).await?;
                    // Record the config source on the backend so the `reload-config` LocalAPI verb (Go
                    // `tailscaled`'s `reload-config`) can re-read this exact source and re-adopt its
                    // fields into the running node. Done only when a config actually loaded — a
                    // config-less daemon has nothing to reload (and `reload_config` errors clearly in
                    // that case).
                    backend.set_config_source(flag.source.clone());
                    authkey
                }
                // `optional:` + absent: `ConfigFlag::load` already logged which source was missing.
                None => None,
            }
        }
        None => None,
    };

    // `--tun <name>`: map the resolved data path onto the TUN prefs — the only route to the engine
    // here, where Go has a `wgengine.Config` field. Applied AFTER `--config` so an explicit flag on
    // the command line outranks a config document, the way `--verbose` outranks `TAILNETD_LOG`.
    // `apply_tun_flag` persists ONLY when the value changes something, so the overwhelmingly common
    // `--tun=userspace-networking` in a unit file writes nothing at all; `persisted` in the log line
    // below says which happened, so the flag is never silent about having rewritten an intent.
    if let Some(transport) = &tun_transport {
        let persisted = backend
            .apply_tun_flag(transport)
            .await
            .context("applying --tun")?;
        match transport {
            tailscaled_rs::tunflag::TunTransport::Netstack => tracing::info!(
                persisted,
                "--tun: userspace networking; no kernel TUN interface (the engine's netstack)"
            ),
            tailscaled_rs::tunflag::TunTransport::Tun { name } => tracing::info!(
                persisted,
                name = name.as_deref().unwrap_or("<platform default>"),
                "--tun: kernel TUN data path"
            ),
        }
    }

    // Describe the daemon's effective posture once at boot so an operator tailing the log knows which
    // control plane it talks to, which data path it uses, and the exact build — without having to run
    // `tnet status`/`version`. (`control_url = None` → the engine default, Tailscale SaaS; `transport`
    // is the kernel-TUN data path vs the userspace netstack.)
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        control_url = backend.prefs_control_url().unwrap_or("default"),
        transport = if backend.prefs_tun() {
            "tun"
        } else {
            "netstack"
        },
        ephemeral = backend.prefs_ephemeral(),
        ssh = backend.prefs_ssh(),
        "tailnetd posture"
    );

    // Reap host network state a previous, HARD-KILLED run left behind (macOS): a SIGKILL/abort skips
    // the engine's graceful route/DNS teardown, so stale `utun` routes and a stale `scutil` resolver
    // dictionary can outlive the daemon and keep blackholing traffic and DNS. Done here — after the
    // posture log, and crucially BEFORE `auto_start` brings the engine up — so the cleanup can never
    // race the fresh TUN device or its routes. Best-effort and non-fatal (a failure is logged; it is
    // never a reason to refuse to bring the node up), a no-op off macOS / when not root, and
    // skippable with `TAILNETD_NO_REAP=1`.
    tailscaled_rs::hostreap::reap_stale_host_state();

    // Auto-start if the persisted intent was "up". A `--config` auth key (if supplied, already a
    // `SecretString`) is threaded in as the registration credential, taking precedence over
    // `TS_AUTH_KEY`.
    auto_start(&mut backend, config_authkey).await;

    // Tell systemd we are ready (Go `tailscaled`'s `systemd.Ready()`): the LocalAPI socket is bound,
    // the backend has loaded, and auto-start has been attempted — i.e. the daemon can now serve. A
    // no-op off systemd (NOTIFY_SOCKET unset) and best-effort (never fatal). This is what lets the
    // packaged unit move to `Type=notify` so `systemctl start` blocks until the daemon is genuinely up.
    sd_notify_ready();

    let backend = Arc::new(Mutex::new(backend));

    // Captive-portal detection (Go `ipn/ipnlocal/captiveportal.go`): a daemon-lifetime task that
    // notices when this node is stuck behind an airport/hotel Wi-Fi login page and raises the
    // `captive-portal-detected` health warning `tnet status` prints. Its own gate makes it inert
    // outside `Running`, which is how it expresses the loop lifetime Go gets from starting the loop
    // on entry to `ipn.Running` and cancelling it on the way out: it probes only while the node is
    // up, wants to be up, and can reach no relay server. A healthy node, a node still coming up and
    // a deliberately-down node all make zero requests, so it costs nothing on a headless node.
    //
    // Detached rather than a `select!` arm: it must never be able to end `serve`, and it owns no
    // resource needing orderly teardown beyond its `Arc`. Its handle is aborted after `serve` returns
    // so the loop cannot outlive the backend it reports on.
    let captive_portal_task = tokio::spawn(ipn::captive_portal_loop(Arc::clone(&backend)));

    // Serve the LocalAPI socket until SIGINT/SIGTERM, with SIGHUP handled *concurrently* as a reload
    // (never a shutdown). `serve`'s shutdown future is still SIGINT/SIGTERM only — the SIGHUP loop is
    // a SEPARATE `select!` branch that holds its own `Arc` clone and runs forever, so a SIGHUP can
    // reconcile the live backend without ending `serve`. The `select!` returns when `serve` returns
    // (i.e. on SIGINT/SIGTERM): at that point the still-pending `sighup_reload_loop` future is simply
    // dropped (cancelled) — it owns no resource that needs an orderly teardown beyond the `Arc`.
    let serve_result = {
        let server_backend = Arc::clone(&backend);
        let sighup_backend = Arc::clone(&backend);
        let sighup_prefs_path = prefs_path.clone();
        // Optional SOCKS5 proxy (Go `--socks5-server`): a process-level listener that dials over the
        // tailnet, sharing the same backend handle. Bound only when the flag is given; otherwise the
        // arm is an inert `pending()` future that never fires, so the `select!` shape is uniform. The
        // listen address was validated above (fail-fast), so this only fails on a real bind error —
        // which, like Go, ends the daemon (a requested proxy that can't bind is a startup failure).
        let socks5_backend = Arc::clone(&backend);
        let socks5_addr = socks5_listen.clone();
        let http_proxy_backend = Arc::clone(&backend);
        let http_proxy_addr = http_proxy_listen.clone();
        let debug_backend = Arc::clone(&backend);
        let debug_addr = debug_listen.clone();
        tokio::select! {
            r = tailscaled_rs::server::serve(&socket_path, server_backend, shutdown_signal()) => r,
            // The SOCKS5 proxy arm: a bind/serve error ends the daemon (matches Go). When no
            // `--socks5-server` was given, `run_optional_socks5` is `pending()` and never wins.
            r = run_optional_socks5(socks5_addr, socks5_backend) => r,
            // The HTTP-proxy arm: same model — bind/serve error ends the daemon; `pending()` when the
            // `--outbound-http-proxy-listen` flag is absent.
            r = run_optional_http_proxy(http_proxy_addr, http_proxy_backend) => r,
            // The debug-HTTP arm (Go `--debug`): same model — a bind/serve error ends the daemon;
            // `pending()` when `--debug` is absent.
            r = run_optional_debug(debug_addr, debug_backend) => r,
            // `sighup_reload_loop` never returns; this arm only wins if it somehow does (it logs and
            // exits the loop only if installing the SIGHUP handler fails), in which case we keep
            // serving — losing reload is not a reason to tear the daemon down.
            () = sighup_reload_loop(sighup, sighup_backend, sighup_prefs_path) => {
                tracing::warn!("SIGHUP reload loop ended; continuing to serve without reload support");
                // Re-await serve alone so the daemon still shuts down cleanly on SIGINT/SIGTERM.
                let server_backend = Arc::clone(&backend);
                tailscaled_rs::server::serve(&socket_path, server_backend, shutdown_signal()).await
            }
        }
    };
    // The daemon is exiting: stop reporting on a backend that is about to be torn down. Aborting
    // before `shutdown` also guarantees the loop is not holding the backend lock we need next.
    captive_portal_task.abort();

    serve_result?;

    backend.lock().await.shutdown().await;
    Ok(())
}

/// `--cleanup` body: reclaim the OS-level state a previous run may have left, then return the
/// process exit code (`main` calls `std::process::exit` with it). Prints to stderr/stdout directly
/// rather than via `tracing` — `--cleanup` runs before logging is initialized (it precedes the
/// experiment gate), and an operator runs it as a one-shot command expecting plain output.
///
/// In userspace/netstack mode the only system state the daemon owns is the LocalAPI socket, so this
/// is the whole teardown. The node key and `prefs.json` are NEVER touched (that is `logout`/state
/// reset — a separate operation; Go's `--cleanup` likewise never deletes identity). This is enforced
/// structurally: the function is handed only `socket_path` and never the key/prefs paths, so it
/// *cannot* reach them. If a daemon is currently listening on the socket, refuse (exit 1) rather than
/// yanking the socket from under a live process; a stale socket (path exists but nothing accepts) is
/// removed; an absent socket is a no-op success.
///
/// There is a benign probe→unlink TOCTOU: a daemon that races startup in the window between the
/// liveness probe and the `remove_file` could have its just-bound socket removed. This is acceptable
/// — `--cleanup`'s contract is "the daemon is stopped," racing it against a starting daemon is
/// operator error, and the blast radius is only the socket inode (the running daemon keeps its open
/// fd and existing connections; only *new* LocalAPI clients fail to connect until the socket is
/// re-created by a restart/SIGHUP). No key/pref/data loss is possible. Go is stricter-than-us nowhere
/// here: it does not probe at all and operates unconditionally, so this probe is a safety addition.
async fn run_cleanup(socket_path: &Path) -> i32 {
    if !socket_path.exists() {
        println!(
            "cleanup: nothing to do (no socket at {})",
            socket_path.display()
        );
        return 0;
    }

    // Probe liveness: a successful connect means a daemon is accepting on the socket. Bound by a
    // short timeout so a wedged peer that accepts-but-never-responds (the connect still completes at
    // the OS level) doesn't matter — we only need the connect itself. A connect error (ECONNREFUSED
    // / ENOENT) means the socket file is stale (no listener), so it is safe to remove.
    let live = matches!(
        tokio::time::timeout(
            Duration::from_secs(2),
            tokio::net::UnixStream::connect(socket_path),
        )
        .await,
        Ok(Ok(_))
    );
    if live {
        eprintln!(
            "cleanup: a tailnetd appears to be running on {} — refusing to remove a live socket; \
             stop the daemon first",
            socket_path.display()
        );
        return 1;
    }

    // NB: this is the deliberately conservative sibling of `server::serve`'s socket removal, which
    // unlinks any pre-existing socket UNCONDITIONALLY (it is about to `bind`, so a leftover is
    // stale-to-it by definition). `--cleanup` must NOT yank a *different* live daemon's socket, hence
    // the liveness probe above gates this unlink. The asymmetry is intentional — do not "harmonize".
    match tokio::fs::remove_file(socket_path).await {
        Ok(()) => {
            println!("cleanup: removed stale socket {}", socket_path.display());
            0
        }
        // A race where the socket vanished between the probe and the unlink is still success.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            println!(
                "cleanup: nothing to do (no socket at {})",
                socket_path.display()
            );
            0
        }
        Err(e) => {
            eprintln!(
                "cleanup: failed to remove stale socket {}: {e}",
                socket_path.display()
            );
            1
        }
    }
}

/// Run the SOCKS5 proxy if `--socks5-server` was given, else an inert future that never resolves.
///
/// Returning a uniform `Result` future lets `main`'s `select!` treat the proxy as a peer of `serve`:
/// when configured, a bind/serve error ends the daemon (Go does the same — a requested proxy that
/// can't bind is a startup failure); when not configured, this is `pending()` and the arm never wins.
/// The proxy shares the backend handle and shuts down with the daemon (its own `shutdown_signal`).
async fn run_optional_socks5(
    listen: Option<String>,
    backend: Arc<Mutex<tailscaled_rs::ipn::Backend>>,
) -> anyhow::Result<()> {
    match listen {
        Some(addr) => tailscaled_rs::socks5::serve(&addr, backend, shutdown_signal()).await,
        // No proxy requested: never resolve, so this `select!` arm stays dormant for the daemon's life.
        None => std::future::pending().await,
    }
}

/// Run the outbound HTTP proxy if `--outbound-http-proxy-listen` was given, else an inert future.
/// Same uniform-`select!`-arm pattern as [`run_optional_socks5`].
async fn run_optional_http_proxy(
    listen: Option<String>,
    backend: Arc<Mutex<tailscaled_rs::ipn::Backend>>,
) -> anyhow::Result<()> {
    match listen {
        Some(addr) => tailscaled_rs::httpproxy::serve(&addr, backend, shutdown_signal()).await,
        None => std::future::pending().await,
    }
}

/// Run the debug HTTP server if `--debug` was given, else an inert future. Same uniform-`select!`-arm
/// pattern as [`run_optional_socks5`] — a bind/serve error ends the daemon (Go does the same); when
/// not configured, this is `pending()` and the arm never wins.
async fn run_optional_debug(
    listen: Option<String>,
    backend: Arc<Mutex<tailscaled_rs::ipn::Backend>>,
) -> anyhow::Result<()> {
    match listen {
        Some(addr) => tailscaled_rs::debugserver::serve(&addr, backend, shutdown_signal()).await,
        None => std::future::pending().await,
    }
}

/// Resolve when the process receives SIGINT or SIGTERM. **Deliberately not SIGHUP** — SIGHUP is a
/// reload, handled by [`sighup_reload_loop`], and must never end `serve` (that would drop a healthy
/// tunnel on a config re-read).
async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    // PROOF: `signal()` registration only fails on resource exhaustion (out of memory/fds) or for a
    // reserved signal already overridden by a non-default disposition; neither is reachable for
    // SIGINT/SIGTERM at daemon startup (first handler install, on a fresh process), so the expect is
    // safe — an early panic here is the correct response to an impossible-in-practice OS failure.
    let mut sigint = signal(SignalKind::interrupt()).expect("install SIGINT handler");
    let mut sigterm = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    tokio::select! {
        _ = sigint.recv() => tracing::info!("SIGINT received, shutting down"),
        _ = sigterm.recv() => tracing::info!("SIGTERM received, shutting down"),
    }
}

/// Notify systemd that the daemon is up, the analogue of Go `tailscaled`'s `systemd.Ready()` (and what
/// lets the unit move to `Type=notify`). Sends the `READY=1` datagram to the socket named by
/// `$NOTIFY_SOCKET` (the sd_notify protocol), implemented directly over `libc` — no `libsystemd`
/// dependency. A no-op (returns cleanly) when `$NOTIFY_SOCKET` is unset (foreground / non-systemd /
/// macOS) or on any send failure: readiness notification is best-effort telemetry, never a reason to
/// fail the daemon. Linux-only (the protocol is systemd-specific); a stub on other targets.
///
/// Call it once, AFTER the LocalAPI socket is bound and the backend has loaded + attempted auto-start
/// — i.e. the point the daemon can actually serve — so `Type=notify` start-up completes exactly when
/// the daemon is genuinely ready (not merely exec'd).
#[cfg(target_os = "linux")]
fn sd_notify_ready() {
    let Some(socket) = std::env::var_os("NOTIFY_SOCKET") else {
        return; // not run under systemd's notify protocol — nothing to do.
    };
    let path = std::path::Path::new(&socket);
    let (addr, addr_len) = match notify_socket_sockaddr(path.as_os_str().as_encoded_bytes()) {
        Some(pair) => pair,
        None => {
            tracing::debug!(
                "NOTIFY_SOCKET set but unusable (empty or too long); skipping sd_notify"
            );
            return;
        }
    };
    // SOCK_DGRAM AF_UNIX socket; CLOEXEC so it never leaks into the SSH/proxy subprocesses.
    // SAFETY: socket() with constant args; returns -1 on failure (checked).
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        tracing::debug!("sd_notify: socket() failed; skipping readiness notification");
        return;
    }
    const MSG: &[u8] = b"READY=1\n";
    // SAFETY: `addr` is a validly-initialized sockaddr_un of `addr_len` bytes (built by
    // `notify_socket_sockaddr`); MSG is a valid byte buffer; fd is the socket just opened. sendto on a
    // SOCK_DGRAM unix socket is connectionless — no prior connect needed. Return value is checked.
    let sent = unsafe {
        libc::sendto(
            fd,
            MSG.as_ptr() as *const libc::c_void,
            MSG.len(),
            0,
            &addr as *const libc::sockaddr_un as *const libc::sockaddr,
            addr_len,
        )
    };
    // SAFETY: fd is the socket we opened and have not closed; close once.
    unsafe { libc::close(fd) };
    if sent < 0 {
        tracing::debug!("sd_notify: sendto failed; readiness not delivered (non-fatal)");
    } else {
        tracing::info!("notified systemd: READY=1");
    }
}

/// Non-Linux stub: the sd_notify protocol is systemd-specific, so there is nothing to do on
/// macOS/other (launchd has its own readiness model). Kept so the call site is unconditional.
#[cfg(not(target_os = "linux"))]
fn sd_notify_ready() {}

/// Build the `sockaddr_un` (+ its valid length) for a `$NOTIFY_SOCKET` value. Pure — no syscalls — so
/// the address encoding (the fiddly part) is unit-testable. Returns `None` for an empty or too-long
/// path (`> sun_path`), which the caller treats as "skip the notify".
///
/// Two address forms, per the sd_notify protocol:
/// - **Abstract socket**: a value starting with `@` (or, historically, a NUL). The leading byte maps
///   to a NUL in `sun_path[0]`, and the *rest* of the name follows; the address length covers exactly
///   the used bytes (NUL + name), NOT the whole buffer, and the name is NOT NUL-terminated.
/// - **Filesystem path**: a normal path copied into `sun_path`, NUL-terminated; the length covers the
///   path + the terminating NUL.
#[cfg(target_os = "linux")]
fn notify_socket_sockaddr(value: &[u8]) -> Option<(libc::sockaddr_un, libc::socklen_t)> {
    if value.is_empty() {
        return None;
    }
    // SAFETY: an all-zero sockaddr_un is valid (AF_UNSPEC + empty path); we set the fields below.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    // The bytes we actually write into sun_path, and whether the first is the abstract-namespace NUL.
    let sun_path_len = addr.sun_path.len();
    // Base offset of sun_path within sockaddr_un, for the abstract-socket length computation.
    let base = {
        // offset_of is stable; compute the start of sun_path relative to the struct.
        std::mem::offset_of!(libc::sockaddr_un, sun_path)
    };
    if value[0] == b'@' || value[0] == 0 {
        // Abstract: sun_path[0] = NUL, then the remaining name bytes (skip the leading '@'/NUL marker).
        let name = &value[1..];
        // Need 1 (leading NUL) + name.len() bytes in sun_path; reject if it does not fit.
        if 1 + name.len() > sun_path_len {
            return None;
        }
        // sun_path[0] is already 0 (zeroed); copy the name after it. sun_path is c_char (i8) on Linux,
        // so cast each byte through u8→c_char.
        for (i, &b) in name.iter().enumerate() {
            addr.sun_path[1 + i] = b as libc::c_char;
        }
        // Length = base offset + 1 (NUL) + name length (NO trailing NUL for abstract sockets).
        let len = (base + 1 + name.len()) as libc::socklen_t;
        Some((addr, len))
    } else {
        // Filesystem path: copy + NUL-terminate; need value.len()+1 bytes in sun_path.
        if value.len() + 1 > sun_path_len {
            return None;
        }
        for (i, &b) in value.iter().enumerate() {
            addr.sun_path[i] = b as libc::c_char;
        }
        // sun_path[value.len()] stays 0 (the terminator, already zeroed).
        let len = (base + value.len() + 1) as libc::socklen_t;
        Some((addr, len))
    }
}

/// Handle `SIGHUP` as a **graceful reload** for as long as the daemon runs.
///
/// SIGHUP is the conventional "re-read your config" signal, and a reload must NOT tear down a
/// healthy engine: this loop never resolves under normal operation, so it can sit in a `tokio::select!`
/// arm beside `serve` without ever ending it (see `main`). On each SIGHUP it [`reconcile_on_reload`]s
/// the live backend against the persisted prefs on disk.
///
/// It returns (ending the loop) only if the SIGHUP handler cannot be installed — an unexpected,
/// process-fatal-ish condition we treat as "reload unsupported" rather than crashing the daemon; the
/// caller keeps serving.
async fn sighup_reload_loop(
    sighup: Option<tokio::signal::unix::Signal>,
    backend: Arc<Mutex<Backend>>,
    prefs_path: PathBuf,
) {
    // The handler was installed early in `main` (before the startup handshake) so SIGHUP can't kill
    // the daemon mid-boot. If installation failed there, reload is disabled — but we must still never
    // return (returning ends the `select!` arm); park forever so `serve` remains the only exit path.
    let Some(mut sighup) = sighup else {
        std::future::pending::<()>().await;
        unreachable!("pending() never resolves");
    };
    loop {
        if sighup.recv().await.is_none() {
            // The signal stream closed (shouldn't happen for SIGHUP) — stop reloading, keep serving.
            tracing::warn!("SIGHUP signal stream closed; reload disabled");
            return;
        }
        tracing::info!("SIGHUP: reloading");
        // Pass the shared `Arc<Mutex<Backend>>` (NOT a held guard): `reconcile_on_reload` must be
        // free to release the lock across the multi-second bring-up handshake, exactly like the
        // LocalAPI server, so a reload-triggered re-auth never head-of-line blocks concurrent
        // `status`/`down`. Holding the guard here (the previous design) reintroduced that stall.
        reconcile_on_reload(&backend, &prefs_path).await;
    }
}

/// Reconcile the live backend against the persisted prefs on disk after a SIGHUP.
///
/// ## What this does (the honest, non-destructive slice)
///
/// 1. Re-reads `prefs.json` from disk (the operator may have hand-edited it — the classic SIGHUP
///    use case) and reports any drift from the backend's in-memory intent.
/// 2. Re-evaluates **auto-start for a currently-down node**: if the intent is `want_running` and no
///    device is up, it re-runs [`auto_start`] (the same resume/auth-key path used at boot). A
///    transient registration failure that left the node down can thus be retried with `kill -HUP`.
/// 3. If a device is already up and the intent is still `want_running`, it is a **no-op** — a reload
///    must never churn a working tunnel.
///
/// ## Deliberate limitations (kept honest rather than half-built)
///
/// - **No teardown on SIGHUP.** If the persisted intent is *not* `want_running` while a device is
///   up, this does NOT bring the node down. Tearing a tunnel down is a destructive action that
///   belongs to an explicit `tnet down`, not a config re-read; doing it from SIGHUP would surprise
///   operators who HUP for an unrelated reason. (`bd` follow-up if a reload-driven down is ever
///   wanted.)
/// - **Out-of-band prefs edits are not pushed into the live engine config.** The engine's
///   construction config (hostname / control_url / ephemeral) is rebuilt from the backend's
///   *in-memory* [`Prefs`] inside the bring-up path → `build_config`. This crate does not own `ipn.rs`
///   and `Backend` exposes no primitive to replace its in-memory prefs from disk, so a SIGHUP cannot
///   adopt an out-of-band edit to those fields into a running engine. We DETECT the drift and warn;
///   fully applying it needs a minimal `Backend::reload_prefs(&mut self) -> Result<()>` added to
///   `ipn.rs` (which would re-`Prefs::load` into `self.prefs`). Filed as a follow-up there rather
///   than faking a partial reload across a file this crate doesn't own.
/// - **SIGHUP only retries a bring-up THIS process already attempted (`boot_attempted_up`).** It will
///   not *originate* a connection from a node that was never auto-started this run — so a stale or
///   hand-restored `prefs.json` flipped to `want_running=true` out-of-band does NOT cause a silent
///   rejoin on the next `kill -HUP`. The actionable case (a transient boot-time registration failure)
///   is retried; the surprising case (resurrecting a node the operator downed) is not.
///
/// Takes the shared `Arc<Mutex<Backend>>` rather than a held `&mut Backend` guard precisely so it can
/// **release the lock across the bring-up handshake** (via [`ipn::drive_up`]); holding the lock here
/// would block every concurrent `status`/`down` for the multi-second re-auth.
async fn reconcile_on_reload(backend: &Arc<Mutex<Backend>>, prefs_path: &std::path::Path) {
    // Re-read persisted prefs from disk. A read/parse error is non-fatal: log and keep the running
    // state untouched (a transient FS error must not knock a healthy node off).
    let disk = match Prefs::load(prefs_path).await {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, path = %prefs_path.display(),
                "SIGHUP reload: failed to re-read prefs; leaving running state unchanged");
            return;
        }
    };
    let disk_wants_running = disk.want_running && !disk.logged_out;

    // Snapshot the live view under a brief lock, then DROP it before any handshake.
    let (live_wants_running, device_up, boot_attempted_up, state) = {
        let be = backend.lock().await;
        let state = be.status().await.state;
        (
            be.wants_running(),
            matches!(state.as_str(), "Running" | "Starting"),
            be.boot_attempted_up(),
            state,
        )
    };

    // Surface drift between the on-disk intent and the backend's in-memory view. In normal operation
    // the daemon is the sole writer of prefs.json, so these agree; a disagreement means an
    // out-of-band edit, which we can detect+report but not fully adopt (see the doc note above).
    if disk_wants_running != live_wants_running {
        tracing::warn!(
            disk_want_running = disk_wants_running,
            live_want_running = live_wants_running,
            "SIGHUP reload: on-disk intent differs from the live backend (an out-of-band prefs \
             edit); config-field edits (hostname/control_url/ephemeral) cannot be adopted into a \
             running engine without an ipn.rs reload_prefs primitive, and a reload will NOT \
             originate a connection from an out-of-band intent flip — see reconcile_on_reload docs"
        );
    }

    if !live_wants_running {
        // Intent is down. We deliberately do not tear a device down from SIGHUP (see doc note).
        tracing::info!(state = %state,
            "SIGHUP reload: intent is not 'want_running'; nothing to start (no teardown on reload)");
        return;
    }
    if device_up {
        // Healthy tunnel + still-up intent → leave it. Do NOT churn on a reload.
        tracing::info!(state = %state, "SIGHUP reload: intent is up and a device is running; no-op");
        return;
    }
    if !boot_attempted_up {
        // Intent says up, nothing is running, and THIS process never attempted to bring it up — so
        // the "up" intent arrived out-of-band (stale/hand-edited prefs). Do not silently resurrect a
        // node the operator may have intentionally downed; require an explicit `tnet up`.
        tracing::warn!(state = %state,
            "SIGHUP reload: on-disk intent is up but this process never auto-started the node \
             (likely an out-of-band prefs edit); NOT auto-starting — run `tnet up` to bring it up");
        return;
    }
    // Intent is up, nothing is running, and we DID attempt bring-up at boot (it failed transiently,
    // e.g. control was unreachable) → retry the same resume/auth-key path, OFF-LOCK via drive_up.
    tracing::info!(state = %state,
        "SIGHUP reload: intent is up but no device is running; retrying auto-start (off-lock)");
    auto_start_arc(backend).await;
}

/// Bring the node up iff the persisted intent is "up", picking resume-vs-fresh-auth from the
/// available key material. Shared by the boot path and the SIGHUP reload so the resume logic lives
/// in exactly one place.
///
/// A real daemon should *resume* from its persisted node key on reboot, the way `tailscaled`
/// does: it re-`POST`s `/machine/register` with the node key it already holds and, for a node
/// control still recognizes as authorized, comes straight back up with NO auth key. The engine
/// does exactly this — `Device::new(cfg, None)` → `check_auth`/`register` send the persisted
/// `node_key` and simply omit the `auth` field when there is no key (see
/// `ts_control::tokio::register`). So an auth key must only be required when there is *no* usable
/// persisted key (first run, or the key was expired/GC'd by control), not on every boot.
///
/// Path selection (highest-priority match wins):
///
/// - persisted key present AND no `TS_AUTH_KEY` → RESUME (`up(None, ..)`).
/// - `TS_AUTH_KEY` set → FRESH AUTH (env key wins; covers first run and deliberate re-pair / key
///   rotation).
/// - no persisted key AND no `TS_AUTH_KEY` → nothing to resume from and no key to auth with; still
///   attempt `up(None, ..)` so the engine yields the authoritative needs-login state, not a guess.
async fn auto_start(backend: &mut Backend, config_authkey: Option<secrecy::SecretString>) {
    if !backend.wants_running() {
        return;
    }
    // Record that THIS process attempted a bring-up. The SIGHUP path consults this so it only
    // *retries* a boot we already attempted (a transient failure), never *originates* a connection
    // from an out-of-band intent flip.
    backend.mark_boot_attempted_up();

    // Registration credential precedence: a `--config` auth key (the explicit declarative source for
    // a config-driven boot) wins over `TS_AUTH_KEY`; either is a fresh-auth key that beats resume.
    let explicit_authkey = config_authkey.or_else(env_authkey);
    let has_key = backend.has_persisted_node_key().await;
    let (authkey, resuming) = resume_decision(has_key, explicit_authkey);
    log_resume_decision(resuming, authkey.is_some(), backend.prefs_ephemeral());

    // Auto-start uses persisted prefs as-is (no overrides) — TUN/hostname/control-url all come from
    // the stored prefs the user set via `tnet up`, not from the boot path. No external lock is held
    // at boot (this runs before `serve`), so the inline `up` is fine here.
    match backend.up(authkey, ipn::UpOptions::default()).await {
        // Boot success was previously silent — log it so an operator tailing the log sees the node
        // came up at boot (the node then converges to Running once the netmap arrives).
        Ok(()) => tracing::info!("auto-start: node is up"),
        Err(e) => {
            // Non-fatal: come up in a needs-login/stopped state and let the CLI drive `up`. Append the
            // resulting state so the warn says *what* state we're awaiting `up` from (e.g. NeedsLogin).
            let state = backend.status().await.state;
            tracing::warn!(
                error = %format!("{e:#}"),
                state = %state,
                "auto-start failed; awaiting `tnet up`"
            );
        }
    }
}

/// SIGHUP-path counterpart to [`auto_start`] that runs against the shared `Arc<Mutex<Backend>>` and
/// drives the bring-up **off-lock** via [`ipn::drive_up`], so a reload-triggered re-auth never
/// head-of-line blocks concurrent `status`/`down`. The caller ([`reconcile_on_reload`]) has already
/// established that the intent is up, no device is running, and this process attempted bring-up at
/// boot (`boot_attempted_up`); this fn re-reads the key material under a brief lock, then handshakes
/// unlocked.
async fn auto_start_arc(backend: &Arc<Mutex<Backend>>) {
    let env_authkey = env_authkey();
    // Brief lock to read the resume inputs; released before the handshake.
    let (has_key, ephemeral) = {
        let be = backend.lock().await;
        (be.has_persisted_node_key().await, be.prefs_ephemeral())
    };
    let (authkey, resuming) = resume_decision(has_key, env_authkey);
    log_resume_decision(resuming, authkey.is_some(), ephemeral);

    // The SIGHUP reload resume carries no workload-identity creds (it resumes from the persisted key
    // or the env auth key) → `None`.
    if let Err(e) = ipn::drive_up(backend, authkey, None, ipn::UpOptions::default()).await {
        tracing::warn!(error = %format!("{e:#}"), "SIGHUP auto-start retry failed; awaiting `tnet up`");
    }
}

/// Read `TS_AUTH_KEY` as a `SecretString` (never logged), treating a set-but-empty value as absent
/// (matching the CLI's guard) so an empty `TS_AUTH_KEY` doesn't masquerade as a real key.
fn env_authkey() -> Option<secrecy::SecretString> {
    tailscale::config::auth_key_from_env()
        .filter(|k| !k.is_empty())
        .map(secrecy::SecretString::from)
}

/// The resume-vs-fresh-auth decision, pure so it is unit-testable without an engine.
///
/// Returns `(authkey_to_use, resuming)`. We resume (no key) only when a persisted node key exists
/// AND no env key was provided; otherwise the env key (possibly `None`) governs. An explicit
/// `TS_AUTH_KEY` always wins, so an operator can force re-auth / rotate. With neither a persisted key
/// nor an env key, we still attempt `up(None)` so the engine yields the authoritative needs-login
/// state rather than the daemon guessing.
fn resume_decision(
    has_persisted_key: bool,
    env_authkey: Option<secrecy::SecretString>,
) -> (Option<secrecy::SecretString>, bool) {
    if has_persisted_key && env_authkey.is_none() {
        (None, true)
    } else {
        (env_authkey, false)
    }
}

/// Emit the operator-facing log line explaining which auth path the bring-up took. Split out so both
/// [`auto_start`] and [`auto_start_arc`] log identically.
fn log_resume_decision(resuming: bool, have_authkey: bool, ephemeral: bool) {
    if resuming {
        tracing::info!(
            "persisted intent is up and a persisted node key exists; \
             resuming registration without an auth key"
        );
        // Honest caveat: an ephemeral node (the default — see `ipn::Backend::build_config`) is
        // garbage-collected by control shortly after it disconnects, so its persisted key may
        // already be invalid after a reboot and this resume can still fail at registration. A
        // node meant to survive reboots and resume from its key alone needs `ephemeral = false`.
        if ephemeral {
            tracing::warn!(
                "node is configured ephemeral; control may have garbage-collected it after \
                 its last disconnect, so resume-without-authkey may fail — a node that must \
                 survive reboots needs ephemeral=false (or pass TS_AUTH_KEY to re-register)"
            );
        }
    } else if have_authkey {
        tracing::info!("persisted intent is up; auto-starting with TS_AUTH_KEY (fresh auth)");
    } else {
        // No key to resume from and none provided — surface why so the operator can act.
        tracing::warn!(
            "persisted intent is up but there is no persisted node key and no TS_AUTH_KEY; \
             cannot resume or authenticate — set TS_AUTH_KEY (or run `tnet up`) to register"
        );
    }
}

/// The `--bird-socket` refusal decision and its message, pure so it can be unit-tested.
///
/// Ported from Go `cmd/tailscaled/tailscaled.go` @ `53a0d659afa51835dd7a9283873cca44261454f8`,
/// which registers the flag and then fatals early when the build carries no BIRD hook:
///
/// ```text
/// if buildfeatures.HasBird && args.birdSocketPath != "" && !wgengine.HookNewBird.IsSet() {
///     log.SetFlags(0)
///     log.Fatalf("--bird-socket is not supported on %s", runtime.GOOS)
/// }
/// ```
///
/// This fork is permanently in that "no hook linked in" case, so the refusal is unconditional —
/// but it names the real reason (no BIRD integration in the engine) rather than blaming the OS,
/// because unlike Go's the gap here is not platform-specific.
///
/// One Go edge case ports with it: the empty path is **not** a refusal. Go's guard is
/// `birdSocketPath != ""`, so `--bird-socket=""` means "no BIRD socket" exactly like omitting the
/// flag — hence `Some("")` maps to `None` here, and the daemon starts normally.
///
/// Returns `None` when there is nothing to refuse, else the operator-facing message.
fn bird_socket_refusal(path: Option<&str>) -> Option<String> {
    // Go: `args.birdSocketPath != ""` — an unset *or* explicitly empty path is "no BIRD socket".
    let path = path.filter(|p| !p.is_empty())?;
    Some(format!(
        "error: --bird-socket is not supported by tailnetd (given {path:?}).\n\
         Go accepts this flag for a subnet router that hands its advertised routes to a BIRD BGP \
         daemon: it passes the socket path to its engine (`wgengine.Config.BIRDSocket`, built via \
         `wgengine.HookNewBird`), which enables BIRD's `tailscale` protocol while this node is a \
         primary subnet router and disables it otherwise.\n\
         That toggle belongs to the engine's reconfigure cycle, which this daemon does not own, and \
         the tailscale-rs engine exposes no BIRD hook — so there is nothing here to hand the socket \
         to. tailnetd therefore refuses at startup, the way Go refuses on a build with no BIRD hook, \
         instead of accepting the flag as a no-op: a silently ignored --bird-socket would leave a \
         subnet router believing its BGP announcements track its primary-route status when nothing \
         was ever connected to BIRD.\n\
         Drop the flag to start tailnetd. Routes are still advertised to the tailnet with `tnet up \
         --advertise-routes=<prefix,...>`; driving BIRD from that state needs a BIRD hook in the \
         engine, and is out of scope here until it has one."
    ))
}

/// This host's OS in Go's `runtime.GOOS` spelling, so a message ported from Go names the platform
/// the way Go's `%s` of `runtime.GOOS` would. Rust spells macOS `"macos"`; every other target this
/// daemon builds for already agrees with Go.
fn goos() -> &'static str {
    match std::env::consts::OS {
        "macos" => "darwin",
        other => other,
    }
}

/// Go `strconv.ParseBool` — the parser behind `cmd/tailscaled`'s `boolFlag.Set`
/// (`cmd/tailscaled/flag.go` @ `53a0d659afa51835dd7a9283873cca44261454f8`).
///
/// Accepts exactly Go's twelve spellings and nothing else, so `--encrypt-state=yes` is refused here
/// the way `tailscaled` refuses it instead of being accepted — or, worse, read as false — by a
/// looser parser. The message is Go's own `strconv` error, which is what `boolFlag.Set` returns and
/// Go's `flag` package prints back to the operator.
fn parse_go_bool(s: &str) -> Result<bool, String> {
    match s {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Ok(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Ok(false),
        _ => Err(format!("strconv.ParseBool: parsing {s:?}: invalid syntax")),
    }
}

/// Whether hardware attestation could be enabled here — Go `canUseHardwareAttestation`
/// (`cmd/tailscaled/tailscaled.go` @ `53a0d659afa51835dd7a9283873cca44261454f8`).
///
/// Go's first test is `key.NewEmptyHardwareAttestationKey() == key.ErrUnsupported`: does this
/// platform *and this build* have a hardware-attestation key type at all. This fork is permanently
/// on that branch — neither the daemon nor the `tailscale-rs` engine has a hardware key store — so
/// the answer is always no, and the error is Go's sentence with this binary's name in it.
///
/// Go's second test has nothing to port to: it refuses the flag against a **portable** state store
/// (`kube:`, `arn:`) because a TPM-bound key cannot be migrated to another machine. `tailnetd` has
/// no `--state` flag and no state-store providers, so every state path it can have is the local file
/// store Go's `isPortableStore` reports as non-portable, and the refusal is unreachable. It lands
/// the day a provider-prefixed `--state` does.
///
/// `Err` carries the short Go-shaped sentence; the callers decide whether it becomes a fatal
/// refusal (an explicit flag) or a log line (a policy that asked for it).
fn can_use_hardware_attestation() -> Result<(), String> {
    Err(
        "--hardware-attestation is not supported on this platform or in this build of tailnetd"
            .to_string(),
    )
}

/// Whether state-at-rest encryption could be enabled here — Go `canEncryptState`
/// (`cmd/tailscaled/tailscaled.go` @ `53a0d659afa51835dd7a9283873cca44261454f8`).
///
/// Go's three tests, in order:
///
/// 1. `runtime.GOOS` is neither `windows` nor `linux` → `--encrypt-state is not supported on %s`.
///    Ported verbatim: it is exactly as true of this fork as it is of Go, so an operator on macOS
///    gets Go's own sentence.
/// 2. `!feature.TPMAvailable()` → Go blames the device. Here the cause is the *build* — there is no
///    TPM code to be available — so the sentence keeps Go's shape and names the honest reason.
/// 3. `--state` carries a known provider prefix → `--encrypt-state can only be used with --state set
///    to a local file path`. Unreachable for the same reason as the portable-store refusal in
///    [`can_use_hardware_attestation`]: there is no `--state` flag and no provider prefixes.
///
/// `goos` is Go's `runtime.GOOS` spelling (pass [`goos()`]), taken as a parameter so the
/// platform-specific arm is testable on any host.
fn can_encrypt_state(goos: &str) -> Result<(), String> {
    // Go: TPM encryption is only configurable on Windows and Linux; other platforms either use
    // system APIs and are not configurable (Android/Apple) or support no encryption at all.
    if goos != "windows" && goos != "linux" {
        return Err(format!("--encrypt-state is not supported on {goos}"));
    }
    Err("--encrypt-state is not supported on this device or in this build of tailnetd".to_string())
}

/// The **explicit-flag** half of Go's `handleTPMFlags` — its two `case args.X.v:` arms, which fire
/// when a flag was set *and* set to true, validate it, and `log.SetFlags(0)` + `log.Fatal(err)` when
/// it cannot be honoured. Pure so it can be unit-tested; returns `None` when there is nothing to
/// refuse, else the operator-facing message the caller prints before `exit(1)`.
///
/// The tri-state matters and is Go's: `--hardware-attestation=false` matches **neither** arm of Go's
/// switch (the first needs `.v`, the second needs `!.set`), so an explicit "off" is inert and is not
/// even validated. Only `None` — the flag omitted — reaches the policy half,
/// [`tpm_policy_notices`].
///
/// Hardware attestation is checked before state encryption, which is Go's order: with both flags
/// explicitly on, the attestation refusal is the one the operator sees.
///
/// Go runs both halves from one `handleTPMFlags()` call. This fork splits them because their
/// preconditions differ: this half needs nothing but the command line, so it runs early — before
/// `--cleanup` and before the experiment gate, exactly where the `--bird-socket` refusal runs and
/// for the same reason (an operator who asked for a feature that does not exist should be told
/// that, not told about an unrelated environment variable, and `--cleanup` must not quietly swallow
/// the refusal — Go refuses ahead of its own cleanup too). The policy half needs the syspolicy file
/// loaded and the logger up, so it runs where those exist.
fn explicit_tpm_flag_refusal(
    encrypt_state: Option<bool>,
    hardware_attestation: Option<bool>,
    goos: &str,
) -> Option<String> {
    // Go: `case args.hardwareAttestation.v:` — set AND true.
    if hardware_attestation == Some(true)
        && let Err(e) = can_use_hardware_attestation()
    {
        return Some(format!(
            "error: {e}.\n\
                 Go uses this flag to bind the node identity to a hardware-backed key — TPM 2.0 on \
                 Linux and Windows, the Secure Enclave on macOS and iOS, Keystore on Android — and \
                 then marks the node hardware-attested to its backend.\n\
                 This fork has no hardware key store: the node key is generated and held by the \
                 tailscale-rs engine and persisted as an ordinary file under the 0700 state dir \
                 (docs/THREAT_MODEL.md records that as a trust boundary). With no attestation key \
                 there is nothing to bind an identity to and nothing to report as attested, so \
                 tailnetd refuses instead of accepting the flag as a no-op: a silently ignored \
                 --hardware-attestation would leave an operator believing this node's identity is \
                 sealed to this machine, when the key is a file that copies to any other machine.\n\
                 Drop the flag to start tailnetd. Hardware-bound node identity is out of scope \
                 until there is a platform key store to bind to — see docs/DESIGN.md."
        ));
    }
    // Go: `case args.encryptState.v:` — "explicitly enabled, validate".
    if encrypt_state == Some(true)
        && let Err(e) = can_encrypt_state(goos)
    {
        return Some(format!(
            "error: {e}.\n\
                 Go encrypts the state file at rest by sealing it to the device's TPM (Linux and \
                 Windows only), prefixing the state path with `tpm:` so the state store seals and \
                 unseals through the TPM, and enables that by itself when the flag is unset and the \
                 platform supports it.\n\
                 tailnetd has no state-store provider layer and no TPM or keystore integration: \
                 prefs and the node key are written as plain JSON under a 0700 state dir, protected \
                 by filesystem permissions and best-effort process hardening (mlockall + coredump \
                 suppression), not by a key. docs/THREAT_MODEL.md records that as a trust boundary, \
                 and refusing here is what keeps it honest — accepting --encrypt-state as a no-op \
                 would claim at-rest protection this build does not provide.\n\
                 Drop the flag to start tailnetd. State-at-rest encryption is out of scope until \
                 there is a platform key store to seal to — see docs/DESIGN.md."
        ));
    }
    None
}

/// The **system-policy** half of Go's `handleTPMFlags` — its two `case !args.X.set:` arms, which
/// fire when the flag was omitted, read the matching policy key, and default the flag from it *if*
/// the device can honour it.
///
/// In this fork neither [`can_use_hardware_attestation`] nor [`can_encrypt_state`] can succeed, so
/// Go's "default it on" branches are unreachable: both features stay off no matter what the policy
/// says, and nothing downstream consumes a resolved value. What is left is the reporting Go does on
/// the way past, which is the whole point of running this at all — an admin who wrote
/// `{"HardwareAttestation": true}` into `--syspolicy-file` must not be left thinking it took effect.
///
/// Returns the lines to log, in Go's order (hardware attestation first). Two of them:
///
/// * `[unexpected] policy requires hardware attestation, but device does not support it: …` — Go's,
///   verbatim, including its `[unexpected]` prefix.
/// * A **fork addition** for `EncryptState`. Go stays silent there: its `case !args.encryptState.set`
///   arm just leaves encryption off when `canEncryptState` fails, because on a Go build the operator
///   can usually fix the device. Here the gap is permanent, so silence would leave `EncryptState`
///   sitting in a policy file looking effective forever. The wording is deliberately not Go's, so
///   nobody mistakes an addition for a port.
///
/// `policy_boolean` reads a boolean policy key (pass a closure over
/// [`ipn::syspolicy::get_boolean`]); it is a parameter both so the branch stays testable without a
/// registered policy source and so the read stays *lazy*, as Go's is — a flag that was set never
/// consults the policy at all.
fn tpm_policy_notices(
    encrypt_state: Option<bool>,
    hardware_attestation: Option<bool>,
    policy_boolean: impl Fn(&str) -> bool,
    goos: &str,
) -> Vec<String> {
    let mut notices = Vec::new();
    // Go: `case !args.hardwareAttestation.set:`, whose `canUseHardwareAttestation` error branch then
    // sets `args.hardwareAttestation.v = false` — off, which is the only value this fork can reach,
    // and which nothing here consumes. The `&&` chain keeps the policy read lazy, as Go's is.
    if hardware_attestation.is_none()
        && let Err(e) = can_use_hardware_attestation()
        && policy_boolean(ipn::syspolicy::PKEY_HARDWARE_ATTESTATION)
    {
        notices.push(format!(
            "[unexpected] policy requires hardware attestation, but device does not support it: {e}"
        ));
    }
    // Go: `case !args.encryptState.set:` — where Go stays silent (see the doc comment above).
    if encrypt_state.is_none()
        && let Err(e) = can_encrypt_state(goos)
        && policy_boolean(ipn::syspolicy::PKEY_ENCRYPT_STATE)
    {
        notices.push(format!(
            "policy sets {}, but state-at-rest encryption is not available here, so the state file \
             stays unencrypted: {e}",
            ipn::syspolicy::PKEY_ENCRYPT_STATE
        ));
    }
    notices
}

/// The stock `--syspolicy-file` path for **this host** — Go `defaultSyspolicyFile`
/// (`cmd/tailscaled/syspolicy.go`). Thin wrapper over [`default_syspolicy_file_for`] so the decision
/// itself stays testable on any platform.
fn default_syspolicy_file() -> String {
    default_syspolicy_file_for(cfg!(windows), std::env::var("ProgramData").ok().as_deref())
}

/// Where `--syspolicy-file` points when the operator does not say — Go's `defaultSyspolicyFile`,
/// with the host facts passed in rather than read from the environment.
///
/// On Windows the file sits with the rest of Tailscale's machine state under
/// `%ProgramData%\Tailscale`; if `ProgramData` is somehow unset Go returns the **empty string**,
/// which disables the source rather than guessing a path — so that case ports too. Everywhere else
/// (Linux, the BSDs, illumos/Solaris, and a GUI-less macOS daemon) it is `/etc/tailscale`, the
/// conventional home for admin-provided configuration.
///
/// Note that the default naming a file that does not exist is the *normal* case: an absent policy
/// file is simply no policy (see `syspolicy::load_json_policy_file`), which is what makes it safe to
/// point at a path the operator has never created. Pure → unit-testable.
fn default_syspolicy_file_for(windows: bool, program_data: Option<&str>) -> String {
    if windows {
        return match program_data.filter(|pd| !pd.is_empty()) {
            Some(pd) => Path::new(pd)
                .join("Tailscale")
                .join("syspolicy.json")
                .to_string_lossy()
                .into_owned(),
            // Go returns "" here, and an empty value disables the source.
            None => String::new(),
        };
    }
    "/etc/tailscale/syspolicy.json".to_string()
}

/// Register `--syspolicy-file` as a device-scope policy source — the body of Go's `loadSyspolicy`
/// hook in `cmd/tailscaled/syspolicy.go`, which runs once after flag parsing and before anything
/// reads a policy setting.
///
/// Three behaviours port together, and each of them is the point:
/// - **empty path disables it.** Go's hook returns immediately on `syspolicyFile == ""`, so
///   `--syspolicy-file=""` is how an operator turns the file source off entirely (including on a
///   Windows host with no `ProgramData`, whose default is already empty).
/// - **an absent file is silent.** Not an error, no source registered — the shipped default path
///   exists on almost no host.
/// - **a load failure is logged and the daemon continues.** Go's hook is
///   `if err := ...; err != nil { log.Printf("%v", err) }` — deliberately not `log.Fatal`. A policy
///   file with a typo in it must not be able to keep a node off the tailnet, so the error is
///   reported and startup proceeds with the source unregistered (all of it, never half of it).
fn load_syspolicy_file(path: &str) {
    if path.is_empty() {
        tracing::debug!("--syspolicy-file is empty; the file policy source is disabled");
        return;
    }
    match ipn::syspolicy::load_json_policy_file(
        ipn::syspolicy::JSON_FILE_SOURCE_NAME,
        Path::new(path),
    ) {
        Ok(ipn::syspolicy::LoadOutcome::NoFile) => {
            tracing::debug!(
                path,
                "no system-policy file; the file policy source is inactive"
            );
        }
        Ok(ipn::syspolicy::LoadOutcome::Registered { settings }) => {
            tracing::info!(path, settings, "registered the system-policy file");
        }
        // Go: `log.Printf("%v", err)` — report it, keep going.
        Err(e) => tracing::error!("{e}"),
    }
}

/// The experimental-gate decision, pure so it can be unit-tested: the gate passes only when the
/// env var holds exactly the required opt-in value. `None` (unset) and any other value fail.
fn experiment_gate_ok(value: Option<&str>) -> bool {
    value == Some(REQUIRED_EXPERIMENT_VALUE)
}

/// Map a numeric `--verbose` level to a `tracing` env-filter directive (Go's numeric verbosity →
/// our level-based filter). `0` = `info` (the default), `1` = `debug`, `2` or higher = `trace` (the
/// most verbose level `tracing` has — Go's higher integers just mean "even more", which saturates
/// here). Pure → unit-testable.
fn verbose_to_level(level: u8) -> &'static str {
    match level {
        0 => "info",
        1 => "debug",
        _ => "trace",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syspolicy_file_defaults_to_the_unix_admin_config_path() {
        // Go's non-Windows branch is a literal, and it is the path an admin is told to create.
        assert_eq!(
            default_syspolicy_file_for(false, None),
            "/etc/tailscale/syspolicy.json"
        );
        // `ProgramData` is a Windows notion; it must not leak into the Unix default.
        assert_eq!(
            default_syspolicy_file_for(false, Some("C:\\ProgramData")),
            "/etc/tailscale/syspolicy.json"
        );
    }

    #[test]
    fn syspolicy_file_defaults_under_program_data_on_windows() {
        let resolved = default_syspolicy_file_for(true, Some("C:\\ProgramData"));
        // Asserted by parts rather than as one literal: the separator `Path::join` produces depends
        // on the host running the test, and only the placement is Go's contract.
        assert!(
            resolved.starts_with("C:\\ProgramData"),
            "the file belongs under %ProgramData%: {resolved}"
        );
        assert!(
            resolved.contains("Tailscale"),
            "the file sits in the Tailscale machine-state directory: {resolved}"
        );
        assert!(
            resolved.ends_with("syspolicy.json"),
            "the file is named syspolicy.json: {resolved}"
        );
    }

    #[test]
    fn syspolicy_file_default_is_empty_when_windows_has_no_program_data() {
        // Go returns "" rather than guessing a path, and an empty value disables the source — so a
        // Windows host with no ProgramData starts with no file policy instead of reading a wrong
        // file. An empty variable is the same case as an unset one.
        assert_eq!(default_syspolicy_file_for(true, None), "");
        assert_eq!(default_syspolicy_file_for(true, Some("")), "");
    }

    #[test]
    fn experiment_gate_rejects_unset() {
        assert!(!experiment_gate_ok(None));
    }

    #[test]
    fn experiment_gate_rejects_wrong_value() {
        assert!(!experiment_gate_ok(Some("")));
        assert!(!experiment_gate_ok(Some("yes")));
        assert!(!experiment_gate_ok(Some("this_is_unstable_software ")));
    }

    #[test]
    fn experiment_gate_accepts_exact_value() {
        assert!(experiment_gate_ok(Some(REQUIRED_EXPERIMENT_VALUE)));
        assert!(experiment_gate_ok(Some("this_is_unstable_software")));
    }

    // sd_notify address encoding (Linux-only — the helper is cfg(linux)). Validates the two
    // $NOTIFY_SOCKET forms: a filesystem path (NUL-terminated in sun_path) and an abstract socket
    // (leading '@' → NUL first byte, name follows, NO trailing NUL). The byte math (offsets + lengths)
    // is the bug-prone part, so pin it.
    #[cfg(target_os = "linux")]
    #[test]
    fn notify_socket_sockaddr_encodes_path_and_abstract() {
        let base = std::mem::offset_of!(libc::sockaddr_un, sun_path);

        // Filesystem path: "/run/systemd/notify" → sun_path holds the bytes + a terminating NUL;
        // len = base + path.len() + 1.
        let path = b"/run/systemd/notify";
        let (addr, len) = notify_socket_sockaddr(path).expect("path form must encode");
        assert_eq!(addr.sun_family, libc::AF_UNIX as libc::sa_family_t);
        assert_eq!(
            len as usize,
            base + path.len() + 1,
            "path len = base + path + NUL"
        );
        // sun_path starts with the path bytes and is NUL-terminated at [path.len()].
        for (i, &b) in path.iter().enumerate() {
            assert_eq!(addr.sun_path[i] as u8, b);
        }
        assert_eq!(
            addr.sun_path[path.len()] as u8,
            0,
            "path must be NUL-terminated"
        );

        // Abstract socket: "@/org/freedesktop/...": sun_path[0] = NUL, then the name AFTER the '@';
        // len = base + 1 + name.len() with NO trailing NUL.
        let abs = b"@abstractname";
        let name = &abs[1..]; // "abstractname"
        let (addr, len) = notify_socket_sockaddr(abs).expect("abstract form must encode");
        assert_eq!(
            len as usize,
            base + 1 + name.len(),
            "abstract len = base + NUL + name"
        );
        assert_eq!(
            addr.sun_path[0] as u8, 0,
            "abstract sockets lead with a NUL in sun_path"
        );
        for (i, &b) in name.iter().enumerate() {
            assert_eq!(
                addr.sun_path[1 + i] as u8,
                b,
                "name follows the leading NUL"
            );
        }

        // Empty → None (nothing to notify).
        assert!(notify_socket_sockaddr(b"").is_none());

        // Too long for sun_path → None (rejected, not truncated). sun_path is ~108 bytes on Linux.
        let too_long = vec![b'x'; 4096];
        assert!(notify_socket_sockaddr(&too_long).is_none());
    }

    // `resume_decision` is the resume-vs-fresh-auth path selection shared by the boot and SIGHUP
    // auto-start paths. It is pure, so the four quadrants are table-testable without an engine — and
    // a regression here (e.g. inverting the priority so the env key loses to a persisted key) would
    // otherwise be invisible. `secrecy::SecretString` has no value-equality, so we assert on
    // `is_some()` + the `resuming` flag, which fully characterizes the decision.
    fn sk(s: &str) -> secrecy::SecretString {
        secrecy::SecretString::from(s.to_owned())
    }

    #[test]
    fn resume_decision_persisted_key_no_env_resumes() {
        // Persisted key, no env key → resume with NO auth key.
        let (key, resuming) = resume_decision(true, None);
        assert!(resuming);
        assert!(key.is_none());
    }

    #[test]
    fn resume_decision_env_key_always_wins() {
        // Env key present → fresh auth, even when a persisted key also exists (operator forcing a
        // re-pair / rotation must win over resume).
        let (key, resuming) = resume_decision(true, Some(sk("tskey-auth-x")));
        assert!(!resuming);
        assert!(key.is_some());

        let (key, resuming) = resume_decision(false, Some(sk("tskey-auth-x")));
        assert!(!resuming);
        assert!(key.is_some());
    }

    #[test]
    fn resume_decision_no_key_no_env_attempts_unauthed() {
        // Neither a persisted key nor an env key → not "resuming", and no key to send; the daemon
        // still attempts `up(None)` so the engine yields the authoritative needs-login state.
        let (key, resuming) = resume_decision(false, None);
        assert!(!resuming);
        assert!(key.is_none());
    }

    #[test]
    fn verbose_to_level_maps_go_verbosity() {
        // 0 = info (default), 1 = debug, 2+ saturates at trace (the most verbose tracing level).
        assert_eq!(verbose_to_level(0), "info");
        assert_eq!(verbose_to_level(1), "debug");
        assert_eq!(verbose_to_level(2), "trace");
        assert_eq!(verbose_to_level(9), "trace");
    }

    #[test]
    fn args_parse_flags_and_defaults() {
        use clap::Parser;
        // All flags omitted → every override is None (env/default resolution stands).
        let a = Args::parse_from(["tailnetd"]);
        assert!(a.statedir.is_none() && a.socket.is_none() && a.verbose.is_none());
        // Flags parse to their override values.
        let a = Args::parse_from([
            "tailnetd",
            "--statedir",
            "/var/lib/x",
            "--socket",
            "/run/x.sock",
            "--verbose",
            "2",
        ]);
        assert_eq!(
            a.statedir.as_deref(),
            Some(std::path::Path::new("/var/lib/x"))
        );
        assert_eq!(
            a.socket.as_deref(),
            Some(std::path::Path::new("/run/x.sock"))
        );
        assert_eq!(a.verbose, Some(2));
        // `-v` short form works too.
        assert_eq!(Args::parse_from(["tailnetd", "-v", "1"]).verbose, Some(1));
        // The lifecycle bool flags default off and parse on when given.
        let a = Args::parse_from(["tailnetd"]);
        assert!(!a.cleanup && !a.no_logs_no_support);
        let a = Args::parse_from(["tailnetd", "--cleanup", "--no-logs-no-support"]);
        assert!(a.cleanup && a.no_logs_no_support);
        // `--debug [host:]port` (Go `tailscaled --debug`): None by default, the value when given.
        assert!(Args::parse_from(["tailnetd"]).debug.is_none());
        assert_eq!(
            Args::parse_from(["tailnetd", "--debug", "9090"])
                .debug
                .as_deref(),
            Some("9090")
        );
    }

    // --- `--bird-socket` (Go `tailscaled --bird-socket`) ---------------------------------------
    //
    // Go registers the flag and then fatals when the build has no BIRD hook linked in. This fork is
    // permanently in that case, so the three things worth pinning are: the flag PARSES (a Go-shaped
    // command line must reach the refusal, not clap's "unexpected argument"), an omitted or empty
    // path is NOT a refusal (Go's guard is `birdSocketPath != ""`), and a real path IS refused with
    // a message that says why.

    #[test]
    fn bird_socket_flag_parses_rather_than_being_an_unknown_argument() {
        use clap::Parser;
        // Absent → None (nothing to refuse).
        assert!(Args::parse_from(["tailnetd"]).bird_socket.is_none());
        // Present → the path, in both `--flag value` and `--flag=value` spellings.
        assert_eq!(
            Args::parse_from(["tailnetd", "--bird-socket", "/run/bird.ctl"])
                .bird_socket
                .as_deref(),
            Some("/run/bird.ctl")
        );
        assert_eq!(
            Args::parse_from(["tailnetd", "--bird-socket=/run/bird.ctl"])
                .bird_socket
                .as_deref(),
            Some("/run/bird.ctl")
        );
        // The empty path parses too (Go's flag is a plain string) — `bird_socket_refusal` is what
        // decides that it means "no BIRD socket".
        assert_eq!(
            Args::parse_from(["tailnetd", "--bird-socket="])
                .bird_socket
                .as_deref(),
            Some("")
        );
    }

    #[test]
    fn bird_socket_absent_or_empty_is_not_a_refusal() {
        // Omitted: nothing to refuse.
        assert_eq!(bird_socket_refusal(None), None);
        // Explicitly empty: Go tests `args.birdSocketPath != ""`, so `--bird-socket=""` is "no BIRD
        // socket" and the daemon starts normally. Ported deliberately — do not "tidy" this into a
        // refusal.
        assert_eq!(bird_socket_refusal(Some("")), None);
    }

    #[test]
    fn bird_socket_path_is_refused_and_the_message_says_why() {
        let message =
            bird_socket_refusal(Some("/run/bird.ctl")).expect("a non-empty path must be refused");
        // Names the flag, so the operator can tell which argument stopped the daemon.
        assert!(
            message.contains("--bird-socket is not supported"),
            "keeps Go's refusal wording; got {message:?}"
        );
        // Echoes the rejected path.
        assert!(
            message.contains("/run/bird.ctl"),
            "names the path it was given; got {message:?}"
        );
        // Names the actual reason (no BIRD hook in the engine) rather than just "unsupported".
        assert!(
            message.contains("BIRD") && message.contains("engine exposes no BIRD hook"),
            "says WHY it is unsupported; got {message:?}"
        );
        // Tells the operator what to do instead.
        assert!(
            message.contains("--advertise-routes"),
            "points at the route-advertising path that does work; got {message:?}"
        );
    }

    // --- `--encrypt-state` / `--hardware-attestation` (Go `tailscaled`'s TPM flags) -------------
    //
    // Go registers both only on a `buildfeatures.HasTPM` build and validates them in
    // `handleTPMFlags`. This fork declares them unconditionally and refuses the "on" case, so a
    // Go-shaped command line reaches a named refusal instead of clap's "unexpected argument". The
    // cases below pin the tri-state (absent / on / explicitly off), the refusal messages, and the
    // policy-driven reporting.

    #[test]
    fn parse_go_bool_accepts_exactly_gos_spellings() {
        for on in ["1", "t", "T", "TRUE", "true", "True"] {
            assert_eq!(parse_go_bool(on), Ok(true), "{on:?} is a Go true");
        }
        for off in ["0", "f", "F", "FALSE", "false", "False"] {
            assert_eq!(parse_go_bool(off), Ok(false), "{off:?} is a Go false");
        }
        // Go's `strconv.ParseBool` takes none of these, so neither do we: a mistyped value must be
        // a parse error, never a silent "false" that would look like the flag was honoured.
        for bad in ["yes", "no", "on", "off", "TrUe", "2", ""] {
            let err = parse_go_bool(bad).expect_err("{bad:?} is not a Go boolean");
            assert!(
                err.contains("strconv.ParseBool") && err.contains("invalid syntax"),
                "keeps Go's error text; got {err:?}"
            );
        }
    }

    #[test]
    fn the_tpm_flags_parse_as_a_tristate_rather_than_being_unknown_arguments() {
        // Omitted: neither flag was set, which is what sends them to the policy half.
        let none = Args::parse_from(["tailnetd"]);
        assert_eq!(none.encrypt_state, None);
        assert_eq!(none.hardware_attestation, None);
        // Bare: Go's `boolFlag` reports `IsBoolFlag`, so the flag alone means true.
        let bare = Args::parse_from(["tailnetd", "--encrypt-state", "--hardware-attestation"]);
        assert_eq!(bare.encrypt_state, Some(true));
        assert_eq!(bare.hardware_attestation, Some(true));
        // `=value`: the only form Go's flag package accepts for a bool, in Go's spellings.
        let explicit = Args::parse_from([
            "tailnetd",
            "--encrypt-state=false",
            "--hardware-attestation=T",
        ]);
        assert_eq!(explicit.encrypt_state, Some(false));
        assert_eq!(explicit.hardware_attestation, Some(true));
        // A non-boolean value is refused by the parser, not coerced.
        assert!(Args::try_parse_from(["tailnetd", "--encrypt-state=yes"]).is_err());
    }

    #[test]
    fn neither_tpm_feature_is_available_in_this_build() {
        // Hardware attestation: Go's build/platform arm, which this fork is permanently on.
        let e = can_use_hardware_attestation().expect_err("no hardware key store exists here");
        assert!(
            e.contains("--hardware-attestation is not supported on this platform or in this build"),
            "keeps Go's sentence; got {e:?}"
        );
        // State encryption on a platform Go does not support either: Go's `%s`-of-GOOS arm, ported
        // verbatim, so the operator sees the same sentence `tailscaled` would print.
        assert_eq!(
            can_encrypt_state("darwin"),
            Err("--encrypt-state is not supported on darwin".to_string())
        );
        assert_eq!(
            can_encrypt_state("freebsd"),
            Err("--encrypt-state is not supported on freebsd".to_string())
        );
        // On the two platforms Go CAN encrypt on, the refusal names the build rather than the OS,
        // because that is the honest reason here — there is no TPM code to be unavailable.
        for os in ["linux", "windows"] {
            let e = can_encrypt_state(os).expect_err("no TPM support is linked into this build");
            assert!(
                e.contains("--encrypt-state is not supported on this device or in this build"),
                "names the build, not the OS, on {os}; got {e:?}"
            );
            assert!(
                !e.contains(os),
                "must not blame the platform Go supports; got {e:?}"
            );
        }
    }

    #[test]
    fn an_omitted_or_explicitly_off_tpm_flag_is_not_a_refusal() {
        // Go's switch fires only on `args.X.v`, so both of these fall through untouched — an
        // operator can leave `--encrypt-state=false` in a unit file and the daemon still starts.
        assert_eq!(explicit_tpm_flag_refusal(None, None, "linux"), None);
        assert_eq!(
            explicit_tpm_flag_refusal(Some(false), Some(false), "linux"),
            None
        );
        assert_eq!(
            explicit_tpm_flag_refusal(Some(false), Some(false), "darwin"),
            None
        );
    }

    #[test]
    fn an_explicit_encrypt_state_is_refused_and_the_message_says_why() {
        let message = explicit_tpm_flag_refusal(Some(true), None, "linux")
            .expect("--encrypt-state must be refused");
        // Names the flag, so the operator can tell which argument stopped the daemon.
        assert!(
            message.contains("--encrypt-state is not supported"),
            "keeps Go's refusal wording; got {message:?}"
        );
        // Says what Go does with the flag, so the refusal is legible to someone porting a Go unit
        // file rather than reading as an arbitrary rejection.
        assert!(
            message.contains("TPM"),
            "says what Go's flag does; got {message:?}"
        );
        // Names the actual reason: no state-store provider / keystore here, and what DOES protect
        // the state dir instead.
        assert!(
            message.contains("no state-store provider layer") && message.contains("0700 state dir"),
            "says WHY it is unsupported and what protects the state today; got {message:?}"
        );
        // Records the parity decision where the operator hits it, and points at the write-up.
        assert!(
            message.contains("out of scope") && message.contains("docs/DESIGN.md"),
            "states the decision and where it is recorded; got {message:?}"
        );
        // Tells the operator what to do.
        assert!(
            message.contains("Drop the flag"),
            "says how to start the daemon; got {message:?}"
        );
    }

    #[test]
    fn an_explicit_hardware_attestation_is_refused_and_the_message_says_why() {
        let message = explicit_tpm_flag_refusal(None, Some(true), "linux")
            .expect("--hardware-attestation must be refused");
        assert!(
            message.contains("--hardware-attestation is not supported"),
            "keeps Go's refusal wording; got {message:?}"
        );
        assert!(
            message.contains("no hardware key store"),
            "says WHY it is unsupported; got {message:?}"
        );
        // The concrete consequence of ignoring it, which is why this is a refusal and not a no-op.
        assert!(
            message.contains("copies to any other machine"),
            "says what a silent no-op would let an operator believe; got {message:?}"
        );
        assert!(
            message.contains("out of scope") && message.contains("Drop the flag"),
            "states the decision and how to proceed; got {message:?}"
        );
    }

    #[test]
    fn hardware_attestation_is_refused_before_encrypt_state() {
        // Go validates the attestation flag in the first switch, so with both flags on that is the
        // error `log.Fatal` prints. Only one message ever reaches the operator, so which one it is
        // matters.
        let message = explicit_tpm_flag_refusal(Some(true), Some(true), "linux")
            .expect("both flags on must still refuse");
        assert!(
            message.contains("--hardware-attestation is not supported"),
            "Go's order puts hardware attestation first; got {message:?}"
        );
        assert!(
            !message.contains("--encrypt-state"),
            "only the first refusal is reported; got {message:?}"
        );
    }

    #[test]
    fn a_policy_that_asks_for_the_tpm_features_is_reported_not_silently_dropped() {
        let notices = tpm_policy_notices(None, None, |_| true, "linux");
        assert_eq!(notices.len(), 2, "one per key; got {notices:?}");
        // Go's line, verbatim including its `[unexpected]` prefix.
        assert!(
            notices[0].starts_with(
                "[unexpected] policy requires hardware attestation, but device does not support it:"
            ),
            "keeps Go's wording and order; got {:?}",
            notices[0]
        );
        // The fork addition: Go stays silent here, which would leave `EncryptState` looking
        // effective forever on a build that can never honour it.
        assert!(
            notices[1].contains("policy sets EncryptState")
                && notices[1].contains("stays unencrypted"),
            "says the policy did not take effect; got {:?}",
            notices[1]
        );
    }

    #[test]
    fn a_policy_that_asks_for_neither_feature_says_nothing() {
        // The default path on every host: no policy file, or one that sets other keys. Startup must
        // stay quiet, exactly as Go's does when `GetBoolean` returns its default.
        assert!(tpm_policy_notices(None, None, |_| false, "linux").is_empty());
        assert!(tpm_policy_notices(None, None, |_| false, "darwin").is_empty());
    }

    #[test]
    fn a_flag_that_was_set_never_consults_the_policy() {
        // Go reads the policy only in its `case !args.X.set:` arm, so a daemon started with
        // `--encrypt-state=false` must not be told about an `EncryptState` policy it already
        // overrode. The closure panics to prove the read is not merely ignored but never made.
        let notices = tpm_policy_notices(
            Some(false),
            Some(false),
            |key| panic!("the policy must not be read for a flag that was set (asked for {key:?})"),
            "linux",
        );
        assert!(notices.is_empty());
        // Only the omitted flag's key is read when just one flag was set.
        let notices = tpm_policy_notices(
            Some(false),
            None,
            |key| {
                assert_eq!(
                    key,
                    tailscaled_rs::ipn::syspolicy::PKEY_HARDWARE_ATTESTATION
                );
                true
            },
            "linux",
        );
        assert_eq!(notices.len(), 1);
    }

    // --- the `debug` subcommand (Go `tailscaled debug`) ----------------------------------------
    //
    // The decision and the refusals are `tailscaled_rs::debugmode`'s, and are tested there. What
    // belongs here is the daemon's own wiring: that `debug` is a subcommand at all, that its flag
    // set is separate from the daemon's, that a stray positional REACHES the refusal instead of
    // dying as clap's "unexpected argument", and that the unrelated `--debug` flag still works.

    #[test]
    fn debug_subcommand_parses_alongside_the_daemons_own_flags() {
        use clap::Parser;
        // No subcommand is the ordinary case: run the daemon.
        assert!(Args::parse_from(["tailnetd"]).command.is_none());

        let Some(Command::Debug(debug)) =
            Args::parse_from(["tailnetd", "debug", "--ifconfig"]).command
        else {
            panic!("`tailnetd debug --ifconfig` should parse as the debug subcommand");
        };
        assert!(debug.ifconfig && !debug.monitor && debug.rest.is_empty());

        // A stray positional is carried through rather than rejected by clap, so
        // `debugmode::select` can refuse it with Go's own message.
        let Some(Command::Debug(debug)) =
            Args::parse_from(["tailnetd", "debug", "monitor"]).command
        else {
            panic!("a stray argument should still parse into the debug subcommand");
        };
        assert_eq!(debug.rest, vec!["monitor".to_string()]);

        // A daemon-startup flag is NOT in the debug flag set (Go's is a separate `flag.FlagSet`).
        assert!(Args::try_parse_from(["tailnetd", "debug", "--statedir", "/var/lib/x"]).is_err());

        // …and the daemon's own `--debug <addr>` (the metrics server's listen address) is an
        // unrelated flag that still parses on its own, with no subcommand.
        let a = Args::parse_from(["tailnetd", "--debug", "9090"]);
        assert_eq!(a.debug.as_deref(), Some("9090"));
        assert!(a.command.is_none());
    }

    #[test]
    fn args_rejects_unknown_flag() {
        use clap::Parser;
        // An unknown flag is a parse error (clap), not silently ignored — matches Go's flag set.
        assert!(Args::try_parse_from(["tailnetd", "--nope"]).is_err());
    }

    #[test]
    fn long_version_has_go_shape() {
        // `--version` block: semver on line 1, then two-space-indented detail lines (the shape of
        // Go's `version.String()`). The build-stamped values may be `unknown` in some build
        // environments, so assert structure, not the literal SHA.
        let mut lines = LONG_VERSION.lines();
        assert_eq!(
            lines.next(),
            Some(env!("CARGO_PKG_VERSION")),
            "line 1 is the bare semver"
        );
        let commit = lines.next().unwrap();
        assert!(
            commit.starts_with("  commit: "),
            "line 2 is the two-space-indented commit line, got {commit:?}"
        );
        let rustc = lines.next().unwrap();
        assert!(
            rustc.starts_with("  rustc version: "),
            "line 3 is the two-space-indented rustc line, got {rustc:?}"
        );
    }

    #[tokio::test]
    async fn cleanup_removes_stale_socket() {
        // A socket file with no listener (the post-crash case) is stale → removed, exit 0.
        let dir =
            std::env::temp_dir().join(format!("tailnetd-cleanup-stale-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let sock = dir.join("tailnetd.sock");
        // A plain file at the socket path stands in for a stale socket: connect() fails (not a
        // socket / nothing accepting), so cleanup treats it as stale and unlinks it.
        tokio::fs::write(&sock, b"stale").await.unwrap();

        let rc = run_cleanup(&sock).await;
        assert_eq!(rc, 0, "stale socket cleanup must succeed");
        assert!(
            !tokio::fs::try_exists(&sock).await.unwrap(),
            "the stale socket must have been removed"
        );
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn cleanup_absent_socket_is_noop_success() {
        // No socket at all → nothing to do, exit 0 (not an error).
        let dir =
            std::env::temp_dir().join(format!("tailnetd-cleanup-absent-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        let sock = dir.join("tailnetd.sock");
        assert_eq!(run_cleanup(&sock).await, 0);
    }

    #[tokio::test]
    async fn cleanup_refuses_live_socket() {
        // A socket with a live listener (a running daemon) must NOT be removed — exit 1, file intact.
        let dir =
            std::env::temp_dir().join(format!("tailnetd-cleanup-live-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let sock = dir.join("tailnetd.sock");
        // Bind a real listener so connect() succeeds → cleanup sees it as live and refuses.
        let _listener = tokio::net::UnixListener::bind(&sock).unwrap();

        let rc = run_cleanup(&sock).await;
        assert_eq!(rc, 1, "cleanup must refuse a live socket");
        assert!(
            tokio::fs::try_exists(&sock).await.unwrap(),
            "a live socket must NOT be removed"
        );
        drop(_listener);
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn cleanup_never_touches_key_or_prefs() {
        // The load-bearing safety invariant: `--cleanup` reclaims OS state (the socket) but NEVER the
        // node identity. Stand up a state dir with a key file + prefs.json alongside a stale socket,
        // run cleanup, and assert the socket is gone but the key and prefs survive untouched.
        let dir =
            std::env::temp_dir().join(format!("tailnetd-cleanup-keep-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let sock = dir.join("tailnetd.sock");
        let key = dir.join("tailnetd.key");
        let prefs = dir.join("prefs.json");
        tokio::fs::write(&sock, b"stale").await.unwrap();
        tokio::fs::write(&key, b"node-key-material").await.unwrap();
        tokio::fs::write(&prefs, b"{\"WantRunning\":true}")
            .await
            .unwrap();

        assert_eq!(run_cleanup(&sock).await, 0);
        assert!(
            !tokio::fs::try_exists(&sock).await.unwrap(),
            "the stale socket must be removed"
        );
        assert_eq!(
            tokio::fs::read(&key).await.unwrap(),
            b"node-key-material",
            "cleanup must NEVER delete or alter the node key"
        );
        assert_eq!(
            tokio::fs::read(&prefs).await.unwrap(),
            b"{\"WantRunning\":true}",
            "cleanup must NEVER delete or alter prefs"
        );
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }
}
