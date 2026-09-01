//! `tailnetd debug` — the daemon's own, daemon-LESS network diagnostics subcommand.
//!
//! Upstream: `cmd/tailscaled/debug.go` (`debugMode`, `runMonitor`, `getURL`, `checkDerp`,
//! `debugPortmap`) @ `53a0d659afa51835dd7a9283873cca44261454f8`.
//!
//! ## Why it lives on the daemon and not on the CLI
//!
//! Go's `tailscaled` takes `debug` as a **subcommand** with its own flag set, dispatched at the very
//! top of `main` — before the daemon's own flags are parsed, before any state is loaded, and without
//! a running daemon or a LocalAPI socket anywhere in the picture. That is the whole point of it:
//! it is the tool you reach for when the node will not come up at all, which is exactly when the
//! CLI-side `tnet debug` verbs (which speak to a live daemon over its socket) cannot help you.
//!
//! This is therefore NOT the daemon's `--debug` flag, which is an unrelated thing: the listen
//! address of the read-only debug-metrics HTTP server (`crate::debugserver`).
//!
//! ## What this fork can and cannot do
//!
//! | Go flag | here |
//! |---|---|
//! | `--ifconfig` | **ported** — dumps the host network state once as JSON |
//! | `--monitor`  | **ported** — dumps it, then re-dumps on every link change, forever |
//! | `--get-url`  | **ported** — fetches a URL with a coarse connection trace |
//! | `--derp`     | **refused by name** — no standalone DERP client here ([`derp_refusal`]) |
//! | `--portmap`  | **refused by name** — no port mapper in the engine ([`portmap_refusal`]) |
//!
//! Both refusals are refusals *with a reason*, never silent no-ops: a diagnostic that appears to run
//! and reports nothing is worse than one that says which piece is missing.
//!
//! Go's two error paths port with the flags, because on a diagnostic tool they matter more than
//! usual — a mistyped invocation that seems to succeed sends you off diagnosing the wrong thing:
//!
//! * a stray positional argument is `unknown non-flag debug subcommand arguments`
//!   ([`STRAY_ARGS_ERROR`]), and
//! * no recognised flag at all is an **error**, not a no-op ([`NOTHING_SELECTED_ERROR`]).
//!
//! ## Output streams
//!
//! Go's are copied, deliberately, because they are not obvious. `runMonitor` writes its JSON dump to
//! **stderr** (`os.Stderr.Write(j)`) alongside its `log.Printf` progress lines, so a state dump is
//! piped with `tailnetd debug --ifconfig 2>&1 >/dev/null | jq .`. `getURL` calls
//! `log.SetOutput(os.Stdout)` and writes the response with `res.Write(os.Stdout)`, so its trace and
//! its response both land on **stdout**. Progress lines here are plain `println!`/`eprintln!` rather
//! than `tracing`: this subcommand runs before the daemon's log subscriber is installed, and Go's
//! are equally plain (its `log` output, minus Go's timestamp prefix).

use std::io::Write as _;
use std::net::ToSocketAddrs as _;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

use crate::ipn::linkmon::{self, NetworkState};

/// Go's refusal for a non-flag argument after the `debug` flag set: `if len(fs.Args()) > 0`.
/// Ported verbatim — `tailnetd debug monitor` (the plausible typo for `--monitor`) has to fail
/// loudly, because the alternative is a diagnostic that silently ran nothing.
pub const STRAY_ARGS_ERROR: &str = "unknown non-flag debug subcommand arguments";

/// Go's fall-through refusal when no mode flag was given, adapted to the modes this fork actually
/// runs. Go's literal string is `only --monitor is available at the moment` — a sentence that has
/// been stale in Go itself for years (`--ifconfig`, `--get-url` and `--derp` all work there), so
/// copying it verbatim would port a bug rather than a behaviour. What is ported is the shape and,
/// more importantly, the decision behind it: an invocation that selected no mode is an error.
pub const NOTHING_SELECTED_ERROR: &str =
    "only --ifconfig, --monitor and --get-url are available at the moment";

/// How long [`Mode::GetUrl`] waits for the whole fetch before giving up.
///
/// Go sets no timeout on `getURL` and lets you interrupt it. Bounding it here is a deliberate
/// deviation in the tool's own spirit: this command exists to diagnose a node that cannot reach its
/// control plane, and "timed out after 30s" is a diagnosis, while a process that hangs with no
/// output is the very symptom you came to investigate.
const GET_URL_TIMEOUT: Duration = Duration::from_secs(30);

/// The `tailnetd debug` flag set — the port of Go's `debugArgs` + the `flag.NewFlagSet("debug", …)`
/// registrations in `debugMode`.
///
/// It is a *separate* flag set in Go, and a separate clap `Args` here for the same reason: none of
/// the daemon-startup flags (`--statedir`, `--port`, …) mean anything to a command that never starts
/// the daemon, so they must not be accepted alongside these.
#[derive(clap::Args, Debug, Default, Clone)]
pub struct DebugArgs {
    /// Print the host's network interface state once, as JSON, and exit (Go `--ifconfig`).
    #[arg(long)]
    pub ifconfig: bool,
    /// Run the link monitor forever, printing the network state on every change (Go `--monitor`).
    /// Precludes the other options.
    #[arg(long)]
    pub monitor: bool,
    /// Run port-mapping (NAT-PMP/PCP/UPnP) debugging (Go `--portmap`). REFUSED — see
    /// [`portmap_refusal`]; Go's own daemon-side flag is a refusal too.
    #[arg(long)]
    pub portmap: bool,
    /// Fetch the given URL, printing a connection trace and the raw response (Go `--get-url`). The
    /// value `login` is shorthand for the default control plane's login URL.
    #[arg(long, value_name = "URL")]
    pub get_url: Option<String>,
    /// Test a DERP round trip via the named region code, e.g. `fra` (Go `--derp`). REFUSED — see
    /// [`derp_refusal`].
    #[arg(long, value_name = "REGION")]
    pub derp: Option<String>,
    /// Any non-flag argument. Declared only so it can be REFUSED the way Go refuses it
    /// ([`STRAY_ARGS_ERROR`]) instead of dying as clap's generic "unexpected argument"; hidden from
    /// the help, because there is no positional argument this subcommand accepts.
    #[arg(value_name = "ARG", hide = true)]
    pub rest: Vec<String>,
}

/// Which diagnostic `tailnetd debug` selected — the outcome of Go's `if` chain in `debugMode`,
/// split out so the *decision* is testable without running any of the diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    /// `--derp <region>`.
    Derp(String),
    /// `--ifconfig`: dump the network state once.
    Ifconfig,
    /// `--monitor`: dump it and follow link changes forever.
    Monitor,
    /// `--portmap`.
    Portmap,
    /// `--get-url <url>`.
    GetUrl(String),
}

/// Pick the mode, or return the operator-facing refusal — the pure port of `debugMode`'s dispatch.
///
/// Two details are ported exactly rather than tidied:
///
/// * **the order**. Go checks `derp`, `ifconfig`, `monitor`, `portmap`, then `get-url`, so with more
///   than one flag given the FIRST in that order wins and the rest are ignored. (Go's `--monitor`
///   help text says "Precludes all other options", but nothing enforces it; the order is the only
///   rule there is.)
/// * **an empty string is not a value**. Go guards its string flags with `!= ""`, so `--derp=""` and
///   `--get-url=""` select nothing at all — the same carve-out `--bird-socket=""` gets in the daemon.
pub fn select(args: &DebugArgs) -> Result<Mode, String> {
    // Go: `if len(fs.Args()) > 0` — checked before anything is dispatched.
    if !args.rest.is_empty() {
        return Err(STRAY_ARGS_ERROR.to_string());
    }
    if let Some(region) = nonempty(args.derp.as_deref()) {
        return Ok(Mode::Derp(region.to_string()));
    }
    if args.ifconfig {
        return Ok(Mode::Ifconfig);
    }
    if args.monitor {
        return Ok(Mode::Monitor);
    }
    if args.portmap {
        return Ok(Mode::Portmap);
    }
    if let Some(url) = nonempty(args.get_url.as_deref()) {
        return Ok(Mode::GetUrl(url.to_string()));
    }
    Err(NOTHING_SELECTED_ERROR.to_string())
}

/// A string flag's value, or `None` when it was absent **or empty** (Go's `!= ""` guard).
fn nonempty(value: Option<&str>) -> Option<&str> {
    value.filter(|v| !v.is_empty())
}

/// Run `tailnetd debug` — the body of Go's `debugMode`.
///
/// **Blocking**, like Go's: it enumerates interfaces, sleeps between polls and drives a blocking
/// HTTP client. Nothing about it is async, and the caller runs it before the daemon exists, so it is
/// called straight from `main` rather than being wrapped in a task.
///
/// An `Err` is what Go's `log.Fatal(err)` prints: one bare line on stderr, then exit 1.
pub fn run(args: &DebugArgs) -> Result<()> {
    match select(args).map_err(anyhow::Error::msg)? {
        Mode::Derp(region) => bail!(derp_refusal(&region)),
        Mode::Ifconfig => run_monitor(false),
        Mode::Monitor => run_monitor(true),
        Mode::Portmap => bail!(portmap_refusal()),
        Mode::GetUrl(url) => get_url(&url),
    }
}

/// `--ifconfig` (`follow = false`) and `--monitor` (`follow = true`) — the port of Go's `runMonitor`,
/// including its progress lines and the order it prints them in.
///
/// Go subscribes to OS link events and re-dumps whenever a change is "major"; this fork's monitor
/// POLLS (see the module docs on `linkmon` for why) every
/// [`POLL_INTERVAL`](linkmon::POLL_INTERVAL) and re-dumps when the path signal differs. The
/// difference an operator can see: Go prints `Network monitor fired; not a significant change` for
/// an event it decided to ignore, and there is no such line here — a poll that found nothing is not
/// an event, and printing one every few seconds forever would bury the changes you are watching for.
///
/// The change decision is [`NetworkState::path_changed`], i.e. the *same* comparison the running
/// daemon rebinds on, so what this prints is what the daemon would have acted on.
fn run_monitor(follow: bool) -> Result<()> {
    if follow {
        eprintln!("Starting link change monitor; initial state:");
    }
    let mut last = NetworkState::current();
    dump(&last);
    if !follow {
        return Ok(());
    }
    eprintln!("Started link change monitor; waiting...");
    loop {
        std::thread::sleep(linkmon::POLL_INTERVAL);
        let now = NetworkState::current();
        if last.path_changed(&now) {
            eprintln!("Network monitor fired. New state:");
            dump(&now);
            last = now;
        }
    }
}

/// Write one network-state dump — Go's `dump` closure (`json.MarshalIndent` → `os.Stderr`).
///
/// Go writes the JSON with no trailing newline, which runs the next log line onto the closing brace;
/// one newline is added here so a follow-on `Network monitor fired.` line starts at a column 0 and a
/// piped dump ends the way every other line-oriented tool ends.
fn dump(state: &NetworkState) {
    eprintln!("{}", state.to_json());
}

/// `--get-url <url>` — the port of Go's `getURL`.
///
/// What ports exactly: the `login` shorthand, the fact that the response is written **raw** to
/// stdout (status line, headers, body — Go's `res.Write(os.Stdout)`), that redirects are NOT
/// followed (Go drives a bare `http.Transport`, which does not), that a non-2xx status is a normal
/// outcome to be printed rather than an error, and that the environment's proxy is reported before
/// the request.
///
/// What is coarser: Go hangs `net/http/httptrace` hooks on the request and gets exact
/// `DNSStart`/`DNSDone`/`GetConn`/`GotConn`/`TLSHandshakeDone` callbacks from inside the transport.
/// `ureq` exposes no such hooks, so the phases are timed from the outside and the DNS lookup printed
/// here is a *separate* resolution done for visibility — it is what a resolver answers now, which is
/// not necessarily the answer the request itself used. It still separates the three failures this
/// command is used to tell apart: name resolution, connection, and the HTTP exchange.
fn get_url(raw: &str) -> Result<()> {
    let url = resolve_url(raw);
    let parsed = url::Url::parse(&url).with_context(|| format!("parse URL {url:?}"))?;
    let (host, port) = host_port(&parsed)?;

    // Go: `log.Printf("GetConn(%q)", hostPort)`.
    println!("GetConn(\"{host}:{port}\")");
    println!("DNSStart: {{Host:{host}}}");
    let started = Instant::now();
    match (host.as_str(), port).to_socket_addrs() {
        Ok(addrs) => {
            let addrs: Vec<String> = addrs.map(|a| a.ip().to_string()).collect();
            println!(
                "DNSDone: addrs={addrs:?} in {:?} (a separate lookup, for visibility)",
                started.elapsed()
            );
        }
        // Not fatal on its own: report it and still attempt the request, so the client's own error
        // (which may differ — a proxy resolves the name itself) is the one that decides.
        Err(e) => println!("DNSDone: err={e} in {:?}", started.elapsed()),
    }
    // Go: `log.Printf("proxy: %v", proxyURL)`, printing `<nil>` when there is none.
    println!(
        "proxy: {}",
        proxy_env_note(parsed.scheme(), |name| std::env::var(name).ok())
            .unwrap_or_else(|| "<nil>".to_string())
    );

    let started = Instant::now();
    let mut response = ureq::get(url.as_str())
        .config()
        // Go's bare `http.Transport` does not follow redirects: a 302 is the answer, not a detour.
        .max_redirects(0)
        // A 404/502 is a diagnosis to print, not an `Err` to abort on — Go prints whatever came back.
        .http_status_as_error(false)
        .timeout_global(Some(GET_URL_TIMEOUT))
        .build()
        .call()
        .with_context(|| format!("HTTP GET {url}"))?;
    println!("Response in {:?}", started.elapsed());

    let head = format_response_head(response.version(), response.status(), response.headers());
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(head.as_bytes())?;
    // Unbounded, like Go's `res.Write`: the body goes straight to the terminal or the pipe the
    // operator aimed it at, so there is nothing to exhaust by streaming it.
    std::io::copy(&mut response.body_mut().as_reader(), &mut stdout)
        .with_context(|| format!("reading response body from {url}"))?;
    stdout.flush()?;
    Ok(())
}

/// Go's one `--get-url` shorthand: the bare word `login` means the default control plane's login
/// URL (`ipn.DefaultControlURL`), so the commonest check — "can this host reach the control plane at
/// all?" — is one word rather than a URL to remember.
fn resolve_url(raw: &str) -> String {
    if raw == "login" {
        return "https://login.tailscale.com".to_string();
    }
    raw.to_string()
}

/// The `host:port` a URL dials, with the scheme's default port filled in — what Go's `GetConn` hook
/// is handed. Non-HTTP schemes are refused here rather than deeper in the client, where the error
/// would name a transport instead of the flag.
fn host_port(url: &url::Url) -> Result<(String, u16)> {
    let default_port = match url.scheme() {
        "http" => 80,
        "https" => 443,
        other => bail!("unsupported protocol scheme {other:?} in --get-url (want http or https)"),
    };
    let host = url
        .host_str()
        .with_context(|| format!("--get-url {url} has no host"))?
        .to_string();
    Ok((host, url.port().unwrap_or(default_port)))
}

/// Report the proxy environment the HTTP client will honour for this scheme — the analogue of Go's
/// `proxy: %v` line, which prints the `*url.URL` its `ProxyFromEnvironment` picked.
///
/// This *reports* the environment rather than claiming which variable won: `ureq` resolves the proxy
/// itself from these same variables, and a line asserting a precedence this code does not implement
/// would be a confident lie in the one place an operator is trying to establish facts. The first
/// non-empty variable in the conventional order is named, with its value, so
/// `proxy: HTTPS_PROXY=http://proxy.example:3128` answers "is a proxy in play at all, and which
/// setting put it there".
fn proxy_env_note(scheme: &str, lookup: impl Fn(&str) -> Option<String>) -> Option<String> {
    let scheme_vars: &[&str] = if scheme == "https" {
        &["HTTPS_PROXY", "https_proxy"]
    } else {
        &["HTTP_PROXY", "http_proxy"]
    };
    ["ALL_PROXY", "all_proxy"]
        .iter()
        .chain(scheme_vars)
        .find_map(|name| {
            lookup(name)
                .filter(|value| !value.is_empty())
                .map(|value| format!("{name}={value}"))
        })
}

/// Render the response's status line and headers in HTTP wire format — the head half of Go's
/// `res.Write(os.Stdout)`, which writes the response exactly as it came off the wire.
///
/// CRLF line endings and the blank line before the body are part of that format, so they are kept.
/// One thing is not byte-identical to Go: header names print in the client's normalised lower-case
/// form (`content-type`) rather than Go's canonical `Content-Type`, because that is how they are
/// held in memory by the time we can read them.
fn format_response_head(
    version: ureq::http::Version,
    status: ureq::http::StatusCode,
    headers: &ureq::http::HeaderMap,
) -> String {
    // `Version` renders as `HTTP/1.1` through `Debug`; `StatusCode` renders as `200 OK`.
    let mut head = format!("{version:?} {status}\r\n");
    for (name, value) in headers {
        head.push_str(name.as_str());
        head.push_str(": ");
        head.push_str(&String::from_utf8_lossy(value.as_bytes()));
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    head
}

/// The `--derp <region>` refusal, naming the missing piece.
///
/// Go's `checkDerp` fetches `<control>/derpmap/default`, finds the region with that code, then opens
/// **two** DERP clients with fresh node keys, sends a packet from one to the other and prints the
/// round-trip time — an end-to-end DERP reachability test that needs no tailnet membership.
///
/// The fetch would port fine; the two clients do not. A standalone DERP client is not something this
/// daemon has: the `tailscale-rs` engine speaks DERP internally (its `ts_derp` crate is a
/// magicsock-side component), but the `tailscale` facade re-exports no DERP client at the pinned
/// rev, so there is nothing here to dial a region with. Refusing by name beats a half-test that
/// fetches the DERP map and then reports success on having parsed some JSON.
pub fn derp_refusal(region: &str) -> String {
    format!(
        "error: --derp is not supported by tailnetd (given region {region:?}).\n\
         Go's `tailscaled debug --derp <region>` fetches the DERP map from the control plane, opens \
         two DERP clients with fresh node keys, sends a packet from one to the other and prints the \
         round-trip time.\n\
         That needs a standalone DERP client, which this daemon does not own: the tailscale-rs \
         engine speaks DERP internally (its `ts_derp` crate is a magicsock-side component), but the \
         `tailscale` facade re-exports no DERP client at the pinned rev, so there is nothing here to \
         dial a region with. tailnetd refuses rather than running half of the test, because a check \
         that only proves the DERP map parsed would be reported as DERP working.\n\
         What does work today: `tnet netcheck` reports per-region DERP latency, and `tnet status` \
         names the home region — both need the daemon to be running, which is the case this \
         subcommand exists for and they do not cover."
    )
}

/// The `--portmap` refusal, naming the missing piece.
///
/// This one is a refusal on BOTH sides of the fork. Go's `debugPortmap` no longer probes anything
/// either — it returns `this flag has been deprecated in favour of 'tailscale debug portmap'`, i.e.
/// upstream moved the probe to the CLI and left the daemon-side flag as an error. Here the CLI verb
/// it redirects to does not exist either, and the reason is a layer down: port mapping (NAT-PMP,
/// PCP, UPnP IGD) is absent from the `tailscale-rs` engine altogether — there is no port-mapper
/// crate in the engine workspace — so neither `tailnetd` nor `tnet` can probe a gateway for one.
pub fn portmap_refusal() -> String {
    "error: --portmap is not supported by tailnetd.\n\
     Go refuses this flag too — its `debugPortmap` returns `this flag has been deprecated in favour \
     of 'tailscale debug portmap'`, having moved the probe to the CLI — but the redirection does not \
     help here, because that verb has no counterpart in this fork either.\n\
     The reason is a layer below the daemon: port mapping (NAT-PMP, PCP, UPnP IGD) does not exist in \
     the tailscale-rs engine at all — there is no port-mapper component in the engine workspace — so \
     nothing on either side of this fork can ask a gateway for a mapping, let alone report on one. \
     A port-mapping probe here has to start with the engine gaining a port mapper.\n\
     Traversal that does work today is direct/disco UDP with a DERP fallback; `tnet netcheck` reports \
     what the node's path actually looks like, and `--port` pins the UDP port when a firewall needs a \
     fixed pinhole."
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse a `tailnetd debug …` command line the way the daemon's clap surface does, so the tests
    /// exercise the real flag definitions rather than a hand-built struct.
    fn parse(argv: &[&str]) -> DebugArgs {
        use clap::Parser as _;
        #[derive(clap::Parser)]
        struct Wrapper {
            #[command(flatten)]
            debug: DebugArgs,
        }
        Wrapper::parse_from(std::iter::once("debug").chain(argv.iter().copied())).debug
    }

    #[test]
    fn each_mode_flag_parses_and_selects_itself() {
        assert_eq!(select(&parse(&["--ifconfig"])), Ok(Mode::Ifconfig));
        assert_eq!(select(&parse(&["--monitor"])), Ok(Mode::Monitor));
        assert_eq!(select(&parse(&["--portmap"])), Ok(Mode::Portmap));
        assert_eq!(
            select(&parse(&["--derp", "fra"])),
            Ok(Mode::Derp("fra".to_string()))
        );
        assert_eq!(
            select(&parse(&["--get-url", "https://example.com/health"])),
            Ok(Mode::GetUrl("https://example.com/health".to_string()))
        );
        // The `--flag=value` spelling reaches the same place.
        assert_eq!(
            select(&parse(&["--derp=nyc"])),
            Ok(Mode::Derp("nyc".to_string()))
        );
    }

    #[test]
    fn dispatch_order_matches_go() {
        // Go checks derp → ifconfig → monitor → portmap → get-url and returns on the first hit, so
        // with several flags given the earliest in that order wins. `--monitor`'s help says it
        // "Precludes all other options", but nothing enforces that: the order is the only rule.
        assert_eq!(
            select(&parse(&["--monitor", "--ifconfig"])),
            Ok(Mode::Ifconfig),
            "--ifconfig is checked before --monitor"
        );
        assert_eq!(
            select(&parse(&["--ifconfig", "--derp", "fra"])),
            Ok(Mode::Derp("fra".to_string())),
            "--derp is checked first of all"
        );
        assert_eq!(
            select(&parse(&["--get-url", "https://example.com", "--portmap"])),
            Ok(Mode::Portmap),
            "--portmap is checked before --get-url"
        );
    }

    #[test]
    fn empty_string_flag_values_select_nothing() {
        // Go guards both string flags with `!= ""`, so an explicitly empty value is "not given" —
        // the same carve-out `--bird-socket=""` gets. Ported deliberately: do not "tidy" these into
        // a Derp("")/GetUrl("") that would go on to fail somewhere less legible.
        assert_eq!(
            select(&parse(&["--derp="])),
            Err(NOTHING_SELECTED_ERROR.to_string())
        );
        assert_eq!(
            select(&parse(&["--get-url="])),
            Err(NOTHING_SELECTED_ERROR.to_string())
        );
        // …and an empty one alongside a real flag does not shadow it.
        assert_eq!(
            select(&parse(&["--derp=", "--ifconfig"])),
            Ok(Mode::Ifconfig)
        );
    }

    #[test]
    fn a_stray_positional_is_refused_with_gos_message() {
        // `tailnetd debug monitor` — the plausible typo — must not run anything.
        assert_eq!(
            select(&parse(&["monitor"])),
            Err(STRAY_ARGS_ERROR.to_string())
        );
        // Checked BEFORE the mode flags, exactly as Go checks `fs.Args()` before dispatching, so a
        // stray argument cannot ride along with a valid mode.
        assert_eq!(
            select(&parse(&["--ifconfig", "extra"])),
            Err(STRAY_ARGS_ERROR.to_string())
        );
    }

    #[test]
    fn no_flags_at_all_is_an_error_not_a_no_op() {
        // Go's fall-through returns an error, which `main` turns into a fatal. A `debug` invocation
        // that quietly exits 0 having done nothing is the failure mode this prevents.
        assert_eq!(
            select(&DebugArgs::default()),
            Err(NOTHING_SELECTED_ERROR.to_string())
        );
        assert_eq!(select(&parse(&[])), Err(NOTHING_SELECTED_ERROR.to_string()));
    }

    #[test]
    fn derp_and_portmap_run_as_named_refusals() {
        // The refusals are what `run` produces for those modes: an error whose message names the
        // flag and the missing piece, never a silent success.
        let err = run(&parse(&["--derp", "fra"])).expect_err("--derp must be refused");
        let message = format!("{err}");
        assert!(
            message.contains("--derp is not supported") && message.contains("\"fra\""),
            "names the flag and echoes the region; got {message}"
        );
        assert!(
            message.contains("no DERP client") || message.contains("re-exports no DERP client"),
            "says WHY it is unsupported; got {message}"
        );
        assert!(
            message.contains("tnet netcheck"),
            "points at what does work; got {message}"
        );

        let err = run(&parse(&["--portmap"])).expect_err("--portmap must be refused");
        let message = format!("{err}");
        assert!(
            message.contains("--portmap is not supported"),
            "names the flag; got {message}"
        );
        assert!(
            message.contains("tailscale debug portmap"),
            "cites Go's own deprecation of the daemon-side flag; got {message}"
        );
        assert!(
            message.contains("port mapping (NAT-PMP, PCP, UPnP IGD) does not exist"),
            "names the engine-level gap; got {message}"
        );
    }

    #[test]
    fn stray_args_and_no_mode_reach_run_as_errors() {
        // `run` must surface both of `select`'s refusals verbatim — they are the messages the
        // operator sees, and `main` prints them as-is.
        assert_eq!(
            format!("{}", run(&parse(&["monitor"])).expect_err("stray arg")),
            STRAY_ARGS_ERROR
        );
        assert_eq!(
            format!("{}", run(&parse(&[])).expect_err("no mode")),
            NOTHING_SELECTED_ERROR
        );
    }

    #[test]
    fn get_url_login_is_shorthand_for_the_control_plane() {
        // Go's one shorthand: the bare word `login` → the default control plane's login URL.
        assert_eq!(resolve_url("login"), "https://login.tailscale.com");
        // Everything else is passed through untouched, including something that merely contains it.
        assert_eq!(
            resolve_url("https://headscale.example.com/health"),
            "https://headscale.example.com/health"
        );
        assert_eq!(resolve_url("login.example.com"), "login.example.com");
    }

    #[test]
    fn host_port_fills_in_the_scheme_default() {
        let hp = |u: &str| host_port(&url::Url::parse(u).unwrap()).unwrap();
        assert_eq!(
            hp("https://example.com/x"),
            ("example.com".to_string(), 443)
        );
        assert_eq!(hp("http://example.com/x"), ("example.com".to_string(), 80));
        // An explicit port wins over the default.
        assert_eq!(
            hp("https://example.com:8443/x"),
            ("example.com".to_string(), 8443)
        );
        // A documentation-range literal host is a host like any other.
        assert_eq!(
            hp("http://192.0.2.10:8080/"),
            ("192.0.2.10".to_string(), 8080)
        );
    }

    #[test]
    fn host_port_refuses_a_non_http_scheme() {
        // Refused here, where the message can name `--get-url`, rather than inside the HTTP client.
        let err = host_port(&url::Url::parse("ftp://example.com/x").unwrap())
            .expect_err("ftp is not fetchable");
        let message = format!("{err}");
        assert!(
            message.contains("unsupported protocol scheme") && message.contains("--get-url"),
            "got {message}"
        );
    }

    #[test]
    fn proxy_env_note_reports_the_first_variable_that_is_set() {
        let env = |pairs: Vec<(&'static str, &'static str)>| {
            move |name: &str| {
                pairs
                    .iter()
                    .find(|(k, _)| *k == name)
                    .map(|(_, v)| (*v).to_string())
            }
        };
        // Nothing set → nothing to report (the caller prints Go's `<nil>`).
        assert_eq!(proxy_env_note("https", env(vec![])), None);
        // The scheme decides which of HTTPS_PROXY/HTTP_PROXY is consulted.
        assert_eq!(
            proxy_env_note(
                "https",
                env(vec![("HTTPS_PROXY", "http://proxy.example:3128")])
            ),
            Some("HTTPS_PROXY=http://proxy.example:3128".to_string())
        );
        assert_eq!(
            proxy_env_note(
                "https",
                env(vec![("HTTP_PROXY", "http://proxy.example:3128")])
            ),
            None,
            "HTTP_PROXY does not apply to an https URL"
        );
        assert_eq!(
            proxy_env_note(
                "http",
                env(vec![("http_proxy", "http://proxy.example:3128")])
            ),
            Some("http_proxy=http://proxy.example:3128".to_string()),
            "the lower-case spelling counts too"
        );
        // ALL_PROXY is reported ahead of the scheme-specific ones.
        assert_eq!(
            proxy_env_note(
                "https",
                env(vec![
                    ("HTTPS_PROXY", "http://scheme.example:3128"),
                    ("ALL_PROXY", "socks5://all.example:1080"),
                ])
            ),
            Some("ALL_PROXY=socks5://all.example:1080".to_string())
        );
        // An empty value is not a proxy.
        assert_eq!(
            proxy_env_note("https", env(vec![("HTTPS_PROXY", "")])),
            None
        );
    }

    #[test]
    fn response_head_is_http_wire_format() {
        let mut headers = ureq::http::HeaderMap::new();
        headers.insert("content-type", "application/json".parse().unwrap());
        headers.insert("content-length", "2".parse().unwrap());
        let head = format_response_head(
            ureq::http::Version::HTTP_11,
            ureq::http::StatusCode::OK,
            &headers,
        );
        assert!(
            head.starts_with("HTTP/1.1 200 OK\r\n"),
            "status line first, CRLF-terminated; got {head:?}"
        );
        assert!(
            head.contains("content-type: application/json\r\n"),
            "got {head:?}"
        );
        assert!(head.contains("content-length: 2\r\n"), "got {head:?}");
        assert!(
            head.ends_with("\r\n\r\n"),
            "a blank line separates the head from the body; got {head:?}"
        );
        // A redirect is printed, not followed — so its status line and Location must survive.
        let mut headers = ureq::http::HeaderMap::new();
        headers.insert("location", "https://example.com/next".parse().unwrap());
        let head = format_response_head(
            ureq::http::Version::HTTP_11,
            ureq::http::StatusCode::FOUND,
            &headers,
        );
        assert!(head.starts_with("HTTP/1.1 302 Found\r\n"), "got {head:?}");
        assert!(
            head.contains("location: https://example.com/next\r\n"),
            "got {head:?}"
        );
    }
}
