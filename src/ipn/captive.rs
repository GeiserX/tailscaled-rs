//! Captive-portal detection — is this node sitting behind an airport/hotel Wi-Fi login page?
//!
//! A port of Go `net/captivedetection/captivedetection.go` + `net/captivedetection/endpoints.go`
//! (the prober) and the health half of `ipn/ipnlocal/captiveportal.go` (the trigger + the
//! `captive-portal-detected` warnable), from upstream `tailscale` **v1.100.0**.
//!
//! ## Why the daemon wants this
//!
//! Behind a captive portal every outbound request is intercepted and answered by the portal, so the
//! control client's registration/map-poll attempts fail in a way that looks like a broken network.
//! Go detects the portal so it can (a) stop reading those failures as "control is down" and (b) tell
//! the operator the truth — *this network wants you to log in in a browser* — instead of an opaque
//! connect error. That is the whole point: the detection does not fix connectivity, it **explains**
//! it, so the node stops hammering control and the human knows what to do.
//!
//! ## How the probe works (Go's algorithm, unchanged)
//!
//! Each [`Endpoint`] is a plain-HTTP (port 80) URL that is *known* to answer `204 No Content` with
//! an empty body. A portal cannot pass that through untouched: it answers `200` with its login page,
//! or `302`s to it. So a response that is **not** exactly what the endpoint promised is read as
//! "a portal is tampering with this connection".
//!
//! DERP endpoints additionally carry a challenge/response handshake: the request sends
//! `X-Tailscale-Challenge: ts_<host>` and a genuine DERP server echoes
//! `X-Tailscale-Response: response ts_<host>`. A portal that happens to answer `204` still cannot
//! produce that header, so the challenge closes the "portal mimics a 204" hole.
//!
//! ## Honest reduced scope vs Go (all deliberate, none silent)
//!
//! - **No DERP-node endpoints.** Go builds most of its endpoint list from the live `DERPMap`'s node
//!   IPv4s (`CanPort80` nodes), and falls back to the baked-in `dnsfallback` static DERP map when the
//!   netmap has not arrived yet. The engine at this pin exposes neither the live DERP map nor a
//!   static one to the daemon ([`tailscale::Device`] surfaces only region *ids* + latencies via
//!   `netcheck()`), and this fork ships no hard-coded DERP IP list of its own. So
//!   [`available_endpoints`] is called with an empty region set live, and the probe uses the two
//!   Tailscale endpoints Go *always* appends. The DERP branch is fully ported and unit-tested, so
//!   wiring a real DERP map in later is a one-argument change at the call site (engine ask #33).
//! - **No per-interface socket binding.** Go retries the whole probe once per candidate interface,
//!   binding the socket to that interface's index (`IP_BOUND_IF`/`SO_BINDTODEVICE`), because on macOS
//!   no default route exists until the user dismisses the system captive-portal sheet. We keep Go's
//!   *interface gate* — [`detection_interfaces`] applies the same up/loopback/name-prefix filter, and
//!   no candidate interface means no probe at all — but run a single pass over the host's default
//!   path rather than fabricating a per-interface bind the HTTP client cannot do.
//! - **No `captiveportal_detected` client metric.** Go bumps a `clientmetric` counter; this daemon
//!   has no client-metric registry of its own (`tnet metrics` proxies the engine's).
//! - **One connectivity signal instead of a health tracker.** Go probes while *any* warnable with
//!   `ImpactsConnectivity` is unhealthy. This fork has no health tracker, so
//!   [`Backend::connectivity_impacted`](super::Backend) reads the single connectivity fact the engine
//!   publishes — the net report names no reachable DERP region — which is what Go registers as
//!   `no-derp-home` (`health/warnings.go`) and the warnable a portal actually trips, since the portal
//!   answers the relay connections itself. The *state* the trigger runs in is Go's unchanged:
//!   `Running`, and only `Running`.

use std::collections::BTreeSet;
use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

/// Per-request timeout for a captive-portal probe (Go `captivedetection.Timeout`). Deliberately
/// short: the portal intercepting the request is on the LAN, so a slow answer is itself evidence
/// that nothing is answering rather than that a portal is thinking.
pub(super) const TIMEOUT: Duration = Duration::from_secs(3);

/// How many endpoints one detection pass probes concurrently (Go `detectOnInterface`'s
/// `use := min(len(endpoints), 5)`). The list is preference-ordered, so this takes the best five.
const MAX_ENDPOINTS_PER_PASS: usize = 5;

/// Cap on the response body read when an endpoint declares `expected_content`
/// (Go `io.ReadAll(io.LimitReader(r.Body, 4096))`). A portal's login page can be arbitrarily large;
/// the check only ever looks for a short marker string, so 4 KiB is both Go's number and plenty.
const MAX_BODY_BYTES: u64 = 4096;

/// The `Code` of Go's `captivePortalWarnable` (`ipn/ipnlocal/captiveportal.go`) — the stable,
/// machine-readable identifier for this health warning.
pub(super) const WARNABLE_CODE: &str = "captive-portal-detected";

/// The human `Text` of Go's `captivePortalWarnable`, verbatim. This is the string that lands in Go's
/// `ipnstate.Status.Health` (its `health.Tracker.Strings()` emits each unhealthy warnable's `Text`),
/// so `tnet status`'s health block reads exactly like `tailscale status`'s.
pub(super) const WARNABLE_TEXT: &str =
    "This network requires you to log in using your web browser.";

/// How long connectivity must stay impacted before the first detection pass runs (Go
/// `captivePortalDetectionInterval`). A short blip on the way up must not fire a probe.
pub(super) const DETECTION_INTERVAL: Duration = Duration::from_secs(2);

/// How long "this node cannot reach any relay server" must persist before it counts as a
/// connectivity problem at all — Go `health.noDERPHomeWarnable`'s `TimeToVisible`
/// (`health/warnings.go`: *"Tailscale could not connect to any relay server"*, `ImpactsConnectivity:
/// true`, `TimeToVisible: 10 * time.Second`).
///
/// That warnable is the one this fork stands in for: with no health tracker, "the engine measured no
/// reachable DERP region" is the observable that Go turns into `no-derp-home`, and Go only feeds it
/// to captive-portal detection once it has been unhealthy for this long. Honouring the same delay
/// keeps a node whose *first* DERP measurement simply has not landed yet — an empty report on a
/// freshly-`Running` node is indistinguishable from a dead one — from probing on every bring-up.
/// Go's [`DETECTION_INTERVAL`] is then spent on top, exactly as it is upstream, where the health
/// change arrives at the loop only after the warnable becomes visible.
pub(super) const NO_DERP_HOME_TIME_TO_VISIBLE: Duration = Duration::from_secs(10);

/// How long to wait before re-probing while connectivity *stays* impacted.
///
/// FORK BEHAVIOUR, not a Go constant. Go re-triggers detection from its health tracker: every health
/// state change while connectivity is impacted pushes onto `needsCaptiveDetection`, which re-arms the
/// 2s timer. This fork has no health-event bus (see `crate::localapi`'s note on the reduced `Notify`),
/// so the loop polls instead — and a bare 2s poll would mean an unreachable-control node probes
/// tailscale.com every two seconds forever. The first pass of an episode keeps Go's settle time
/// ([`NO_DERP_HOME_TIME_TO_VISIBLE`] + [`DETECTION_INTERVAL`]); subsequent passes back off to this,
/// which still notices a portal that appears while the node is already stuck.
pub(super) const RECHECK_INTERVAL: Duration = Duration::from_secs(30);

/// The captive-portal loop's tick — how often it re-reads whether connectivity is impacted. Fine
/// enough to honour [`DETECTION_INTERVAL`] without a timer per state edge.
pub(super) const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Where an [`Endpoint`] came from (Go `captivedetection.EndpointProvider`). The declaration order
/// **is** the preference order: [`available_endpoints`] sorts on it, so a DERP node in the node's own
/// preferred region is probed before a DERP node elsewhere, which is probed before the generic
/// Tailscale endpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum EndpointProvider {
    /// A DERP node inside the region this node measured as its preferred (lowest-latency) home.
    DerpMapPreferred,
    /// A DERP node in any other region.
    DerpMapOther,
    /// The Tailscale coordination server / admin console (Go's always-appended pair).
    Tailscale,
}

impl fmt::Display for EndpointProvider {
    /// Go `EndpointProvider.String()`, same spellings — these appear in the probe's trace logs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            EndpointProvider::DerpMapPreferred => "DERPMapPreferred",
            EndpointProvider::DerpMapOther => "DERPMapOther",
            EndpointProvider::Tailscale => "Tailscale",
        };
        f.write_str(s)
    }
}

/// One captive-portal probe target and the response it promises (Go `captivedetection.Endpoint`).
/// Anything the endpoint answers that deviates from this contract is read as portal interference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Endpoint {
    /// The URL to `GET`. Always plain `http://` on port 80: a portal cannot transparently intercept
    /// TLS without a certificate error, so the *plaintext* probe is the one that sees the portal.
    pub(super) url: url::Url,
    /// The status code a non-intercepted response must carry (204 for every endpoint we build).
    pub(super) status_code: u16,
    /// A marker string the body must contain, or empty to skip the body check entirely (Go's
    /// `ExpectedContent`). Empty for every endpoint we build — the `204` endpoints have no body.
    pub(super) expected_content: String,
    /// Whether this endpoint echoes `X-Tailscale-Challenge` back in `X-Tailscale-Response`. True only
    /// for DERP nodes; the Tailscale coordination/console endpoints do not implement it.
    pub(super) supports_tailscale_challenge: bool,
    /// The endpoint's source, which is also its priority — see [`EndpointProvider`].
    pub(super) provider: EndpointProvider,
}

impl Endpoint {
    /// The URL's authority as Go's `url.URL.Host` renders it: host, plus `:port` only when the URL
    /// carries an explicit non-default port. This is the value the challenge is built from, so it has
    /// to match Go character-for-character or the DERP server's echo will not compare equal.
    pub(super) fn host(&self) -> String {
        let host = self.url.host_str().unwrap_or_default();
        match self.url.port() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_string(),
        }
    }

    /// The `X-Tailscale-Challenge` value to send (Go: `chal := "ts_" + e.URL.Host`). The DERP server
    /// restricts which characters it will echo, which is why this is a host and not a nonce.
    pub(super) fn challenge(&self) -> String {
        format!("ts_{}", self.host())
    }

    /// The `X-Tailscale-Response` value a genuine DERP server answers with (Go:
    /// `expectedResponse := "response ts_" + e.URL.Host`).
    pub(super) fn expected_response(&self) -> String {
        format!("response ts_{}", self.host())
    }

    /// Go `Endpoint.responseLooksLikeCaptive`: does this response deviate from what the endpoint
    /// promised, i.e. is somebody in the middle? Pure — the caller does the I/O — so every arm below,
    /// including the failure arms, is unit-testable without a network.
    ///
    /// The checks, in Go's order:
    ///
    /// 1. **Status mismatch ⇒ captive.** The portal's login page (`200`) or redirect (`302`) instead
    ///    of the promised `204`.
    /// 2. **Missing/incorrect `X-Tailscale-Response` ⇒ captive**, for challenge-capable endpoints
    ///    only. This is what catches a portal that answers a bare `204` to look innocent.
    /// 3. **No `expected_content` ⇒ not captive.** The body is not even read in this case.
    /// 4. **Body missing the marker ⇒ captive.**
    ///
    /// `body` is `None` when the body could not be read. Go treats that as **not** captive
    /// (`io.ReadAll` error → `return false`): a truncated read is a local I/O failure, and detection
    /// fails *open* rather than raising a portal warning it cannot substantiate.
    pub(super) fn response_looks_like_captive(
        &self,
        status: u16,
        tailscale_response: Option<&str>,
        body: Option<&[u8]>,
    ) -> bool {
        if status != self.status_code {
            tracing::debug!(
                want = self.status_code,
                got = status,
                url = %self.url,
                "captive: unexpected status code in captive portal response"
            );
            return true;
        }

        if self.supports_tailscale_challenge {
            let expected = self.expected_response();
            if tailscale_response != Some(expected.as_str()) {
                // A correct status with a wrong (or absent) echo means somebody synthesized the
                // response: exactly the portal-mimics-204 case the challenge exists to catch.
                tracing::info!(
                    want = %expected,
                    got = tailscale_response.unwrap_or(""),
                    url = %self.url,
                    "captive: response did not carry the expected X-Tailscale-Response header"
                );
                return true;
            }
        }

        if self.expected_content.is_empty() {
            return false;
        }

        let Some(body) = body else {
            // Go's `io.ReadAll` error arm: log and report NOT captive.
            tracing::debug!(url = %self.url, "captive: reading check response body failed");
            return false;
        };
        if !contains_subslice(body, self.expected_content.as_bytes()) {
            tracing::debug!(
                want = %self.expected_content,
                url = %self.url,
                "captive: check response body did not contain the expected content"
            );
            return true;
        }

        false
    }
}

/// Go's `mem.Contains(mem.B(b), mem.S(e.ExpectedContent))` — a byte-level substring test (the body is
/// arbitrary bytes, not necessarily UTF-8, so this must not go through `str`). An empty needle is
/// never asked for here (the caller returns early), but would trivially match, as in Go.
fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// One DERP node as [`available_endpoints`] reads it — the two fields of Go's `tailcfg.DERPNode`
/// that endpoint construction touches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DerpNode {
    /// The node's IPv4 literal. Go probes DERP nodes **by IP, not hostname**, deliberately: a captive
    /// portal usually hijacks DNS too, so a hostname probe would test the portal's resolver rather
    /// than the path. Empty ⇒ the node is skipped.
    pub(super) ipv4: String,
    /// Whether the node serves plain HTTP on port 80 (Go `DERPNode.CanPort80`). A node that does not
    /// cannot answer a `/generate_204` probe at all, so it is skipped.
    pub(super) can_port80: bool,
}

/// One DERP region as [`available_endpoints`] reads it — the fields of Go's `tailcfg.DERPRegion` that
/// gate whether its nodes may be probed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DerpRegion {
    /// The region id, compared against the node's preferred region to assign
    /// [`EndpointProvider::DerpMapPreferred`].
    pub(super) region_id: u32,
    /// Control asked clients to stay away from this region entirely (Go `DERPRegion.Avoid`).
    pub(super) avoid: bool,
    /// The region is not to be measured or homed to (Go `DERPRegion.NoMeasureNoHome`) — e.g. a
    /// region that exists only as an explicit relay target.
    pub(super) no_measure_no_home: bool,
    /// The region's DERP nodes.
    pub(super) nodes: Vec<DerpNode>,
}

/// Go `captivedetection.availableEndpoints`: build the preference-ordered probe list.
///
/// DERP nodes come first (skipping `Avoid`/`NoMeasureNoHome` regions, and nodes with no IPv4 or no
/// port-80 support), with nodes in `preferred_region_id` ranked above the rest; then Go's two
/// always-appended Tailscale endpoints. A node IPv4 that does not parse into a URL is logged and
/// skipped rather than aborting the list — one malformed DERP entry from control must not disable
/// detection.
///
/// Go substitutes its baked-in `dnsfallback` DERP map when `regions` is empty; this fork has no such
/// static map (see the module docs), so an empty `regions` simply yields the two Tailscale endpoints.
/// The live caller passes `&[]` today — the DERP branch exists, and is tested, for the engine ask that
/// will supply a real map.
pub(super) fn available_endpoints(
    regions: &[DerpRegion],
    preferred_region_id: Option<u32>,
) -> Vec<Endpoint> {
    let mut endpoints: Vec<Endpoint> = Vec::new();

    for region in regions {
        if region.avoid || region.no_measure_no_home {
            continue;
        }
        for node in &region.nodes {
            if node.ipv4.is_empty() || !node.can_port80 {
                continue;
            }
            let raw = format!("http://{}/generate_204", node.ipv4);
            let Ok(url) = url::Url::parse(&raw) else {
                tracing::warn!(url = %raw, "captive: failed to parse DERP node URL; skipping");
                continue;
            };
            let provider = if Some(region.region_id) == preferred_region_id {
                EndpointProvider::DerpMapPreferred
            } else {
                EndpointProvider::DerpMapOther
            };
            endpoints.push(Endpoint {
                url,
                status_code: 204,
                expected_content: String::new(),
                supports_tailscale_challenge: true,
                provider,
            });
        }
    }

    // Go: "Let's also try the default Tailscale coordination server and admin console. These are
    // likely to be blocked on some networks." Hostname-based (no DERP map needed) and NOT
    // challenge-capable — neither echoes `X-Tailscale-Response`, so only the 204 is checked.
    for host in ["controlplane.tailscale.com", "login.tailscale.com"] {
        let raw = format!("http://{host}/generate_204");
        let Ok(url) = url::Url::parse(&raw) else {
            tracing::warn!(url = %raw, "captive: failed to parse Tailscale URL; skipping");
            continue;
        };
        endpoints.push(Endpoint {
            url,
            status_code: 204,
            expected_content: String::new(),
            supports_tailscale_challenge: false,
            provider: EndpointProvider::Tailscale,
        });
    }

    // Preferred-region DERP, then other DERP, then the Tailscale pair. `sort_by_key` is stable, so
    // endpoints sharing a provider keep the DERP map's own order (Go's `slices.SortFunc` leaves that
    // order unspecified; keeping it is a strictly stronger guarantee, and it makes the list
    // deterministic to test).
    endpoints.sort_by_key(|e| e.provider);
    endpoints
}

/// Go `interfaceNameDoesNotNeedCaptiveDetection`: is this interface one we should not bother probing?
///
/// Two reasons an interface is excluded: it is a tunnel/virtual device whose path is not the host's
/// real uplink (so a portal cannot be on it, and probing `tailscale`/`wg`/`docker` would in the worst
/// case send the probe back through the very tunnel we are diagnosing), or it is a cellular modem
/// (`pdp` on iOS, `rmnet` on Android), where a periodic probe is a needless battery and data cost and
/// carriers do not run captive portals.
///
/// `goos` is Go's `runtime.GOOS` spelling (`"darwin"`, not Rust's `"macos"`) — pass [`goos`].
pub(super) fn interface_name_does_not_need_captive_detection(name: &str, goos: &str) -> bool {
    let name = name.to_lowercase();
    const BASE: &[&str] = &["tailscale", "tun", "tap", "docker", "kube", "wg", "ipsec"];
    let extra: &[&str] = match goos {
        "windows" => &["loopback", "tunnel", "ppp", "isatap", "teredo", "6to4"],
        "darwin" | "ios" => &[
            "pdp", "awdl", "bridge", "ap", "utun", "tap", "llw", "anpi", "lo", "stf", "gif", "xhc",
            "pktap",
        ],
        "android" => &["rmnet", "p2p", "dummy", "sit"],
        _ => &[],
    };
    BASE.iter()
        .chain(extra)
        .any(|prefix| name.starts_with(prefix))
}

/// This host's OS in Go's `runtime.GOOS` spelling, so the ported per-OS prefix lists in
/// [`interface_name_does_not_need_captive_detection`] key off the same strings Go's do. Rust spells
/// macOS `"macos"`; every other target we build for already agrees with Go.
pub(super) fn goos() -> &'static str {
    match std::env::consts::OS {
        "macos" => "darwin",
        other => other,
    }
}

/// The interfaces a captive-portal probe is worth running on, from `(name, address)` pairs as
/// `if_addrs` enumerates them — Go's per-interface filter in `detectCaptivePortalWithGOOS`, hoisted
/// into a pure function so it is testable without touching the host's real interfaces.
///
/// Kept: an interface that has at least one address, is not loopback, and whose name is not excluded
/// by [`interface_name_does_not_need_captive_detection`]. (Enumeration by `if_addrs` implies the
/// interface is up, which is Go's `i.IsUp()` gate; an interface with no addresses simply contributes
/// no pairs and so never appears.)
///
/// An empty result is Go's `!ifState.AnyInterfaceUp()` case: no path to probe, so [`detect`] reports
/// "no portal" without making a single request.
pub(super) fn detection_interfaces<'a>(
    ifaces: impl IntoIterator<Item = (&'a str, IpAddr)>,
    goos: &str,
) -> BTreeSet<String> {
    ifaces
        .into_iter()
        .filter(|(name, addr)| {
            !addr.is_loopback() && !interface_name_does_not_need_captive_detection(name, goos)
        })
        .map(|(name, _)| name.to_string())
        .collect()
}

/// Snapshot the host's candidate probe interfaces (the live [`detection_interfaces`] source). An
/// enumeration failure is logged and read as "no candidates", which makes [`detect`] report no portal
/// — failing *open*, never raising a warning off a failed syscall.
fn host_detection_interfaces() -> BTreeSet<String> {
    match if_addrs::get_if_addrs() {
        Ok(ifaces) => {
            let pairs: Vec<(String, IpAddr)> =
                ifaces.into_iter().map(|i| (i.name, i.addr.ip())).collect();
            detection_interfaces(pairs.iter().map(|(n, a)| (n.as_str(), *a)), goos())
        }
        Err(e) => {
            tracing::warn!(error = %e, "captive: failed to enumerate interfaces; skipping detection");
            BTreeSet::new()
        }
    }
}

/// The one HTTP request a captive-portal probe makes, as [`probe_endpoint_with`] hands it to a
/// transport. Split out so the request the check *builds* — the cache-busting stamp, the challenge —
/// is inspectable, rather than only observable as a side effect of a live socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ProbeRequest {
    /// The URL to `GET`, including the `?t=<unix>` stamp.
    pub(super) url: url::Url,
    /// The `X-Tailscale-Challenge` value to send, or `None` for an endpoint that does not echo.
    pub(super) challenge: Option<String>,
    /// Whether the transport must read the response body at all (only when the endpoint declares
    /// `expected_content`; Go likewise never touches the body otherwise).
    pub(super) wants_body: bool,
}

/// The parts of an HTTP response the captive check looks at (Go reads exactly these off
/// `*http.Response`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ProbeResponse {
    /// The response status code.
    pub(super) status: u16,
    /// The `X-Tailscale-Response` header, if the response carried one.
    pub(super) tailscale_response: Option<String>,
    /// The response body, or `None` when it was not requested or could not be read (Go's `io.ReadAll`
    /// error arm — see [`Endpoint::response_looks_like_captive`]).
    pub(super) body: Option<Vec<u8>>,
}

/// `GET` one endpoint through `transport` and decide whether the answer looks like a portal (Go
/// `Detector.verifyCaptivePortalEndpoint`).
///
/// The transport is a parameter so the whole check — the `?t=` stamp Go appends, the challenge header
/// it attaches only for challenge-capable endpoints, and the mapping from response to verdict — is
/// exercisable against canned responses. [`probe_endpoint`] supplies the real HTTP one.
///
/// `now_unix` is the cache-busting stamp (Go `d.Now().Unix()`); a parameter rather than a clock read
/// so it can be pinned.
///
/// `Err` means the request itself failed (DNS, connect, timeout). Go's caller treats that as *not*
/// captive: an endpoint we could not reach at all proves nothing about interception.
fn probe_endpoint_with(
    endpoint: &Endpoint,
    now_unix: u64,
    transport: impl FnOnce(&ProbeRequest) -> anyhow::Result<ProbeResponse>,
) -> anyhow::Result<bool> {
    // Go appends a `t=<unix>` query param so no cache along the way can answer with a stale 204.
    let mut url = endpoint.url.clone();
    url.query_pairs_mut()
        .append_pair("t", &now_unix.to_string());

    let request = ProbeRequest {
        url,
        // Only DERP endpoints echo, and sending the header to one that does not would be noise.
        challenge: endpoint
            .supports_tailscale_challenge
            .then(|| endpoint.challenge()),
        wants_body: !endpoint.expected_content.is_empty(),
    };
    let response = transport(&request)?;

    Ok(endpoint.response_looks_like_captive(
        response.status,
        response.tailscale_response.as_deref(),
        response.body.as_deref(),
    ))
}

/// The live HTTP transport for [`probe_endpoint_with`]. **Blocking** — `ureq` is a blocking client —
/// so [`detect`] drives it on a `spawn_blocking` thread.
///
/// Client settings, each mirroring Go's `http.Client`:
/// - **no redirects** (`max_redirects(0)`) — a portal's `302` to its login page is *the signal*, so it
///   must be observed, never followed;
/// - **status is not an error** (`http_status_as_error(false)`) — a `200`/`302` is a normal outcome
///   here and has to reach [`Endpoint::response_looks_like_captive`], not be turned into an `Err`;
/// - **no proxy** (`proxy(None)`) — Go builds a bare `http.Transport` with no `Proxy` field, so its
///   probes never go through `HTTP_PROXY`. `ureq` picks the environment proxy up by default, and that
///   would be wrong twice over: the probe must measure the *local network path* a portal sits on, and
///   a probe tunnelled through a proxy would report on the proxy's connectivity instead;
/// - **a hard [`TIMEOUT`]**.
fn http_probe(request: &ProbeRequest) -> anyhow::Result<ProbeResponse> {
    let mut req = ureq::get(request.url.as_str())
        .config()
        .max_redirects(0)
        .http_status_as_error(false)
        .proxy(None)
        .timeout_global(Some(TIMEOUT))
        .build()
        // Go sets the same value, for the same reason as the `t=` param: never let a cache answer.
        .header(
            "Cache-Control",
            "no-cache, no-store, must-revalidate, no-transform, max-age=0",
        );
    if let Some(challenge) = &request.challenge {
        req = req.header("X-Tailscale-Challenge", challenge);
    }

    let mut resp = req.call()?;
    let status = resp.status().as_u16();
    let tailscale_response = resp
        .headers()
        .get("X-Tailscale-Response")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let body: Option<Vec<u8>> = if request.wants_body {
        // A read failure maps to `None`, which `response_looks_like_captive` treats as Go's
        // `io.ReadAll` error arm: fail open, do not raise a warning off a truncated read.
        resp.body_mut()
            .with_config()
            .limit(MAX_BODY_BYTES)
            .read_to_vec()
            .ok()
    } else {
        None
    };

    Ok(ProbeResponse {
        status,
        tailscale_response,
        body,
    })
}

/// [`probe_endpoint_with`] over the live HTTP transport — what [`detect`] calls.
fn probe_endpoint(endpoint: &Endpoint, now_unix: u64) -> anyhow::Result<bool> {
    probe_endpoint_with(endpoint, now_unix, http_probe)
}

/// Go `Detector.Detect`: is this node behind a captive portal?
///
/// Gate, then probe. The gate is Go's interface scan ([`host_detection_interfaces`]): with no
/// candidate interface there is no path a portal could sit on, and we return `false` without a single
/// request. Otherwise the best [`MAX_ENDPOINTS_PER_PASS`] endpoints are probed **concurrently** and
/// the first one that looks intercepted wins — Go's "one match is good enough". A probe that errors
/// contributes nothing (an unreachable endpoint is not evidence of a portal).
///
/// Reports `false` in every ambiguous case, which is the conservative direction: a false negative
/// leaves the operator with today's opaque connect error, while a false positive would tell them to
/// open a browser on a network that has no portal.
pub(super) async fn detect(regions: &[DerpRegion], preferred_region_id: Option<u32>) -> bool {
    let interfaces = host_detection_interfaces();
    if interfaces.is_empty() {
        tracing::debug!("captive: no candidate interfaces up; not probing");
        return false;
    }

    let mut endpoints = available_endpoints(regions, preferred_region_id);
    endpoints.truncate(MAX_ENDPOINTS_PER_PASS);
    if endpoints.is_empty() {
        return false;
    }
    tracing::debug!(
        interfaces = interfaces.len(),
        endpoints = endpoints.len(),
        "captive: running captive-portal detection"
    );

    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // One blocking probe per endpoint, all in flight at once. `spawn_blocking` tasks cannot be
    // interrupted, but each is bounded by `TIMEOUT`, so dropping the `JoinSet` on an early win leaves
    // at most a few short-lived threads to finish and be discarded — Go's `cancel()` in spirit.
    let mut tasks: tokio::task::JoinSet<(Endpoint, anyhow::Result<bool>)> =
        tokio::task::JoinSet::new();
    for endpoint in endpoints {
        tasks.spawn_blocking(move || {
            let outcome = probe_endpoint(&endpoint, now_unix);
            (endpoint, outcome)
        });
    }

    while let Some(joined) = tasks.join_next().await {
        let Ok((endpoint, outcome)) = joined else {
            // The blocking thread panicked; treat it like a failed probe (no evidence either way).
            continue;
        };
        match outcome {
            Ok(true) => {
                tracing::info!(
                    url = %endpoint.url,
                    provider = %endpoint.provider,
                    "captive: captive portal detected"
                );
                return true;
            }
            Ok(false) => {}
            Err(e) => {
                tracing::debug!(
                    url = %endpoint.url,
                    error = %e,
                    "captive: endpoint check failed (not evidence of a portal)"
                );
            }
        }
    }

    tracing::debug!("captive: no captive portal detected");
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// A 204 endpoint with the DERP challenge, at the given (documentation-range) IPv4.
    fn derp_endpoint(ip: &str) -> Endpoint {
        Endpoint {
            url: url::Url::parse(&format!("http://{ip}/generate_204")).unwrap(),
            status_code: 204,
            expected_content: String::new(),
            supports_tailscale_challenge: true,
            provider: EndpointProvider::DerpMapOther,
        }
    }

    #[test]
    fn challenge_and_response_use_gos_host_spelling() {
        let e = derp_endpoint("192.0.2.10");
        assert_eq!(e.host(), "192.0.2.10");
        assert_eq!(e.challenge(), "ts_192.0.2.10");
        assert_eq!(e.expected_response(), "response ts_192.0.2.10");

        // An explicit non-default port is part of Go's `url.URL.Host`, so it is part of the challenge.
        let mut with_port = e.clone();
        with_port.url = url::Url::parse("http://192.0.2.10:8080/generate_204").unwrap();
        assert_eq!(with_port.host(), "192.0.2.10:8080");
        assert_eq!(with_port.challenge(), "ts_192.0.2.10:8080");

        // ...but the default port 80 is not (Go's `url.Parse` leaves it out of `Host`).
        let mut default_port = e.clone();
        default_port.url = url::Url::parse("http://192.0.2.10:80/generate_204").unwrap();
        assert_eq!(
            default_port.host(),
            "192.0.2.10",
            "an explicit :80 is the default for http and must not appear in the challenge"
        );
    }

    #[test]
    fn a_clean_204_with_the_echo_is_not_captive() {
        let e = derp_endpoint("192.0.2.10");
        assert!(
            !e.response_looks_like_captive(204, Some("response ts_192.0.2.10"), None),
            "the promised status plus the correct challenge echo is a clean network"
        );
    }

    #[test]
    fn a_wrong_status_is_captive() {
        let e = derp_endpoint("192.0.2.10");
        // The two shapes a portal actually takes: it serves its login page, or redirects to it.
        for status in [200u16, 302] {
            assert!(
                e.response_looks_like_captive(status, Some("response ts_192.0.2.10"), None),
                "status {status} instead of the promised 204 must read as captive"
            );
        }
    }

    #[test]
    fn a_204_without_the_correct_echo_is_captive() {
        let e = derp_endpoint("192.0.2.10");
        // The portal-mimics-204 case the challenge exists to catch: right status, no echo.
        assert!(
            e.response_looks_like_captive(204, None, None),
            "a 204 with no X-Tailscale-Response must read as captive"
        );
        // ...and an echo naming a different host (a replayed/forged header) is no better.
        assert!(
            e.response_looks_like_captive(204, Some("response ts_192.0.2.99"), None),
            "an echo for a different host must read as captive"
        );
        assert!(
            e.response_looks_like_captive(204, Some(""), None),
            "an empty X-Tailscale-Response must read as captive"
        );
    }

    #[test]
    fn a_missing_echo_is_ignored_when_the_endpoint_does_not_support_the_challenge() {
        // The Tailscale coordination/console endpoints do not echo, so only the status is checked.
        let mut e = derp_endpoint("192.0.2.10");
        e.supports_tailscale_challenge = false;
        assert!(
            !e.response_looks_like_captive(204, None, None),
            "a non-challenge endpoint answering 204 is clean even with no echo header"
        );
    }

    #[test]
    fn expected_content_is_matched_against_the_body() {
        let mut e = derp_endpoint("192.0.2.10");
        e.supports_tailscale_challenge = false;
        e.status_code = 200;
        e.expected_content = "Success".to_string();

        assert!(
            !e.response_looks_like_captive(200, None, Some(b"<html>Success</html>")),
            "the marker is present, so the response is clean"
        );
        assert!(
            e.response_looks_like_captive(200, None, Some(b"<html>Please log in</html>")),
            "the marker is absent, so somebody replaced the body"
        );
        // Go's `io.ReadAll` failure arm: a body we could not read is NOT evidence of a portal.
        assert!(
            !e.response_looks_like_captive(200, None, None),
            "an unreadable body must fail open (Go returns false), not raise a portal warning"
        );
    }

    #[test]
    fn available_endpoints_without_a_derp_map_yields_the_tailscale_pair() {
        // The live shape today: no DERP map reachable from the daemon, so Go's always-appended pair
        // is the whole list.
        let endpoints = available_endpoints(&[], None);
        let urls: Vec<String> = endpoints.iter().map(|e| e.url.to_string()).collect();
        assert_eq!(
            urls,
            vec![
                "http://controlplane.tailscale.com/generate_204".to_string(),
                "http://login.tailscale.com/generate_204".to_string(),
            ]
        );
        for e in &endpoints {
            assert_eq!(e.provider, EndpointProvider::Tailscale);
            assert_eq!(e.status_code, 204);
            assert!(
                !e.supports_tailscale_challenge,
                "neither Tailscale endpoint echoes the challenge header"
            );
        }
    }

    #[test]
    fn available_endpoints_ranks_the_preferred_region_first() {
        let regions = vec![
            DerpRegion {
                region_id: 2,
                avoid: false,
                no_measure_no_home: false,
                nodes: vec![DerpNode {
                    ipv4: "192.0.2.20".to_string(),
                    can_port80: true,
                }],
            },
            DerpRegion {
                region_id: 1,
                avoid: false,
                no_measure_no_home: false,
                nodes: vec![DerpNode {
                    ipv4: "192.0.2.10".to_string(),
                    can_port80: true,
                }],
            },
        ];
        // Region 1 is this node's home even though region 2 comes first in the map.
        let endpoints = available_endpoints(&regions, Some(1));
        let providers: Vec<EndpointProvider> = endpoints.iter().map(|e| e.provider).collect();
        assert_eq!(
            providers,
            vec![
                EndpointProvider::DerpMapPreferred,
                EndpointProvider::DerpMapOther,
                EndpointProvider::Tailscale,
                EndpointProvider::Tailscale,
            ]
        );
        assert_eq!(
            endpoints[0].url.as_str(),
            "http://192.0.2.10/generate_204",
            "the preferred region's node must be probed first"
        );
        assert!(
            endpoints[0].supports_tailscale_challenge,
            "DERP endpoints carry the challenge"
        );
    }

    #[test]
    fn available_endpoints_skips_unprobeable_derp_nodes() {
        let regions = vec![
            // Control told clients to avoid this region.
            DerpRegion {
                region_id: 1,
                avoid: true,
                no_measure_no_home: false,
                nodes: vec![DerpNode {
                    ipv4: "192.0.2.10".to_string(),
                    can_port80: true,
                }],
            },
            // Not to be measured or homed to.
            DerpRegion {
                region_id: 2,
                avoid: false,
                no_measure_no_home: true,
                nodes: vec![DerpNode {
                    ipv4: "192.0.2.20".to_string(),
                    can_port80: true,
                }],
            },
            // Probeable region, but neither node can answer: one has no IPv4, one has no port 80.
            DerpRegion {
                region_id: 3,
                avoid: false,
                no_measure_no_home: false,
                nodes: vec![
                    DerpNode {
                        ipv4: String::new(),
                        can_port80: true,
                    },
                    DerpNode {
                        ipv4: "192.0.2.30".to_string(),
                        can_port80: false,
                    },
                ],
            },
        ];
        let endpoints = available_endpoints(&regions, Some(1));
        assert!(
            endpoints
                .iter()
                .all(|e| e.provider == EndpointProvider::Tailscale),
            "every DERP node here is unprobeable, so only the Tailscale pair may survive: {:?}",
            endpoints.iter().map(|e| e.url.as_str()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn excluded_interface_prefixes_match_go_per_goos() {
        // Excluded everywhere: our own tunnel and the other virtual/tunnel devices.
        for name in [
            "tailscale0",
            "tun0",
            "tap0",
            "docker0",
            "kube-br",
            "wg0",
            "ipsec1",
        ] {
            assert!(
                interface_name_does_not_need_captive_detection(name, "linux"),
                "{name} is a virtual/tunnel device and must never be probed"
            );
        }
        // A real uplink is not excluded.
        for name in ["eth0", "wlan0", "enp3s0"] {
            assert!(
                !interface_name_does_not_need_captive_detection(name, "linux"),
                "{name} is a real uplink and must be probed"
            );
        }
        // Per-GOOS lists apply only on their own GOOS.
        assert!(interface_name_does_not_need_captive_detection(
            "utun3", "darwin"
        ));
        assert!(interface_name_does_not_need_captive_detection(
            "awdl0", "darwin"
        ));
        assert!(
            !interface_name_does_not_need_captive_detection("awdl0", "linux"),
            "the darwin-only prefixes must not leak onto other platforms"
        );
        assert!(interface_name_does_not_need_captive_detection(
            "rmnet0", "android"
        ));
        assert!(
            !interface_name_does_not_need_captive_detection("rmnet0", "darwin"),
            "the android-only prefixes must not leak onto other platforms"
        );
        assert!(interface_name_does_not_need_captive_detection(
            "teredo", "windows"
        ));
        // Go lowercases the name before matching, so Windows' friendly names match too.
        assert!(
            interface_name_does_not_need_captive_detection(
                "Loopback Pseudo-Interface 1",
                "windows"
            ),
            "matching must be case-insensitive, as in Go"
        );
    }

    #[test]
    fn goos_reports_gos_spelling_for_this_host() {
        // The per-OS prefix lists are keyed on Go's names, so macOS must map to "darwin".
        assert_eq!(
            goos(),
            if cfg!(target_os = "macos") {
                "darwin"
            } else {
                std::env::consts::OS
            }
        );
    }

    #[test]
    fn detection_interfaces_keeps_only_real_uplinks() {
        let v4 = |a, b, c, d| IpAddr::V4(Ipv4Addr::new(a, b, c, d));
        let ifaces = [
            ("wlan0", v4(192, 0, 2, 5)),
            ("eth0", v4(198, 51, 100, 7)),
            ("lo", IpAddr::V4(Ipv4Addr::LOCALHOST)),
            ("lo", IpAddr::V6(Ipv6Addr::LOCALHOST)),
            ("tailscale0", v4(100, 64, 0, 3)),
            ("docker0", v4(203, 0, 113, 1)),
        ];
        let kept = detection_interfaces(ifaces.iter().copied(), "linux");
        assert_eq!(
            kept,
            ["eth0".to_string(), "wlan0".to_string()]
                .into_iter()
                .collect::<BTreeSet<_>>(),
            "only the real uplinks survive: loopback, the tailnet tunnel and docker are all excluded"
        );
    }

    #[test]
    fn detection_interfaces_is_empty_when_nothing_is_up() {
        // Go's `!ifState.AnyInterfaceUp()` case — `detect` must not probe at all.
        let kept = detection_interfaces(std::iter::empty(), "linux");
        assert!(kept.is_empty());
        // Loopback alone is still "nothing to probe".
        let only_lo = detection_interfaces([("lo", IpAddr::V4(Ipv4Addr::LOCALHOST))], "linux");
        assert!(
            only_lo.is_empty(),
            "a host with only loopback has no path a portal could sit on"
        );
    }

    /// A canned transport for [`probe_endpoint_with`]: records the request the check built (so the
    /// stamp + challenge can be asserted) and answers with `response`.
    fn canned(
        seen: &std::cell::RefCell<Option<ProbeRequest>>,
        response: ProbeResponse,
    ) -> impl FnOnce(&ProbeRequest) -> anyhow::Result<ProbeResponse> + '_ {
        move |req| {
            *seen.borrow_mut() = Some(req.clone());
            Ok(response)
        }
    }

    #[test]
    fn probe_builds_gos_request_and_reads_a_clean_derp_answer_as_no_portal() {
        let endpoint = Endpoint {
            url: url::Url::parse("http://192.0.2.10/generate_204").unwrap(),
            status_code: 204,
            expected_content: String::new(),
            supports_tailscale_challenge: true,
            provider: EndpointProvider::DerpMapPreferred,
        };
        let seen = std::cell::RefCell::new(None);
        let found = probe_endpoint_with(
            &endpoint,
            1_700_000_000,
            canned(
                &seen,
                ProbeResponse {
                    status: 204,
                    tailscale_response: Some("response ts_192.0.2.10".to_string()),
                    body: None,
                },
            ),
        )
        .expect("the canned transport cannot fail");
        assert!(
            !found,
            "a 204 carrying the correct challenge echo is a clean network, not a portal"
        );

        let req = seen
            .into_inner()
            .expect("the transport must have been called");
        assert_eq!(
            req.url.as_str(),
            "http://192.0.2.10/generate_204?t=1700000000",
            "Go appends a unix-second `t` param so no cache can answer the probe"
        );
        assert_eq!(
            req.challenge.as_deref(),
            Some("ts_192.0.2.10"),
            "a DERP endpoint must be sent the challenge naming its own host"
        );
        assert!(
            !req.wants_body,
            "with no expected_content Go never reads the body"
        );
    }

    #[test]
    fn probe_does_not_challenge_an_endpoint_that_cannot_echo() {
        // The Tailscale coordination/console endpoints do not implement the echo; sending the header
        // to them would be noise, and Go only attaches it for `SupportsTailscaleChallenge`.
        let endpoint = Endpoint {
            url: url::Url::parse("http://controlplane.tailscale.com/generate_204").unwrap(),
            status_code: 204,
            expected_content: String::new(),
            supports_tailscale_challenge: false,
            provider: EndpointProvider::Tailscale,
        };
        let seen = std::cell::RefCell::new(None);
        let found = probe_endpoint_with(
            &endpoint,
            1_700_000_000,
            canned(
                &seen,
                ProbeResponse {
                    status: 204,
                    tailscale_response: None,
                    body: None,
                },
            ),
        )
        .expect("the canned transport cannot fail");
        assert!(
            !found,
            "a clean 204 from a non-echoing endpoint is not a portal"
        );
        assert_eq!(
            seen.into_inner().unwrap().challenge,
            None,
            "no challenge header may be sent to an endpoint that cannot echo it"
        );
    }

    #[test]
    fn probe_sees_a_portal_redirect() {
        // What a real portal does to a `/generate_204`: a 302 at its login page.
        let endpoint = Endpoint {
            url: url::Url::parse("http://controlplane.tailscale.com/generate_204").unwrap(),
            status_code: 204,
            expected_content: String::new(),
            supports_tailscale_challenge: false,
            provider: EndpointProvider::Tailscale,
        };
        let seen = std::cell::RefCell::new(None);
        let found = probe_endpoint_with(
            &endpoint,
            1_700_000_000,
            canned(
                &seen,
                ProbeResponse {
                    status: 302,
                    tailscale_response: None,
                    body: None,
                },
            ),
        )
        .expect("the canned transport cannot fail");
        assert!(
            found,
            "a 302 to a login page instead of the promised 204 is exactly the captive-portal signal"
        );
    }

    #[test]
    fn probe_sees_a_portal_that_answers_204_without_the_echo() {
        // The subtle case: the portal returns the promised status but cannot produce the echo.
        let endpoint = Endpoint {
            url: url::Url::parse("http://192.0.2.10/generate_204").unwrap(),
            status_code: 204,
            expected_content: String::new(),
            supports_tailscale_challenge: true,
            provider: EndpointProvider::DerpMapPreferred,
        };
        let seen = std::cell::RefCell::new(None);
        let found = probe_endpoint_with(
            &endpoint,
            1_700_000_000,
            canned(
                &seen,
                ProbeResponse {
                    status: 204,
                    tailscale_response: None,
                    body: None,
                },
            ),
        )
        .expect("the canned transport cannot fail");
        assert!(
            found,
            "a 204 with no X-Tailscale-Response must be caught by the challenge check"
        );
    }

    #[test]
    fn probe_propagates_a_transport_failure_instead_of_calling_it_a_portal() {
        // Go's caller treats a failed request as no evidence either way, so the check must surface
        // the error rather than convert an unreachable endpoint into a captive-portal verdict.
        let endpoint = Endpoint {
            url: url::Url::parse("http://192.0.2.10/generate_204").unwrap(),
            status_code: 204,
            expected_content: String::new(),
            supports_tailscale_challenge: true,
            provider: EndpointProvider::DerpMapOther,
        };
        let outcome = probe_endpoint_with(&endpoint, 1_700_000_000, |_| {
            Err(anyhow::anyhow!("connection refused"))
        });
        assert!(
            outcome.is_err(),
            "an unreachable endpoint must be an error, never a captive-portal verdict"
        );
    }

    #[test]
    fn probe_asks_for_the_body_only_when_content_is_expected() {
        // Go reads the body only for an endpoint that declares ExpectedContent; the request carries
        // that decision so the transport does not pull a portal's whole login page for nothing.
        let mut endpoint = Endpoint {
            url: url::Url::parse("http://192.0.2.10/generate_204").unwrap(),
            status_code: 200,
            expected_content: "Success".to_string(),
            supports_tailscale_challenge: false,
            provider: EndpointProvider::DerpMapOther,
        };
        let seen = std::cell::RefCell::new(None);
        let found = probe_endpoint_with(
            &endpoint,
            1_700_000_000,
            canned(
                &seen,
                ProbeResponse {
                    status: 200,
                    tailscale_response: None,
                    body: Some(b"<html>Success</html>".to_vec()),
                },
            ),
        )
        .expect("the canned transport cannot fail");
        assert!(
            !found,
            "the expected marker is present, so the body is clean"
        );
        assert!(
            seen.into_inner().unwrap().wants_body,
            "an endpoint with expected_content must ask the transport for the body"
        );

        endpoint.expected_content = String::new();
        let seen = std::cell::RefCell::new(None);
        let _ = probe_endpoint_with(
            &endpoint,
            1_700_000_000,
            canned(
                &seen,
                ProbeResponse {
                    status: 200,
                    tailscale_response: None,
                    body: None,
                },
            ),
        );
        assert!(!seen.into_inner().unwrap().wants_body);
    }

    #[test]
    fn warnable_text_matches_go() {
        // The exact string Go's health tracker puts in `ipnstate.Status.Health`, which `tnet status`
        // prints. Pinned so a reword can't silently diverge from `tailscale status`.
        assert_eq!(
            WARNABLE_TEXT,
            "This network requires you to log in using your web browser."
        );
        assert_eq!(WARNABLE_CODE, "captive-portal-detected");
    }
}
