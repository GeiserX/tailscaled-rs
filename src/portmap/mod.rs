//! Port mapper: NAT-PMP, PCP and UPnP-IGD — the port of Go's `net/portmapper` package
//! (tailscale v1.100.0).
//!
//! ## What it is for
//!
//! Two nodes behind NAT reach each other directly only if each can learn a public `ip:port` that
//! forwards to its local WireGuard socket. STUN discovers one when the NAT is well-behaved; when it
//! is not, the fallback is to *ask the router for one*. Most consumer routers speak at least one of
//! three protocols for exactly that:
//!
//! | Protocol | Spec | Transport |
//! |---|---|---|
//! | NAT-PMP | RFC 6886 | UDP to `gateway:5351` ([`pmp`]) |
//! | PCP | RFC 6887 | UDP to `gateway:5351` ([`pcp`]) |
//! | UPnP-IGD | UPnP Forum | SSDP over UDP `1900`, then HTTP/SOAP ([`upnp`]) |
//!
//! A mapping obtained this way is what turns a would-be DERP-relayed connection into a direct one,
//! which is why Go runs the port mapper alongside every net-report.
//!
//! ## What this module is (and what it is not)
//!
//! It is a complete, standalone client for those three protocols: discovery
//! ([`Client::probe`]) and mapping acquisition ([`Client::create_mapping`]), addressed at the
//! gateway found by [`gateway::gateway_and_self_ip`].
//!
//! It is **not** wired into the data plane, and cannot be from here. Deciding which endpoints to
//! advertise to peers is magicsock's job, and magicsock lives in the engine (`tailscale-rs`), which
//! at the pinned rev has no port-mapping code and no seam to hand an externally-mapped endpoint to.
//! Closing that last gap is an engine change, so what this daemon can own — and what it does own —
//! is the client itself plus the operator-facing diagnostic that drives it end to end
//! (`tnet debug portmap`, Go's `tailscale debug portmap`): does this network offer port mapping, and
//! what external endpoint does it hand out?
//!
//! ## Structure
//!
//! - [`pmp`] / [`pcp`] — the two UDP protocols' wire formats, as pure functions.
//! - [`upnp`] — SSDP discovery, device-description parsing, service selection and the SOAP calls.
//! - [`gateway`] — finding the default gateway and this host's address on its LAN.
//! - [`debug`] — the `debug portmap` diagnostic that drives all of the above and narrates it.
//! - This file — the [`Client`] that drives them: one UDP socket, Go's probe loop, and Go's
//!   PCP-vs-PMP-vs-UPnP preference order when acquiring a mapping.
//!
//! ## Deviations from Go, all deliberate
//!
//! - **No mapping cache, no renewal loop.** Go's `Client` keeps the current mapping, renews it at
//!   half its lifetime, and republishes it on an event bus for magicsock. With no consumer for the
//!   mapping (see above) there is nothing to keep alive, so [`Client::create_mapping`] is one-shot:
//!   it acquires a mapping and reports it. The lifetime the router granted is reported so the
//!   renewal deadline is still visible.
//! - **No `goupnp`.** See [`upnp`].
//! - **`ErrGatewayIPv6` has no counterpart.** Go checks whether the discovered gateway is IPv6 and
//!   refuses; [`gateway`] here only ever yields an IPv4 gateway, so the case cannot arise.

pub mod debug;
pub mod gateway;
pub mod pcp;
pub mod pmp;
pub mod upnp;

use std::fmt;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;

/// How long we wait for a port-mapping service to answer before deciding it is not there. Go:
/// `portMapServiceTimeout` — "Since these services are on the same LAN as this machine and a single
/// L3 hop away, we don't give them much time to respond."
pub const PORT_MAP_SERVICE_TIMEOUT: Duration = Duration::from_millis(250);

/// How long the probe keeps listening for further UPnP answers after the first packet arrives.
///
/// A LAN can hold more than one UPnP router; Go waits this long "rather than randomly picking
/// whichever arrives first", then ranks the collected responses deterministically.
pub const UPNP_SETTLE_TIMEOUT: Duration = Duration::from_millis(50);

/// Cap on how many UPnP discovery responses are kept (Go: "too many UPnP responses: skipping"). A
/// bound on what an SSDP flood can make the client hold.
pub const MAX_UPNP_RESPONSES: usize = 10;

/// Where a log line from the port mapper goes. `tnet debug portmap` streams these to the operator,
/// so it is a callback rather than a `tracing` target: the caller decides where each line lands.
pub type LogSink = Arc<dyn Fn(&str) + Send + Sync>;

/// The port mapper's logger: an always-on line ([`Logger::log`]) and a verbose-only one
/// ([`Logger::vlog`]), matching Go's `c.logf` / `c.vlogf` split so a normal run stays quiet and
/// `--verbose`-style debugging gets the packet-level detail.
#[derive(Clone)]
pub struct Logger {
    sink: LogSink,
    verbose: bool,
}

impl Logger {
    /// A logger writing to `sink`; `verbose` enables [`Logger::vlog`] (Go: `DebugKnobs.VerboseLogs`).
    pub fn new(sink: LogSink, verbose: bool) -> Self {
        Self { sink, verbose }
    }

    /// A logger that drops everything — for callers that only want the result.
    pub fn discard() -> Self {
        Self::new(Arc::new(|_: &str| {}), false)
    }

    /// Log a line unconditionally.
    pub fn log(&self, msg: impl AsRef<str>) {
        (self.sink)(msg.as_ref());
    }

    /// Log a line only in verbose mode.
    pub fn vlog(&self, msg: impl AsRef<str>) {
        if self.verbose {
            (self.sink)(msg.as_ref());
        }
    }
}

impl fmt::Debug for Logger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Logger")
            .field("verbose", &self.verbose)
            .finish_non_exhaustive()
    }
}

/// Debug configuration for a [`Client`] (Go: `portmapper.DebugKnobs`). The zero value is the normal
/// production configuration: quiet, and all three protocols enabled.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DebugKnobs {
    /// Print the per-packet detail (Go: `VerboseLogs`).
    pub verbose_logs: bool,
    /// Print the UPnP HTTP requests and responses, "useful when debugging buggy UPnP
    /// implementations" (Go: `LogHTTP`).
    pub log_http: bool,
    /// Skip UPnP entirely.
    pub disable_upnp: bool,
    /// Skip NAT-PMP entirely.
    pub disable_pmp: bool,
    /// Skip PCP entirely.
    pub disable_pcp: bool,
}

/// The `type` selector of Go's `debug-portmap` endpoint refused: it was not one of the four values
/// the endpoint accepts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnknownDebugType(pub String);

impl fmt::Display for UnknownDebugType {
    /// Go's `serveDebugPortmap` answers this exact text with a 400.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unknown portmap debug type")
    }
}

impl std::error::Error for UnknownDebugType {}

impl DebugKnobs {
    /// Knobs for one `debug portmap --type` selector (Go: the `switch r.FormValue("type")` in
    /// `serveDebugPortmap`).
    ///
    /// The empty string means "try everything"; each named protocol is expressed by *disabling the
    /// other two*, which is exactly how Go isolates one protocol. Anything else is refused rather
    /// than silently treated as "all" — a typo'd `--type upnpp` must not look like a successful
    /// all-protocol run.
    pub fn for_debug_type(ty: &str) -> Result<Self, UnknownDebugType> {
        // Go's handler always sets VerboseLogs for this endpoint: the whole point of the command is
        // to watch what the protocols do.
        let base = DebugKnobs {
            verbose_logs: true,
            ..DebugKnobs::default()
        };
        match ty {
            "" => Ok(base),
            "pmp" => Ok(DebugKnobs {
                disable_pcp: true,
                disable_upnp: true,
                ..base
            }),
            "pcp" => Ok(DebugKnobs {
                disable_pmp: true,
                disable_upnp: true,
                ..base
            }),
            "upnp" => Ok(DebugKnobs {
                disable_pcp: true,
                disable_pmp: true,
                ..base
            }),
            other => Err(UnknownDebugType(other.to_string())),
        }
    }

    /// Whether every protocol is disabled, i.e. there is nothing left to try (Go: the
    /// `DisableUPnP() && DisablePCP() && DisablePMP()` check in `createOrGetMapping`).
    pub fn all_disabled(&self) -> bool {
        self.disable_upnp && self.disable_pmp && self.disable_pcp
    }

    /// Apply the environment kill-switches Go honours: `TS_DISABLE_PORTMAPPER` turns the whole port
    /// mapper off (Go: `disablePortMapperEnv`), `TS_DISABLE_UPNP` turns off UPnP alone (Go:
    /// `disableUPnpEnv`). Both are read here, once, so a [`Client`] carries the decision rather than
    /// re-reading the environment per packet.
    pub fn with_env_overrides(mut self, env: impl Fn(&str) -> Option<String>) -> Self {
        if truthy(env("TS_DISABLE_PORTMAPPER").as_deref()) {
            self.disable_upnp = true;
            self.disable_pmp = true;
            self.disable_pcp = true;
        }
        if truthy(env("TS_DISABLE_UPNP").as_deref()) {
            self.disable_upnp = true;
        }
        self
    }
}

/// Go's `envknob` boolean parse, reduced to what these two knobs need: an unset or empty variable is
/// false, `0`/`false` is false, anything else set is true.
fn truthy(v: Option<&str>) -> bool {
    match v {
        None | Some("") | Some("0") | Some("false") | Some("FALSE") | Some("False") => false,
        Some(_) => true,
    }
}

/// Which port-mapping services answered a [`Client::probe`] (Go: `portmappertype.ProbeResult`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProbeResult {
    /// A PCP server answered, and is willing to serve us.
    pub pcp: bool,
    /// A NAT-PMP server answered.
    pub pmp: bool,
    /// At least one UPnP-IGD device answered the SSDP search.
    pub upnp: bool,
}

impl ProbeResult {
    /// Whether any service at all is available — Go's `!res.PCP && !res.PMP && !res.UPnP` check,
    /// after which `debug portmap` prints "no portmapping services available" and stops.
    pub fn any(&self) -> bool {
        self.pcp || self.pmp || self.upnp
    }
}

impl fmt::Display for ProbeResult {
    /// Go's handler logs the probe with `%+v`, i.e. `{PCP:false PMP:true UPnP:false}`. Reproduced so
    /// the transcripts line up.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{PCP:{} PMP:{} UPnP:{}}}",
            self.pcp, self.pmp, self.upnp
        )
    }
}

/// Which protocol produced a mapping (Go: `mapping.MappingType()`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MappingKind {
    /// NAT-PMP.
    Pmp,
    /// PCP.
    Pcp,
    /// UPnP-IGD.
    Upnp,
}

impl fmt::Display for MappingKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Pmp => "pmp",
            Self::Pcp => "pcp",
            Self::Upnp => "upnp",
        })
    }
}

/// A port mapping the gateway granted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mapping {
    /// The external endpoint the mapping forwards from — what a peer would dial.
    pub external: SocketAddrV4,
    /// Which protocol produced it.
    pub kind: MappingKind,
    /// How long the gateway said the mapping is good for. Go renews at half this; with no renewal
    /// loop here (see the module docs) it is reported so the deadline is at least visible.
    pub lifetime: Duration,
}

/// Why no mapping could be obtained. The four sentinel cases are Go's package-level errors, with
/// their exact messages, because they are what the operator sees in a `debug portmap` transcript.
#[derive(Debug)]
pub enum Error {
    /// Go: `ErrPortMappingDisabled`.
    PortMappingDisabled,
    /// Go: `ErrNoPortMappingServices`.
    NoPortMappingServices,
    /// Go: `ErrGatewayRange`.
    GatewayRange,
    /// Go wraps every mapping failure in `NoMappingError` so callers can tell "this network has no
    /// port mapping" from a real I/O failure (`portmapper.IsNoMappingError`).
    NoMapping(Box<Error>),
    /// A socket error.
    Io(std::io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PortMappingDisabled => f.write_str("port mapping is disabled"),
            Self::NoPortMappingServices => f.write_str("no port mapping services were found"),
            Self::GatewayRange => {
                f.write_str("skipping portmap; gateway range likely lacks support")
            }
            Self::NoMapping(inner) => write!(f, "no NAT mapping available: {inner}"),
            Self::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NoMapping(inner) => Some(inner),
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl Error {
    /// Whether this is Go's `NoMappingError` — "there is no mapping to be had here", as opposed to a
    /// transport failure worth reporting loudly (Go: `IsNoMappingError`).
    pub fn is_no_mapping(&self) -> bool {
        matches!(self, Self::NoMapping(_))
    }

    /// Wrap `self` the way Go's `NoMappingError{err}` does.
    fn no_mapping(self) -> Self {
        Self::NoMapping(Box::new(self))
    }
}

/// A port-mapping client bound to one gateway (Go: `portmapper.Client`).
///
/// Unlike Go's, it holds no mapping and runs no background goroutine — see the module docs. What it
/// does hold between calls is the set of UPnP discovery responses [`Client::probe`] collected, which
/// is what the UPnP mapping path needs and what Go likewise caches on the client (`uPnPMetas`).
#[derive(Debug)]
pub struct Client {
    gw: Ipv4Addr,
    self_ip: Ipv4Addr,
    local_port: u16,
    knobs: DebugKnobs,
    log: Logger,
    upnp_metas: Vec<upnp::DiscoResponse>,
}

impl Client {
    /// A client that will ask `gw` for mappings that forward to `self_ip:local_port`.
    pub fn new(
        gw: Ipv4Addr,
        self_ip: Ipv4Addr,
        local_port: u16,
        knobs: DebugKnobs,
        log: Logger,
    ) -> Self {
        Self {
            gw,
            self_ip,
            local_port,
            knobs,
            log,
            upnp_metas: Vec::new(),
        }
    }

    /// The UPnP discovery responses the last [`Client::probe`] collected, deduplicated and ordered.
    pub fn upnp_metas(&self) -> &[upnp::DiscoResponse] {
        &self.upnp_metas
    }

    /// Ask the network which port-mapping services it offers (Go: `Client.Probe`).
    ///
    /// One UDP socket sends all three probes — a NAT-PMP "what is my external address", a PCP
    /// ANNOUNCE, and the two SSDP searches — and then reads answers until every service has been
    /// heard from or [`PORT_MAP_SERVICE_TIMEOUT`] expires. The SSDP searches go to the gateway's
    /// unicast address *and* the multicast group, in that order, for the reasons Go documents at
    /// length: some devices only answer multicast, some LANs break multicast, and sending the unicast
    /// query first teaches a stateful host firewall to expect the unicast reply that a multicast
    /// query produces.
    pub async fn probe(&mut self) -> Result<ProbeResult, Error> {
        if self.knobs.all_disabled() {
            return Err(Error::PortMappingDisabled);
        }
        let mut res = ProbeResult::default();

        let sock = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)).await?;
        let pxp_addr = SocketAddrV4::new(self.gw, pmp::DEFAULT_PORT);
        let upnp_addr = SocketAddrV4::new(self.gw, upnp::DEFAULT_PORT);
        let upnp_multicast_addr = SocketAddrV4::new(upnp::SSDP_MULTICAST_ADDR, upnp::DEFAULT_PORT);

        if !self.knobs.disable_pmp {
            self.send(&sock, &pmp::REQ_EXTERNAL_ADDR_PACKET, pxp_addr)
                .await;
        }
        if !self.knobs.disable_pcp {
            self.send(&sock, &pcp::announce_request(self.self_ip), pxp_addr)
                .await;
        }
        if !self.knobs.disable_upnp {
            self.send(&sock, &upnp::m_search_all_packet(), upnp_addr)
                .await;
            self.send(&sock, &upnp::m_search_all_packet(), upnp_multicast_addr)
                .await;
            self.send(&sock, &upnp::m_search_igd_packet(), upnp_multicast_addr)
                .await;
        }

        let deadline = tokio::time::Instant::now() + PORT_MAP_SERVICE_TIMEOUT;
        // The settle timer starts when the FIRST packet arrives, not now: it exists to collect the
        // stragglers of a multi-router LAN, not to delay a quiet network.
        let mut upnp_settled_at: Option<tokio::time::Instant> = None;
        let mut pcp_heard = false;
        let mut upnp_responses: Vec<upnp::DiscoResponse> = Vec::new();
        let mut buf = vec![0u8; 1500];

        loop {
            if pcp_heard && res.pmp && res.upnp {
                // Everything answered. Keep reading only while the UPnP settle window is open.
                match upnp_settled_at {
                    Some(at) if tokio::time::Instant::now() >= at => break,
                    None => break,
                    Some(_) => {}
                }
            }
            let now = tokio::time::Instant::now();
            if now >= deadline {
                break;
            }
            let read = tokio::time::timeout_at(deadline, sock.recv_from(&mut buf)).await;
            let (n, src) = match read {
                // Go treats a deadline-exceeded read as a successful, complete probe.
                Err(_elapsed) => break,
                Ok(Err(e)) => return Err(Error::Io(e)),
                Ok(Ok(v)) => v,
            };
            if upnp_settled_at.is_none() {
                upnp_settled_at = Some(tokio::time::Instant::now() + UPNP_SETTLE_TIMEOUT);
            }
            let SocketAddr::V4(src) = src else {
                continue; // the socket is IPv4; anything else is not an answer to these probes
            };
            let payload = &buf[..n];

            // Go dispatches on the SOURCE port, and the order matters: 1900 is a UPnP answer, 5351
            // is PMP or PCP, and a datagram from ANY OTHER port is still taken as a UPnP answer if it
            // mentions an InternetGatewayDevice (tailscale#7377 — devices really do reply from an
            // ephemeral port).
            let looks_upnp = contains(payload, b":InternetGatewayDevice:");
            if src.port() == upnp::DEFAULT_PORT {
                if looks_upnp {
                    self.handle_upnp_response(payload, src, &mut res, &mut upnp_responses);
                }
                continue;
            }
            if src.port() != pmp::DEFAULT_PORT {
                if looks_upnp {
                    self.log.log(format!(
                        "UPnP discovery response from non-UPnP port {}",
                        src.port()
                    ));
                    self.handle_upnp_response(payload, src, &mut res, &mut upnp_responses);
                }
                continue;
            }

            // A datagram from the PMP/PCP port: PCP first (its version byte is 2), then
            // NAT-PMP (version 0) — the same order Go tries them in on this shared port.
            if let Some(pres) = pcp::parse_response(payload)
                && pres.op_code == pcp::OP_REPLY | pcp::OP_ANNOUNCE
            {
                pcp_heard = true;
                match pres.result_code {
                    pcp::ResultCode::OK => {
                        self.log
                            .vlog(format!("Got PCP response: epoch: {}", pres.epoch));
                        res.pcp = true;
                        continue;
                    }
                    // A PCP service is running but refuses to serve us; and a PCP service
                    // behind another NAT cannot help us. Both are "PCP is not available",
                    // NOT "no PCP here" — which is why Go records them separately.
                    pcp::ResultCode::NOT_AUTHORIZED | pcp::ResultCode::ADDRESS_MISMATCH => {
                        self.log.log(format!(
                            "PCP probe answered {} ({}); PCP unavailable",
                            pres.result_code, pres.result_code.0
                        ));
                        res.pcp = false;
                        continue;
                    }
                    _ => {
                        self.log
                            .log(format!("unexpected PCP probe response: {pres:?}"));
                    }
                }
            }
            if let Some(pres) = pmp::parse_response(payload) {
                if pres.op_code != pmp::OP_REPLY | pmp::OP_MAP_PUBLIC_ADDR {
                    self.log
                        .log(format!("unexpected PMP probe response opcode: {pres:?}"));
                    continue;
                }
                match pres.result_code {
                    pmp::ResultCode::OK => {
                        self.log.vlog(format!(
                            "Got PMP response; IP: {:?}, epoch: {}",
                            pres.public_addr, pres.seconds_since_epoch
                        ));
                        res.pmp = true;
                    }
                    code => {
                        // NotAuthorized / NetworkFailure / OutOfResources and anything else: a
                        // NAT-PMP server IS there, but it will not give us a mapping.
                        self.log
                            .log(format!("PMP probe failed due result code: {code}"));
                    }
                }
            }
        }

        if res.upnp && !upnp_responses.is_empty() {
            self.upnp_metas = upnp::process_upnp_responses(upnp_responses);
            self.log.vlog(format!("UPnP meta: {:?}", self.upnp_metas));
        }
        Ok(res)
    }

    /// Ask for a mapping of `local_port`, and report the external endpoint it produced (Go:
    /// `Client.createOrGetMapping`, minus the cache and renewal — see the module docs).
    ///
    /// `probe` is the result of a preceding [`Client::probe`] and decides the order things are tried
    /// in, exactly as Go's "did we see this recently" state does: PCP is preferred only when PMP was
    /// NOT seen and PCP was (or when PMP is disabled), because NAT-PMP is the more widely working of
    /// the two; UPnP is the fallback when the UDP protocols produce nothing.
    pub async fn create_mapping(&self, probe: &ProbeResult) -> Result<Mapping, Error> {
        if self.knobs.all_disabled() {
            return Err(Error::PortMappingDisabled.no_mapping());
        }
        let internal = SocketAddrV4::new(self.self_ip, self.local_port);

        // Nothing but UPnP is left to try.
        if self.knobs.disable_pcp && self.knobs.disable_pmp {
            return match self.upnp_mapping(internal, 0).await {
                Some(m) => Ok(m),
                None => {
                    self.log
                        .vlog("fallback to UPnP due to PCP and PMP being disabled failed");
                    Err(Error::NoPortMappingServices.no_mapping())
                }
            };
        }

        // The probe found neither UDP protocol: go straight to UPnP rather than waiting out another
        // 250 ms of silence (Go cuts the same corner off the latency of the common case).
        if !probe.pmp && !probe.pcp {
            return match self.upnp_mapping(internal, 0).await {
                Some(m) => Ok(m),
                None => {
                    self.log
                        .vlog("fallback to UPnP due to no PCP and PMP failed");
                    Err(Error::NoPortMappingServices.no_mapping())
                }
            };
        }

        let sock = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)).await?;
        let pxp_addr = SocketAddrV4::new(self.gw, pmp::DEFAULT_PORT);
        let prefer_pcp =
            !self.knobs.disable_pcp && (self.knobs.disable_pmp || (!probe.pmp && probe.pcp));

        if prefer_pcp {
            let pkt = pcp::build_request_mapping_packet(
                self.self_ip,
                self.local_port,
                0,
                pcp::MAP_LIFETIME_SEC,
                Ipv4Addr::UNSPECIFIED,
                pcp::random_nonce(),
            );
            self.send(&sock, &pkt, pxp_addr).await;
        } else {
            // NAT-PMP needs two answers to build a mapping: the external ADDRESS comes from the
            // public-address op and the external PORT from the map op, so both requests go out.
            self.send(&sock, &pmp::REQ_EXTERNAL_ADDR_PACKET, pxp_addr)
                .await;
            let pkt = pmp::build_request_mapping_packet(self.local_port, 0, pmp::MAP_LIFETIME_SEC);
            self.send(&sock, &pkt, pxp_addr).await;
        }

        let deadline = tokio::time::Instant::now() + PORT_MAP_SERVICE_TIMEOUT;
        let mut buf = vec![0u8; 1500];
        let mut pmp_external_addr: Option<Ipv4Addr> = None;
        let mut pmp_external_port: Option<u16> = None;
        let mut pmp_lifetime = Duration::ZERO;

        loop {
            let read = tokio::time::timeout_at(deadline, sock.recv_from(&mut buf)).await;
            let (n, src) = match read {
                // Silence (or the deadline) — fall back to UPnP, as Go does on a read error.
                Err(_elapsed) => {
                    return match self.upnp_mapping(internal, 0).await {
                        Some(m) => Ok(m),
                        None => Err(Error::NoPortMappingServices.no_mapping()),
                    };
                }
                Ok(Err(e)) => return Err(Error::Io(e)),
                Ok(Ok(v)) => v,
            };
            let SocketAddr::V4(src) = src else { continue };
            if src != pxp_addr {
                continue;
            }
            let payload = &buf[..n];
            match payload.first().copied() {
                Some(pmp::VERSION) => {
                    let Some(pres) = pmp::parse_response(payload) else {
                        self.log
                            .log(format!("unexpected PMP response: {payload:02x?}"));
                        continue;
                    };
                    if pres.result_code != pmp::ResultCode::OK {
                        return Err(Error::NoMapping(Box::new(Error::Io(
                            std::io::Error::other(format!(
                                "PMP response Op=0x{:x},Res=0x{:x}",
                                pres.op_code, pres.result_code.0
                            )),
                        ))));
                    }
                    if pres.op_code == pmp::OP_REPLY | pmp::OP_MAP_PUBLIC_ADDR {
                        pmp_external_addr = pres.public_addr;
                    }
                    if pres.op_code == pmp::OP_REPLY | pmp::OP_MAP_UDP {
                        pmp_external_port = Some(pres.external_port);
                        pmp_lifetime = Duration::from_secs(u64::from(pres.mapping_valid_seconds));
                    }
                }
                Some(pcp::VERSION) => match pcp::parse_map_response(payload) {
                    Ok(m) => {
                        return Ok(Mapping {
                            external: m.external,
                            kind: MappingKind::Pcp,
                            lifetime: Duration::from_secs(u64::from(m.lifetime_secs)),
                        });
                    }
                    Err(e) => {
                        // PCP answers a MAP with exactly one packet, so a bad one ends the attempt.
                        self.log.log(format!("failed to get PCP mapping: {e}"));
                        return Err(Error::NoPortMappingServices.no_mapping());
                    }
                },
                other => {
                    self.log
                        .log(format!("unknown PMP/PCP version number: {other:?}"));
                    return Err(Error::NoPortMappingServices.no_mapping());
                }
            }

            if let (Some(addr), Some(port)) = (pmp_external_addr, pmp_external_port) {
                return Ok(Mapping {
                    external: SocketAddrV4::new(addr, port),
                    kind: MappingKind::Pmp,
                    lifetime: pmp_lifetime,
                });
            }
        }
    }

    /// The UPnP half of mapping acquisition, off the async runtime (Go: `getUPnPPortMapping`).
    ///
    /// UPnP control is blocking HTTP, so it runs on a blocking thread; everything it needs — the
    /// discovery responses from the probe, the knobs and the log sink — is cloned in.
    async fn upnp_mapping(&self, internal: SocketAddrV4, prev_port: u16) -> Option<Mapping> {
        if self.knobs.disable_upnp {
            return None;
        }
        if self.upnp_metas.is_empty() {
            self.log
                .vlog("no UPnP discovery responses; nothing to ask for a mapping");
            return None;
        }
        let (gw, metas, knobs, log) = (
            self.gw,
            self.upnp_metas.clone(),
            self.knobs,
            self.log.clone(),
        );
        let external = tokio::task::spawn_blocking(move || {
            upnp::get_port_mapping(gw, internal, prev_port, &metas, knobs, &log)
        })
        .await
        .ok()??;
        Some(Mapping {
            external,
            kind: MappingKind::Upnp,
            // UPnP's AddPortMapping has no "granted lifetime" in its response, so Go simply assumes
            // the lease it asked for (`pmpMapLifetimeSec`) and re-checks on a schedule.
            lifetime: Duration::from_secs(u64::from(pmp::MAP_LIFETIME_SEC)),
        })
    }

    /// Record one UPnP discovery response (Go: the `handleUPnPResponse` closure in `Probe`).
    ///
    /// A response that does not parse is logged and dropped rather than failing the probe: an SSDP
    /// group carries traffic from every kind of device, and one unparseable datagram must not hide
    /// the router's answer.
    fn handle_upnp_response(
        &self,
        payload: &[u8],
        src: SocketAddrV4,
        res: &mut ProbeResult,
        upnp_responses: &mut Vec<upnp::DiscoResponse>,
    ) {
        if *src.ip() != self.gw {
            // tailscale#5502: a floating gateway address; still usable, worth reporting.
            self.log.log(format!(
                "UPnP discovery response from {}, but gateway IP is {}",
                src.ip(),
                self.gw
            ));
        }
        match upnp::parse_disco_response(payload) {
            Ok(meta) => {
                res.upnp = true;
                if upnp_responses.len() > MAX_UPNP_RESPONSES {
                    self.log.log("too many UPnP responses: skipping");
                } else {
                    self.log.vlog(format!("UPnP reply {meta:?}"));
                    upnp_responses.push(meta);
                }
            }
            Err(e) => {
                self.log.log(format!(
                    "unrecognized UPnP discovery response; ignoring: {e}"
                ));
            }
        }
    }

    /// Send one probe/request datagram, logging (but not failing on) a send error: one protocol's
    /// packet being refused by the host — a firewall dropping multicast, say — must not abort the
    /// other two.
    async fn send(&self, sock: &UdpSocket, pkt: &[u8], to: SocketAddrV4) {
        if let Err(e) = sock.send_to(pkt, to).await {
            self.log.vlog(format!("send to {to} failed: {e}"));
        }
    }
}

/// Whether `haystack` contains `needle` (Go uses `mem.Contains` on the raw packet for the same
/// "does this datagram mention InternetGatewayDevice" sniff).
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_type_selects_by_disabling_the_others() {
        let all = DebugKnobs::for_debug_type("").expect("the empty type means all protocols");
        assert!(!all.disable_pmp && !all.disable_pcp && !all.disable_upnp);
        assert!(all.verbose_logs, "the debug endpoint always logs verbosely");

        let pmp = DebugKnobs::for_debug_type("pmp").unwrap();
        assert!(!pmp.disable_pmp && pmp.disable_pcp && pmp.disable_upnp);

        let pcp = DebugKnobs::for_debug_type("pcp").unwrap();
        assert!(pcp.disable_pmp && !pcp.disable_pcp && pcp.disable_upnp);

        let upnp = DebugKnobs::for_debug_type("upnp").unwrap();
        assert!(upnp.disable_pmp && upnp.disable_pcp && !upnp.disable_upnp);
    }

    #[test]
    fn an_unknown_debug_type_is_refused_not_treated_as_all() {
        let err = DebugKnobs::for_debug_type("upnpp").expect_err("a typo must not run everything");
        assert_eq!(err, UnknownDebugType("upnpp".to_string()));
        assert_eq!(err.to_string(), "unknown portmap debug type");
    }

    #[test]
    fn no_single_type_disables_everything() {
        for ty in ["", "pmp", "pcp", "upnp"] {
            assert!(
                !DebugKnobs::for_debug_type(ty).unwrap().all_disabled(),
                "--type {ty} must leave something to try"
            );
        }
    }

    #[test]
    fn the_env_kill_switches_disable_what_go_disables() {
        let disabled = DebugKnobs::default()
            .with_env_overrides(|name| (name == "TS_DISABLE_PORTMAPPER").then(|| "1".to_string()));
        assert!(
            disabled.all_disabled(),
            "TS_DISABLE_PORTMAPPER kills all three"
        );

        let no_upnp = DebugKnobs::default()
            .with_env_overrides(|name| (name == "TS_DISABLE_UPNP").then(|| "true".to_string()));
        assert!(no_upnp.disable_upnp);
        assert!(
            !no_upnp.disable_pmp && !no_upnp.disable_pcp,
            "TS_DISABLE_UPNP must leave the UDP protocols alone"
        );

        // An unset (or explicitly false) knob changes nothing.
        let untouched = DebugKnobs::default().with_env_overrides(|_| None);
        assert_eq!(untouched, DebugKnobs::default());
        let off = DebugKnobs::default().with_env_overrides(|_| Some("0".to_string()));
        assert_eq!(off, DebugKnobs::default());
    }

    #[test]
    fn probe_result_reports_whether_anything_answered() {
        assert!(!ProbeResult::default().any());
        assert!(
            ProbeResult {
                upnp: true,
                ..Default::default()
            }
            .any()
        );
    }

    #[test]
    fn probe_result_renders_like_gos_struct_print() {
        assert_eq!(
            ProbeResult {
                pcp: false,
                pmp: true,
                upnp: false
            }
            .to_string(),
            "{PCP:false PMP:true UPnP:false}"
        );
    }

    #[test]
    fn error_messages_are_gos_sentinel_texts() {
        assert_eq!(
            Error::PortMappingDisabled.to_string(),
            "port mapping is disabled"
        );
        assert_eq!(
            Error::NoPortMappingServices.to_string(),
            "no port mapping services were found"
        );
        assert_eq!(
            Error::GatewayRange.to_string(),
            "skipping portmap; gateway range likely lacks support"
        );
        // Go wraps mapping failures so a caller can tell them from transport errors.
        let wrapped = Error::NoPortMappingServices.no_mapping();
        assert!(wrapped.is_no_mapping());
        assert!(!Error::NoPortMappingServices.is_no_mapping());
        assert_eq!(
            wrapped.to_string(),
            "no NAT mapping available: no port mapping services were found"
        );
    }

    #[test]
    fn mapping_kinds_print_like_gos_mapping_type() {
        assert_eq!(MappingKind::Pmp.to_string(), "pmp");
        assert_eq!(MappingKind::Pcp.to_string(), "pcp");
        assert_eq!(MappingKind::Upnp.to_string(), "upnp");
    }

    #[test]
    fn the_gateway_device_sniff_finds_the_marker_anywhere_in_a_datagram() {
        let body =
            b"HTTP/1.1 200 OK\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:2\r\n\r\n";
        assert!(contains(body, b":InternetGatewayDevice:"));
        assert!(!contains(
            b"HTTP/1.1 200 OK\r\n\r\n",
            b":InternetGatewayDevice:"
        ));
        assert!(!contains(b"", b":InternetGatewayDevice:"));
    }

    #[test]
    fn a_client_with_everything_disabled_refuses_to_probe_or_map() {
        let knobs = DebugKnobs {
            disable_pmp: true,
            disable_pcp: true,
            disable_upnp: true,
            ..DebugKnobs::default()
        };
        let mut client = Client::new(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 42),
            41641,
            knobs,
            Logger::discard(),
        );
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let err = client.probe().await.expect_err("nothing is enabled");
            assert_eq!(err.to_string(), "port mapping is disabled");
            let err = client
                .create_mapping(&ProbeResult::default())
                .await
                .expect_err("nothing is enabled");
            assert!(err.is_no_mapping());
            assert_eq!(
                err.to_string(),
                "no NAT mapping available: port mapping is disabled"
            );
        });
    }

    #[test]
    fn a_logger_routes_verbose_lines_only_when_verbose() {
        let seen: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = {
            let seen = Arc::clone(&seen);
            Arc::new(move |line: &str| seen.lock().unwrap().push(line.to_string())) as LogSink
        };
        let quiet = Logger::new(Arc::clone(&sink), false);
        quiet.log("always");
        quiet.vlog("only when verbose");
        assert_eq!(*seen.lock().unwrap(), vec!["always".to_string()]);

        let loud = Logger::new(sink, true);
        loud.vlog("now shown");
        assert_eq!(
            *seen.lock().unwrap(),
            vec!["always".to_string(), "now shown".to_string()]
        );
    }
}
