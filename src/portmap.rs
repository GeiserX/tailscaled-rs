//! Port-mapping client — NAT-PMP (RFC 6886), PCP (RFC 6887) and UPnP-IGD discovery.
//!
//! A port of Go `net/portmapper` (`portmapper.go` + `pcp.go` + the discovery half of `upnp.go`) and
//! of the gateway lookup those three protocols all start from (Go `net/netmon`'s
//! `likelyHomeRouterIPLinux` / `likelyHomeRouterIPBSDFetchRIB`), from upstream `tailscale`
//! **v1.100.0**.
//!
//! ## Why the daemon wants this
//!
//! Two peers behind NATs only get a *direct* path when each one's NAT has a hole punched through
//! it. STUN + disco does that when the NAT is well-behaved, but a NAT that maps each destination to
//! a different external port (a "hard" / symmetric NAT) defeats it, and the connection falls back to
//! a DERP relay — slower and more expensive for everyone. Many home routers offer a way to ask for a
//! mapping *explicitly*: NAT-PMP, its successor PCP, or UPnP-IGD. When one of those answers, the
//! node learns a stable `external-ip:port` that peers can dial directly, and the relay is skipped.
//!
//! This module is the client for that conversation: it finds the default gateway, asks it which of
//! the three protocols it speaks ([`Client::probe`]), and — over NAT-PMP or PCP — asks for and holds
//! a UDP mapping for the node's local port ([`Client::create_or_get_mapping`]).
//!
//! ## Honest reduced scope vs Go (all deliberate, none silent)
//!
//! - **The mapping is diagnostic, not yet wired into the data plane.** Go hands the acquired
//!   `external` address to magicsock, which advertises it as one of this node's endpoints. That
//!   consumer is *engine*-side: the engine (`tailscale-rs`, pinned by `rev`) owns magicsock and
//!   exposes no way to inject an endpoint, so the daemon cannot complete the loop from here. What
//!   this module gives the operator today is the honest answer to "does my router offer port
//!   mapping, and what would it give me?" — surfaced by `tnet debug portmap`, exactly Go's
//!   `tailscale debug portmap`. Closing the loop needs one engine addition: a way to hand magicsock
//!   an externally-learned endpoint (Go's `magicsock.Conn` consumes the portmapper's `Mapping`
//!   events), which no `Device` method at the pinned rev provides.
//! - **UPnP is discovery-only.** [`Client::probe`] fully implements Go's UPnP leg — both SSDP
//!   M-SEARCH probes, the discovery-response parse, the dedupe/preference ordering — so a
//!   UPnP-capable router is *detected* and reported. Acquiring a mapping over UPnP is the one part
//!   not ported: Go delegates that to `github.com/huin/goupnp`, i.e. fetching and walking the
//!   device-description XML and then driving `AddAnyPortMapping`/`AddPortMapping` over SOAP, and
//!   this tree has neither an XML nor a SOAP stack. [`Client::create_or_get_mapping`] therefore says
//!   so on its log sink and falls through to [`PortmapError::NoPortMappingServices`], rather than
//!   pretending UPnP was absent.
//! - **No client metrics.** Go bumps ~25 `clientmetric` counters along these paths; this daemon has
//!   no client-metric registry of its own (`tnet metrics` proxies the engine's).
//! - **No `netns`-bound sockets.** Go binds the probe socket to the default-route interface through
//!   `netns` so a router-mode host cannot loop its own probe back through the tunnel. This fork's
//!   sockets are plain `0.0.0.0:0` binds, matching how the rest of the daemon dials.
//!
//! ## Layering
//!
//! Everything that touches bytes is a **pure function** — [`build_pmp_request_mapping_packet`],
//! [`parse_pmp_response`], [`build_pcp_request_mapping_packet`], [`parse_pcp_map_response`],
//! [`parse_upnp_disco_response`], [`process_upnp_responses`], and the two gateway-table parsers —
//! so the wire format and every refusal in it are unit-testable with no network at all. [`Client`]
//! is the only part that opens a socket, and it takes `test_pxp_port`/`test_upnp_port` overrides
//! (Go's, same names) so a fake IGD on loopback can drive the real [`Client::probe`] end to end.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// How long we wait for a port-mapping service to answer before deciding it is not there (Go
/// `portMapServiceTimeout`). These services sit on the same LAN one L3 hop away, so a slow answer is
/// itself evidence that nothing is answering.
pub const PORT_MAP_SERVICE_TIMEOUT: Duration = Duration::from_millis(250);

/// How long a "we saw this service" observation stays trusted before it is re-probed (Go
/// `trustServiceStillAvailableDuration`).
pub const TRUST_SERVICE_STILL_AVAILABLE: Duration = Duration::from_secs(10 * 60);

/// How long the probe keeps listening after the *first* response, so that a LAN with several
/// UPnP-capable routers is seen whole instead of "whichever answered first" (Go's 50ms
/// `upnpTimer`).
const UPNP_SETTLE: Duration = Duration::from_millis(50);

/// Cap on how many UPnP discovery responses one probe collects (Go's `len(upnpResponses) > 10`).
const MAX_UPNP_RESPONSES: usize = 10;

/// Receive buffer for one probe/mapping datagram (Go's `make([]byte, 1500)`).
const RECV_BUF: usize = 1500;

// ───────────────────────────── errors ─────────────────────────────

/// Why no port mapping could be obtained. The four sentinel variants carry Go's verbatim strings
/// (`net/portmapper/portmappertype`'s `ErrNoPortMappingServices` / `ErrGatewayRange` /
/// `ErrGatewayIPv6` / `ErrPortMappingDisabled`), so an operator reading `tnet debug portmap` sees
/// what `tailscale debug portmap` prints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortmapError {
    /// Nothing on the LAN answered NAT-PMP, PCP or UPnP (Go `ErrNoPortMappingServices`).
    NoPortMappingServices,
    /// No default gateway could be found, so there is nobody to ask (Go `ErrGatewayRange`).
    GatewayRange,
    /// The default gateway is IPv6; port mapping is an IPv4-NAT concern (Go `ErrGatewayIPv6`).
    GatewayIPv6,
    /// Port mapping was switched off by configuration (Go `ErrPortMappingDisabled`).
    PortMappingDisabled,
    /// A mapping attempt reached a service but did not come back with one — Go's `NoMappingError`,
    /// whose `Error()` is `"no NAT mapping available: <inner>"`. `inner` is the rendered cause (one
    /// of the sentinels above, or a protocol-level refusal such as `PMP response Op=0x81,Res=0x2`).
    NoMapping(String),
    /// A socket operation failed (bind / send / receive). Go surfaces these as a bare `error`.
    Io(String),
}

impl PortmapError {
    /// Wrap `self` as Go's `NoMappingError{err}` — the shape `createOrGetMapping` returns so callers
    /// can tell "we asked and got nothing" apart from "the socket broke".
    fn no_mapping(self) -> Self {
        PortmapError::NoMapping(self.to_string())
    }
}

impl fmt::Display for PortmapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PortmapError::NoPortMappingServices => {
                f.write_str("no port mapping services were found")
            }
            PortmapError::GatewayRange => {
                f.write_str("skipping portmap; gateway range likely lacks support")
            }
            PortmapError::GatewayIPv6 => {
                f.write_str("skipping portmap; no IPv6 support for portmapping")
            }
            PortmapError::PortMappingDisabled => f.write_str("port mapping is disabled"),
            PortmapError::NoMapping(inner) => write!(f, "no NAT mapping available: {inner}"),
            PortmapError::Io(e) => f.write_str(e),
        }
    }
}

impl std::error::Error for PortmapError {}

// ───────────────────────────── knobs + probe result ─────────────────────────────

/// Debug configuration for a [`Client`] (Go `portmapper.DebugKnobs`). The zero value is the normal
/// production posture: nothing disabled, no extra logging.
///
/// Go models each `Disable*` as a `func() bool` so a live control knob can flip it between calls;
/// this fork's client is constructed per operation (the `debug portmap` handler builds one, uses it,
/// drops it), so plain booleans carry the same information with no indirection.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DebugKnobs {
    /// Print the extra per-step detail Go's `vlogf` gates on `VerboseLogs`.
    pub verbose_logs: bool,
    /// Log raw HTTP for the UPnP leg (Go `LogHTTP`). Accepted and carried for parity; this fork's
    /// UPnP leg is discovery-only (no HTTP is issued), so it currently changes no output — the
    /// discovery-only note in the module docs is the honest reason.
    pub log_http: bool,
    /// Do not probe or map over UPnP (Go `DisableUPnPFunc`).
    pub disable_upnp: bool,
    /// Do not probe or map over NAT-PMP (Go `DisablePMPFunc`).
    pub disable_pmp: bool,
    /// Do not probe or map over PCP (Go `DisablePCPFunc`).
    pub disable_pcp: bool,
    /// Disable port mapping entirely (Go `DisableAll`, plus its `TS_DISABLE_PORTMAPPER` envknob).
    pub disable_all: bool,
}

/// Which port-mapping protocols answered a probe (Go `portmappertype.ProbeResult`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProbeResult {
    /// A PCP service answered the ANNOUNCE and is willing to map.
    pub pcp: bool,
    /// A NAT-PMP service answered the public-address request.
    pub pmp: bool,
    /// An Internet Gateway Device answered SSDP discovery.
    pub upnp: bool,
}

impl ProbeResult {
    /// Whether no protocol at all answered — Go's `!res.PCP && !res.PMP && !res.UPnP` guard in
    /// `serveDebugPortmap`, which is what turns into "no portmapping services available".
    pub fn is_empty(&self) -> bool {
        !self.pcp && !self.pmp && !self.upnp
    }
}

impl fmt::Display for ProbeResult {
    /// Go's `%+v` rendering of the struct, field order and spelling included, because that exact
    /// text is the `Probe: {PCP:false PMP:false UPnP:false}` line `tailscale debug portmap` prints.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{PCP:{} PMP:{} UPnP:{}}}",
            self.pcp, self.pmp, self.upnp
        )
    }
}

// ───────────────────────────── NAT-PMP wire format (RFC 6886) ─────────────────────────────

/// The UDP port NAT-PMP and PCP both listen on (Go `pmpDefaultPort` / `pcpDefaultPort`).
pub const PXP_PORT: u16 = 5351;

/// Lifetime we request for a NAT-PMP mapping, in seconds — RFC 6886's recommended two hours (Go
/// `pmpMapLifetimeSec`). PCP reuses the same number (Go `pcpMapLifetimeSec`).
pub const MAP_LIFETIME_SEC: u32 = 7200;

/// The lifetime that *deletes* a mapping instead of creating one (Go `pmpMapLifetimeDelete`).
pub const MAP_LIFETIME_DELETE: u32 = 0;

/// NAT-PMP protocol version (Go `pmpVersion`). Also the discriminator that tells a NAT-PMP reply
/// from a PCP one: both arrive from port 5351, and byte 0 is the version.
pub const PMP_VERSION: u8 = 0;

/// NAT-PMP opcode: "tell me the external address" (Go `pmpOpMapPublicAddr`).
pub const PMP_OP_MAP_PUBLIC_ADDR: u8 = 0;

/// NAT-PMP opcode: "map this UDP port" (Go `pmpOpMapUDP`).
pub const PMP_OP_MAP_UDP: u8 = 1;

/// OR'd into a request opcode to form the reply opcode (Go `pmpOpReply`).
pub const PMP_OP_REPLY: u8 = 0x80;

/// The two-byte NAT-PMP "what is my external address?" request (Go `pmpReqExternalAddrPacket`).
pub const PMP_REQ_EXTERNAL_ADDR_PACKET: [u8; 2] = [PMP_VERSION, PMP_OP_MAP_PUBLIC_ADDR];

/// A NAT-PMP result code (Go `pmpResultCode`). [`fmt::Display`] reproduces Go's generated
/// `stringer` output (`pmpresultcode_string.go`), including its `pmpResultCode(N)` fallback for a
/// code the RFC does not define, so log lines read identically.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PmpResultCode(pub u16);

impl PmpResultCode {
    /// Success (Go `pmpCodeOK`).
    pub const OK: PmpResultCode = PmpResultCode(0);
    /// The gateway does not speak this NAT-PMP version (Go `pmpCodeUnsupportedVersion`).
    pub const UNSUPPORTED_VERSION: PmpResultCode = PmpResultCode(1);
    /// Mapping is supported but switched off by the router's owner (Go `pmpCodeNotAuthorized`).
    pub const NOT_AUTHORIZED: PmpResultCode = PmpResultCode(2);
    /// The gateway itself has no upstream address yet (Go `pmpCodeNetworkFailure`).
    pub const NETWORK_FAILURE: PmpResultCode = PmpResultCode(3);
    /// The gateway is out of mapping slots (Go `pmpCodeOutOfResources`).
    pub const OUT_OF_RESOURCES: PmpResultCode = PmpResultCode(4);
    /// The gateway does not implement the requested opcode (Go `pmpCodeUnsupportedOpcode`).
    pub const UNSUPPORTED_OPCODE: PmpResultCode = PmpResultCode(5);
}

impl fmt::Display for PmpResultCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            0 => f.write_str("OK"),
            1 => f.write_str("UnsupportedVersion"),
            2 => f.write_str("NotAuthorized"),
            3 => f.write_str("NetworkFailure"),
            4 => f.write_str("OutOfResources"),
            5 => f.write_str("UnsupportedOpcode"),
            other => write!(f, "pmpResultCode({other})"),
        }
    }
}

/// Build the 12-byte NAT-PMP "map this UDP port" request (Go `buildPMPRequestMappingPacket`).
///
/// `prev_port` is the external port we held last time and would like back; `0` means "give me any".
/// `lifetime_sec` of [`MAP_LIFETIME_DELETE`] turns the same packet into a *release*. Pure.
pub fn build_pmp_request_mapping_packet(
    local_port: u16,
    prev_port: u16,
    lifetime_sec: u32,
) -> [u8; 12] {
    let mut pkt = [0u8; 12];
    // pkt[0] stays 0: the NAT-PMP version. pkt[2..4] stays 0: the reserved field.
    pkt[1] = PMP_OP_MAP_UDP;
    pkt[4..6].copy_from_slice(&local_port.to_be_bytes());
    pkt[6..8].copy_from_slice(&prev_port.to_be_bytes());
    pkt[8..12].copy_from_slice(&lifetime_sec.to_be_bytes());
    pkt
}

/// A parsed NAT-PMP response (Go `pmpResponse`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PmpResponse {
    /// The reply opcode — the request's opcode with [`PMP_OP_REPLY`] set.
    pub op_code: u8,
    /// The gateway's verdict.
    pub result_code: PmpResultCode,
    /// The gateway's epoch counter; a *decrease* means it rebooted and forgot our mappings.
    pub seconds_since_epoch: u32,
    /// How long the granted mapping lives (map replies only).
    pub mapping_valid_seconds: u32,
    /// The internal port that was mapped (map replies only).
    pub internal_port: u16,
    /// The external port the gateway assigned (map replies only).
    pub external_port: u16,
    /// The gateway's external address (public-address replies only). `None` when the gateway
    /// answered `0.0.0.0`, which Go zeroes out so an unusable address is never mistaken for one.
    pub public_addr: Option<Ipv4Addr>,
}

impl Default for PmpResultCode {
    fn default() -> Self {
        PmpResultCode::OK
    }
}

impl fmt::Display for PmpResponse {
    /// Go's `%+v` on `pmpResponse`, which is what its "unexpected PMP probe response: %+v" and
    /// "PMP probe failed due result code: %+v" lines print.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{OpCode:{} ResultCode:{} SecondsSinceEpoch:{} MappingValidSeconds:{} InternalPort:{} ExternalPort:{} PublicAddr:{}}}",
            self.op_code,
            self.result_code,
            self.seconds_since_epoch,
            self.mapping_valid_seconds,
            self.internal_port,
            self.external_port,
            // Go prints a zero netip.Addr as "invalid IP".
            self.public_addr
                .map_or_else(|| "invalid IP".to_string(), |a| a.to_string()),
        )
    }
}

/// Parse a NAT-PMP response (Go `parsePMPResponse`). Returns `None` — Go's `ok=false` — for every
/// shape the RFC does not allow: a datagram shorter than the 12-byte common header, a version other
/// than 0, a map reply that is not exactly 16 bytes, or a public-address reply that is not exactly
/// 12. Those length checks are the whole reason a PCP datagram (version 2) never parses as NAT-PMP.
/// Pure.
pub fn parse_pmp_response(pkt: &[u8]) -> Option<PmpResponse> {
    if pkt.len() < 12 {
        return None;
    }
    if pkt[0] != PMP_VERSION {
        return None;
    }
    let mut res = PmpResponse {
        op_code: pkt[1],
        result_code: PmpResultCode(u16::from_be_bytes([pkt[2], pkt[3]])),
        seconds_since_epoch: u32::from_be_bytes([pkt[4], pkt[5], pkt[6], pkt[7]]),
        ..Default::default()
    };

    if res.op_code == PMP_OP_REPLY | PMP_OP_MAP_UDP {
        if pkt.len() != 16 {
            return None;
        }
        res.internal_port = u16::from_be_bytes([pkt[8], pkt[9]]);
        res.external_port = u16::from_be_bytes([pkt[10], pkt[11]]);
        res.mapping_valid_seconds = u32::from_be_bytes([pkt[12], pkt[13], pkt[14], pkt[15]]);
    }

    if res.op_code == PMP_OP_REPLY | PMP_OP_MAP_PUBLIC_ADDR {
        if pkt.len() != 12 {
            return None;
        }
        let addr = Ipv4Addr::new(pkt[8], pkt[9], pkt[10], pkt[11]);
        // Zero it out so an unspecified address is never Valid and used accidentally elsewhere
        // (Go zeroes the netip.Addr for exactly this reason).
        res.public_addr = if addr.is_unspecified() {
            None
        } else {
            Some(addr)
        };
    }

    Some(res)
}

// ───────────────────────────── PCP wire format (RFC 6887) ─────────────────────────────

/// PCP protocol version (Go `pcpVersion`). Byte 0 of every PCP datagram; also how a PCP reply is
/// told apart from a NAT-PMP one on the shared port 5351.
pub const PCP_VERSION: u8 = 2;

/// OR'd into a request opcode to form the reply opcode (Go `pcpOpReply`).
pub const PCP_OP_REPLY: u8 = 0x80;

/// PCP opcode: ANNOUNCE, "are you there?" (Go `pcpOpAnnounce`).
pub const PCP_OP_ANNOUNCE: u8 = 0;

/// PCP opcode: MAP, "give me a mapping" (Go `pcpOpMap`).
pub const PCP_OP_MAP: u8 = 1;

/// IANA protocol number for UDP, the protocol we map (Go `pcpUDPMapping`).
pub const PCP_UDP_MAPPING: u8 = 17;

/// A PCP result code (Go `pcpResultCode`). [`fmt::Display`] reproduces Go's generated `stringer`
/// output (`pcpresultcode_string.go`) including the `pcpResultCode(N)` fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PcpResultCode(pub u8);

impl PcpResultCode {
    /// Success (Go `pcpCodeOK`).
    pub const OK: PcpResultCode = PcpResultCode(0);
    /// A PCP service is running but refuses to hand out mappings (Go `pcpCodeNotAuthorized`).
    pub const NOT_AUTHORIZED: PcpResultCode = PcpResultCode(2);
    /// RFC 6887's `ADDRESS_MISMATCH`: the source address of the request does not match the client
    /// address in it, because there is *another* NAT between us and the PCP server — so it cannot
    /// help us (Go `pcpCodeAddressMismatch`).
    pub const ADDRESS_MISMATCH: PcpResultCode = PcpResultCode(12);
}

impl fmt::Display for PcpResultCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            0 => f.write_str("OK"),
            2 => f.write_str("NotAuthorized"),
            12 => f.write_str("AddressMismatch"),
            other => write!(f, "pcpResultCode({other})"),
        }
    }
}

/// Render an address the way PCP carries one: 16 bytes, with IPv4 written as its IPv4-mapped IPv6
/// form (Go `netip.Addr.As16()`).
fn as16(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}

/// Build the 24-byte PCP ANNOUNCE request (Go `pcpAnnounceRequest`, RFC 6887 §7.1) — the probe that
/// asks "is a PCP server here?". Pure.
pub fn pcp_announce_request(my_ip: IpAddr) -> [u8; 24] {
    let mut pkt = [0u8; 24];
    pkt[0] = PCP_VERSION;
    pkt[1] = PCP_OP_ANNOUNCE;
    pkt[8..24].copy_from_slice(&as16(my_ip));
    pkt
}

/// Build the 60-byte PCP MAP request: a 24-byte common header plus 36 bytes of MAP-specific fields
/// (Go `buildPCPRequestMappingPacket`).
///
/// `nonce` is RFC 6887's 96-bit mapping nonce, which ties a response to this request; Go fills it
/// from `crypto/rand` at the call site, and it is a *parameter* here so the packet builder stays
/// pure and its bytes can be pinned by a golden test. `prev_port` of `0` means "any port", and
/// `prev_external_ip` of `0.0.0.0` means "I do not know my previous external address".
/// `lifetime_sec` of [`MAP_LIFETIME_DELETE`] turns this into a *release*. Pure.
pub fn build_pcp_request_mapping_packet(
    nonce: [u8; 12],
    my_ip: IpAddr,
    local_port: u16,
    prev_port: u16,
    lifetime_sec: u32,
    prev_external_ip: IpAddr,
) -> [u8; 60] {
    let mut pkt = [0u8; 60];
    pkt[0] = PCP_VERSION;
    pkt[1] = PCP_OP_MAP;
    pkt[4..8].copy_from_slice(&lifetime_sec.to_be_bytes());
    pkt[8..24].copy_from_slice(&as16(my_ip));

    // The MAP opcode's own 36 bytes start at 24.
    pkt[24..36].copy_from_slice(&nonce);
    // Go's TODO is kept as-is: mapping "all protocols" (0) is possible but then no local port may be
    // named, so this maps UDP specifically.
    pkt[36] = PCP_UDP_MAPPING;
    // pkt[37..40] is the reserved field, left zero.
    pkt[40..42].copy_from_slice(&local_port.to_be_bytes());
    pkt[42..44].copy_from_slice(&prev_port.to_be_bytes());
    pkt[44..60].copy_from_slice(&as16(prev_external_ip));
    pkt
}

/// A parsed PCP common header (Go `pcpResponse`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PcpResponse {
    /// The reply opcode — the request's opcode with [`PCP_OP_REPLY`] set.
    pub op_code: u8,
    /// The server's verdict.
    pub result_code: PcpResultCode,
    /// The granted lifetime, in seconds.
    pub lifetime: u32,
    /// The server's epoch counter; a *decrease* means it lost our mappings.
    pub epoch: u32,
}

impl fmt::Display for PcpResponse {
    /// Go's `%+v` on `pcpResponse` — the text of its "unexpected PCP probe response: %+v" line.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{OpCode:{} ResultCode:{} Lifetime:{} Epoch:{}}}",
            self.op_code, self.result_code, self.lifetime, self.epoch
        )
    }
}

/// Parse a PCP common header (Go `parsePCPResponse`). Returns `None` for anything under 24 bytes or
/// carrying a version other than [`PCP_VERSION`] — which is exactly what keeps a NAT-PMP datagram
/// (version 0) from parsing as PCP. Pure.
pub fn parse_pcp_response(b: &[u8]) -> Option<PcpResponse> {
    if b.len() < 24 || b[0] != PCP_VERSION {
        return None;
    }
    Some(PcpResponse {
        op_code: b[1],
        result_code: PcpResultCode(b[3]),
        lifetime: u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
        epoch: u32::from_be_bytes([b[8], b[9], b[10], b[11]]),
    })
}

/// What a successful PCP MAP response granted: the external address/port and the lifetime clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PcpMapResponse {
    /// The external `ip:port` the server assigned.
    pub external: SocketAddr,
    /// How long the mapping is good for, from the moment the response was parsed.
    pub lifetime: Duration,
    /// The server's epoch counter at the time of the grant.
    pub epoch: u32,
}

/// Parse a PCP MAP response into the grant it describes (Go `parsePCPMapResponse`).
///
/// Every one of Go's four refusals is kept, with its message: a datagram shorter than the 60-byte
/// MAP response (`Does not appear to be PCP MAP response`), a header that does not parse
/// (`Invalid PCP common header`), the specific "PCP is here but the owner turned it off" case
/// ([`PcpResultCode::NOT_AUTHORIZED`] → `PCP is implemented but not enabled in the router`), and any
/// other non-OK code (`PCP response not ok, code N`). Pure.
///
/// NOTE (Go's own TODO, kept): the 96-bit nonce echoed at bytes 24..36 is *not* checked against the
/// nonce we sent.
pub fn parse_pcp_map_response(resp: &[u8]) -> Result<PcpMapResponse, String> {
    if resp.len() < 60 {
        return Err("Does not appear to be PCP MAP response".to_string());
    }
    let res = parse_pcp_response(&resp[..24]).ok_or("Invalid PCP common header")?;
    if res.result_code == PcpResultCode::NOT_AUTHORIZED {
        return Err("PCP is implemented but not enabled in the router".to_string());
    }
    if res.result_code != PcpResultCode::OK {
        return Err(format!("PCP response not ok, code {}", res.result_code.0));
    }
    let external_port = u16::from_be_bytes([resp[42], resp[43]]);
    let mut ip_bytes = [0u8; 16];
    ip_bytes.copy_from_slice(&resp[44..60]);
    let external_ip = unmap(std::net::Ipv6Addr::from(ip_bytes));

    Ok(PcpMapResponse {
        external: SocketAddr::new(external_ip, external_port),
        lifetime: Duration::from_secs(u64::from(res.lifetime)),
        epoch: res.epoch,
    })
}

/// Collapse an IPv4-mapped IPv6 address back to IPv4 (Go `netip.Addr.Unmap()`), leaving a genuine
/// IPv6 address alone.
fn unmap(v6: std::net::Ipv6Addr) -> IpAddr {
    match v6.to_ipv4_mapped() {
        Some(v4) => IpAddr::V4(v4),
        None => IpAddr::V6(v6),
    }
}

// ───────────────────────────── UPnP-IGD discovery (SSDP) ─────────────────────────────

/// The UDP port SSDP discovery uses (Go `upnpDefaultPort`). The device's *control* port is
/// discovered later, from the `Location` header.
pub const UPNP_PORT: u16 = 1900;

/// The SSDP multicast group discovery is addressed to.
///
/// Not an example address and not substitutable: this is the group the UPnP Device Architecture
/// assigns to SSDP, so it is part of the protocol exactly as port 1900 is. It is
/// administratively-scoped multicast (the `239/8` range) — link-local by definition, never routed off
/// the LAN — and it is what the mandatory `HOST:` header of every M-SEARCH must name.
pub const SSDP_MULTICAST: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);

/// The search target of the generic M-SEARCH probe (Go `uPnPPacket`) — "tell me about everything
/// you offer".
pub const SSDP_ST_ALL: &str = "ssdp:all";

/// The search target of the IGD-specific M-SEARCH probe (Go `uPnPIGDPacket`). Sent as well as the
/// generic one because some devices answer `ssdp:all` with only their *first* descriptor, which is
/// often not the gateway service we care about.
pub const SSDP_ST_IGD: &str = "urn:schemas-upnp-org:device:InternetGatewayDevice:1";

/// Build one SSDP M-SEARCH probe for the given search target (Go's `uPnPPacket` /
/// `uPnPIGDPacket`, which differ only in their `ST:` line).
///
/// The `HOST:` header is composed from [`SSDP_MULTICAST`] and [`UPNP_PORT`] rather than written
/// out, so the group has exactly one definition in this module and the two probes cannot drift
/// apart from it. The bytes on the wire are unchanged; `upnp_m_search_packets_match_gos_bytes`
/// pins them. Pure.
pub fn upnp_packet(st: &str) -> Vec<u8> {
    format!(
        "M-SEARCH * HTTP/1.1\r\n\
         HOST: {SSDP_MULTICAST}:{UPNP_PORT}\r\n\
         ST: {st}\r\n\
         MAN: \"ssdp:discover\"\r\n\
         MX: 2\r\n\r\n"
    )
    .into_bytes()
}

/// The marker that identifies a discovery response as coming from an Internet Gateway Device — the
/// substring Go checks with `mem.Contains` before parsing a datagram at all.
pub const IGD_MARKER: &str = ":InternetGatewayDevice:";

/// One parsed SSDP discovery response (Go `uPnPDiscoResponse`).
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct UpnpDiscoResponse {
    /// The URL of the device-description XML — where a UPnP mapping attempt would go next.
    pub location: String,
    /// The device's software identity, e.g. `MiniUPnPd/2.1`.
    pub server: String,
    /// The Unique Service Name, which also names the service offered, e.g.
    /// `uuid:…::urn:schemas-upnp-org:device:InternetGatewayDevice:2`.
    pub usn: String,
}

/// Parse a UPnP HTTP-over-UDP discovery response (Go `parseUPnPDiscoResponse`, which hands the
/// datagram to `http.ReadResponse`).
///
/// A discovery response is an HTTP response with no body: a status line, then headers. This
/// reproduces the refusals that matter — a datagram with no status line, a status line that is not
/// `HTTP/<version> <code>[ reason]`, a non-numeric status code, or a header line with no colon — so
/// a stray datagram on port 1900 is rejected rather than half-parsed into an empty response. Header
/// lookup is case-insensitive, matching Go's canonicalizing `Header.Get`. Pure.
pub fn parse_upnp_disco_response(body: &[u8]) -> Result<UpnpDiscoResponse, String> {
    let text = std::str::from_utf8(body).map_err(|_| "malformed HTTP response".to_string())?;
    let mut lines = text.split("\r\n").flat_map(|l| l.split('\n'));

    let status = lines.next().ok_or("malformed HTTP response")?;
    let mut parts = status.splitn(3, ' ');
    let proto = parts.next().unwrap_or("");
    if !proto.starts_with("HTTP/") {
        return Err(format!("malformed HTTP response {status:?}"));
    }
    let code = parts
        .next()
        .ok_or_else(|| format!("malformed HTTP response {status:?}"))?;
    if code.len() != 3 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("malformed HTTP status code {code:?}"));
    }

    let mut r = UpnpDiscoResponse::default();
    for line in lines {
        // A blank line ends the header block; SSDP responses carry no body after it.
        if line.is_empty() {
            break;
        }
        let (key, value) = line
            .split_once(':')
            .ok_or_else(|| format!("malformed MIME header line: {line}"))?;
        let value = value.trim().to_string();
        // Go's http.Header.Get canonicalizes the key, so the match is case-insensitive.
        match key.to_ascii_lowercase().as_str() {
            "location" => r.location = value,
            "server" => r.server = value,
            "usn" => r.usn = value,
            _ => {}
        }
    }
    Ok(r)
}

/// Sort and de-duplicate the discovery responses one probe collected (Go `processUPnPResponses`).
///
/// Two M-SEARCH probes go out per run, so the same device usually answers more than once. The sort
/// puts the USN in **reverse** order so that `InternetGatewayDevice:2` sorts before
/// `InternetGatewayDevice:1` — the newer service wins — and the compaction that follows keys on
/// `(location, server)` only, *not* the USN, so those two entries for one device collapse to the
/// first (the `:2` one). Pure.
pub fn process_upnp_responses(mut metas: Vec<UpnpDiscoResponse>) -> Vec<UpnpDiscoResponse> {
    metas.sort_by(|a, b| {
        b.usn
            .cmp(&a.usn)
            .then_with(|| a.location.cmp(&b.location))
            .then_with(|| a.server.cmp(&b.server))
    });
    metas.dedup_by(|a, b| a.location == b.location && a.server == b.server);
    metas
}

// ───────────────────────────── gateway lookup ─────────────────────────────

/// The default gateway and this host's address on the way to it — Go `netmon.LikelyHomeRouterIP` /
/// `GatewayAndSelfIP`, the starting point of every port-mapping conversation.
///
/// Returns `None` when no default gateway to a **private** address could be found, which is exactly
/// the condition Go turns into [`PortmapError::GatewayRange`] ("skipping portmap; gateway range
/// likely lacks support") — a host whose default route is a public address is not behind a home
/// router, so there is nothing to ask.
///
/// Per-OS, matching Go: **Linux** parses `/proc/net/route`; **macOS/BSD** dumps the kernel routing
/// table over `PF_ROUTE`. On any other platform there is no port-mapping-relevant route table this
/// fork reads, so it returns `None` and the operator can still supply both addresses by hand
/// (`tnet debug portmap --gateway-addr/--self-addr`, Go's own escape hatch).
pub fn likely_home_router_ip() -> Option<(IpAddr, IpAddr)> {
    likely_home_router_ip_os()
}

/// Cap on how many `/proc/net/route` lines are read before giving up (Go `maxProcNetRouteRead`).
/// A machine with a routing table this large is a router, not a home system, and will not have a
/// port-mapping service to find.
#[cfg(target_os = "linux")]
const MAX_PROC_NET_ROUTE_READ: usize = 1000;

/// Linux: the gateway is the first `RTF_UP|RTF_GATEWAY` route whose gateway is a private address
/// (Go `likelyHomeRouterIPLinux`).
#[cfg(target_os = "linux")]
fn likely_home_router_ip_os() -> Option<(IpAddr, IpAddr)> {
    let contents = std::fs::read_to_string("/proc/net/route").ok()?;
    let (gw, iface) = parse_proc_net_route(&contents)?;
    // Go looks up the first IPv4 address of the interface that owns the route, to short-circuit
    // finding the local address associated with this gateway. It is explicitly "not fatal if it
    // fails", so an interface we cannot enumerate yields an unspecified self address rather than no
    // gateway at all.
    let self_ip = if_addrs::get_if_addrs()
        .ok()
        .into_iter()
        .flatten()
        .find(|i| i.name == iface && i.ip().is_ipv4())
        .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |i| i.ip());
    Some((IpAddr::V4(gw), self_ip))
}

/// Parse `/proc/net/route` for the likely home router (Go `likelyHomeRouterIPLinux`'s loop), and the
/// name of the interface that owns that route.
///
/// The file is a header line then one route per line, whitespace-separated, with the gateway and
/// flags as **little-endian** hex:
///
/// ```text
/// Iface   Destination     Gateway         Flags   RefCnt  Use     Metric  Mask  MTU  Window  IRTT
/// ens18   00000000        0100000A        0003    0       0       0       00000000  0    0       0
/// ```
///
/// A line is considered only when it is both up and a gateway route (`RTF_UP|RTF_GATEWAY`), and the
/// first such route to a **private** address wins. A malformed field skips that line and the scan
/// continues, exactly as Go's `continue`-on-error does. Pure → unit-testable with no `/proc`.
#[cfg(target_os = "linux")]
pub fn parse_proc_net_route(contents: &str) -> Option<(Ipv4Addr, String)> {
    /// `RTF_UP` — the route is usable.
    const RTF_UP: u16 = 0x0001;
    /// `RTF_GATEWAY` — the destination is reached via an intermediary.
    const RTF_GATEWAY: u16 = 0x0002;

    for (line_num, line) in contents.lines().enumerate() {
        // Skip the header line.
        if line_num == 0 {
            continue;
        }
        if line_num > MAX_PROC_NET_ROUTE_READ {
            break;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 4 {
            continue;
        }
        let Ok(flags) = u16::from_str_radix(f[3], 16) else {
            continue; // ignore error, skip line and keep going
        };
        if flags & (RTF_UP | RTF_GATEWAY) != RTF_UP | RTF_GATEWAY {
            continue;
        }
        let Ok(ipu32) = u32::from_str_radix(f[2], 16) else {
            continue; // ignore error, skip line and keep going
        };
        // /proc/net/route writes the address little-endian, so the low byte is the first octet.
        let ip = Ipv4Addr::new(
            ipu32 as u8,
            (ipu32 >> 8) as u8,
            (ipu32 >> 16) as u8,
            (ipu32 >> 24) as u8,
        );
        if ip.is_private() {
            return Some((ip, f[0].to_string()));
        }
    }
    None
}

/// macOS/BSD: dump the kernel routing table and take the first default route with a gateway (Go
/// `likelyHomeRouterIPBSDFetchRIB`).
#[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd"))]
fn likely_home_router_ip_os() -> Option<(IpAddr, IpAddr)> {
    let rib = fetch_routing_table().ok()?;
    let (gw, self_ip) = parse_routing_table(&rib)?;
    Some((
        IpAddr::V4(gw),
        self_ip.map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), IpAddr::V4),
    ))
}

/// Ask the kernel for the whole IPv4 routing table (Go's `route.FetchRIB(0, unix.NET_RT_DUMP, 0)`).
///
/// This is the one syscall in this module that has no portable wrapper: `sysctl` over `PF_ROUTE`
/// returns a packed stream of `rt_msghdr` records, which [`parse_routing_table`] walks. It is called
/// twice — once with a null buffer to size the answer, once to read it — because the table can grow
/// between the two calls.
#[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd"))]
fn fetch_routing_table() -> std::io::Result<Vec<u8>> {
    // CTL_NET.PF_ROUTE.0.AF_INET.NET_RT_DUMP.0 — "dump every IPv4 route".
    let mut mib: [libc::c_int; 6] = [
        libc::CTL_NET,
        libc::PF_ROUTE,
        0,
        libc::AF_INET,
        libc::NET_RT_DUMP,
        0,
    ];
    let mut needed: libc::size_t = 0;

    // SAFETY: `mib` is a valid 6-element array of the MIB the kernel expects for a route dump, and a
    // null `oldp` with a valid `oldlenp` is the documented "how big is the answer?" form of sysctl.
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            std::ptr::null_mut(),
            &mut needed,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if needed == 0 {
        return Ok(Vec::new());
    }

    let mut buf = vec![0u8; needed];
    // SAFETY: `buf` is `needed` bytes long and `needed` is passed by pointer, so the kernel writes
    // at most that many bytes and updates the length in place; `mib` is unchanged from above.
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            buf.as_mut_ptr().cast::<libc::c_void>(),
            &mut needed,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    buf.truncate(needed);
    Ok(buf)
}

/// Walk a `PF_ROUTE` dump and return the default gateway plus, if the route carries one, this host's
/// interface address for it (Go `likelyHomeRouterIPBSDFetchRIB` + `isDefaultGateway`).
///
/// A record qualifies as the default route when it has `RTF_GATEWAY` set, is **not** interface-scoped
/// (`RTF_IFSCOPE` — those are per-interface duplicates of the default route, which Go skips so a
/// secondary interface's copy is never mistaken for the real one), and its destination *and* netmask
/// are both `0.0.0.0`. The gateway comes from the `RTAX_GATEWAY` slot and the optional self address
/// from `RTAX_IFA`.
///
/// Takes the raw dump as a slice so it is pure: a hand-built buffer drives it in tests with no
/// syscall. A truncated or nonsensical record ends the walk rather than reading past the buffer.
#[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd"))]
pub fn parse_routing_table(rib: &[u8]) -> Option<(Ipv4Addr, Option<Ipv4Addr>)> {
    /// `RTF_GATEWAY` — destination requires forwarding by an intermediary.
    const RTF_GATEWAY: libc::c_int = 0x2;
    /// `RTF_IFSCOPE` — the route is scoped to one interface. Defined locally because FreeBSD's libc
    /// does not export it (Go defines it locally for the same reason).
    const RTF_IFSCOPE: libc::c_int = 0x1000000;
    /// Address slots in a routing message, in the order the kernel packs them.
    const RTAX_DST: usize = 0;
    const RTAX_GATEWAY: usize = 1;
    const RTAX_NETMASK: usize = 2;
    const RTAX_IFA: usize = 5;
    const RTAX_MAX: usize = 8;

    let hdr_len = std::mem::size_of::<libc::rt_msghdr>();
    let mut off = 0usize;
    while off + hdr_len <= rib.len() {
        // SAFETY: the bounds check above guarantees `hdr_len` readable bytes at `off`, and
        // `read_unaligned` imposes no alignment requirement on the source.
        let hdr: libc::rt_msghdr =
            unsafe { std::ptr::read_unaligned(rib[off..].as_ptr().cast::<libc::rt_msghdr>()) };
        let msg_len = hdr.rtm_msglen as usize;
        // A zero or short length would not advance the walk (or would overrun): stop rather than
        // spin.
        if msg_len < hdr_len || off + msg_len > rib.len() {
            break;
        }
        let body = &rib[off + hdr_len..off + msg_len];
        off += msg_len;

        if hdr.rtm_flags & RTF_GATEWAY == 0 || hdr.rtm_flags & RTF_IFSCOPE != 0 {
            continue;
        }

        // The address slots present are named by the RTA bitmask; each present one is a sockaddr
        // laid out back to back, self-describing via its leading length byte.
        let mut addrs: [Option<(u8, &[u8])>; RTAX_MAX] = Default::default();
        let mut p = 0usize;
        for (slot, addr) in addrs.iter_mut().enumerate() {
            if hdr.rtm_addrs & (1 << slot) == 0 {
                continue;
            }
            if p + 2 > body.len() {
                break;
            }
            let sa_len = body[p] as usize;
            let sa_family = body[p + 1];
            // A sockaddr with a zero length still consumes its minimum 4-byte slot (the BSD
            // convention Go's route parser also applies).
            let advance = if sa_len == 0 { 4 } else { (sa_len + 3) & !3 };
            if p + sa_len > body.len() {
                break;
            }
            *addr = Some((sa_family, &body[p..p + sa_len]));
            p += advance;
        }

        // Addrs is [RTAX_DST, RTAX_GATEWAY, RTAX_NETMASK, ...]; a default route needs all three.
        let (Some(dst), Some(netmask)) = (addrs[RTAX_DST], addrs[RTAX_NETMASK]) else {
            continue;
        };
        if sockaddr_in_addr(dst) != Some(Ipv4Addr::UNSPECIFIED)
            || sockaddr_in_addr(netmask) != Some(Ipv4Addr::UNSPECIFIED)
        {
            continue;
        }
        let Some(gw) = addrs[RTAX_GATEWAY].and_then(sockaddr_in_addr) else {
            continue;
        };
        // The interface address is optional (Go: "If the route entry has an interface address
        // associated with it, then parse and return that. This is optional.").
        let self_ip = addrs[RTAX_IFA].and_then(sockaddr_in_addr);
        return Some((gw, self_ip));
    }
    None
}

/// Read the IPv4 address out of a `sockaddr` slot, or `None` if the slot is not an `AF_INET`
/// sockaddr with its four address bytes present.
///
/// A routing-table netmask is a *truncated* sockaddr — the kernel writes only as many bytes as the
/// mask needs, so an all-zero (default-route) mask arrives as a 0-length or family-only sockaddr.
/// Those short forms are read as `0.0.0.0`, which is exactly what they mean.
#[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd"))]
fn sockaddr_in_addr((family, bytes): (u8, &[u8])) -> Option<Ipv4Addr> {
    // Offset of `sin_addr` within `sockaddr_in`: len(1) + family(1) + port(2).
    const SIN_ADDR_OFF: usize = 4;
    if bytes.len() <= 1 {
        // A zero-length sockaddr is the wildcard the kernel writes for a zero netmask/destination.
        return Some(Ipv4Addr::UNSPECIFIED);
    }
    if libc::c_int::from(family) != libc::AF_INET {
        return None;
    }
    if bytes.len() < SIN_ADDR_OFF + 4 {
        // A truncated AF_INET sockaddr: the bytes the kernel elided are zero.
        let mut octets = [0u8; 4];
        let have = bytes.len().saturating_sub(SIN_ADDR_OFF);
        octets[..have].copy_from_slice(&bytes[SIN_ADDR_OFF..SIN_ADDR_OFF + have]);
        return Some(Ipv4Addr::from(octets));
    }
    Some(Ipv4Addr::new(
        bytes[SIN_ADDR_OFF],
        bytes[SIN_ADDR_OFF + 1],
        bytes[SIN_ADDR_OFF + 2],
        bytes[SIN_ADDR_OFF + 3],
    ))
}

/// Any other platform: this fork reads no routing table, so the operator must supply the pair by
/// hand (`--gateway-addr`/`--self-addr`).
#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd"
)))]
fn likely_home_router_ip_os() -> Option<(IpAddr, IpAddr)> {
    None
}

// ───────────────────────────── the client ─────────────────────────────

/// Where a [`Client`] writes its log lines (Go `logger.Logf`). The `debug portmap` handler points
/// this at the operator's connection so the run narrates itself; the daemon's own use would point it
/// at `tracing`.
pub type LogSink = Arc<dyn Fn(&str) + Send + Sync>;

/// How a [`Client`] finds the gateway and this host's address for it (Go's
/// `SetGatewayLookupFunc`). Defaults to [`likely_home_router_ip`]; `tnet debug portmap
/// --gateway-addr/--self-addr` replaces it with a constant pair.
pub type GatewayLookup = Arc<dyn Fn() -> Option<(IpAddr, IpAddr)> + Send + Sync>;

/// Which protocol produced a mapping (Go's `MappingType()`, whose strings appear in log lines).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MappingKind {
    /// NAT-PMP (Go `pmpMapping`).
    Pmp,
    /// PCP (Go `pcpMapping`).
    Pcp,
}

impl MappingKind {
    fn as_str(self) -> &'static str {
        match self {
            MappingKind::Pmp => "pmp",
            MappingKind::Pcp => "pcp",
        }
    }
}

/// An established port mapping (Go's `mapping` interface, collapsed to an enum-tagged struct: the
/// two implementations this fork has differ only in which protocol released them and how they log).
#[derive(Debug, Clone, Copy)]
struct Mapping {
    kind: MappingKind,
    /// The gateway's `ip:5351`, kept so the mapping can be released to the same place it came from.
    gw: SocketAddr,
    /// This node's `ip:port` behind the NAT.
    internal: SocketAddr,
    /// The `ip:port` the outside world reaches [`internal`](Mapping::internal) at.
    external: SocketAddr,
    /// When to start trying to renew (half the lifetime, Go's `d / 2`).
    renew_after: SystemTime,
    /// When the lease expires.
    good_until: SystemTime,
    /// The service's epoch counter at the time of the grant.
    epoch: u32,
}

/// Render a [`SystemTime`] as Go's `Time.Unix()` — seconds since the epoch — for the debug strings.
fn unix(t: SystemTime) -> i64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl Mapping {
    /// Go's `MappingDebug()`, per protocol — the line `createOrGetMapping` prints under verbose logs.
    fn mapping_debug(&self) -> String {
        match self.kind {
            MappingKind::Pmp => format!(
                "pmpMapping{{gw:{}, external:{}, internal:{}, renewAfter:{}, goodUntil:{}, epoch:{}}}",
                self.gw,
                self.external,
                self.internal,
                unix(self.renew_after),
                unix(self.good_until),
                self.epoch
            ),
            MappingKind::Pcp => format!(
                "pcpMapping{{gw:{}, external:{}, internal:{}, renewAfter:{}, goodUntil:{}}}",
                self.gw,
                self.external,
                self.internal,
                unix(self.renew_after),
                unix(self.good_until)
            ),
        }
    }

    /// The datagram that releases this mapping: a zero-lifetime request of the same protocol (Go
    /// `pmpMapping.Release` / `pcpMapping.Release`).
    fn release_packet(&self, nonce: [u8; 12]) -> Vec<u8> {
        match self.kind {
            MappingKind::Pmp => build_pmp_request_mapping_packet(
                self.internal.port(),
                self.external.port(),
                MAP_LIFETIME_DELETE,
            )
            .to_vec(),
            MappingKind::Pcp => build_pcp_request_mapping_packet(
                nonce,
                self.internal.ip(),
                self.internal.port(),
                self.external.port(),
                MAP_LIFETIME_DELETE,
                self.external.ip(),
            )
            .to_vec(),
        }
    }
}

/// Everything a [`Client`] remembers between calls (Go's `Client` fields under `mu`).
#[derive(Debug, Default)]
struct State {
    /// The gateway/self pair the cached observations below belong to. When it changes, they are all
    /// invalidated — a mapping from the previous network is worse than none.
    last_gw: Option<IpAddr>,
    last_my_ip: Option<IpAddr>,
    closed: bool,
    /// Whether a background `create_or_get_mapping` is already in flight (Go's `runningCreate`).
    running_create: bool,
    /// When the last probe finished, so a mapping attempt right after a fruitless probe can skip
    /// straight to the UPnP fallback instead of asking again.
    last_probe: Option<SystemTime>,
    /// NAT-PMP: the external address the gateway last reported, and when.
    pmp_pub_ip: Option<Ipv4Addr>,
    pmp_pub_ip_time: Option<SystemTime>,
    pmp_last_epoch: u32,
    /// PCP: when a PCP service last answered.
    pcp_saw_time: Option<SystemTime>,
    pcp_last_epoch: u32,
    /// UPnP: when a device last answered discovery, and what it said.
    upnp_saw_time: Option<SystemTime>,
    upnp_metas: Vec<UpnpDiscoResponse>,
    /// The local UDP port we want mapped (Go `SetLocalPort`).
    local_port: u16,
    mapping: Option<Mapping>,
}

/// A port-mapping client (Go `portmapper.Client`).
///
/// Construct it with [`Client::new`], point it at a gateway with [`Client::set_gateway_lookup`] (or
/// leave the default [`likely_home_router_ip`]), then [`Client::probe`] to learn what the network
/// offers and [`Client::create_or_get_mapping`] to ask for one.
pub struct Client {
    logf: LogSink,
    debug: DebugKnobs,
    gateway_lookup: Mutex<GatewayLookup>,
    on_change: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    /// Non-zero in tests only: the port a fake NAT-PMP/PCP service listens on (Go `testPxPPort`).
    test_pxp_port: u16,
    /// Non-zero in tests only: the port a fake SSDP responder listens on (Go `testUPnPPort`).
    test_upnp_port: u16,
    state: Mutex<State>,
}

impl Client {
    /// Build a client that logs to `logf` and honours `debug`.
    pub fn new(logf: LogSink, debug: DebugKnobs) -> Arc<Self> {
        Arc::new(Client {
            logf,
            debug,
            gateway_lookup: Mutex::new(Arc::new(likely_home_router_ip)),
            on_change: Mutex::new(None),
            test_pxp_port: 0,
            test_upnp_port: 0,
            state: Mutex::new(State::default()),
        })
    }

    /// Build a client whose NAT-PMP/PCP and SSDP traffic goes to the given loopback ports instead of
    /// 5351/1900, so a fake IGD can drive the real probe (Go's `testPxPPort`/`testUPnPPort`).
    #[cfg(test)]
    fn new_for_test(logf: LogSink, debug: DebugKnobs, pxp_port: u16, upnp_port: u16) -> Arc<Self> {
        Arc::new(Client {
            logf,
            debug,
            gateway_lookup: Mutex::new(Arc::new(likely_home_router_ip)),
            on_change: Mutex::new(None),
            test_pxp_port: pxp_port,
            test_upnp_port: upnp_port,
            state: Mutex::new(State::default()),
        })
    }

    /// Replace how the gateway and self address are found (Go `SetGatewayLookupFunc`). Must be
    /// called before the client is used.
    pub fn set_gateway_lookup(&self, f: GatewayLookup) {
        *self.gateway_lookup.lock().expect("gateway lookup lock") = f;
    }

    /// Register the hook that fires when a background mapping attempt changes the mapping state (Go's
    /// `Config.OnChange`). Set after construction because the hook usually wants the client itself.
    pub fn set_on_change(&self, f: Arc<dyn Fn() + Send + Sync>) {
        *self.on_change.lock().expect("on_change lock") = Some(f);
    }

    fn logf(&self, msg: impl AsRef<str>) {
        (self.logf)(msg.as_ref());
    }

    /// Go's `vlogf`: logged only under [`DebugKnobs::verbose_logs`].
    fn vlogf(&self, msg: impl AsRef<str>) {
        if self.debug.verbose_logs {
            (self.logf)(msg.as_ref());
        }
    }

    /// The NAT-PMP/PCP port: 5351, except in tests (Go `pxpPort`).
    fn pxp_port(&self) -> u16 {
        if self.test_pxp_port != 0 {
            self.test_pxp_port
        } else {
            PXP_PORT
        }
    }

    /// The SSDP discovery port: 1900, except in tests (Go `upnpPort`).
    fn upnp_port(&self) -> u16 {
        if self.test_upnp_port != 0 {
            self.test_upnp_port
        } else {
            UPNP_PORT
        }
    }

    /// Whether every mapping protocol is switched off (Go `DebugKnobs.disableAll`, including its
    /// `TS_DISABLE_PORTMAPPER` envknob).
    fn disable_all(&self) -> bool {
        self.debug.disable_all
            || std::env::var("TS_DISABLE_PORTMAPPER")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false)
    }

    /// Whether we hold a mapping that has not expired (Go `HaveMapping`).
    pub fn have_mapping(&self) -> bool {
        let st = self.state.lock().expect("portmap state lock");
        st.mapping
            .as_ref()
            .is_some_and(|m| m.good_until > SystemTime::now())
    }

    /// Set the local UDP port we want mapped (Go `SetLocalPort`). Changing it invalidates any
    /// mapping we hold, because that mapping points at the old port.
    pub fn set_local_port(&self, local_port: u16) {
        let mut st = self.state.lock().expect("portmap state lock");
        if st.local_port == local_port {
            return;
        }
        st.local_port = local_port;
        Self::invalidate_mappings_locked(&mut st, true);
    }

    /// Note that the network went away (Go `NoteNetworkDown`). It is too late to release mappings —
    /// the Wi-Fi may already be off — but they must not be trusted when it comes back.
    pub fn note_network_down(&self) {
        let mut st = self.state.lock().expect("portmap state lock");
        Self::invalidate_mappings_locked(&mut st, false);
    }

    /// Release what we hold and refuse further use (Go `Close`). Idempotent.
    ///
    /// The change hook is dropped too — Go's `Close` stops publishing mapping updates — which also
    /// releases whatever the hook captured (for `debug portmap`, the operator's log sink), so a
    /// background attempt that outlives the run cannot keep writing to it.
    pub fn close(&self) {
        {
            let mut st = self.state.lock().expect("portmap state lock");
            if st.closed {
                return;
            }
            st.closed = true;
            Self::invalidate_mappings_locked(&mut st, true);
        }
        // Taken AFTER the state lock is released: the background-attempt path holds this lock (to
        // clone the hook) before it takes the state lock, so taking them in that order here too
        // would be a lock-order inversion.
        *self.on_change.lock().expect("on_change lock") = None;
    }

    /// Drop every cached observation, and — when `release_old` — fire off a release for the mapping
    /// we were holding (Go `invalidateMappingsLocked`).
    ///
    /// Go's `Release` blocks; here the release is a fire-and-forget task, so this stays callable
    /// from the synchronous setters above. With no Tokio runtime in scope (a unit test) there is
    /// nothing to spawn onto and the release is skipped — the state is invalidated either way.
    fn invalidate_mappings_locked(st: &mut State, release_old: bool) {
        if let Some(m) = st.mapping.take()
            && release_old
            && let Ok(handle) = tokio::runtime::Handle::try_current()
        {
            let pkt = m.release_packet(mapping_nonce().unwrap_or([0u8; 12]));
            let gw = m.gw;
            handle.spawn(async move {
                // Best effort, exactly like Go's: bind, write once, drop.
                if let Ok(sock) = tokio::net::UdpSocket::bind("0.0.0.0:0").await {
                    let _ = sock.send_to(&pkt, gw).await;
                }
            });
        }
        st.pmp_pub_ip = None;
        st.pmp_pub_ip_time = None;
        st.pmp_last_epoch = 0;
        st.pcp_saw_time = None;
        st.pcp_last_epoch = 0;
        st.upnp_saw_time = None;
        st.upnp_metas.clear();
    }

    /// The gateway and our address for it, invalidating everything cached if either moved (Go
    /// `gatewayAndSelfIP`).
    fn gateway_and_self_ip(&self) -> Option<(IpAddr, IpAddr)> {
        let lookup = Arc::clone(&self.gateway_lookup.lock().expect("gateway lookup lock"));
        let found = lookup();
        let (gw, my_ip) = match found {
            Some(pair) => (Some(pair.0), Some(pair.1)),
            None => (None, None),
        };
        let mut st = self.state.lock().expect("portmap state lock");
        if gw != st.last_gw || my_ip != st.last_my_ip || found.is_none() {
            st.last_my_ip = my_ip;
            st.last_gw = gw;
            Self::invalidate_mappings_locked(&mut st, true);
        }
        found
    }

    /// Whether NAT-PMP was seen recently enough to still be trusted (Go `sawPMPRecentlyLocked`).
    fn saw_pmp_recently(st: &State) -> bool {
        st.pmp_pub_ip.is_some() && recent(st.pmp_pub_ip_time)
    }

    /// Whether PCP was seen recently enough to still be trusted (Go `sawPCPRecentlyLocked`).
    fn saw_pcp_recently(st: &State) -> bool {
        recent(st.pcp_saw_time)
    }

    /// Whether UPnP was seen recently enough to still be trusted (Go `sawUPnPRecently`).
    fn saw_upnp_recently(st: &State) -> bool {
        recent(st.upnp_saw_time)
    }

    /// Discard a cached NAT-PMP mapping when the gateway's epoch went *backwards*, which means it
    /// rebooted and no longer has our mapping (Go `maybeInvalidatePMPMappingLocked`).
    fn maybe_invalidate_pmp_mapping_locked(&self, st: &mut State, epoch: u32) {
        if epoch == 0 {
            return;
        }
        let Some(m) = st.mapping else { return };
        if m.kind != MappingKind::Pmp || epoch >= m.epoch {
            // Epoch increased, which is fine.
            return;
        }
        self.logf(format!(
            "invalidating PMP mappings since returned epoch {epoch} < stored epoch {}",
            m.epoch
        ));
        st.mapping = None;
        st.pmp_pub_ip = None;
        st.pmp_pub_ip_time = None;
        st.pmp_last_epoch = 0;
    }

    /// The PCP twin of [`Self::maybe_invalidate_pmp_mapping_locked`] (Go
    /// `maybeInvalidatePCPMappingLocked`).
    fn maybe_invalidate_pcp_mapping_locked(&self, st: &mut State, epoch: u32) {
        if epoch == 0 {
            return;
        }
        let Some(m) = st.mapping else { return };
        if m.kind != MappingKind::Pcp || epoch >= m.epoch {
            return;
        }
        self.logf(format!(
            "invalidating PCP mappings since returned epoch {epoch} < stored epoch {}",
            m.epoch
        ));
        st.mapping = None;
        st.pcp_saw_time = None;
        st.pcp_last_epoch = 0;
    }
}

/// Whether an observation is inside [`TRUST_SERVICE_STILL_AVAILABLE`] (Go's
/// `t.After(time.Now().Add(-trustServiceStillAvailableDuration))`).
fn recent(t: Option<SystemTime>) -> bool {
    match t {
        Some(t) => SystemTime::now()
            .checked_sub(TRUST_SERVICE_STILL_AVAILABLE)
            .is_some_and(|cutoff| t > cutoff),
        None => false,
    }
}

/// A fresh 96-bit PCP mapping nonce (Go's `rand.Read(mapOp[:12])` over `crypto/rand`).
///
/// Read from the kernel CSPRNG. The nonce is what lets a client tell its own MAP response from an
/// off-path forgery, so a failed read must not silently fall back to something guessable: it returns
/// `None`, and the mapping path refuses rather than sending a predictable nonce. (The
/// fire-and-forget *release* path substitutes zeros — that mapping is being torn down either way,
/// and a release carrying the wrong nonce is simply ignored by the server.)
fn mapping_nonce() -> Option<[u8; 12]> {
    use std::io::Read;
    let mut nonce = [0u8; 12];
    let mut f = std::fs::File::open("/dev/urandom").ok()?;
    f.read_exact(&mut nonce).ok()?;
    Some(nonce)
}

impl Client {
    /// Ask the network which port-mapping protocols it offers (Go `Client.Probe`).
    ///
    /// One UDP socket sends, in Go's order, a NAT-PMP public-address request, a PCP ANNOUNCE, and
    /// three SSDP M-SEARCHes — unicast to the gateway, then multicast, then the IGD-specific probe
    /// to multicast. The unicast probe goes first on purpose: many routers answer it, and sending it
    /// first teaches a stateful host firewall to expect a unicast reply, so the multicast probe's
    /// reply (which arrives from the device's *unicast* address) is not dropped.
    ///
    /// A protocol seen within [`TRUST_SERVICE_STILL_AVAILABLE`] for this same gateway is reported
    /// straight from cache and not re-probed at all, so a caller that probes often does not flood
    /// the router.
    ///
    /// Returns after [`PORT_MAP_SERVICE_TIMEOUT`], or as soon as all three have answered *and* the
    /// [`UPNP_SETTLE`] window has closed — that extra window exists because a LAN can hold several
    /// UPnP routers and taking whichever replied first would be arbitrary.
    pub async fn probe(&self) -> Result<ProbeResult, PortmapError> {
        if self.disable_all() {
            return Err(PortmapError::PortMappingDisabled);
        }
        let Some((gw, my_ip)) = self.gateway_and_self_ip() else {
            return Err(PortmapError::GatewayRange);
        };

        let sock = tokio::net::UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| {
                self.logf(format!("ProbePCP: {e}"));
                PortmapError::Io(e.to_string())
            })?;

        let pxp_addr = SocketAddr::new(gw, self.pxp_port());
        let upnp_addr = SocketAddr::new(gw, self.upnp_port());
        let upnp_multicast_addr =
            SocketAddr::V4(SocketAddrV4::new(SSDP_MULTICAST, self.upnp_port()));

        let mut res = ProbeResult::default();
        // Don't send probes to services we recently learned (for the same gw/myIP) are available.
        let (saw_pmp, saw_pcp, saw_upnp) = {
            let st = self.state.lock().expect("portmap state lock");
            (
                Self::saw_pmp_recently(&st),
                Self::saw_pcp_recently(&st),
                Self::saw_upnp_recently(&st),
            )
        };

        // Every send below is best-effort, exactly as Go ignores each WriteToUDPAddrPort's error:
        // a router that is not there simply never answers, and a multicast send can fail outright on
        // a host with no multicast route without saying anything about the unicast probes.
        if saw_pmp {
            res.pmp = true;
        } else if !self.debug.disable_pmp {
            let _ = sock.send_to(&PMP_REQ_EXTERNAL_ADDR_PACKET, pxp_addr).await;
        }
        if saw_pcp {
            res.pcp = true;
        } else if !self.debug.disable_pcp {
            let _ = sock.send_to(&pcp_announce_request(my_ip), pxp_addr).await;
        }
        if saw_upnp {
            res.upnp = true;
        } else if !self.debug.disable_upnp {
            let generic = upnp_packet(SSDP_ST_ALL);
            let igd = upnp_packet(SSDP_ST_IGD);
            let _ = sock.send_to(&generic, upnp_addr).await;
            let _ = sock.send_to(&generic, upnp_multicast_addr).await;
            let _ = sock.send_to(&igd, upnp_multicast_addr).await;
        }

        let deadline = tokio::time::Instant::now() + PORT_MAP_SERVICE_TIMEOUT;
        let mut upnp_settle_deadline: Option<tokio::time::Instant> = None;
        let mut upnp_responses: Vec<UpnpDiscoResponse> = Vec::new();
        let mut pcp_heard = false;
        let mut buf = [0u8; RECV_BUF];
        let mut io_err: Option<PortmapError> = None;

        loop {
            if pcp_heard
                && res.pmp
                && res.upnp
                && upnp_settle_deadline.is_some_and(|d| tokio::time::Instant::now() >= d)
            {
                // Nothing more to discover.
                break;
            }
            let now = tokio::time::Instant::now();
            if now >= deadline {
                break;
            }
            let read = tokio::time::timeout(deadline - now, sock.recv_from(&mut buf)).await;
            let (n, src) = match read {
                // The deadline passed: Go's context expiry, which is a normal end, not an error.
                Err(_elapsed) => break,
                Ok(Err(e)) => {
                    io_err = Some(PortmapError::Io(e.to_string()));
                    break;
                }
                Ok(Ok(v)) => v,
            };
            // Start the settle timer once the first response lands.
            if upnp_settle_deadline.is_none() {
                upnp_settle_deadline = Some(tokio::time::Instant::now() + UPNP_SETTLE);
            }
            let pkt = &buf[..n];
            let ip = unmap_socket_addr(src);
            let port = src.port();

            if port == self.upnp_port() {
                if contains(pkt, IGD_MARKER.as_bytes()) {
                    self.handle_upnp_response(pkt, ip, gw, &mut res, &mut upnp_responses);
                }
            } else if port == self.pxp_port() {
                self.handle_pxp_response(pkt, &mut res, &mut pcp_heard);
            } else if contains(pkt, IGD_MARKER.as_bytes()) {
                // Some devices answer discovery from a port other than 1900.
                self.logf(format!("UPnP discovery response from non-UPnP port {port}"));
                self.handle_upnp_response(pkt, ip, gw, &mut res, &mut upnp_responses);
            }
        }

        // Record what we learned about UPnP, whatever ended the loop (Go does this in a defer).
        if res.upnp && !upnp_responses.is_empty() {
            let upnp_responses = process_upnp_responses(upnp_responses);
            let mut st = self.state.lock().expect("portmap state lock");
            st.upnp_saw_time = Some(SystemTime::now());
            if st.upnp_metas != upnp_responses {
                self.logf(format!("UPnP meta changed: {upnp_responses:?}"));
                st.upnp_metas = upnp_responses;
            }
        }

        if let Some(e) = io_err {
            return Err(e);
        }
        self.state.lock().expect("portmap state lock").last_probe = Some(SystemTime::now());
        Ok(res)
    }

    /// Fold one SSDP discovery datagram into the probe result (Go's `handleUPnPResponse` closure).
    fn handle_upnp_response(
        &self,
        pkt: &[u8],
        src: IpAddr,
        gw: IpAddr,
        res: &mut ProbeResult,
        upnp_responses: &mut Vec<UpnpDiscoResponse>,
    ) {
        if src != gw {
            // Not fatal: a device other than the default gateway can still be the IGD.
            self.logf(format!(
                "UPnP discovery response from {src}, but gateway IP is {gw}"
            ));
        }
        let meta = match parse_upnp_disco_response(pkt) {
            Ok(meta) => meta,
            Err(e) => {
                self.logf(format!(
                    "unrecognized UPnP discovery response; ignoring: {e}"
                ));
                return;
            }
        };
        self.vlogf(format!(
            "UPnP reply {meta:?}, {:?}",
            String::from_utf8_lossy(pkt)
        ));
        res.upnp = true;
        if upnp_responses.len() > MAX_UPNP_RESPONSES {
            self.logf("too many UPnP responses: skipping");
        } else {
            upnp_responses.push(meta);
        }
    }

    /// Fold one datagram from port 5351 into the probe result — it is either PCP or NAT-PMP, told
    /// apart by its version byte (Go's `case c.pxpPort()` arm).
    fn handle_pxp_response(&self, pkt: &[u8], res: &mut ProbeResult, pcp_heard: &mut bool) {
        if let Some(pres) = parse_pcp_response(pkt) {
            if pres.op_code == PCP_OP_REPLY | PCP_OP_ANNOUNCE {
                *pcp_heard = true;
                {
                    let mut st = self.state.lock().expect("portmap state lock");
                    // Must run before we overwrite the stored epoch below.
                    self.maybe_invalidate_pcp_mapping_locked(&mut st, pres.epoch);
                    st.pcp_saw_time = Some(SystemTime::now());
                    st.pcp_last_epoch = pres.epoch;
                }
                match pres.result_code {
                    PcpResultCode::OK => {
                        self.vlogf(format!("Got PCP response: epoch: {}", pres.epoch));
                        res.pcp = true;
                        return;
                    }
                    // A PCP service is running, but refuses to provide port mapping services.
                    PcpResultCode::NOT_AUTHORIZED => {
                        res.pcp = false;
                        return;
                    }
                    // A PCP service is running, but it is behind a NAT, so it can't help us.
                    PcpResultCode::ADDRESS_MISMATCH => {
                        res.pcp = false;
                        return;
                    }
                    // Fall through to the unexpected-response log line.
                    _ => {}
                }
            }
            self.logf(format!("unexpected PCP probe response: {pres}"));
        }
        if let Some(pres) = parse_pmp_response(pkt) {
            if pres.op_code != PMP_OP_REPLY | PMP_OP_MAP_PUBLIC_ADDR {
                self.logf(format!("unexpected PMP probe response opcode: {pres}"));
                return;
            }
            match pres.result_code {
                PmpResultCode::OK => {
                    self.vlogf(format!(
                        "Got PMP response; IP: {}, epoch: {}",
                        pres.public_addr
                            .map_or_else(|| "invalid IP".to_string(), |a| a.to_string()),
                        pres.seconds_since_epoch
                    ));
                    res.pmp = true;
                    let mut st = self.state.lock().expect("portmap state lock");
                    // Must run before we overwrite the stored epoch below.
                    self.maybe_invalidate_pmp_mapping_locked(&mut st, pres.seconds_since_epoch);
                    st.pmp_pub_ip = pres.public_addr;
                    st.pmp_pub_ip_time = Some(SystemTime::now());
                    st.pmp_last_epoch = pres.seconds_since_epoch;
                }
                PmpResultCode::NOT_AUTHORIZED
                | PmpResultCode::NETWORK_FAILURE
                | PmpResultCode::OUT_OF_RESOURCES => {
                    self.logf(format!("PMP probe failed due result code: {pres}"));
                }
                _ => {
                    self.logf(format!("unexpected PMP probe response: {pres}"));
                }
            }
        }
    }

    /// Return the cached mapping if we have a good one, otherwise start creating one in the
    /// background and report that we have none yet (Go `GetCachedMappingOrStartCreatingOne`).
    ///
    /// When the background attempt succeeds, the hook registered with [`Client::set_on_change`]
    /// fires — that is how a caller learns about the mapping this call could not return.
    pub fn get_cached_mapping_or_start_creating_one(self: &Arc<Self>) -> Option<SocketAddr> {
        let now = SystemTime::now();
        let cached = {
            let st = self.state.lock().expect("portmap state lock");
            st.mapping
        };
        if let Some(m) = cached
            && now < m.good_until
        {
            if now > m.renew_after {
                self.maybe_start_mapping();
            }
            return Some(m.external);
        }
        self.maybe_start_mapping();
        None
    }

    /// Kick off a background mapping attempt unless one is already running (Go
    /// `maybeStartMappingLocked` + `createMapping`). A no-op with no Tokio runtime in scope.
    fn maybe_start_mapping(self: &Arc<Self>) {
        {
            let mut st = self.state.lock().expect("portmap state lock");
            if st.running_create {
                return;
            }
            st.running_create = true;
        }
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            self.state
                .lock()
                .expect("portmap state lock")
                .running_create = false;
            return;
        };
        let this = Arc::clone(self);
        handle.spawn(async move {
            // Go bounds the background attempt at 5 seconds.
            let result =
                tokio::time::timeout(Duration::from_secs(5), this.create_or_get_mapping()).await;
            this.state
                .lock()
                .expect("portmap state lock")
                .running_create = false;
            match result {
                Ok(Ok(_)) => {}
                Ok(Err(PortmapError::NoMapping(_))) => return,
                Ok(Err(e)) => {
                    this.logf(format!("createOrGetMapping: {e}"));
                    return;
                }
                Err(_elapsed) => return,
            }
            let hook = this.on_change.lock().expect("on_change lock").clone();
            if let Some(hook) = hook {
                hook();
            }
        });
    }

    /// Create a port mapping, or return the cached one if it is still fresh (Go
    /// `createOrGetMapping`).
    ///
    /// NAT-PMP is the default; PCP is preferred only when PCP was seen recently and NAT-PMP was not
    /// (or NAT-PMP is disabled), because a NAT-PMP mapping takes two round trips — one for the
    /// external address, one for the port — while PCP answers with everything in a single packet.
    /// When neither answers, the UPnP fallback runs.
    ///
    /// Every failure is a [`PortmapError::NoMapping`], carrying Go's cause, so a caller can tell
    /// "asked, got nothing" apart from a broken socket.
    pub async fn create_or_get_mapping(&self) -> Result<SocketAddr, PortmapError> {
        if self.disable_all() {
            return Err(PortmapError::PortMappingDisabled.no_mapping());
        }
        if self.debug.disable_upnp && self.debug.disable_pcp && self.debug.disable_pmp {
            return Err(PortmapError::NoPortMappingServices.no_mapping());
        }
        let Some((gw, my_ip)) = self.gateway_and_self_ip() else {
            return Err(PortmapError::GatewayRange.no_mapping());
        };
        if gw.is_ipv6() {
            return Err(PortmapError::GatewayIPv6.no_mapping());
        }

        let now = SystemTime::now();
        let pxp_addr = SocketAddr::new(gw, self.pxp_port());

        // Everything read out of the state cell up front, so no lock is held across an await.
        enum Next {
            /// The cached mapping is still fresh; hand it back untouched.
            Reuse(SocketAddr),
            /// Go straight to UPnP (PCP+PMP disabled, or a just-completed probe found neither).
            Upnp { prev_port: u16 },
            /// Ask over NAT-PMP/PCP.
            Ask {
                prev_port: u16,
                have_recent_pmp: bool,
                have_recent_pcp: bool,
                known_external_ip: Option<Ipv4Addr>,
            },
        }
        let internal_addr;
        let next = {
            let st = self.state.lock().expect("portmap state lock");
            internal_addr = SocketAddr::new(my_ip, st.local_port);
            // prevPort is the port we had most previously, if any. We try to ask for the same port;
            // 0 means "give us any port".
            let mut prev_port = 0u16;
            let mut reuse = None;
            if let Some(m) = st.mapping {
                if now < m.renew_after {
                    reuse = Some(m.external);
                } else {
                    // The mapping might still be valid, so just try to renew it.
                    prev_port = m.external.port();
                }
            }
            if let Some(external) = reuse {
                Next::Reuse(external)
            } else if self.debug.disable_pcp && self.debug.disable_pmp {
                Next::Upnp { prev_port }
            } else {
                let have_recent_pmp = Self::saw_pmp_recently(&st);
                let have_recent_pcp = Self::saw_pcp_recently(&st);
                // If we just did a Probe (e.g. via netcheck) but didn't find a PMP service, bail out
                // early rather than probing again. Cuts down latency for most clients.
                let probed_just_now = st
                    .last_probe
                    .and_then(|t| now.duration_since(t).ok())
                    .is_some_and(|d| d < Duration::from_secs(5));
                if probed_just_now && !have_recent_pmp && !have_recent_pcp {
                    Next::Upnp { prev_port }
                } else {
                    Next::Ask {
                        prev_port,
                        have_recent_pmp,
                        have_recent_pcp,
                        known_external_ip: if have_recent_pmp { st.pmp_pub_ip } else { None },
                    }
                }
            }
        };

        let (prev_port, have_recent_pmp, have_recent_pcp, known_external_ip) = match next {
            Next::Reuse(external) => {
                self.vlogf(format!("reusing existing mapping: external={external}"));
                return Ok(external);
            }
            Next::Upnp { prev_port } => {
                return self.upnp_fallback(gw, internal_addr, prev_port);
            }
            Next::Ask {
                prev_port,
                have_recent_pmp,
                have_recent_pcp,
                known_external_ip,
            } => (
                prev_port,
                have_recent_pmp,
                have_recent_pcp,
                known_external_ip,
            ),
        };

        let sock = tokio::net::UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| PortmapError::Io(e.to_string()))?;

        let prefer_pcp = !self.debug.disable_pcp
            && (self.debug.disable_pmp || (!have_recent_pmp && have_recent_pcp));

        if prefer_pcp {
            // Only do PCP mapping when PMP did not appear to be available recently.
            let Some(nonce) = mapping_nonce() else {
                return Err(PortmapError::Io(
                    "reading /dev/urandom for the PCP mapping nonce failed".into(),
                ));
            };
            let pkt = build_pcp_request_mapping_packet(
                nonce,
                my_ip,
                internal_addr.port(),
                prev_port,
                MAP_LIFETIME_SEC,
                // TODO(upstream's own): use the previous external IP here when it is known.
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            );
            self.send_or_no_mapping(&sock, &pkt, pxp_addr).await?;
        } else {
            // Ask for our external address if we do not already know it.
            if known_external_ip.is_none() {
                self.send_or_no_mapping(&sock, &PMP_REQ_EXTERNAL_ADDR_PACKET, pxp_addr)
                    .await?;
            }
            let pkt =
                build_pmp_request_mapping_packet(internal_addr.port(), prev_port, MAP_LIFETIME_SEC);
            self.send_or_no_mapping(&sock, &pkt, pxp_addr).await?;
        }

        // The NAT-PMP answer arrives in up to two packets (address, then port), so the loop keeps
        // reading until both halves are known; PCP answers in one.
        let mut external_ip: Option<IpAddr> = known_external_ip.map(IpAddr::V4);
        let mut external_port: u16 = 0;
        let mut good_until = now;
        let mut renew_after = now;
        let mut epoch = 0u32;
        let mut buf = [0u8; RECV_BUF];
        let deadline = tokio::time::Instant::now() + PORT_MAP_SERVICE_TIMEOUT;

        loop {
            let read_now = tokio::time::Instant::now();
            let timed_out = read_now >= deadline;
            let read = if timed_out {
                None
            } else {
                match tokio::time::timeout(deadline - read_now, sock.recv_from(&mut buf)).await {
                    Ok(Ok(v)) => Some(v),
                    // A read error (or the deadline) means nobody is answering: fall back to UPnP.
                    Ok(Err(_)) | Err(_) => None,
                }
            };
            let Some((n, src)) = read else {
                return self.upnp_fallback(gw, internal_addr, prev_port);
            };
            if unmap_socket_addr(src) != gw || src.port() != self.pxp_port() {
                continue;
            }
            let pkt = &buf[..n];
            match pkt.first().copied() {
                Some(PMP_VERSION) => {
                    let Some(pres) = parse_pmp_response(pkt) else {
                        self.logf(format!("unexpected PMP response: {}", hex_spaced(pkt)));
                        continue;
                    };
                    if pres.result_code != PmpResultCode::OK {
                        // A bare cause: `Display for PortmapError` adds the
                        // "no NAT mapping available: " prefix, exactly as Go's
                        // `NoMappingError.Error()` wraps its inner `PMP response Op=…,Res=…`.
                        return Err(PortmapError::NoMapping(format!(
                            "PMP response Op=0x{:x},Res=0x{:x}",
                            pres.op_code, pres.result_code.0
                        )));
                    }
                    if pres.op_code == PMP_OP_REPLY | PMP_OP_MAP_PUBLIC_ADDR {
                        external_ip = pres.public_addr.map(IpAddr::V4);
                    }
                    if pres.op_code == PMP_OP_REPLY | PMP_OP_MAP_UDP {
                        external_port = pres.external_port;
                        let d = Duration::from_secs(u64::from(pres.mapping_valid_seconds));
                        let stamp = SystemTime::now();
                        good_until = stamp + d;
                        // Renew in half the time.
                        renew_after = stamp + d / 2;
                        epoch = pres.seconds_since_epoch;
                    }
                }
                Some(PCP_VERSION) => {
                    let grant = match parse_pcp_map_response(pkt) {
                        Ok(g) => g,
                        Err(e) => {
                            self.logf(format!("failed to get PCP mapping: {e}"));
                            // PCP should only have a single packet response.
                            return Err(PortmapError::NoPortMappingServices.no_mapping());
                        }
                    };
                    let stamp = SystemTime::now();
                    let m = Mapping {
                        kind: MappingKind::Pcp,
                        gw: pxp_addr,
                        internal: internal_addr,
                        external: grant.external,
                        renew_after: stamp + grant.lifetime / 2,
                        good_until: stamp + grant.lifetime,
                        epoch: grant.epoch,
                    };
                    self.store_mapping(m);
                    return Ok(m.external);
                }
                other => {
                    self.logf(format!(
                        "unknown PMP/PCP version number: {} {}",
                        other.unwrap_or(0),
                        hex_spaced(pkt)
                    ));
                    return Err(PortmapError::NoPortMappingServices.no_mapping());
                }
            }

            // Both halves of the NAT-PMP answer are in: we have a mapping.
            if let Some(ip) = external_ip
                && external_port != 0
            {
                let m = Mapping {
                    kind: MappingKind::Pmp,
                    gw: pxp_addr,
                    internal: internal_addr,
                    external: SocketAddr::new(ip, external_port),
                    renew_after,
                    good_until,
                    epoch,
                };
                self.store_mapping(m);
                return Ok(m.external);
            }
        }
    }

    /// Send one datagram, mapping a "the network dropped it" write error onto
    /// [`PortmapError::NoPortMappingServices`] the way Go's `neterror.TreatAsLostUDP` does.
    async fn send_or_no_mapping(
        &self,
        sock: &tokio::net::UdpSocket,
        pkt: &[u8],
        to: SocketAddr,
    ) -> Result<(), PortmapError> {
        match sock.send_to(pkt, to).await {
            Ok(_) => Ok(()),
            Err(e) if treat_as_lost_udp(&e) => {
                Err(PortmapError::NoPortMappingServices.no_mapping())
            }
            Err(e) => Err(PortmapError::Io(e.to_string())),
        }
    }

    /// Record a freshly created mapping and log it the way Go's deferred summary does.
    fn store_mapping(&self, m: Mapping) {
        {
            let mut st = self.state.lock().expect("portmap state lock");
            st.mapping = Some(m);
        }
        if self.debug.verbose_logs {
            self.logf(format!(
                "successfully obtained mapping: now={} external={} type={} mapping={}",
                unix(SystemTime::now()),
                m.external,
                m.kind.as_str(),
                m.mapping_debug()
            ));
        } else {
            self.logf(format!(
                "successfully obtained mapping: now={} external={} type={} goodUntil={} renewAfter={}",
                unix(SystemTime::now()),
                m.external,
                m.kind.as_str(),
                unix(m.good_until),
                unix(m.renew_after)
            ));
        }
    }

    /// The UPnP leg of `createOrGetMapping` (Go `getUPnPPortMapping`).
    ///
    /// **Not ported**, and deliberately loud about it: obtaining a UPnP mapping means fetching the
    /// device-description XML named by the discovery response, walking it for a
    /// `WANIPConnection`/`WANPPPConnection` service, and driving `AddAnyPortMapping`/
    /// `AddPortMapping` over SOAP — which Go delegates to `github.com/huin/goupnp` and this tree has
    /// no XML/SOAP stack for. Discovery itself *is* ported ([`Client::probe`] detects and reports a
    /// UPnP router), so the honest answer here is "found it, cannot use it yet" rather than a silent
    /// "no services".
    fn upnp_fallback(
        &self,
        gw: IpAddr,
        internal: SocketAddr,
        prev_port: u16,
    ) -> Result<SocketAddr, PortmapError> {
        if self.debug.disable_upnp {
            return Err(PortmapError::NoPortMappingServices.no_mapping());
        }
        let metas = {
            let st = self.state.lock().expect("portmap state lock");
            st.upnp_metas.clone()
        };
        self.vlogf(format!(
            "UPnP fallback for gw={gw} internal={internal} prevPort={prev_port}"
        ));
        if metas.is_empty() {
            self.vlogf("fallback to UPnP failed: no UPnP device was discovered");
        } else {
            for meta in &metas {
                self.logf(format!(
                    "UPnP device discovered at {} ({}), but obtaining a UPnP mapping is not implemented by this build; NAT-PMP and PCP are",
                    meta.location, meta.server
                ));
            }
        }
        Err(PortmapError::NoPortMappingServices.no_mapping())
    }
}

/// Whether a UDP write error means "the datagram was lost", which is not a failure of the client
/// (Go `neterror.TreatAsLostUDP`): an ICMP-driven `ECONNREFUSED`/`EHOSTUNREACH`/`ENETUNREACH` from a
/// previous send is reported on the *next* one, and a message too large for the path is likewise not
/// a broken socket.
fn treat_as_lost_udp(e: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    matches!(
        e.kind(),
        ErrorKind::ConnectionRefused | ErrorKind::HostUnreachable | ErrorKind::NetworkUnreachable
    )
}

/// The source address of a datagram with any IPv4-mapped IPv6 form collapsed back to IPv4 (Go
/// `netaddr.Unmap`), so it compares equal to the gateway address we sent to.
fn unmap_socket_addr(addr: SocketAddr) -> IpAddr {
    match addr.ip() {
        IpAddr::V6(v6) => unmap(v6),
        v4 => v4,
    }
}

/// Whether `haystack` contains `needle` (Go `mem.Contains`).
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Hex-dump a datagram the way Go's `% 02x` verb does — space-separated, two digits per byte — for
/// the "unexpected PMP response" log lines.
fn hex_spaced(b: &[u8]) -> String {
    b.iter()
        .map(|x| format!("{x:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

// ───────────────────────────── the `debug portmap` run ─────────────────────────────

/// What `tnet debug portmap` asked for (Go `local.DebugPortmapOpts`, as decoded by
/// `serveDebugPortmap` from its query string).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebugPortmapOpts {
    /// How long the whole run may take before it is cut off (Go's `duration`, default 5s).
    pub duration: Duration,
    /// Which protocol to exercise: `""` (all), `"pmp"`, `"pcp"` or `"upnp"`. Anything else is
    /// refused by [`debug_portmap`].
    pub ty: String,
    /// `"<gateway>/<self>"`, overriding gateway auto-detection (Go's `gateway_and_self` form).
    /// `None` auto-detects.
    pub gateway_and_self: Option<String>,
    /// Log raw HTTP for the UPnP leg (Go's `log_http`).
    pub log_http: bool,
}

impl Default for DebugPortmapOpts {
    /// Go's defaults: five seconds, every protocol, auto-detected gateway, no HTTP logging.
    fn default() -> Self {
        DebugPortmapOpts {
            duration: Duration::from_secs(5),
            ty: String::new(),
            gateway_and_self: None,
            log_http: false,
        }
    }
}

/// Run one port-mapping diagnostic, narrating it to `logf` (Go
/// `feature/debugportmapper.serveDebugPortmap`).
///
/// The sequence, and every line it emits, is Go's: resolve the gateway (`gw=…; self=…`), bind a
/// local UDP port so the mapping is for a real port, [`Client::probe`] (`Probe: {PCP:… PMP:… UPnP:…}`),
/// stop early if nothing answered (`no portmapping services available`), then ask for a mapping
/// (`mapping: …` / `no mapping`) and wait — up to [`DebugPortmapOpts::duration`] — for the
/// background attempt's callback to report one (`portmapping changed.` / `cb: mapping: …`).
///
/// Returns `Err` only for the one input Go rejects with a 400 before doing anything: a `--type` that
/// is not one of `""`, `"pmp"`, `"pcp"`, `"upnp"`. Everything after that is *reported* on `logf`
/// rather than returned, because by then the operator is reading a live log, not an error.
pub async fn debug_portmap(logf: LogSink, opts: &DebugPortmapOpts) -> Result<(), String> {
    // Verbose logs are always on for this endpoint — the whole point is to see the detail.
    let mut debug = DebugKnobs {
        verbose_logs: true,
        log_http: opts.log_http,
        ..Default::default()
    };
    match opts.ty.as_str() {
        "" => {}
        "pmp" => {
            debug.disable_pcp = true;
            debug.disable_upnp = true;
        }
        "pcp" => {
            debug.disable_pmp = true;
            debug.disable_upnp = true;
        }
        "upnp" => {
            debug.disable_pcp = true;
            debug.disable_pmp = true;
        }
        _ => return Err("unknown portmap debug type".to_string()),
    }

    // Go prefixes the portmapper's own lines so they are distinguishable from the handler's.
    let prefixed: LogSink = {
        let logf = Arc::clone(&logf);
        Arc::new(move |s: &str| logf(&format!("portmapper: {s}")))
    };
    let client = Client::new(prefixed, debug);

    // Go's `defer c.Close()`: close the client on EVERY way out of this function — the early
    // returns below, the normal end, and a *cancelled* run (the daemon aborts this task when the
    // client hangs up, so this drop is the only cleanup that gets to happen). Closing drops the
    // change hook and releases a mapping we obtained, so an abandoned diagnostic does not leave a
    // mapping on the router to expire on its own. `close` is idempotent.
    struct CloseOnDrop(Arc<Client>);
    impl Drop for CloseOnDrop {
        fn drop(&mut self) {
            self.0.close();
        }
    }
    // Declared after `client`, so it drops (and closes) before the client itself does.
    let _closer = CloseOnDrop(Arc::clone(&client));

    // An explicit `<gateway>/<self>` pair wins over auto-detection; a malformed one is reported and
    // ends the run rather than being silently ignored (Go parses it with MustParseAddr, having
    // validated it in the CLI first).
    if let Some(gw_self) = &opts.gateway_and_self {
        let Some((gw, self_ip)) = gw_self.split_once('/') else {
            logf(&format!(
                "invalid gateway_and_self {gw_self:?}: want <gateway>/<self>"
            ));
            return Ok(());
        };
        let (Ok(gw), Ok(self_ip)) = (gw.parse::<IpAddr>(), self_ip.parse::<IpAddr>()) else {
            logf(&format!(
                "invalid gateway_and_self {gw_self:?}: not an IP pair"
            ));
            return Ok(());
        };
        client.set_gateway_lookup(Arc::new(move || Some((gw, self_ip))));
    }

    let Some((gw, self_ip)) = (client.gateway_lookup.lock().expect("gateway lookup lock"))() else {
        logf("no gateway or self IP");
        return Ok(());
    };
    logf(&format!("gw={gw}; self={self_ip}"));

    // Bind a local port and map *that*, so the mapping is for a port something could actually
    // listen on (Go binds a socket here for the same reason).
    let uc = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
        Ok(uc) => uc,
        Err(e) => {
            logf(&format!("error binding local UDP socket: {e}"));
            return Ok(());
        }
    };
    let local_port = uc.local_addr().map(|a| a.port()).unwrap_or(0);
    client.set_local_port(local_port);

    // The callback fires when a background mapping attempt changes the mapping state; it is what
    // ends the wait below, so it is installed before anything can trigger it.
    let (done_tx, mut done_rx) = tokio::sync::mpsc::channel::<()>(1);
    {
        let client_hook = Arc::downgrade(&client);
        let logf = Arc::clone(&logf);
        client.set_on_change(Arc::new(move || {
            let Some(c) = client_hook.upgrade() else {
                return;
            };
            logf("portmapping changed.");
            logf(&format!("have mapping: {}", c.have_mapping()));
            if let Some(ext) = c.get_cached_mapping_or_start_creating_one() {
                logf(&format!("cb: mapping: {ext}"));
                // Non-blocking: a full channel already carries the "we are done" signal.
                let _ = done_tx.try_send(());
                return;
            }
            logf("cb: no mapping");
        }));
    }

    let deadline = tokio::time::Instant::now() + opts.duration;
    let res = match tokio::time::timeout_at(deadline, client.probe()).await {
        Ok(Ok(res)) => res,
        Ok(Err(e)) => {
            logf(&format!("error in Probe: {e}"));
            return Ok(());
        }
        // Go's `Probe` derives its OWN 250ms context and turns that context's
        // `DeadlineExceeded` into `err = nil` with a zero `ProbeResult`, so an outer deadline
        // that expires first is a normal, empty probe — not an early return. Reporting it as
        // an empty result keeps the `Probe:` line and the "no portmapping services available"
        // line that Go prints for any `--duration` under the 250ms cap (and for a clamped
        // negative one). The `context done` line belongs to the post-probe wait below, which is
        // where Go actually emits it.
        Err(_elapsed) => ProbeResult::default(),
    };
    logf(&format!("Probe: {res}"));

    if res.is_empty() {
        logf("no portmapping services available");
        return Ok(());
    }

    if let Some(ext) = client.get_cached_mapping_or_start_creating_one() {
        logf(&format!("mapping: {ext}"));
    } else {
        logf("no mapping");
    }

    // Wait for the background attempt's callback, or for the run's deadline.
    tokio::select! {
        _ = done_rx.recv() => {}
        _ = tokio::time::sleep_until(deadline) => {
            logf("serveDebugPortmap: context done: context deadline exceeded");
        }
    }
    // `_closer` closes the client here, and on every early return above.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    /// A log sink that keeps every line, so a test can assert on what a run said.
    fn collector() -> (LogSink, Arc<StdMutex<Vec<String>>>) {
        let lines = Arc::new(StdMutex::new(Vec::new()));
        let sink_lines = Arc::clone(&lines);
        let sink: LogSink = Arc::new(move |s: &str| {
            sink_lines.lock().expect("log lock").push(s.to_string());
        });
        (sink, lines)
    }

    /// A sink that throws every line away, for the paths whose output is not what is under test.
    fn discard() -> LogSink {
        Arc::new(|_: &str| {})
    }

    // ───────────────────────────── NAT-PMP wire format ─────────────────────────────

    #[test]
    fn pmp_external_addr_request_is_two_zero_bytes() {
        // Go's `pmpReqExternalAddrPacket = []byte{pmpVersion, pmpOpMapPublicAddr}`.
        assert_eq!(PMP_REQ_EXTERNAL_ADDR_PACKET, [0u8, 0u8]);
    }

    #[test]
    fn pmp_request_mapping_packet_is_go_wire_format() {
        // version 0, opcode 1 (map UDP), 2 reserved bytes, internal port, suggested external port,
        // lifetime — all big-endian (RFC 6886 §3.3).
        let pkt = build_pmp_request_mapping_packet(41641, 12345, MAP_LIFETIME_SEC);
        assert_eq!(
            pkt,
            [
                0x00, 0x01, 0x00, 0x00, // version, op=map UDP, reserved
                0xa2, 0xa9, // internal port 41641
                0x30, 0x39, // suggested external port 12345
                0x00, 0x00, 0x1c, 0x20, // lifetime 7200
            ]
        );
    }

    #[test]
    fn pmp_request_mapping_packet_with_delete_lifetime_is_a_release() {
        // A release is the same packet with a zero lifetime (Go `pmpMapping.Release`).
        let pkt = build_pmp_request_mapping_packet(41641, 12345, MAP_LIFETIME_DELETE);
        assert_eq!(&pkt[8..12], &[0, 0, 0, 0]);
    }

    #[test]
    fn pmp_public_addr_response_parses() {
        let pkt = [
            0x00, 0x80, // version, op = reply|public-addr
            0x00, 0x00, // result OK
            0x00, 0x00, 0x04, 0xd2, // epoch 1234
            192, 0, 2, 1, // public address
        ];
        let res = parse_pmp_response(&pkt).expect("well-formed public-addr reply");
        assert_eq!(res.op_code, PMP_OP_REPLY | PMP_OP_MAP_PUBLIC_ADDR);
        assert_eq!(res.result_code, PmpResultCode::OK);
        assert_eq!(res.seconds_since_epoch, 1234);
        assert_eq!(res.public_addr, Some(Ipv4Addr::new(192, 0, 2, 1)));
    }

    #[test]
    fn pmp_public_addr_response_zeroes_an_unspecified_address() {
        // Go zeroes the netip.Addr so 0.0.0.0 is never treated as a usable external address.
        let pkt = [0x00, 0x80, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        let res = parse_pmp_response(&pkt).expect("well-formed public-addr reply");
        assert_eq!(res.public_addr, None);
    }

    #[test]
    fn pmp_map_response_parses() {
        let pkt = [
            0x00, 0x81, // version, op = reply|map UDP
            0x00, 0x00, // result OK
            0x00, 0x00, 0x00, 0x07, // epoch 7
            0xa2, 0xa9, // internal port 41641
            0x30, 0x39, // external port 12345
            0x00, 0x00, 0x1c, 0x20, // lifetime 7200
        ];
        let res = parse_pmp_response(&pkt).expect("well-formed map reply");
        assert_eq!(res.internal_port, 41641);
        assert_eq!(res.external_port, 12345);
        assert_eq!(res.mapping_valid_seconds, 7200);
    }

    #[test]
    fn pmp_response_refuses_malformed_datagrams() {
        // Shorter than the 12-byte common header.
        assert_eq!(parse_pmp_response(&[0u8; 11]), None);
        // Wrong version (2 is PCP) — this is what keeps a PCP datagram from parsing as NAT-PMP.
        assert_eq!(parse_pmp_response(&[2u8; 24]), None);
        // A map reply must be exactly 16 bytes; 12 and 20 are both refused.
        let mut short_map = [0u8; 12];
        short_map[1] = PMP_OP_REPLY | PMP_OP_MAP_UDP;
        assert_eq!(parse_pmp_response(&short_map), None);
        let mut long_map = [0u8; 20];
        long_map[1] = PMP_OP_REPLY | PMP_OP_MAP_UDP;
        assert_eq!(parse_pmp_response(&long_map), None);
        // A public-address reply must be exactly 12 bytes.
        let mut long_addr = [0u8; 16];
        long_addr[1] = PMP_OP_REPLY | PMP_OP_MAP_PUBLIC_ADDR;
        assert_eq!(parse_pmp_response(&long_addr), None);
    }

    #[test]
    fn pmp_result_codes_render_like_gos_stringer() {
        assert_eq!(PmpResultCode::OK.to_string(), "OK");
        assert_eq!(
            PmpResultCode::UNSUPPORTED_VERSION.to_string(),
            "UnsupportedVersion"
        );
        assert_eq!(PmpResultCode::NOT_AUTHORIZED.to_string(), "NotAuthorized");
        assert_eq!(PmpResultCode::NETWORK_FAILURE.to_string(), "NetworkFailure");
        assert_eq!(
            PmpResultCode::OUT_OF_RESOURCES.to_string(),
            "OutOfResources"
        );
        assert_eq!(
            PmpResultCode::UNSUPPORTED_OPCODE.to_string(),
            "UnsupportedOpcode"
        );
        // Go's stringer falls back to the typed-number form for anything it does not name.
        assert_eq!(PmpResultCode(9).to_string(), "pmpResultCode(9)");
    }

    // ───────────────────────────── PCP wire format ─────────────────────────────

    #[test]
    fn pcp_announce_request_is_go_wire_format() {
        let pkt = pcp_announce_request(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5)));
        assert_eq!(pkt[0], PCP_VERSION);
        assert_eq!(pkt[1], PCP_OP_ANNOUNCE);
        // Bytes 2..8 (reserved + requested lifetime) stay zero on an ANNOUNCE.
        assert_eq!(&pkt[2..8], &[0u8; 6]);
        // The client address is carried IPv4-mapped, as RFC 6887 requires.
        assert_eq!(
            &pkt[8..24],
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 5]
        );
    }

    #[test]
    fn pcp_map_request_is_go_wire_format() {
        let nonce = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let pkt = build_pcp_request_mapping_packet(
            nonce,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5)),
            41641,
            12345,
            MAP_LIFETIME_SEC,
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        );
        assert_eq!(pkt.len(), 60, "24-byte header + 36-byte MAP body");
        assert_eq!(pkt[0], PCP_VERSION);
        assert_eq!(pkt[1], PCP_OP_MAP);
        assert_eq!(&pkt[4..8], &7200u32.to_be_bytes());
        assert_eq!(
            &pkt[8..24],
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 5]
        );
        assert_eq!(&pkt[24..36], &nonce);
        assert_eq!(pkt[36], PCP_UDP_MAPPING);
        assert_eq!(&pkt[37..40], &[0, 0, 0], "reserved");
        assert_eq!(&pkt[40..42], &41641u16.to_be_bytes());
        assert_eq!(&pkt[42..44], &12345u16.to_be_bytes());
        // An unknown previous external address is the IPv4-mapped wildcard.
        assert_eq!(
            &pkt[44..60],
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0]
        );
    }

    /// Build a 60-byte PCP MAP response with the given result code, external port and address.
    fn pcp_map_reply(code: u8, lifetime: u32, epoch: u32, port: u16, ip: Ipv4Addr) -> Vec<u8> {
        let mut pkt = vec![0u8; 60];
        pkt[0] = PCP_VERSION;
        pkt[1] = PCP_OP_REPLY | PCP_OP_MAP;
        pkt[3] = code;
        pkt[4..8].copy_from_slice(&lifetime.to_be_bytes());
        pkt[8..12].copy_from_slice(&epoch.to_be_bytes());
        pkt[42..44].copy_from_slice(&port.to_be_bytes());
        pkt[44..60].copy_from_slice(&ip.to_ipv6_mapped().octets());
        pkt
    }

    #[test]
    fn pcp_map_response_parses_a_grant() {
        let pkt = pcp_map_reply(0, 7200, 42, 12345, Ipv4Addr::new(192, 0, 2, 1));
        let grant = parse_pcp_map_response(&pkt).expect("well-formed MAP response");
        assert_eq!(
            grant.external,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 12345),
            "the IPv4-mapped external address is unmapped back to IPv4"
        );
        assert_eq!(grant.lifetime, Duration::from_secs(7200));
        assert_eq!(grant.epoch, 42);
    }

    #[test]
    fn pcp_map_response_refusals_carry_gos_messages() {
        // Too short to be a MAP response at all.
        assert_eq!(
            parse_pcp_map_response(&[0u8; 59]),
            Err("Does not appear to be PCP MAP response".to_string())
        );
        // Long enough, but the common header does not parse (wrong version).
        let mut bad_version = pcp_map_reply(0, 7200, 1, 1, Ipv4Addr::new(192, 0, 2, 1));
        bad_version[0] = 3;
        assert_eq!(
            parse_pcp_map_response(&bad_version),
            Err("Invalid PCP common header".to_string())
        );
        // The specific "PCP is here, but the owner switched it off" case gets its own message.
        let not_authorized = pcp_map_reply(2, 0, 1, 0, Ipv4Addr::UNSPECIFIED);
        assert_eq!(
            parse_pcp_map_response(&not_authorized),
            Err("PCP is implemented but not enabled in the router".to_string())
        );
        // Any other non-OK code is reported by number.
        let mismatch = pcp_map_reply(12, 0, 1, 0, Ipv4Addr::UNSPECIFIED);
        assert_eq!(
            parse_pcp_map_response(&mismatch),
            Err("PCP response not ok, code 12".to_string())
        );
    }

    #[test]
    fn pcp_result_codes_render_like_gos_stringer() {
        assert_eq!(PcpResultCode::OK.to_string(), "OK");
        assert_eq!(PcpResultCode::NOT_AUTHORIZED.to_string(), "NotAuthorized");
        assert_eq!(
            PcpResultCode::ADDRESS_MISMATCH.to_string(),
            "AddressMismatch"
        );
        assert_eq!(PcpResultCode(7).to_string(), "pcpResultCode(7)");
    }

    #[test]
    fn pcp_response_refuses_short_or_wrong_version_headers() {
        assert_eq!(parse_pcp_response(&[PCP_VERSION; 23]), None);
        // Version 0 is NAT-PMP; it must not parse as a PCP header.
        assert_eq!(parse_pcp_response(&[0u8; 24]), None);
    }

    // ───────────────────────────── UPnP discovery ─────────────────────────────

    /// A realistic SSDP discovery response, as a router's `MiniUPnPd` sends it.
    fn ssdp_response(usn_suffix: &str, location: &str, server: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 200 OK\r\n\
             CACHE-CONTROL: max-age=120\r\n\
             ST: urn:schemas-upnp-org:device:InternetGatewayDevice:{usn_suffix}\r\n\
             USN: uuid:0000e068-20a0-00e0-20a0-48a802086048::urn:schemas-upnp-org:device:InternetGatewayDevice:{usn_suffix}\r\n\
             LOCATION: {location}\r\n\
             SERVER: {server}\r\n\r\n"
        )
        .into_bytes()
    }

    #[test]
    fn upnp_disco_response_reads_the_three_headers_case_insensitively() {
        let body = ssdp_response("1", "http://192.0.2.1:5000/rootDesc.xml", "MiniUPnPd/2.1");
        let meta = parse_upnp_disco_response(&body).expect("well-formed discovery response");
        assert_eq!(meta.location, "http://192.0.2.1:5000/rootDesc.xml");
        assert_eq!(meta.server, "MiniUPnPd/2.1");
        assert!(meta.usn.ends_with("InternetGatewayDevice:1"));

        // Go's http.Header.Get canonicalizes, so header case must not matter.
        let mixed = b"HTTP/1.1 200 OK\r\nlocation: http://192.0.2.1:80/d.xml\r\nSeRvEr: X/1\r\nUsn: u\r\n\r\n";
        let meta = parse_upnp_disco_response(mixed).expect("well-formed discovery response");
        assert_eq!(meta.location, "http://192.0.2.1:80/d.xml");
        assert_eq!(meta.server, "X/1");
        assert_eq!(meta.usn, "u");
    }

    #[test]
    fn upnp_m_search_packets_match_gos_bytes() {
        // The SSDP group is fixed by the UPnP Device Architecture, not a choice this fork makes.
        // Pinned by its octets so there is one definition of it in the module and the probes
        // below are composed from that one.
        let group = Ipv4Addr::new(239, 255, 255, 250);
        assert_eq!(SSDP_MULTICAST, group);
        assert!(
            SSDP_MULTICAST.is_multicast(),
            "SSDP discovery is multicast, never a unicast destination"
        );

        // Go's `uPnPPacket` and `uPnPIGDPacket`, byte for byte: same header order, same CRLFs,
        // same quoted MAN, same MX, same blank-line terminator — differing only in `ST:`.
        assert_eq!(
            String::from_utf8(upnp_packet(SSDP_ST_ALL)).expect("ASCII"),
            format!(
                "M-SEARCH * HTTP/1.1\r\nHOST: {group}:1900\r\nST: ssdp:all\r\n\
                 MAN: \"ssdp:discover\"\r\nMX: 2\r\n\r\n"
            )
        );
        assert_eq!(
            String::from_utf8(upnp_packet(SSDP_ST_IGD)).expect("ASCII"),
            format!(
                "M-SEARCH * HTTP/1.1\r\nHOST: {group}:1900\r\n\
                 ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\
                 MAN: \"ssdp:discover\"\r\nMX: 2\r\n\r\n"
            )
        );
    }

    #[test]
    fn upnp_disco_response_refuses_datagrams_that_are_not_http_responses() {
        // Not an HTTP response at all — a stray datagram on port 1900.
        assert!(parse_upnp_disco_response(b"hello there").is_err());
        // An HTTP *request*, not a response.
        assert!(parse_upnp_disco_response(b"M-SEARCH * HTTP/1.1\r\nHOST: x\r\n\r\n").is_err());
        // A status code that is not three digits.
        assert!(parse_upnp_disco_response(b"HTTP/1.1 2 OK\r\n\r\n").is_err());
        // A header line with no colon.
        assert!(parse_upnp_disco_response(b"HTTP/1.1 200 OK\r\nnot a header\r\n\r\n").is_err());
    }

    #[test]
    fn process_upnp_responses_keeps_the_newest_service_and_dedupes() {
        // The same device answers both M-SEARCH probes, offering IGD:1 and IGD:2 from one Location.
        let v1 = UpnpDiscoResponse {
            location: "http://192.0.2.1:5000/rootDesc.xml".into(),
            server: "MiniUPnPd/2.1".into(),
            usn: "uuid:a::urn:schemas-upnp-org:device:InternetGatewayDevice:1".into(),
        };
        let v2 = UpnpDiscoResponse {
            usn: "uuid:a::urn:schemas-upnp-org:device:InternetGatewayDevice:2".into(),
            ..v1.clone()
        };
        let other = UpnpDiscoResponse {
            location: "http://192.0.2.9:5000/rootDesc.xml".into(),
            server: "OtherUPnP/1.0".into(),
            usn: "uuid:b::urn:schemas-upnp-org:device:InternetGatewayDevice:1".into(),
        };
        let got = process_upnp_responses(vec![v1.clone(), other.clone(), v2.clone(), v1.clone()]);
        assert_eq!(
            got.len(),
            2,
            "the duplicate Location+Server entries collapse to one"
        );
        assert!(
            got.iter().any(|m| m.usn == v2.usn),
            "the IGD:2 entry survives, because the USN sorts in reverse: {got:?}"
        );
        assert!(
            !got.iter().any(|m| m.usn == v1.usn),
            "the IGD:1 entry for the same device is dropped: {got:?}"
        );
        assert!(got.iter().any(|m| m.location == other.location));
    }

    // ───────────────────────────── result + error rendering ─────────────────────────────

    #[test]
    fn probe_result_renders_like_gos_percent_plus_v() {
        assert_eq!(
            ProbeResult::default().to_string(),
            "{PCP:false PMP:false UPnP:false}"
        );
        assert_eq!(
            ProbeResult {
                pcp: true,
                pmp: false,
                upnp: true
            }
            .to_string(),
            "{PCP:true PMP:false UPnP:true}"
        );
        assert!(ProbeResult::default().is_empty());
        assert!(
            !ProbeResult {
                upnp: true,
                ..Default::default()
            }
            .is_empty()
        );
    }

    #[test]
    fn portmap_errors_carry_gos_verbatim_strings() {
        assert_eq!(
            PortmapError::NoPortMappingServices.to_string(),
            "no port mapping services were found"
        );
        assert_eq!(
            PortmapError::GatewayRange.to_string(),
            "skipping portmap; gateway range likely lacks support"
        );
        assert_eq!(
            PortmapError::GatewayIPv6.to_string(),
            "skipping portmap; no IPv6 support for portmapping"
        );
        assert_eq!(
            PortmapError::PortMappingDisabled.to_string(),
            "port mapping is disabled"
        );
        // Go wraps a cause as NoMappingError{err}: "no NAT mapping available: <cause>".
        assert_eq!(
            PortmapError::NoPortMappingServices.no_mapping().to_string(),
            "no NAT mapping available: no port mapping services were found"
        );
    }

    // ───────────────────────────── gateway lookup ─────────────────────────────

    #[cfg(target_os = "linux")]
    #[test]
    fn proc_net_route_finds_the_private_default_gateway() {
        // Real /proc/net/route shape: header, then a default route (destination 00000000) whose
        // gateway is little-endian hex, then an on-link route with no gateway.
        let contents = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
ens18\t00000000\t0100000A\t0003\t0\t0\t0\t00000000\t0\t0\t0
ens18\t0000000A\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0
";
        assert_eq!(
            parse_proc_net_route(contents),
            Some((Ipv4Addr::new(10, 0, 0, 1), "ens18".to_string()))
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn proc_net_route_skips_routes_that_are_not_usable_gateways_to_a_private_address() {
        // A gateway route that is not RTF_UP (flags 0x0002 alone), an up-but-not-gateway route, a
        // malformed flags field, and a default route to a PUBLIC gateway — none of which is a home
        // router — followed by the one that is.
        //
        // The Gateway column is little-endian hex, so it reads back-to-front: `0100000A` is
        // 10.0.0.1, `010200C0` is 192.0.2.1 (public, so not a home router), and `01A8A8C0` is
        // 192.168.168.1. Writing one of these big-endian silently changes which address the row
        // carries — that is how a private gateway turns into a public one and the row stops
        // testing what it is here to test.
        let contents = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
eth0\t00000000\t0100000A\t0002\t0\t0\t0\t00000000\t0\t0\t0
eth0\t0000000A\t0100000A\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0
eth0\t00000000\t0100000A\tzzzz\t0\t0\t0\t00000000\t0\t0\t0
eth0\t00000000\t010200C0\t0003\t0\t0\t0\t00000000\t0\t0\t0
wlan0\t00000000\t01A8A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0
";
        assert_eq!(
            parse_proc_net_route(contents),
            Some((Ipv4Addr::new(192, 168, 168, 1), "wlan0".to_string()))
        );
        // A table with no usable private gateway at all yields nothing, which becomes
        // PortmapError::GatewayRange at the call site.
        assert_eq!(
            parse_proc_net_route("Iface\tDestination\tGateway\tFlags\n"),
            None
        );
    }

    #[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd"))]
    /// Build one `PF_ROUTE` dump record: an `rt_msghdr` followed by the sockaddrs named by
    /// `rtm_addrs`, the layout `parse_routing_table` walks.
    fn rib_message(flags: libc::c_int, addrs: &[(usize, Option<Ipv4Addr>)]) -> Vec<u8> {
        fn sockaddr_in(ip: Ipv4Addr) -> Vec<u8> {
            let mut sa = vec![0u8; 16];
            sa[0] = 16; // sa_len
            sa[1] = libc::AF_INET as u8;
            sa[4..8].copy_from_slice(&ip.octets());
            sa
        }
        let mut body = Vec::new();
        let mut mask = 0;
        for (slot, ip) in addrs {
            mask |= 1 << slot;
            match ip {
                // A zero netmask/destination arrives as a length-only sockaddr, padded to 4 bytes.
                None => body.extend_from_slice(&[0u8; 4]),
                Some(ip) => body.extend_from_slice(&sockaddr_in(*ip)),
            }
        }
        let hdr_len = std::mem::size_of::<libc::rt_msghdr>();
        // SAFETY: `rt_msghdr` is a plain C struct of integers with no padding invariants, so an
        // all-zero value is valid; the fields that matter are set immediately below.
        let mut hdr: libc::rt_msghdr = unsafe { std::mem::zeroed() };
        hdr.rtm_msglen = (hdr_len + body.len()) as libc::c_ushort;
        hdr.rtm_version = libc::RTM_VERSION as libc::c_uchar;
        hdr.rtm_flags = flags;
        hdr.rtm_addrs = mask;
        // SAFETY: reading `hdr_len` bytes from a live `rt_msghdr` as bytes; `rt_msghdr` has no
        // padding requirements that make this unsound and the slice never outlives `hdr`.
        let hdr_bytes: &[u8] =
            unsafe { std::slice::from_raw_parts((&raw const hdr).cast::<u8>(), hdr_len) };
        let mut out = hdr_bytes.to_vec();
        out.extend_from_slice(&body);
        out
    }

    #[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd"))]
    #[test]
    fn routing_table_finds_the_default_gateway_and_self_address() {
        const RTF_GATEWAY: libc::c_int = 0x2;
        const RTF_IFSCOPE: libc::c_int = 0x1000000;
        let mut rib = Vec::new();
        // A non-gateway route: skipped.
        rib.extend(rib_message(
            0,
            &[
                (0, Some(Ipv4Addr::new(192, 0, 2, 0))),
                (1, Some(Ipv4Addr::new(192, 0, 2, 1))),
                (2, None),
            ],
        ));
        // An interface-scoped copy of the default route: skipped, so a secondary interface's
        // duplicate is never mistaken for the real default.
        rib.extend(rib_message(
            RTF_GATEWAY | RTF_IFSCOPE,
            &[
                (0, None),
                (1, Some(Ipv4Addr::new(198, 51, 100, 1))),
                (2, None),
            ],
        ));
        // A gateway route to a specific destination (non-default): skipped.
        rib.extend(rib_message(
            RTF_GATEWAY,
            &[
                (0, Some(Ipv4Addr::new(203, 0, 113, 0))),
                (1, Some(Ipv4Addr::new(192, 168, 1, 254))),
                (2, Some(Ipv4Addr::new(255, 255, 255, 0))),
            ],
        ));
        // The real default route, carrying an interface address.
        rib.extend(rib_message(
            RTF_GATEWAY,
            &[
                (0, None),
                (1, Some(Ipv4Addr::new(192, 168, 1, 1))),
                (2, None),
                (5, Some(Ipv4Addr::new(192, 168, 1, 50))),
            ],
        ));
        assert_eq!(
            parse_routing_table(&rib),
            Some((
                Ipv4Addr::new(192, 168, 1, 1),
                Some(Ipv4Addr::new(192, 168, 1, 50))
            ))
        );
    }

    #[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd"))]
    #[test]
    fn routing_table_tolerates_a_missing_interface_address_and_a_truncated_dump() {
        const RTF_GATEWAY: libc::c_int = 0x2;
        // The interface address is optional; without it the caller substitutes 0.0.0.0.
        let rib = rib_message(
            RTF_GATEWAY,
            &[(0, None), (1, Some(Ipv4Addr::new(10, 0, 0, 1))), (2, None)],
        );
        assert_eq!(
            parse_routing_table(&rib),
            Some((Ipv4Addr::new(10, 0, 0, 1), None))
        );
        // A dump cut off mid-record ends the walk instead of reading past the buffer.
        assert_eq!(parse_routing_table(&rib[..rib.len() - 4]), None);
        assert_eq!(parse_routing_table(&[]), None);
    }

    // ───────────────────────────── the client, against a fake IGD ─────────────────────────────

    /// Whether this host actually delivers a loopback UDP datagram.
    ///
    /// Every test below that drives the real [`Client`] needs one process to send a datagram to
    /// another on `127.0.0.1` and have it arrive. That is ordinary on a developer machine and in CI,
    /// but some hardened build sandboxes accept the `send` and then drop the packet — in which case
    /// these tests would fail for a reason that has nothing to do with the code under test. This
    /// probes for that up front so the socket-driven tests can say plainly that they were skipped,
    /// instead of failing or quietly pretending to have run. The pure wire-format, parser, ordering
    /// and error-path tests above cover this module unconditionally either way.
    async fn loopback_udp_works() -> bool {
        let Ok(rx) = tokio::net::UdpSocket::bind("127.0.0.1:0").await else {
            return false;
        };
        let Ok(rx_addr) = rx.local_addr() else {
            return false;
        };
        let Ok(tx) = tokio::net::UdpSocket::bind("127.0.0.1:0").await else {
            return false;
        };
        if tx.send_to(b"probe", rx_addr).await.is_err() {
            return false;
        }
        let mut buf = [0u8; 8];
        tokio::time::timeout(Duration::from_millis(250), rx.recv_from(&mut buf))
            .await
            .is_ok_and(|r| r.is_ok())
    }

    /// Report that a socket-driven test could not run here, so a skipped run is visible in the test
    /// output rather than silent.
    fn skipped_no_loopback_udp(name: &str) {
        eprintln!("skipping {name}: this host does not deliver loopback UDP datagrams");
    }

    /// A stand-in for a home router: one UDP socket answering NAT-PMP/PCP on loopback and another
    /// answering SSDP, each replying to whatever the client actually sent. Modelled on Go's
    /// `igd_test.go` fake, and it drives the real [`Client`] — only the ports are redirected.
    struct FakeIgd {
        pxp_port: u16,
        upnp_port: u16,
    }

    /// What the fake router is willing to do.
    #[derive(Clone, Copy)]
    struct FakeIgdConfig {
        /// Answer NAT-PMP public-address + map requests.
        pmp: bool,
        /// Answer PCP ANNOUNCE + MAP requests.
        pcp: bool,
        /// Answer SSDP discovery.
        upnp: bool,
        /// The result code to put in NAT-PMP replies (non-zero exercises the refusal paths).
        pmp_result: u16,
    }

    impl Default for FakeIgdConfig {
        fn default() -> Self {
            FakeIgdConfig {
                pmp: true,
                pcp: false,
                upnp: true,
                pmp_result: 0,
            }
        }
    }

    impl FakeIgd {
        /// Bind both listeners on loopback and start answering. The returned ports are what the
        /// client's `test_pxp_port`/`test_upnp_port` overrides point at.
        async fn start(cfg: FakeIgdConfig) -> FakeIgd {
            let pxp = tokio::net::UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("bind fake pxp socket");
            let upnp = tokio::net::UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("bind fake ssdp socket");
            let pxp_port = pxp.local_addr().expect("pxp local addr").port();
            let upnp_port = upnp.local_addr().expect("ssdp local addr").port();

            tokio::spawn(async move {
                let mut buf = [0u8; RECV_BUF];
                while let Ok((n, src)) = pxp.recv_from(&mut buf).await {
                    let req = &buf[..n];
                    let reply = match req.first().copied() {
                        Some(PMP_VERSION) if cfg.pmp => fake_pmp_reply(req, cfg.pmp_result),
                        Some(PCP_VERSION) if cfg.pcp => fake_pcp_reply(req),
                        _ => None,
                    };
                    if let Some(reply) = reply {
                        let _ = pxp.send_to(&reply, src).await;
                    }
                }
            });
            tokio::spawn(async move {
                let mut buf = [0u8; RECV_BUF];
                while let Ok((n, src)) = upnp.recv_from(&mut buf).await {
                    if !cfg.upnp || !buf[..n].starts_with(b"M-SEARCH") {
                        continue;
                    }
                    let body = ssdp_response(
                        "1",
                        "http://127.0.0.1:5000/rootDesc.xml",
                        "FakeRouter/1.0 UPnP/1.1 MiniUPnPd/2.1",
                    );
                    let _ = upnp.send_to(&body, src).await;
                }
            });

            FakeIgd {
                pxp_port,
                upnp_port,
            }
        }

        /// A client wired to this fake: loopback gateway, loopback self, redirected ports.
        fn client(&self, debug: DebugKnobs, logf: LogSink) -> Arc<Client> {
            let c = Client::new_for_test(logf, debug, self.pxp_port, self.upnp_port);
            c.set_gateway_lookup(Arc::new(|| {
                Some((
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                ))
            }));
            c
        }
    }

    /// The fake router's NAT-PMP answers: a public address for opcode 0, a granted port for opcode 1.
    fn fake_pmp_reply(req: &[u8], result: u16) -> Option<Vec<u8>> {
        match req.get(1).copied()? {
            PMP_OP_MAP_PUBLIC_ADDR => {
                let mut pkt = vec![0u8; 12];
                pkt[1] = PMP_OP_REPLY | PMP_OP_MAP_PUBLIC_ADDR;
                pkt[2..4].copy_from_slice(&result.to_be_bytes());
                pkt[4..8].copy_from_slice(&1234u32.to_be_bytes());
                pkt[8..12].copy_from_slice(&Ipv4Addr::new(192, 0, 2, 1).octets());
                Some(pkt)
            }
            PMP_OP_MAP_UDP => {
                let internal = u16::from_be_bytes([*req.get(4)?, *req.get(5)?]);
                let mut pkt = vec![0u8; 16];
                pkt[1] = PMP_OP_REPLY | PMP_OP_MAP_UDP;
                pkt[2..4].copy_from_slice(&result.to_be_bytes());
                pkt[4..8].copy_from_slice(&1234u32.to_be_bytes());
                pkt[8..10].copy_from_slice(&internal.to_be_bytes());
                pkt[10..12].copy_from_slice(&45678u16.to_be_bytes());
                pkt[12..16].copy_from_slice(&MAP_LIFETIME_SEC.to_be_bytes());
                Some(pkt)
            }
            _ => None,
        }
    }

    /// The fake router's PCP answers: an ANNOUNCE ack, or a MAP grant echoing the client's nonce.
    fn fake_pcp_reply(req: &[u8]) -> Option<Vec<u8>> {
        match req.get(1).copied()? {
            PCP_OP_ANNOUNCE => {
                let mut pkt = vec![0u8; 24];
                pkt[0] = PCP_VERSION;
                pkt[1] = PCP_OP_REPLY | PCP_OP_ANNOUNCE;
                pkt[8..12].copy_from_slice(&99u32.to_be_bytes());
                Some(pkt)
            }
            PCP_OP_MAP => {
                let mut pkt =
                    pcp_map_reply(0, MAP_LIFETIME_SEC, 99, 45678, Ipv4Addr::new(192, 0, 2, 1));
                // Echo the request's nonce, as a real PCP server does.
                pkt[24..36].copy_from_slice(req.get(24..36)?);
                Some(pkt)
            }
            _ => None,
        }
    }

    #[tokio::test]
    async fn probe_reports_every_protocol_the_router_answers() {
        if !loopback_udp_works().await {
            skipped_no_loopback_udp("probe_reports_every_protocol_the_router_answers");
            return;
        }
        let igd = FakeIgd::start(FakeIgdConfig {
            pmp: true,
            pcp: true,
            upnp: true,
            pmp_result: 0,
        })
        .await;
        let (logf, _lines) = collector();
        let c = igd.client(
            DebugKnobs {
                verbose_logs: true,
                ..Default::default()
            },
            logf,
        );
        let res = c.probe().await.expect("probe against the fake router");
        assert_eq!(
            res,
            ProbeResult {
                pcp: true,
                pmp: true,
                upnp: true
            },
            "the fake answers all three"
        );
    }

    #[tokio::test]
    async fn probe_reports_only_upnp_when_that_is_all_the_router_offers() {
        if !loopback_udp_works().await {
            skipped_no_loopback_udp("probe_reports_only_upnp_when_that_is_all_the_router_offers");
            return;
        }
        let igd = FakeIgd::start(FakeIgdConfig {
            pmp: false,
            pcp: false,
            upnp: true,
            ..Default::default()
        })
        .await;
        let (logf, _lines) = collector();
        let c = igd.client(DebugKnobs::default(), logf);
        let res = c.probe().await.expect("probe against the fake router");
        assert!(res.upnp && !res.pmp && !res.pcp, "got {res}");
    }

    #[tokio::test]
    async fn probe_honours_the_disable_knobs() {
        if !loopback_udp_works().await {
            skipped_no_loopback_udp("probe_honours_the_disable_knobs");
            return;
        }
        let igd = FakeIgd::start(FakeIgdConfig {
            pmp: true,
            pcp: true,
            upnp: true,
            ..Default::default()
        })
        .await;
        let (logf, _lines) = collector();
        // Only NAT-PMP may be probed, so nothing else can be reported even though the router
        // would answer — this is exactly what `debug portmap --type pmp` sets up.
        let c = igd.client(
            DebugKnobs {
                disable_pcp: true,
                disable_upnp: true,
                ..Default::default()
            },
            logf,
        );
        let res = c.probe().await.expect("probe against the fake router");
        assert!(res.pmp && !res.pcp && !res.upnp, "got {res}");
    }

    #[tokio::test]
    async fn probe_refuses_when_no_gateway_is_found() {
        let (logf, _lines) = collector();
        let c = Client::new(logf, DebugKnobs::default());
        c.set_gateway_lookup(Arc::new(|| None));
        assert_eq!(c.probe().await, Err(PortmapError::GatewayRange));
    }

    #[tokio::test]
    async fn probe_refuses_when_port_mapping_is_disabled() {
        let (logf, _lines) = collector();
        let c = Client::new(
            logf,
            DebugKnobs {
                disable_all: true,
                ..Default::default()
            },
        );
        assert_eq!(c.probe().await, Err(PortmapError::PortMappingDisabled));
    }

    #[tokio::test]
    async fn create_or_get_mapping_obtains_and_then_reuses_a_nat_pmp_mapping() {
        if !loopback_udp_works().await {
            skipped_no_loopback_udp(
                "create_or_get_mapping_obtains_and_then_reuses_a_nat_pmp_mapping",
            );
            return;
        }
        let igd = FakeIgd::start(FakeIgdConfig::default()).await;
        let (logf, lines) = collector();
        let c = igd.client(DebugKnobs::default(), logf);
        c.set_local_port(41641);

        let external = c
            .create_or_get_mapping()
            .await
            .expect("the fake router grants a NAT-PMP mapping");
        assert_eq!(
            external,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 45678),
            "the external address comes from the public-address reply and the port from the map reply"
        );
        assert!(c.have_mapping(), "the mapping is cached");

        // A second call inside the renewal window reuses the cached mapping without asking again.
        let again = c.create_or_get_mapping().await.expect("cached mapping");
        assert_eq!(again, external);
        let logged = lines.lock().expect("log lock").join("\n");
        assert_eq!(
            logged.matches("successfully obtained mapping").count(),
            1,
            "only the first call talked to the router: {logged}"
        );
    }

    #[tokio::test]
    async fn create_or_get_mapping_reports_a_nat_pmp_refusal_with_its_result_code() {
        if !loopback_udp_works().await {
            skipped_no_loopback_udp(
                "create_or_get_mapping_reports_a_nat_pmp_refusal_with_its_result_code",
            );
            return;
        }
        // The router speaks NAT-PMP but its owner switched mapping off (result code 2).
        let igd = FakeIgd::start(FakeIgdConfig {
            pmp_result: PmpResultCode::NOT_AUTHORIZED.0,
            ..Default::default()
        })
        .await;
        let (logf, _lines) = collector();
        let c = igd.client(DebugKnobs::default(), logf);
        let err = c
            .create_or_get_mapping()
            .await
            .expect_err("a refused mapping is an error, not an empty success");
        // Assert on what an operator actually sees — the rendering, not the private payload.
        // Go's `NoMappingError.Error()` prefixes its inner cause exactly once.
        assert_eq!(
            err.to_string(),
            "no NAT mapping available: PMP response Op=0x80,Res=0x2"
        );
        assert!(!c.have_mapping());
    }

    #[tokio::test]
    async fn create_or_get_mapping_uses_pcp_when_only_pcp_was_seen() {
        if !loopback_udp_works().await {
            skipped_no_loopback_udp("create_or_get_mapping_uses_pcp_when_only_pcp_was_seen");
            return;
        }
        let igd = FakeIgd::start(FakeIgdConfig {
            pmp: false,
            pcp: true,
            upnp: false,
            ..Default::default()
        })
        .await;
        let (logf, _lines) = collector();
        // Disabling NAT-PMP is Go's other route into the PCP branch (`preferPCP`), and it is what
        // `debug portmap --type pcp` sets.
        let c = igd.client(
            DebugKnobs {
                disable_pmp: true,
                ..Default::default()
            },
            logf,
        );
        c.set_local_port(41641);
        let external = c
            .create_or_get_mapping()
            .await
            .expect("the fake router grants a PCP mapping");
        assert_eq!(
            external,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 45678)
        );
    }

    #[tokio::test]
    async fn create_or_get_mapping_refuses_an_ipv6_gateway() {
        let (logf, _lines) = collector();
        let c = Client::new(logf, DebugKnobs::default());
        c.set_gateway_lookup(Arc::new(|| {
            Some((
                "2001:db8::1".parse().expect("doc-range IPv6 gateway"),
                "2001:db8::2".parse().expect("doc-range IPv6 self"),
            ))
        }));
        assert_eq!(
            c.create_or_get_mapping().await,
            Err(PortmapError::GatewayIPv6.no_mapping())
        );
    }

    #[tokio::test]
    async fn create_or_get_mapping_says_so_when_only_upnp_is_available() {
        if !loopback_udp_works().await {
            skipped_no_loopback_udp("create_or_get_mapping_says_so_when_only_upnp_is_available");
            return;
        }
        // The honest-omission path: the router IS discovered over UPnP, but this build cannot ask it
        // for a mapping — and must say that rather than report "no services".
        let igd = FakeIgd::start(FakeIgdConfig {
            pmp: false,
            pcp: false,
            upnp: true,
            ..Default::default()
        })
        .await;
        let (logf, lines) = collector();
        let c = igd.client(DebugKnobs::default(), logf);
        let res = c.probe().await.expect("probe");
        assert!(res.upnp, "the fake router is discovered");

        let err = c
            .create_or_get_mapping()
            .await
            .expect_err("no mapping is obtainable");
        assert_eq!(err, PortmapError::NoPortMappingServices.no_mapping());
        let logged = lines.lock().expect("log lock").join("\n");
        assert!(
            logged.contains("UPnP device discovered at http://127.0.0.1:5000/rootDesc.xml")
                && logged.contains("not implemented by this build"),
            "the run names the device it found and why it cannot use it: {logged}"
        );
    }

    // ───────────────────────────── the `debug portmap` run ─────────────────────────────

    #[tokio::test]
    async fn debug_portmap_refuses_an_unknown_type() {
        let (logf, lines) = collector();
        let err = debug_portmap(
            logf,
            &DebugPortmapOpts {
                ty: "natpmp".into(),
                ..Default::default()
            },
        )
        .await
        .expect_err("an unrecognised --type is refused before anything is probed");
        assert_eq!(err, "unknown portmap debug type");
        assert!(
            lines.lock().expect("log lock").is_empty(),
            "nothing is logged, because nothing ran"
        );
    }

    #[tokio::test]
    async fn debug_portmap_accepts_each_type_go_accepts() {
        for ty in ["", "pmp", "pcp", "upnp"] {
            let (logf, _lines) = collector();
            let res = debug_portmap(
                logf,
                &DebugPortmapOpts {
                    ty: ty.to_string(),
                    duration: Duration::from_millis(50),
                    // A documentation-range gateway: nothing can answer, so the run is deterministic.
                    gateway_and_self: Some("192.0.2.1/192.0.2.2".into()),
                    log_http: false,
                },
            )
            .await;
            assert_eq!(res, Ok(()), "--type {ty:?} is one Go accepts");
        }
    }

    #[tokio::test]
    async fn debug_portmap_narrates_a_network_with_no_port_mapping_service() {
        let (logf, lines) = collector();
        debug_portmap(
            logf,
            &DebugPortmapOpts {
                duration: Duration::from_millis(500),
                // NAT-PMP only. The UPnP leg discovers over SSDP multicast, which the gateway
                // override does not constrain, so on a LAN with a real IGD an all-protocol run
                // would find one and narrate a fourth line. Restricted to NAT-PMP the only packet
                // that leaves is addressed to the unroutable gateway below.
                ty: "pmp".into(),
                gateway_and_self: Some("192.0.2.1/192.0.2.2".into()),
                ..Default::default()
            },
        )
        .await
        .expect("a run against an unreachable gateway is not an error");
        let logged = lines.lock().expect("log lock").clone();
        assert_eq!(
            logged,
            vec![
                "gw=192.0.2.1; self=192.0.2.2".to_string(),
                "Probe: {PCP:false PMP:false UPnP:false}".to_string(),
                "no portmapping services available".to_string(),
            ],
            "the run reports the gateway it used, what it found, and stops"
        );
    }

    /// A `--duration` shorter than [`PORT_MAP_SERVICE_TIMEOUT`] — including the zero a negative
    /// duration is clamped to — must still narrate like Go.
    ///
    /// Go's `Probe` derives its own 250ms context and turns that deadline expiring into `err = nil`
    /// with a zero `ProbeResult`, so `serveDebugPortmap` prints the `Probe:` line and then
    /// `no portmapping services available`. It does NOT report a deadline here; the `context done`
    /// line belongs to the wait that happens after a probe found something.
    #[tokio::test]
    async fn debug_portmap_reports_an_empty_probe_when_the_run_deadline_beats_it() {
        for duration in [Duration::ZERO, Duration::from_millis(1)] {
            let (logf, lines) = collector();
            debug_portmap(
                logf,
                &DebugPortmapOpts {
                    duration,
                    ty: "pmp".into(),
                    gateway_and_self: Some("192.0.2.1/192.0.2.2".into()),
                    ..Default::default()
                },
            )
            .await
            .expect("an already-expired run is not an error");
            let logged = lines.lock().expect("log lock").clone();
            assert_eq!(
                logged,
                vec![
                    "gw=192.0.2.1; self=192.0.2.2".to_string(),
                    "Probe: {PCP:false PMP:false UPnP:false}".to_string(),
                    "no portmapping services available".to_string(),
                ],
                "a {duration:?} run reports an empty probe, not a deadline"
            );
        }
    }

    #[tokio::test]
    async fn debug_portmap_reports_a_malformed_gateway_pair() {
        for bad in ["192.0.2.1", "192.0.2.1/not-an-ip"] {
            let (logf, lines) = collector();
            debug_portmap(
                logf,
                &DebugPortmapOpts {
                    gateway_and_self: Some(bad.to_string()),
                    ..Default::default()
                },
            )
            .await
            .expect("a malformed pair is reported on the log, not returned");
            let logged = lines.lock().expect("log lock").join("\n");
            assert!(
                logged.contains("invalid gateway_and_self"),
                "got {logged:?} for {bad:?}"
            );
        }
    }

    #[tokio::test]
    async fn debug_portmap_reports_when_no_gateway_can_be_found() {
        // No override and no route table answer is Go's "no gateway or self IP" branch. The lookup
        // is the real one here, so this asserts on the branch only when the host genuinely has no
        // private default gateway; otherwise it asserts the run still narrated its gateway.
        let (logf, lines) = collector();
        debug_portmap(
            logf,
            &DebugPortmapOpts {
                duration: Duration::from_millis(50),
                ..Default::default()
            },
        )
        .await
        .expect("run");
        let logged = lines.lock().expect("log lock").join("\n");
        if likely_home_router_ip().is_none() {
            assert_eq!(logged, "no gateway or self IP");
        } else {
            assert!(logged.starts_with("gw="), "got {logged:?}");
        }
    }

    // ───────────────────────────── small helpers ─────────────────────────────

    #[test]
    fn contains_finds_the_igd_marker_anywhere_in_a_datagram() {
        let body = ssdp_response("2", "http://192.0.2.1:80/d.xml", "X/1");
        assert!(contains(&body, IGD_MARKER.as_bytes()));
        assert!(!contains(b"HTTP/1.1 200 OK\r\n\r\n", IGD_MARKER.as_bytes()));
        assert!(contains(b"anything", b""));
    }

    #[test]
    fn hex_dump_matches_gos_space_separated_verb() {
        assert_eq!(hex_spaced(&[0x00, 0x81, 0xff]), "00 81 ff");
        assert_eq!(hex_spaced(&[]), "");
    }

    #[test]
    fn mapping_debug_renders_like_gos_per_protocol_strings() {
        let base = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let m = Mapping {
            kind: MappingKind::Pmp,
            gw: "192.0.2.1:5351".parse().expect("gateway addr"),
            internal: "192.0.2.2:41641".parse().expect("internal addr"),
            external: "192.0.2.1:45678".parse().expect("external addr"),
            renew_after: base,
            good_until: base + Duration::from_secs(3_600),
            epoch: 7,
        };
        assert_eq!(
            m.mapping_debug(),
            "pmpMapping{gw:192.0.2.1:5351, external:192.0.2.1:45678, internal:192.0.2.2:41641, renewAfter:1000, goodUntil:4600, epoch:7}"
        );
        let p = Mapping {
            kind: MappingKind::Pcp,
            ..m
        };
        assert_eq!(
            p.mapping_debug(),
            "pcpMapping{gw:192.0.2.1:5351, external:192.0.2.1:45678, internal:192.0.2.2:41641, renewAfter:1000, goodUntil:4600}"
        );
        assert_eq!(MappingKind::Pmp.as_str(), "pmp");
        assert_eq!(MappingKind::Pcp.as_str(), "pcp");
    }

    #[test]
    fn discard_sink_is_usable_where_output_is_not_under_test() {
        // Guards against the helper rotting unused: it is the sink for paths asserted by return
        // value rather than by log text.
        discard()("ignored");
    }
}
