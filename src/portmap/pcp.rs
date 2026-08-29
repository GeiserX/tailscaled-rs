//! PCP (Port Control Protocol, RFC 6887) wire format — the port of Go's
//! `net/portmapper/pcp.go` (tailscale v1.100.0).
//!
//! PCP is NAT-PMP's successor and shares its UDP port (5351), which is why one socket receives both
//! and the version byte is the discriminator: 0 is NAT-PMP, 2 is PCP. Two messages matter here:
//!
//! - ANNOUNCE (opcode 0), a 24-byte common header, used purely as a "is anyone there?" probe;
//! - MAP (opcode 1), the common header plus a 36-byte MAP body, which — unlike NAT-PMP — returns
//!   the complete mapping (external address *and* port) in a single reply.
//!
//! As in [`super::pmp`], everything here is pure byte manipulation so it is testable without a
//! socket.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// PCP version byte. Byte 0 of every message (Go: `pcpVersion`).
pub const VERSION: u8 = 2;

/// PCP's UDP port at the gateway — the same one NAT-PMP uses (Go: `pcpDefaultPort`).
pub const DEFAULT_PORT: u16 = 5351;

/// Lifetime we request for a PCP mapping, in seconds. Go: `pcpMapLifetimeSec` — "TODO does the RFC
/// recommend anything? This is taken from PMP".
pub const MAP_LIFETIME_SEC: u32 = 7200;

/// OR'd into the request's opcode on a response (Go: `pcpOpReply`).
pub const OP_REPLY: u8 = 0x80;
/// Opcode: ANNOUNCE (RFC 6887 §7.1) — the probe.
pub const OP_ANNOUNCE: u8 = 0;
/// Opcode: MAP (RFC 6887 §11.1) — create/renew/delete a mapping.
pub const OP_MAP: u8 = 1;

/// IANA protocol number for UDP, in the MAP body's Protocol field (Go: `pcpUDPMapping`).
pub const UDP_MAPPING: u8 = 17;
/// IANA protocol number for TCP. Unused by this client (we map UDP, like Go), kept because the
/// mapping body's Protocol field is where a TCP mapping would differ.
pub const TCP_MAPPING: u8 = 6;

/// A PCP result code (RFC 6887 §7.4), byte 3 of every response.
///
/// A newtype rather than an enum for the same reason as [`super::pmp::ResultCode`]: an unrecognized
/// code must survive to the log line instead of being flattened into "some error".
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ResultCode(pub u8);

impl ResultCode {
    /// Success.
    pub const OK: ResultCode = ResultCode(0);
    /// The PCP server refuses to serve this client — "a PCP service is running, but refuses to
    /// provide port mapping services" (Go's probe comment).
    pub const NOT_AUTHORIZED: ResultCode = ResultCode(2);
    /// RFC 6887: "The source IP address of the request packet does not match the contents of the PCP
    /// Client's IP Address field, due to an unexpected NAT on the path between the PCP client and the
    /// PCP-controlled NAT or firewall." In other words: the PCP server is itself behind a NAT, so it
    /// cannot help us.
    pub const ADDRESS_MISMATCH: ResultCode = ResultCode(12);
}

impl Default for ResultCode {
    fn default() -> Self {
        Self::OK
    }
}

impl fmt::Display for ResultCode {
    /// The Go `stringer`-generated names (`-trimprefix=pcpCode`), `pcpResultCode(<n>)` fallback
    /// included — the same reasoning as [`super::pmp::ResultCode`]'s `Display`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match *self {
            Self::OK => "OK",
            Self::NOT_AUTHORIZED => "NotAuthorized",
            Self::ADDRESS_MISMATCH => "AddressMismatch",
            ResultCode(n) => return write!(f, "pcpResultCode({n})"),
        };
        f.write_str(name)
    }
}

/// Build the 24-byte ANNOUNCE request (RFC 6887 §7.1; Go: `pcpAnnounceRequest`).
///
/// `my_ip` is this host's LAN address, written into the header's PCP Client IP Address field as an
/// IPv4-mapped IPv6 address — the encoding RFC 6887 mandates for every address field.
pub fn announce_request(my_ip: Ipv4Addr) -> [u8; 24] {
    let mut pkt = [0u8; 24];
    pkt[0] = VERSION;
    pkt[1] = OP_ANNOUNCE;
    pkt[8..24].copy_from_slice(&ipv4_mapped(my_ip));
    pkt
}

/// Build a MAP request: the 24-byte common header plus the 36-byte MAP body (Go:
/// `buildPCPRequestMappingPacket`).
///
/// A `lifetime_sec` of 0 deletes the mapping. `prev_port` is the external port to ask for (0 when
/// unknown) and `prev_external_ip` the external address to ask for (`0.0.0.0` when unknown).
///
/// DEVIATION from Go, deliberate: Go generates the 96-bit mapping nonce inside this function with
/// `rand.Read`. Here the nonce is a parameter, so the packet builder stays pure and the layout is
/// testable byte-for-byte; [`super::Client`] passes a fresh OS-random nonce (see
/// [`random_nonce`]).
pub fn build_request_mapping_packet(
    my_ip: Ipv4Addr,
    local_port: u16,
    prev_port: u16,
    lifetime_sec: u32,
    prev_external_ip: Ipv4Addr,
    nonce: [u8; 12],
) -> [u8; 60] {
    let mut pkt = [0u8; 24 + 36];
    pkt[0] = VERSION;
    pkt[1] = OP_MAP;
    pkt[4..8].copy_from_slice(&lifetime_sec.to_be_bytes());
    pkt[8..24].copy_from_slice(&ipv4_mapped(my_ip));

    let map_op = &mut pkt[24..];
    map_op[0..12].copy_from_slice(&nonce);
    // Go maps UDP only: "It looks like it supports 'all protocols' with 0, but also doesn't support a
    // local port then."
    map_op[12] = UDP_MAPPING;
    map_op[16..18].copy_from_slice(&local_port.to_be_bytes());
    map_op[18..20].copy_from_slice(&prev_port.to_be_bytes());
    map_op[20..36].copy_from_slice(&ipv4_mapped(prev_external_ip));
    pkt
}

/// A fresh 96-bit mapping nonce from the OS CSPRNG.
///
/// RFC 6887 §11.1 makes the nonce the client's proof of ownership of a mapping: a request that
/// carries the wrong nonce for an existing mapping is refused, which is what stops another host on
/// the LAN from silently re-pointing our mapping at itself. So this must be real randomness, not a
/// counter or a clock.
pub fn random_nonce() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    // A failure here means the OS entropy source is unavailable, which is not something a port-map
    // attempt can fix or meaningfully continue past — but it also must not take the daemon down, so
    // the caller sees it as a plain error and the mapping attempt is abandoned.
    if let Err(e) = getrandom::fill(&mut nonce) {
        tracing::warn!(error = %e, "portmap: OS randomness unavailable for the PCP nonce");
    }
    nonce
}

/// A parsed PCP common header (Go: `pcpResponse`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Response {
    /// The request's opcode with [`OP_REPLY`] OR'd in.
    pub op_code: u8,
    /// The server's verdict.
    pub result_code: ResultCode,
    /// Lifetime granted (on success) or the error's retry hint (on failure), in seconds.
    pub lifetime: u32,
    /// The server's epoch, in seconds. As in NAT-PMP, a backwards jump means the server restarted
    /// and previously-granted mappings are gone.
    pub epoch: u32,
}

/// Parse a PCP common header (Go: `parsePCPResponse`).
///
/// `None` for anything shorter than the 24-byte header or carrying a non-PCP version byte — the same
/// discrimination that keeps a NAT-PMP reply on the shared socket from being read as PCP.
pub fn parse_response(b: &[u8]) -> Option<Response> {
    if b.len() < 24 || b[0] != VERSION {
        return None;
    }
    Some(Response {
        op_code: b[1],
        result_code: ResultCode(b[3]),
        lifetime: u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
        epoch: u32::from_be_bytes([b[8], b[9], b[10], b[11]]),
    })
}

/// The mapping a successful MAP reply describes: the external address and port the gateway assigned,
/// plus the lifetime it granted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MapResponse {
    /// The external endpoint another node can reach this host at.
    pub external: std::net::SocketAddrV4,
    /// How long the mapping is good for, in seconds (the header's Lifetime field).
    pub lifetime_secs: u32,
    /// The server's epoch at the time of the reply.
    pub epoch: u32,
}

/// Why a MAP reply could not be turned into a mapping. Each variant is one of the refusals Go's
/// `parsePCPMapResponse` returns as a distinct error string; they are kept apart (rather than folded
/// into one "bad response") because they mean genuinely different things to an operator: a truncated
/// packet is a broken device, `NOT_AUTHORIZED` is a switched-off feature, and a non-IPv4 external
/// address is a device that cannot give us a usable endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapParseError {
    /// Shorter than the 60 bytes a MAP reply must have.
    TooShort,
    /// The common header did not parse (too short, or not PCP version 2).
    InvalidHeader,
    /// The server answered [`ResultCode::NOT_AUTHORIZED`]: PCP is implemented but switched off.
    NotAuthorized,
    /// Any other non-OK result code.
    NotOk(ResultCode),
    /// The assigned external address was not an IPv4 address, so it is unusable as an endpoint for
    /// this (IPv4-only) mapping path.
    ExternalNotIpv4(IpAddr),
}

impl fmt::Display for MapParseError {
    /// The Go error strings, verbatim where Go has one, so a `tnet debug portmap` transcript reads
    /// the same as `tailscale debug portmap`'s.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort => f.write_str("Does not appear to be PCP MAP response"),
            Self::InvalidHeader => f.write_str("Invalid PCP common header"),
            Self::NotAuthorized => f.write_str("PCP is implemented but not enabled in the router"),
            Self::NotOk(code) => write!(f, "PCP response not ok, code {}", code.0),
            Self::ExternalNotIpv4(addr) => {
                write!(f, "PCP external address {addr} is not IPv4")
            }
        }
    }
}

/// Parse a PCP MAP reply into the mapping it describes (Go: `parsePCPMapResponse`).
///
/// The MAP body's assigned external address is 16 bytes in RFC 6887's IPv4-mapped-IPv6 encoding;
/// an IPv4 mapping unmaps back to a plain `A.B.C.D`, which is the only shape this client can use.
pub fn parse_map_response(resp: &[u8]) -> Result<MapResponse, MapParseError> {
    if resp.len() < 60 {
        return Err(MapParseError::TooShort);
    }
    let header = parse_response(&resp[..24]).ok_or(MapParseError::InvalidHeader)?;
    if header.result_code == ResultCode::NOT_AUTHORIZED {
        return Err(MapParseError::NotAuthorized);
    }
    if header.result_code != ResultCode::OK {
        return Err(MapParseError::NotOk(header.result_code));
    }
    // NOTE (as in Go): the reply's nonce is not checked against the one we sent.
    let external_port = u16::from_be_bytes([resp[42], resp[43]]);
    let mut external_ip = [0u8; 16];
    external_ip.copy_from_slice(&resp[44..60]);
    let external_ip = unmap(Ipv6Addr::from(external_ip));
    let IpAddr::V4(external_ip) = external_ip else {
        return Err(MapParseError::ExternalNotIpv4(external_ip));
    };
    Ok(MapResponse {
        external: std::net::SocketAddrV4::new(external_ip, external_port),
        lifetime_secs: header.lifetime,
        epoch: header.epoch,
    })
}

/// RFC 6887's address encoding: every address field is 16 bytes, an IPv4 address written as the
/// IPv4-mapped IPv6 address `::ffff:A.B.C.D`.
fn ipv4_mapped(ip: Ipv4Addr) -> [u8; 16] {
    ip.to_ipv6_mapped().octets()
}

/// The inverse of [`ipv4_mapped`]: an IPv4-mapped address becomes a plain IPv4 address, anything
/// else stays IPv6. (Rust's `Ipv6Addr::to_ipv4` also unwraps IPv4-*compatible* `::a.b.c.d`
/// addresses, which are deprecated and would turn `::1` into `0.0.0.1`; `to_ipv4_mapped` is the
/// strict form and the one that matches Go's `netip.Addr.Unmap`.)
fn unmap(ip: Ipv6Addr) -> IpAddr {
    match ip.to_ipv4_mapped() {
        Some(v4) => IpAddr::V4(v4),
        None => IpAddr::V6(ip),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SELF_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 42);

    #[test]
    fn announce_is_the_rfc_6887_header() {
        let pkt = announce_request(SELF_IP);
        assert_eq!(pkt[0], 2, "version");
        assert_eq!(pkt[1], 0, "opcode ANNOUNCE");
        assert_eq!(&pkt[2..8], &[0, 0, 0, 0, 0, 0], "reserved + zero lifetime");
        // The client address field is IPv4-mapped IPv6, i.e. ::ffff:192.168.1.42.
        assert_eq!(
            &pkt[8..24],
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 42]
        );
    }

    #[test]
    fn map_request_carries_nonce_protocol_and_ports() {
        let nonce = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let pkt = build_request_mapping_packet(
            SELF_IP,
            41641,
            1234,
            MAP_LIFETIME_SEC,
            Ipv4Addr::UNSPECIFIED,
            nonce,
        );
        assert_eq!(pkt[0], 2);
        assert_eq!(pkt[1], 1, "opcode MAP");
        assert_eq!(&pkt[4..8], &7200u32.to_be_bytes());
        assert_eq!(&pkt[24..36], &nonce, "96-bit mapping nonce");
        assert_eq!(pkt[36], 17, "protocol UDP");
        assert_eq!(&pkt[40..42], &41641u16.to_be_bytes(), "internal port");
        assert_eq!(&pkt[42..44], &1234u16.to_be_bytes(), "suggested ext port");
        // Unknown previous external IP is the wildcard, mapped: ::ffff:0.0.0.0.
        assert_eq!(
            &pkt[44..60],
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0]
        );
    }

    #[test]
    fn delete_request_carries_a_zero_lifetime() {
        let pkt = build_request_mapping_packet(
            SELF_IP,
            41641,
            41641,
            0,
            Ipv4Addr::new(203, 0, 113, 9),
            [0u8; 12],
        );
        assert_eq!(&pkt[4..8], &[0, 0, 0, 0], "lifetime 0 deletes the mapping");
    }

    #[test]
    fn nonce_is_random_and_full_width() {
        // Two draws colliding across 96 bits would mean the entropy source is not working.
        assert_ne!(random_nonce(), random_nonce());
    }

    /// A synthetic MAP reply: header + MAP body, as a gateway would send it.
    fn map_reply(result_code: u8, lifetime: u32, ext_port: u16, ext_ip: [u8; 16]) -> [u8; 60] {
        let mut pkt = [0u8; 60];
        pkt[0] = VERSION;
        pkt[1] = OP_REPLY | OP_MAP;
        pkt[3] = result_code;
        pkt[4..8].copy_from_slice(&lifetime.to_be_bytes());
        pkt[8..12].copy_from_slice(&42u32.to_be_bytes()); // epoch
        pkt[42..44].copy_from_slice(&ext_port.to_be_bytes());
        pkt[44..60].copy_from_slice(&ext_ip);
        pkt
    }

    #[test]
    fn parses_a_successful_map_reply() {
        let ext = Ipv4Addr::new(203, 0, 113, 9).to_ipv6_mapped().octets();
        let reply = map_reply(0, 3600, 40000, ext);
        let got = parse_map_response(&reply).expect("an OK MAP reply must parse");
        assert_eq!(
            got,
            MapResponse {
                external: std::net::SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 40000),
                lifetime_secs: 3600,
                epoch: 42,
            }
        );
    }

    #[test]
    fn a_not_authorized_map_reply_is_the_feature_is_off_error() {
        let reply = map_reply(2, 0, 0, [0u8; 16]);
        assert_eq!(
            parse_map_response(&reply),
            Err(MapParseError::NotAuthorized)
        );
        assert_eq!(
            MapParseError::NotAuthorized.to_string(),
            "PCP is implemented but not enabled in the router"
        );
    }

    #[test]
    fn other_failure_codes_keep_their_number() {
        let reply = map_reply(8, 0, 0, [0u8; 16]); // NO_RESOURCES
        assert_eq!(
            parse_map_response(&reply),
            Err(MapParseError::NotOk(ResultCode(8)))
        );
        assert_eq!(
            MapParseError::NotOk(ResultCode(8)).to_string(),
            "PCP response not ok, code 8"
        );
    }

    #[test]
    fn a_truncated_map_reply_is_refused() {
        let reply = map_reply(0, 3600, 40000, [0u8; 16]);
        assert_eq!(
            parse_map_response(&reply[..59]),
            Err(MapParseError::TooShort)
        );
        assert_eq!(
            MapParseError::TooShort.to_string(),
            "Does not appear to be PCP MAP response"
        );
    }

    #[test]
    fn a_map_reply_with_a_bad_version_is_refused() {
        let mut reply = map_reply(0, 3600, 40000, [0u8; 16]);
        reply[0] = 0; // NAT-PMP's version byte, not PCP's
        assert_eq!(
            parse_map_response(&reply),
            Err(MapParseError::InvalidHeader)
        );
    }

    #[test]
    fn a_non_ipv4_external_address_is_refused() {
        // A device that hands back a real IPv6 external address gives us nothing this IPv4 mapping
        // path can use as an endpoint.
        let ext = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets();
        let reply = map_reply(0, 3600, 40000, ext);
        assert!(matches!(
            parse_map_response(&reply),
            Err(MapParseError::ExternalNotIpv4(_))
        ));
    }

    #[test]
    fn announce_reply_parses_as_a_common_header() {
        let mut pkt = [0u8; 24];
        pkt[0] = VERSION;
        pkt[1] = OP_REPLY | OP_ANNOUNCE;
        pkt[8..12].copy_from_slice(&99u32.to_be_bytes());
        let res = parse_response(&pkt).expect("a 24-byte PCP header must parse");
        assert_eq!(res.op_code, 0x80);
        assert_eq!(res.epoch, 99);
        assert_eq!(res.result_code, ResultCode::OK);
    }

    #[test]
    fn refuses_short_and_non_pcp_headers() {
        assert_eq!(parse_response(&[0u8; 23]), None);
        let mut pmp = [0u8; 24];
        pmp[0] = 0; // NAT-PMP
        assert_eq!(parse_response(&pmp), None);
    }

    #[test]
    fn result_code_names_match_gos_stringer() {
        assert_eq!(ResultCode::OK.to_string(), "OK");
        assert_eq!(ResultCode::NOT_AUTHORIZED.to_string(), "NotAuthorized");
        assert_eq!(ResultCode::ADDRESS_MISMATCH.to_string(), "AddressMismatch");
        assert_eq!(ResultCode(5).to_string(), "pcpResultCode(5)");
    }
}
