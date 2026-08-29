//! NAT-PMP (RFC 6886) wire format — the `pmp*` half of Go's `net/portmapper/portmapper.go`
//! (tailscale v1.100.0).
//!
//! NAT-PMP is the simplest of the three protocols this module speaks: two fixed-size UDP messages to
//! the gateway's port 5351. A 2-byte "what is my public address" request, and a 12-byte "map this
//! UDP port" request; both are answered with a fixed-size reply whose opcode is the request's opcode
//! with [`OP_REPLY`] OR'd in.
//!
//! Everything here is a pure byte-level function so the wire format is unit-testable with no socket:
//! the live send/receive loop lives in [`super::Client`].

use std::fmt;
use std::net::Ipv4Addr;

/// The UDP port NAT-PMP (and PCP — they share it, which is why Go calls it the "pxp" port) listens
/// on at the gateway. Go: `pmpDefaultPort`.
pub const DEFAULT_PORT: u16 = 5351;

/// Lifetime we ask for on a mapping, in seconds. Go: `pmpMapLifetimeSec` — "RFC recommended 2 hour
/// map duration".
pub const MAP_LIFETIME_SEC: u32 = 7200;

/// A zero lifetime deletes a mapping rather than creating one (Go: `pmpMapLifetimeDelete`).
pub const MAP_LIFETIME_DELETE: u32 = 0;

/// NAT-PMP protocol version. Byte 0 of every message; a reply carrying anything else is not NAT-PMP
/// (this is also how the mapping loop tells a PMP reply from a PCP one, which uses version 2).
pub const VERSION: u8 = 0;

/// Opcode: "what is my external address" (Go: `pmpOpMapPublicAddr`).
pub const OP_MAP_PUBLIC_ADDR: u8 = 0;

/// Opcode: "map a UDP port" (Go: `pmpOpMapUDP`).
pub const OP_MAP_UDP: u8 = 1;

/// OR'd into the request's opcode on a response (Go: `pmpOpReply`).
pub const OP_REPLY: u8 = 0x80;

/// The whole "tell me my external address" request: version 0, opcode 0, no payload. Go:
/// `pmpReqExternalAddrPacket`.
pub const REQ_EXTERNAL_ADDR_PACKET: [u8; 2] = [VERSION, OP_MAP_PUBLIC_ADDR];

/// A NAT-PMP result code (RFC 6886 §3.5), as carried in bytes 2..4 of every response.
///
/// Kept as a newtype over the raw `u16` rather than an enum precisely so an *unknown* code round-trips
/// instead of being dropped: a gateway that answers with a code we have never heard of must still be
/// reportable, which is what Go's generated `pmpResultCode.String()` does with
/// `pmpResultCode(<n>)`. [`fmt::Display`] reproduces that stringer byte-for-byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ResultCode(pub u16);

impl ResultCode {
    /// Success.
    pub const OK: ResultCode = ResultCode(0);
    /// The gateway does not speak this version of NAT-PMP.
    pub const UNSUPPORTED_VERSION: ResultCode = ResultCode(1);
    /// "e.g., box supports mapping, but user has turned feature off" (RFC 6886).
    pub const NOT_AUTHORIZED: ResultCode = ResultCode(2);
    /// "e.g., NAT box itself has not obtained a DHCP lease" (RFC 6886).
    pub const NETWORK_FAILURE: ResultCode = ResultCode(3);
    /// The gateway is out of mapping resources.
    pub const OUT_OF_RESOURCES: ResultCode = ResultCode(4);
    /// The gateway does not implement the opcode we sent.
    pub const UNSUPPORTED_OPCODE: ResultCode = ResultCode(5);
}

impl fmt::Display for ResultCode {
    /// The Go `stringer`-generated names (`-trimprefix=pmpCode`), including the
    /// `pmpResultCode(<n>)` fallback for a code outside the RFC's set. The exact strings matter:
    /// they are what `tnet debug portmap` prints for a refusing gateway, and an operator matching
    /// them against Go's output (or against the RFC) should see the same words.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match *self {
            Self::OK => "OK",
            Self::UNSUPPORTED_VERSION => "UnsupportedVersion",
            Self::NOT_AUTHORIZED => "NotAuthorized",
            Self::NETWORK_FAILURE => "NetworkFailure",
            Self::OUT_OF_RESOURCES => "OutOfResources",
            Self::UNSUPPORTED_OPCODE => "UnsupportedOpcode",
            ResultCode(n) => return write!(f, "pmpResultCode({n})"),
        };
        f.write_str(name)
    }
}

/// Build the 12-byte "map this UDP port" request (Go: `buildPMPRequestMappingPacket`).
///
/// `prev_port` is the external port we held previously and would like to keep (0 = "any port"), and
/// `lifetime_sec` of [`MAP_LIFETIME_DELETE`] deletes the mapping instead of creating one.
pub fn build_request_mapping_packet(
    local_port: u16,
    prev_port: u16,
    lifetime_sec: u32,
) -> [u8; 12] {
    let mut pkt = [0u8; 12];
    // pkt[0] stays VERSION (0).
    pkt[1] = OP_MAP_UDP;
    // pkt[2..4] is the reserved field, which stays zero on a request.
    pkt[4..6].copy_from_slice(&local_port.to_be_bytes());
    pkt[6..8].copy_from_slice(&prev_port.to_be_bytes());
    pkt[8..12].copy_from_slice(&lifetime_sec.to_be_bytes());
    pkt
}

/// A parsed NAT-PMP response (Go: `pmpResponse`).
///
/// The op-specific halves are both carried on one struct, exactly as Go does: which of them is
/// meaningful depends on [`op_code`](Response::op_code).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Response {
    /// The request's opcode with [`OP_REPLY`] OR'd in.
    pub op_code: u8,
    /// The gateway's verdict.
    pub result_code: ResultCode,
    /// Seconds since the gateway's port-mapping state was reset — RFC 6886's epoch. A jump backwards
    /// means the gateway rebooted and every mapping it held is gone.
    pub seconds_since_epoch: u32,

    /// For map ops: how long the mapping the gateway actually granted is good for.
    pub mapping_valid_seconds: u32,
    /// For map ops: the internal (local) port the mapping points at.
    pub internal_port: u16,
    /// For map ops: the external port the gateway assigned, which need NOT be the one we asked for.
    pub external_port: u16,

    /// For public-address ops: the gateway's external IPv4 address, or `None` when the gateway
    /// answered with the unspecified address `0.0.0.0` (Go zeroes it out "so it's not Valid and used
    /// accidentally elsewhere" — a gateway with no WAN lease answers exactly that way).
    pub public_addr: Option<Ipv4Addr>,
}

impl Default for ResultCode {
    fn default() -> Self {
        Self::OK
    }
}

/// Parse a NAT-PMP response (Go: `parsePMPResponse`).
///
/// Returns `None` — Go's `ok == false` — for anything that is not a well-formed NAT-PMP reply: too
/// short, a non-zero version byte, or a map/public-address reply whose length is not exactly the one
/// the RFC fixes for that opcode. The strict length check is load-bearing: the same UDP socket also
/// receives PCP and SSDP traffic, and a sloppy parse would happily read a PCP reply's bytes as PMP
/// ports.
pub fn parse_response(pkt: &[u8]) -> Option<Response> {
    if pkt.len() < 12 {
        return None;
    }
    if pkt[0] != VERSION {
        return None;
    }
    let mut res = Response {
        op_code: pkt[1],
        result_code: ResultCode(u16::from_be_bytes([pkt[2], pkt[3]])),
        seconds_since_epoch: u32::from_be_bytes([pkt[4], pkt[5], pkt[6], pkt[7]]),
        ..Response::default()
    };

    if res.op_code == OP_REPLY | OP_MAP_UDP {
        if pkt.len() != 16 {
            return None;
        }
        res.internal_port = u16::from_be_bytes([pkt[8], pkt[9]]);
        res.external_port = u16::from_be_bytes([pkt[10], pkt[11]]);
        res.mapping_valid_seconds = u32::from_be_bytes([pkt[12], pkt[13], pkt[14], pkt[15]]);
    }

    if res.op_code == OP_REPLY | OP_MAP_PUBLIC_ADDR {
        if pkt.len() != 12 {
            return None;
        }
        let addr = Ipv4Addr::new(pkt[8], pkt[9], pkt[10], pkt[11]);
        res.public_addr = if addr.is_unspecified() {
            None
        } else {
            Some(addr)
        };
    }

    Some(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_addr_request_is_two_zero_bytes() {
        // Go: `pmpReqExternalAddrPacket = []byte{pmpVersion, pmpOpMapPublicAddr} // 0, 0`.
        assert_eq!(REQ_EXTERNAL_ADDR_PACKET, [0, 0]);
    }

    #[test]
    fn mapping_request_is_the_rfc_6886_layout() {
        let pkt = build_request_mapping_packet(41641, 1234, MAP_LIFETIME_SEC);
        assert_eq!(
            pkt,
            [
                0, // version
                1, // op: map UDP
                0, 0, // reserved
                0xa2, 0xa9, // internal port 41641
                0x04, 0xd2, // suggested external port 1234
                0, 0, 0x1c, 0x20, // lifetime 7200
            ]
        );
    }

    #[test]
    fn delete_request_carries_a_zero_lifetime() {
        // A delete is the same packet with lifetime 0 — the shape `Release` sends.
        let pkt = build_request_mapping_packet(41641, 41641, MAP_LIFETIME_DELETE);
        assert_eq!(&pkt[8..12], &[0, 0, 0, 0]);
    }

    #[test]
    fn parses_a_public_address_reply() {
        let mut pkt = [0u8; 12];
        pkt[1] = OP_REPLY | OP_MAP_PUBLIC_ADDR;
        pkt[4..8].copy_from_slice(&7u32.to_be_bytes());
        pkt[8..12].copy_from_slice(&[203, 0, 113, 9]);
        let res = parse_response(&pkt).expect("well-formed public-addr reply must parse");
        assert_eq!(res.op_code, 0x80);
        assert_eq!(res.result_code, ResultCode::OK);
        assert_eq!(res.seconds_since_epoch, 7);
        assert_eq!(res.public_addr, Some(Ipv4Addr::new(203, 0, 113, 9)));
    }

    #[test]
    fn unspecified_public_address_becomes_none() {
        // A gateway with no WAN lease answers 0.0.0.0; Go zeroes it so it is never used as an
        // endpoint. `None` is how that lands here.
        let mut pkt = [0u8; 12];
        pkt[1] = OP_REPLY | OP_MAP_PUBLIC_ADDR;
        let res = parse_response(&pkt).expect("0.0.0.0 reply is still a valid reply");
        assert_eq!(res.public_addr, None);
    }

    #[test]
    fn parses_a_map_reply() {
        let mut pkt = [0u8; 16];
        pkt[1] = OP_REPLY | OP_MAP_UDP;
        pkt[4..8].copy_from_slice(&11u32.to_be_bytes());
        pkt[8..10].copy_from_slice(&41641u16.to_be_bytes());
        pkt[10..12].copy_from_slice(&40000u16.to_be_bytes());
        pkt[12..16].copy_from_slice(&3600u32.to_be_bytes());
        let res = parse_response(&pkt).expect("well-formed map reply must parse");
        assert_eq!(res.op_code, 0x81);
        assert_eq!(res.internal_port, 41641);
        assert_eq!(res.external_port, 40000);
        assert_eq!(res.mapping_valid_seconds, 3600);
        assert_eq!(res.seconds_since_epoch, 11);
    }

    #[test]
    fn refuses_short_wrong_version_and_wrong_length_replies() {
        assert_eq!(
            parse_response(&[0u8; 11]),
            None,
            "under 12 bytes is not PMP"
        );
        let mut wrong_version = [0u8; 12];
        wrong_version[0] = 2; // that's PCP, not PMP
        assert_eq!(parse_response(&wrong_version), None);

        // A map reply must be exactly 16 bytes and a public-addr reply exactly 12.
        let mut short_map = [0u8; 12];
        short_map[1] = OP_REPLY | OP_MAP_UDP;
        assert_eq!(parse_response(&short_map), None);
        let mut long_pubaddr = [0u8; 16];
        long_pubaddr[1] = OP_REPLY | OP_MAP_PUBLIC_ADDR;
        assert_eq!(parse_response(&long_pubaddr), None);
    }

    #[test]
    fn a_refusal_parses_and_keeps_its_code() {
        // "box supports mapping, but user has turned feature off": the error path that matters most,
        // because it is the difference between "no NAT-PMP here" and "NAT-PMP is switched off".
        let mut pkt = [0u8; 12];
        pkt[1] = OP_REPLY | OP_MAP_PUBLIC_ADDR;
        pkt[2..4].copy_from_slice(&2u16.to_be_bytes());
        let res = parse_response(&pkt).expect("a refusal is still a well-formed reply");
        assert_eq!(res.result_code, ResultCode::NOT_AUTHORIZED);
        assert_eq!(res.result_code.to_string(), "NotAuthorized");
    }

    #[test]
    fn result_code_names_match_gos_stringer() {
        assert_eq!(ResultCode::OK.to_string(), "OK");
        assert_eq!(
            ResultCode::UNSUPPORTED_VERSION.to_string(),
            "UnsupportedVersion"
        );
        assert_eq!(ResultCode::NETWORK_FAILURE.to_string(), "NetworkFailure");
        assert_eq!(ResultCode::OUT_OF_RESOURCES.to_string(), "OutOfResources");
        assert_eq!(
            ResultCode::UNSUPPORTED_OPCODE.to_string(),
            "UnsupportedOpcode"
        );
        // Outside the RFC's set: Go prints `pmpResultCode(9)` rather than dropping the code.
        assert_eq!(ResultCode(9).to_string(), "pmpResultCode(9)");
    }
}
