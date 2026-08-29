//! UPnP-IGD: SSDP discovery and the SOAP control calls that create a port mapping — the port of
//! Go's `net/portmapper/upnp.go` (+ the SSDP packets and response handling in `portmapper.go`,
//! tailscale v1.100.0).
//!
//! UPnP is the odd one of the three protocols: NAT-PMP and PCP are one UDP request and one UDP
//! reply, while UPnP is a three-step conversation.
//!
//! 1. **Discovery** — an SSDP `M-SEARCH` (HTTP over UDP) to the gateway and to the SSDP multicast
//!    group; devices answer with an HTTP-shaped datagram whose `LOCATION` header points at their
//!    device description.
//! 2. **Description** — an HTTP `GET` of that location returns an XML document listing the device
//!    tree and its services, of which we want a WAN connection service and its control URL.
//! 3. **Control** — SOAP `POST`s to that control URL: `AddAnyPortMapping`/`AddPortMapping` to create
//!    the mapping, `GetExternalIPAddress` to learn the address it is reachable at, plus
//!    `GetStatusInfo` when several candidate services have to be ranked.
//!
//! ## Deviation from Go: no `goupnp`
//!
//! Go delegates steps 2 and 3 to `github.com/huin/goupnp`, whose generated clients cover the whole
//! IGD1/IGD2 surface. This port implements the handful of actions the port mapper actually calls,
//! directly: the device description is read with a small tag scanner rather than a general XML
//! parser, and each SOAP call is a formatted envelope plus a scan of the response for the one or two
//! fields we need. That keeps a large dependency out of a daemon that needs five actions, at the
//! cost of not accepting device descriptions that only a full XML parser could make sense of.
//! Everything except the HTTP itself is a pure function over text, and tested against real router
//! descriptions.

use std::fmt;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use super::DebugKnobs;

/// SSDP's discovery port, for UDP discovery only — the device's HTTP/SOAP port comes later, from the
/// `LOCATION` header (Go: `upnpDefaultPort`).
pub const DEFAULT_PORT: u16 = 1900;

/// The SSDP multicast group every UPnP device joins: the administratively-scoped group SSDP reserves
/// for discovery. Written as octets so the search packets below (and every test that asserts on
/// them) have exactly one source for the address.
pub const SSDP_MULTICAST_ADDR: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);

/// A human-readable label the mapping is filed under on the router's forwarding table. Go:
/// `tsPortMappingDesc`. Kept as the fork's own name — an operator looking at their router's UPnP
/// table should see which daemon asked for the mapping.
pub const PORT_MAPPING_DESC: &str = "tailscaled-rs-portmap";

/// UPnP's protocol name for UDP in `AddPortMapping`'s `NewProtocol` field.
///
/// MUST be upper-case: Go notes that "certain routers will reject the mapping request" otherwise
/// (tailscale#7377), and other implementations (miniupnpc) send it upper-case too.
pub const PROTOCOL_UDP: &str = "UDP";

/// The service types this client knows how to drive, in Go's preference order: IGD2's
/// `WANIPConnection:2` first (it has `AddAnyPortMapping`, which lets the router resolve a port
/// conflict itself), then the IGD1 services, then the two `urn:dslforum-org` service types —
/// deprecated in 2015 but still shipped by older devices, and identical apart from the URN.
pub const SERVICE_TYPES_IN_PREFERENCE_ORDER: [&str; 5] = [
    "urn:schemas-upnp-org:service:WANIPConnection:2",
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
    "urn:dslforum-org:service:WANPPPConnection:1",
    "urn:dslforum-org:service:WANIPConnection:1",
];

/// The one service type that carries `AddAnyPortMapping` (IGD2's WAN IP connection service).
pub const WAN_IP_CONNECTION_2: &str = "urn:schemas-upnp-org:service:WANIPConnection:2";

/// UPnP SOAP error code 725, `OnlyPermanentLeasesSupported`, and 402, `Invalid Args` — the two codes
/// Go retries as a *permanent* (zero-lifetime) lease, because several routers answer them for a
/// perfectly valid request that merely asked for a finite lease (tailscale#9343, tailscale#15223).
pub const ERR_INVALID_ARGS: u32 = 402;
/// See [`ERR_INVALID_ARGS`].
pub const ERR_ONLY_PERMANENT_LEASES: u32 = 725;

/// How long the device description GET is allowed to take. Go: "We're fetching a smallish XML
/// document over plain HTTP across the local LAN, without using DNS. There should be very few round
/// trips and low latency, so one second is a long time."
pub const HTTP_TIMEOUT: Duration = Duration::from_secs(1);

/// Cap on a device-description or SOAP response body. A UPnP description is a few KB; this only
/// bounds memory against a device (or something pretending to be one) that answers with an endless
/// body.
pub const MAX_BODY_BYTES: u64 = 256 * 1024;

/// The SSDP `M-SEARCH` body for `ssdp:all` (Go: `uPnPPacket`).
pub fn m_search_all_packet() -> Vec<u8> {
    m_search_packet("ssdp:all")
}

/// The SSDP `M-SEARCH` body that asks specifically for an InternetGatewayDevice (Go:
/// `uPnPIGDPacket`).
///
/// Sent in addition to the `ssdp:all` search because "some devices respond to ssdp:all with only
/// their first descriptor (which is often not IGD)" — tailscale#3557.
pub fn m_search_igd_packet() -> Vec<u8> {
    m_search_packet("urn:schemas-upnp-org:device:InternetGatewayDevice:1")
}

/// The shared shape of both discovery datagrams: an HTTP-over-UDP request whose `ST` (search target)
/// header is the only difference.
fn m_search_packet(search_target: &str) -> Vec<u8> {
    format!(
        "M-SEARCH * HTTP/1.1\r\n\
         HOST: {SSDP_MULTICAST_ADDR}:{DEFAULT_PORT}\r\n\
         ST: {search_target}\r\n\
         MAN: \"ssdp:discover\"\r\n\
         MX: 2\r\n\r\n"
    )
    .into_bytes()
}

/// A device's answer to an SSDP search (Go: `uPnPDiscoResponse`).
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct DiscoResponse {
    /// URL of the device description document — where step 2 goes.
    pub location: String,
    /// What the device says it is running, e.g. `MiniUPnPd/2.x.x`.
    pub server: String,
    /// The device's unique service name, which also names the service being offered, e.g.
    /// `…::urn:schemas-upnp-org:device:InternetGatewayDevice:2`.
    pub usn: String,
}

/// Why an SSDP datagram was not a usable discovery response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiscoParseError {
    /// The datagram is not valid UTF-8 (SSDP is a text protocol).
    NotText,
    /// The first line is not an HTTP status line (`HTTP/1.x <code> …`). Devices also *send*
    /// `NOTIFY * HTTP/1.1` advertisements to the same multicast group unprompted; those are requests,
    /// not responses to our search, and this is what rejects them.
    NotAnHttpResponse,
}

impl fmt::Display for DiscoParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotText => f.write_str("SSDP response is not valid UTF-8"),
            Self::NotAnHttpResponse => f.write_str("SSDP response has no HTTP status line"),
        }
    }
}

/// Parse a UPnP HTTP-over-UDP discovery response (Go: `parseUPnPDiscoResponse`, which hands the
/// datagram to `http.ReadResponse`).
///
/// Header names are matched case-insensitively because devices are wildly inconsistent about them —
/// the wild samples in Go's own tests carry `LOCATION`, `Location` and `USN`/`Usn` alike.
pub fn parse_disco_response(body: &[u8]) -> Result<DiscoResponse, DiscoParseError> {
    let text = std::str::from_utf8(body).map_err(|_| DiscoParseError::NotText)?;
    let mut lines = text.split("\r\n");
    let status = lines.next().unwrap_or_default();
    // `HTTP/1.1 200 OK` — anything that does not start with the HTTP version token is not a response.
    if !status.starts_with("HTTP/1.") {
        return Err(DiscoParseError::NotAnHttpResponse);
    }
    let mut res = DiscoResponse::default();
    for line in lines {
        if line.is_empty() {
            break; // end of headers; an SSDP response has no body
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim().to_string();
        match name.trim().to_ascii_lowercase().as_str() {
            "location" => res.location = value,
            "server" => res.server = value,
            "usn" => res.usn = value,
            _ => {}
        }
    }
    Ok(res)
}

/// Sort and deduplicate discovery responses (Go: `processUPnPResponses`).
///
/// Two probes go out (`ssdp:all` and the IGD-specific one) and a LAN can hold more than one UPnP
/// router, so duplicates and genuinely different devices both arrive. Sorting first makes the choice
/// deterministic — "if we have multiple valid UPnP destinations a consistent option will be picked
/// every time" — and the USN sorts in REVERSE so `InternetGatewayDevice:2` sorts before `:1` and the
/// newer service survives the dedup.
///
/// Deduplication compares `location` and `server` but NOT `usn`, because the same device answering
/// both probes returns the same location under two different USNs.
pub fn process_upnp_responses(mut metas: Vec<DiscoResponse>) -> Vec<DiscoResponse> {
    metas.sort_by(|a, b| {
        b.usn
            .cmp(&a.usn)
            .then_with(|| a.location.cmp(&b.location))
            .then_with(|| a.server.cmp(&b.server))
    });
    metas.dedup_by(|a, b| a.location == b.location && a.server == b.server);
    metas
}

/// One service entry from a device description.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Service {
    /// e.g. `urn:schemas-upnp-org:service:WANIPConnection:2`.
    pub service_type: String,
    /// e.g. `urn:upnp-org:serviceId:WANIPConn1`.
    pub service_id: String,
    /// The URL SOAP actions are POSTed to; usually a path relative to the description's URL.
    pub control_url: String,
}

/// A parsed device description document (Go: `goupnp.RootDevice`, reduced to the fields the port
/// mapper uses).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RootDevice {
    /// The root device's friendly name, e.g. `OnHub` — logged so an operator can tell which box on
    /// their LAN answered.
    pub friendly_name: String,
    /// The root device's manufacturer, logged for the same reason.
    pub manufacturer: String,
    /// An explicit `<URLBase>`, when the description carries one; relative control URLs resolve
    /// against it instead of against the description's own URL.
    pub url_base: Option<String>,
    /// Every service in the device tree, flattened, in document order — which is what makes the
    /// preference ordering in [`candidate_services`] deterministic.
    pub services: Vec<Service>,
}

/// Parse a UPnP device description (the XML fetched from a discovery response's `LOCATION`).
///
/// This is a tag scanner, not an XML parser (see the module docs): it walks `<service>…</service>`
/// blocks and lifts the three child elements the port mapper needs, plus the first `<friendlyName>`,
/// `<manufacturer>` and `<URLBase>` — which, in document order, belong to the root device. Element
/// names are matched ignoring any namespace prefix, and the handful of XML entities that appear in
/// URLs are decoded.
pub fn parse_root_device(xml: &str) -> RootDevice {
    let mut root = RootDevice {
        friendly_name: first_element(xml, "friendlyName").unwrap_or_default(),
        manufacturer: first_element(xml, "manufacturer").unwrap_or_default(),
        url_base: first_element(xml, "URLBase"),
        services: Vec::new(),
    };
    let mut rest = xml;
    while let Some(open) = find_element_start(rest, "service") {
        let after_open = &rest[open..];
        let Some(body_start) = after_open.find('>') else {
            break;
        };
        let body = &after_open[body_start + 1..];
        let Some(close) = body.find("</service>") else {
            break;
        };
        let block = &body[..close];
        root.services.push(Service {
            service_type: first_element(block, "serviceType").unwrap_or_default(),
            service_id: first_element(block, "serviceId").unwrap_or_default(),
            control_url: first_element(block, "controlURL").unwrap_or_default(),
        });
        rest = &body[close + "</service>".len()..];
    }
    root
}

/// Offset of the start of the next `<name …>` element (`<` included), skipping `<serviceList>` and
/// other elements that merely share a prefix with `name`.
fn find_element_start(haystack: &str, name: &str) -> Option<usize> {
    let mut from = 0;
    while let Some(rel) = haystack[from..].find('<') {
        let at = from + rel;
        let after = &haystack[at + 1..];
        let stripped = after.strip_prefix(name);
        match stripped {
            // `<service>` or `<service attr="…">`, but not `<serviceList>`.
            Some(tail) if tail.starts_with('>') || tail.starts_with(char::is_whitespace) => {
                return Some(at);
            }
            _ => from = at + 1,
        }
    }
    None
}

/// The text of the first `<name>…</name>` element in `xml`, with XML entities decoded and surrounding
/// whitespace trimmed. Namespace-prefixed elements (`<u:name>`) match too, which is what SOAP replies
/// need.
pub fn first_element(xml: &str, name: &str) -> Option<String> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    // Try the bare name first, then any namespace-prefixed form (`<u:name>`).
    let (start, open_len) = match xml.find(&open) {
        Some(i) => (i, open.len()),
        None => {
            let prefixed = format!(":{name}>");
            let i = xml.find(&prefixed)?;
            // Walk back to the '<' that opened this tag.
            let lt = xml[..i].rfind('<')?;
            (lt, i + prefixed.len() - lt)
        }
    };
    let body = &xml[start + open_len..];
    let end = match body.find(&close) {
        Some(i) => i,
        None => {
            let prefixed_close = format!(":{name}>");
            let i = body.find(&prefixed_close)?;
            body[..i].rfind("</")?
        }
    };
    Some(decode_entities(body[..end].trim()))
}

/// Decode the five predefined XML entities. Device descriptions escape `&` in query-string control
/// URLs, which is the case that actually shows up in the wild.
fn decode_entities(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// The services this client knows how to drive, in [`SERVICE_TYPES_IN_PREFERENCE_ORDER`] (Go builds
/// the same list by asking `goupnp` for each client type in that order).
pub fn candidate_services(root: &RootDevice) -> Vec<&Service> {
    let mut out = Vec::new();
    for wanted in SERVICE_TYPES_IN_PREFERENCE_ORDER {
        for svc in &root.services {
            if svc.service_type == wanted {
                out.push(svc);
            }
        }
    }
    out
}

/// What ranking a candidate service needs to know about it. Split out as a trait so the ranking rule
/// below is exercised in tests without a router: the live implementation makes SOAP calls, the test
/// one answers from a table.
pub trait ServiceProbe {
    /// Go's `serviceIsConnected`: `GetStatusInfo`'s connection status is `Connected` or `Up`.
    fn is_connected(&self, svc: &Service) -> bool;
    /// Go's `GetExternalIPAddressCtx`, parsed. `None` when the call fails or the answer is not an
    /// IPv4 address.
    fn external_ip(&self, svc: &Service) -> Option<Ipv4Addr>;
}

/// Pick the service most likely to actually give us a working mapping (Go: `selectBestService`).
///
/// Go's rules, in order, and the reason each exists: a device that is not "connected" cannot forward
/// anything; a connected device with a **public** external IP is the real internet gateway and wins
/// immediately (that is the short-circuit — no further device is probed); failing that, a connected
/// device with a *private* external IP is a second-tier gateway (it is itself behind another NAT, so
/// the mapping is real but the address may not be reachable); failing that, any connected device;
/// and failing everything, the first candidate, because a device that answers nothing is still more
/// likely to work than no attempt at all.
pub fn select_best_service<'a, P: ServiceProbe>(
    candidates: &[&'a Service],
    probe: &P,
) -> Option<&'a Service> {
    if candidates.is_empty() {
        return None;
    }
    if candidates.len() == 1 {
        // Go returns the single candidate without spending a single network request on ranking.
        return Some(candidates[0]);
    }

    let mut connected = Vec::with_capacity(candidates.len());
    let mut external_ips: Vec<Option<Ipv4Addr>> = Vec::with_capacity(candidates.len());
    for svc in candidates {
        let is_connected = probe.is_connected(svc);
        connected.push(is_connected);
        if !is_connected {
            // Go does not bother asking a disconnected device for its external IP.
            external_ips.push(None);
            continue;
        }
        let ext = probe.external_ip(svc);
        external_ips.push(ext);
        if let Some(ip) = ext
            && !ip.is_private()
        {
            // Up, and with a public external address: this is the gateway to the internet.
            return Some(svc);
        }
    }

    // try = 0: up + a (private) external IP. try = 1: up at all.
    for try_num in 0..=1 {
        for (i, svc) in candidates.iter().enumerate() {
            if !connected[i] {
                continue;
            }
            // try 0 accepts only a device that reported an external IP; try 1 accepts any
            // connected device. (Go splits the two branches only to record which rule fired.)
            if external_ips[i].is_some() || try_num == 1 {
                return Some(svc);
            }
        }
    }

    Some(candidates[0])
}

/// Which SOAP action creates the mapping on this service type (Go: the type switch in
/// `addAnyPortMapping`).
///
/// `AddAnyPortMapping` is IGD2-only, and is preferred where available because a router that finds
/// the requested external port already taken picks another one and tells us which, instead of just
/// failing.
pub fn map_action_for(service_type: &str) -> &'static str {
    if service_type == WAN_IP_CONNECTION_2 {
        "AddAnyPortMapping"
    } else {
        "AddPortMapping"
    }
}

/// The external port to ask for (Go: the opening of `addAnyPortMapping`).
///
/// Anything below 1024 — including the "no previous port" 0 — is replaced by a random high port.
/// Two reasons, both from Go: some devices refuse to map privileged ports at all, and the UPnP spec
/// makes external port 0 a WILDCARD that forwards *every* unmapped external port to us, which is
/// emphatically not what we are asking for.
pub fn pick_external_port(prev_port: u16, random_in_range: impl FnOnce(u16) -> u16) -> u16 {
    if prev_port < 1024 {
        // Go: `rand.N(65535-1024) + 1024`, i.e. a value in [1024, 65535).
        return random_in_range(65535 - 1024) + 1024;
    }
    prev_port
}

/// A uniform-enough random value below `n`, from the OS CSPRNG — the live randomness
/// [`pick_external_port`] takes as a parameter. (The modulo bias over a 64511-wide range is
/// irrelevant here: this only has to avoid picking the same external port as the neighbours.)
pub fn os_random_below(n: u16) -> u16 {
    let mut buf = [0u8; 2];
    if let Err(e) = getrandom::fill(&mut buf) {
        tracing::warn!(error = %e, "portmap: OS randomness unavailable for the UPnP external port");
    }
    u16::from_be_bytes(buf) % n.max(1)
}

/// A random high external port: [`pick_external_port`] with no previous port and OS randomness.
pub fn random_external_port() -> u16 {
    pick_external_port(0, os_random_below)
}

/// Whether a failed mapping attempt should be retried as a permanent (zero-lifetime) lease (Go's
/// `code == 402 || code == 725` check).
pub fn should_retry_permanent(code: u32) -> bool {
    code == ERR_INVALID_ARGS || code == ERR_ONLY_PERMANENT_LEASES
}

/// Build a SOAP request envelope for `action` on `service_type` with the given ordered arguments.
///
/// The element order matters: UPnP devices are notoriously strict about receiving the action's
/// arguments in the order the service definition declares them, so callers pass an ordered slice
/// rather than a map.
pub fn soap_envelope(service_type: &str, action: &str, args: &[(&str, String)]) -> String {
    let mut body = String::new();
    for (name, value) in args {
        body.push_str(&format!("<{name}>{}</{name}>", escape_xml(value)));
    }
    format!(
        "<?xml version=\"1.0\"?>\r\n\
         <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
         s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\
         <s:Body><u:{action} xmlns:u=\"{service_type}\">{body}</u:{action}></s:Body>\
         </s:Envelope>\r\n"
    )
}

/// The `SOAPAction` header value a UPnP control request must carry: the service type and action,
/// quoted, separated by `#`.
pub fn soap_action_header(service_type: &str, action: &str) -> String {
    format!("\"{service_type}#{action}\"")
}

/// Escape the XML metacharacters in a SOAP argument value.
fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// The UPnP error code carried in a SOAP fault (Go: `getUPnPErrorCode`).
///
/// A UPnP fault nests a `<UPnPError><errorCode>N</errorCode></UPnPError>` inside the SOAP fault's
/// detail. `None` when the body is not a UPnP fault at all — the same `ok == false` Go returns, which
/// is what stops a plain HTTP or transport failure from being mistaken for an error code.
pub fn parse_soap_fault_code(body: &str) -> Option<u32> {
    if !body.contains("UPnPError") {
        return None;
    }
    first_element(body, "errorCode")?.parse().ok()
}

/// Repoint a discovery response's `LOCATION` at the gateway when it names a different host (Go:
/// `getUPnPRootDevice`'s check, for tailscale#5502).
///
/// Some routers advertise a location on an address that is not the one we reach them at — the
/// gateway address "is assumed to be floating" — so we keep the port and path and substitute the
/// gateway. Returns `None` if the location is not a URL with a host we can parse, in which case
/// there is nothing to fetch.
pub fn repoint_location_at_gateway(location: &str, gw: Ipv4Addr) -> Option<String> {
    let (scheme, rest) = location.split_once("://")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (authority, None),
    };
    if host == gw.to_string() {
        return Some(location.to_string());
    }
    Some(match port {
        Some(p) => format!("{scheme}://{gw}:{p}{path}"),
        None => format!("{scheme}://{gw}{path}"),
    })
}

/// Resolve a service's `controlURL` against the description's own URL (and its `<URLBase>`, when it
/// has one) into an absolute URL to POST to.
///
/// Control URLs come in all three shapes in the wild: absolute (`http://host:port/ctl`),
/// root-relative (`/ctl/IPConn`) and — rarely — path-relative (`ctl/IPConn`).
pub fn resolve_control_url(location: &str, url_base: Option<&str>, control_url: &str) -> String {
    if control_url.starts_with("http://") || control_url.starts_with("https://") {
        return control_url.to_string();
    }
    let base = url_base
        .map(str::trim)
        .filter(|b| !b.is_empty())
        .unwrap_or(location);
    // The origin of the base URL: everything up to the first '/' after the scheme.
    let origin = match base.split_once("://") {
        Some((scheme, rest)) => {
            let authority = rest.split('/').next().unwrap_or(rest);
            format!("{scheme}://{authority}")
        }
        None => base.trim_end_matches('/').to_string(),
    };
    if let Some(path) = control_url.strip_prefix('/') {
        format!("{origin}/{path}")
    } else {
        format!("{origin}/{control_url}")
    }
}

/// The arguments of an `AddPortMapping`/`AddAnyPortMapping` call, in the order the IGD service
/// definition declares them.
///
/// `lease_duration_secs` of 0 asks for a permanent lease — what the 402/725 retry falls back to.
pub fn add_port_mapping_args(
    external_port: u16,
    internal: SocketAddrV4,
    lease_duration_secs: u32,
) -> Vec<(&'static str, String)> {
    vec![
        // Empty remote host = "any host out on the internet can send packets in".
        ("NewRemoteHost", String::new()),
        ("NewExternalPort", external_port.to_string()),
        ("NewProtocol", PROTOCOL_UDP.to_string()),
        ("NewInternalPort", internal.port().to_string()),
        ("NewInternalClient", internal.ip().to_string()),
        ("NewEnabled", "1".to_string()),
        ("NewPortMappingDescription", PORT_MAPPING_DESC.to_string()),
        ("NewLeaseDuration", lease_duration_secs.to_string()),
    ]
}

/// The external port a mapping call granted.
///
/// `AddAnyPortMapping` answers with `NewReservedPort`, which may differ from the port we asked for
/// (that is the whole point of the IGD2 action); `AddPortMapping` answers with an empty body, and the
/// port we asked for is the port we got.
pub fn granted_external_port(action: &str, response_body: &str, requested: u16) -> u16 {
    if action == "AddAnyPortMapping"
        && let Some(port) = first_element(response_body, "NewReservedPort")
        && let Ok(port) = port.parse::<u16>()
    {
        return port;
    }
    requested
}

/// Why an external address a device reported cannot be used.
///
/// Both refusals are Go's, from tailscale/corp#23538: "we've seen cases where UPnP devices return the
/// public IP 0.0.0.0, which obviously doesn't work as an endpoint".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExternalIpError {
    /// The device did not answer with a parseable IPv4 address.
    Unparseable,
    /// `0.0.0.0`.
    Unspecified,
    /// A loopback address.
    Loopback,
}

impl fmt::Display for ExternalIpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unparseable => f.write_str("UPnP returned an unparseable external IP"),
            Self::Unspecified => f.write_str("UPnP returned unspecified external IP"),
            Self::Loopback => f.write_str("UPnP returned loopback external IP"),
        }
    }
}

/// Validate the address a `GetExternalIPAddress` call reported (Go: the checks at the end of
/// `tryUPnPPortmapWithDevice`).
pub fn validate_external_ip(reported: &str) -> Result<Ipv4Addr, ExternalIpError> {
    let ip: Ipv4Addr = reported
        .trim()
        .parse()
        .map_err(|_| ExternalIpError::Unparseable)?;
    if ip.is_unspecified() {
        return Err(ExternalIpError::Unspecified);
    }
    if ip.is_loopback() {
        return Err(ExternalIpError::Loopback);
    }
    Ok(ip)
}

/// Whether a `GetStatusInfo` connection status counts as connected (Go: `serviceIsConnected`).
pub fn status_is_connected(status: &str) -> bool {
    status == "Connected" || status == "Up"
}

// ---------------------------------------------------------------------------------------------
// The live half: HTTP + SOAP against a real device. Everything above this line is pure and tested;
// everything below is I/O, and is deliberately thin over it.
// ---------------------------------------------------------------------------------------------

/// Why a SOAP control call did not produce a usable answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CallError {
    /// The request never completed (connect refused, timeout, unreadable body).
    Transport(String),
    /// The device answered a UPnP fault carrying this error code — the case
    /// [`should_retry_permanent`] inspects.
    Fault(u32),
    /// A non-2xx HTTP status that was not a recognizable UPnP fault.
    Status(u16),
}

impl fmt::Display for CallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "{e}"),
            Self::Fault(code) => write!(f, "UPnP error {code}"),
            Self::Status(code) => write!(f, "HTTP {code}"),
        }
    }
}

/// A blocking HTTP client for one LAN device's description and SOAP endpoints.
///
/// Blocking on purpose: the UPnP conversation is a handful of small request/response round trips on
/// the local link, and the daemon already carries a blocking HTTP client (`ureq`) for the updater.
/// [`super::Client`] calls into this from `spawn_blocking`, so the runtime is never held.
pub struct SoapClient {
    agent: ureq::Agent,
    log_http: bool,
}

impl SoapClient {
    /// A client with the LAN-appropriate timeout, no proxy, and HTTP error statuses delivered as
    /// responses rather than errors.
    ///
    /// Both non-defaults matter. A proxy must never be used: these requests are addressed to a device
    /// on the local link by IP, and an inherited `HTTP_PROXY` would send the daemon's port-mapping
    /// request to a third party. And a UPnP fault arrives as HTTP 500 with the error code *in the
    /// body*, so a client that turns statuses into errors would throw away the very code the
    /// permanent-lease retry keys on.
    pub fn new(log_http: bool) -> Self {
        let agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .proxy(None)
            .timeout_global(Some(HTTP_TIMEOUT))
            .build()
            .new_agent();
        Self { agent, log_http }
    }

    /// GET a device description document.
    pub fn get_description(&self, url: &str, log: &super::Logger) -> Result<String, CallError> {
        if self.log_http {
            log.log(format!("http: GET {url}"));
        }
        let resp = self
            .agent
            .get(url)
            .call()
            .map_err(|e| CallError::Transport(e.to_string()))?;
        let status = resp.status().as_u16();
        let body = resp
            .into_body()
            .with_config()
            .limit(MAX_BODY_BYTES)
            .read_to_string()
            .map_err(|e| CallError::Transport(e.to_string()))?;
        if self.log_http {
            log.log(format!("http: GET {url} -> {status}: {body}"));
        }
        if !(200..300).contains(&status) {
            return Err(CallError::Status(status));
        }
        Ok(body)
    }

    /// POST one SOAP action and return the response body.
    ///
    /// A UPnP fault (HTTP 500 with a `UPnPError` body) becomes [`CallError::Fault`] carrying the
    /// device's error code, which is what lets the caller retry the two codes Go retries instead of
    /// giving up on a router that merely dislikes finite leases.
    pub fn call(
        &self,
        control_url: &str,
        service_type: &str,
        action: &str,
        args: &[(&str, String)],
        log: &super::Logger,
    ) -> Result<String, CallError> {
        let envelope = soap_envelope(service_type, action, args);
        if self.log_http {
            log.log(format!("http: POST {control_url} {action}: {envelope}"));
        }
        let resp = self
            .agent
            .post(control_url)
            .header("Content-Type", "text/xml; charset=\"utf-8\"")
            .header("SOAPAction", soap_action_header(service_type, action))
            .send(envelope)
            .map_err(|e| CallError::Transport(e.to_string()))?;
        let status = resp.status().as_u16();
        let body = resp
            .into_body()
            .with_config()
            .limit(MAX_BODY_BYTES)
            .read_to_string()
            .map_err(|e| CallError::Transport(e.to_string()))?;
        if self.log_http {
            log.log(format!(
                "http: POST {control_url} {action} -> {status}: {body}"
            ));
        }
        if let Some(code) = parse_soap_fault_code(&body) {
            return Err(CallError::Fault(code));
        }
        if !(200..300).contains(&status) {
            return Err(CallError::Status(status));
        }
        Ok(body)
    }
}

/// A [`ServiceProbe`] that answers by actually calling `GetStatusInfo` / `GetExternalIPAddress` on
/// the device — the live counterpart of the table-driven probe the ranking tests use.
struct LiveProbe<'a> {
    soap: &'a SoapClient,
    location: &'a str,
    url_base: Option<&'a str>,
    log: &'a super::Logger,
}

impl LiveProbe<'_> {
    fn control_url(&self, svc: &Service) -> String {
        resolve_control_url(self.location, self.url_base, &svc.control_url)
    }
}

impl ServiceProbe for LiveProbe<'_> {
    fn is_connected(&self, svc: &Service) -> bool {
        match self.soap.call(
            &self.control_url(svc),
            &svc.service_type,
            "GetStatusInfo",
            &[],
            self.log,
        ) {
            Ok(body) => first_element(&body, "NewConnectionStatus")
                .map(|s| status_is_connected(&s))
                .unwrap_or(false),
            Err(e) => {
                self.log
                    .vlog(format!("GetStatusInfo({}): {e}", svc.service_id));
                false
            }
        }
    }

    fn external_ip(&self, svc: &Service) -> Option<Ipv4Addr> {
        let body = self
            .soap
            .call(
                &self.control_url(svc),
                &svc.service_type,
                "GetExternalIPAddress",
                &[],
                self.log,
            )
            .map_err(|e| {
                self.log
                    .vlog(format!("GetExternalIPAddress({}): {e}", svc.service_id));
            })
            .ok()?;
        let reported = first_element(&body, "NewExternalIPAddress")?;
        validate_external_ip(&reported).ok()
    }
}

/// Try every discovered UPnP device in turn for a port mapping (Go: `getUPnPPortMapping`).
///
/// Blocking; [`super::Client::upnp_mapping`] runs it on a blocking thread. Returns the external
/// endpoint of the first device that produced one — a device that fails is logged and the next is
/// tried, because a LAN with two UPnP responders is exactly the case where the first one is the
/// wrong one.
pub fn get_port_mapping(
    gw: Ipv4Addr,
    internal: SocketAddrV4,
    prev_port: u16,
    metas: &[DiscoResponse],
    knobs: DebugKnobs,
    log: &super::Logger,
) -> Option<SocketAddrV4> {
    if knobs.disable_upnp {
        return None;
    }
    let soap = SoapClient::new(knobs.log_http);
    for meta in metas {
        if meta.location.is_empty() {
            continue;
        }
        // tailscale#5502: a device may advertise a location on an address we do not reach it at; the
        // gateway "is assumed to be floating", so the location is repointed at it.
        let Some(location) = repoint_location_at_gateway(&meta.location, gw) else {
            log.log(format!("unexpected UPnP location {:?}", meta.location));
            continue;
        };
        if location != meta.location {
            log.log(format!(
                "UPnP discovered root {:?} does not match gateway IP {gw}; repointing at gateway which is assumed to be floating",
                meta.location
            ));
        }
        log.vlog(format!("fetching {location}"));
        let description = match soap.get_description(&location, log) {
            Ok(body) => body,
            Err(e) => {
                log.vlog(format!("getUPnPRootDevice: loc={location:?} err={e}"));
                continue;
            }
        };
        let root = parse_root_device(&description);
        log.vlog(format!(
            "UPnP root device {:?} by {:?} with {} service(s)",
            root.friendly_name,
            root.manufacturer,
            root.services.len()
        ));
        let candidates = candidate_services(&root);
        let probe = LiveProbe {
            soap: &soap,
            location: &location,
            url_base: root.url_base.as_deref(),
            log,
        };
        let Some(svc) = select_best_service(&candidates, &probe) else {
            // Print what the device DOES offer: the usual cause is a device with no WAN connection
            // service at all (a printer, a media server) answering the same SSDP search.
            for s in &root.services {
                log.vlog(format!(
                    "unsupported UPnP service: Type={:?} ID={:?} ControlURL={:?}",
                    s.service_type, s.service_id, s.control_url
                ));
            }
            log.log("no supported UPnP clients");
            continue;
        };
        match try_portmap_with_service(
            &soap,
            &location,
            root.url_base.as_deref(),
            svc,
            internal,
            prev_port,
            log,
        ) {
            Ok(external) => return Some(external),
            Err(e) => log.log(format!("UPnP portmap via {:?} failed: {e}", svc.service_id)),
        }
    }
    None
}

/// Ask one service for a mapping and confirm the external address (Go:
/// `tryUPnPPortmapWithDevice`).
fn try_portmap_with_service(
    soap: &SoapClient,
    location: &str,
    url_base: Option<&str>,
    svc: &Service,
    internal: SocketAddrV4,
    prev_port: u16,
    log: &super::Logger,
) -> Result<SocketAddrV4, CallError> {
    let control_url = resolve_control_url(location, url_base, &svc.control_url);
    let action = map_action_for(&svc.service_type);
    let requested_port = pick_external_port(prev_port, os_random_below);

    let lease = super::pmp::MAP_LIFETIME_SEC;
    let args = add_port_mapping_args(requested_port, internal, lease);
    let mut body = soap.call(&control_url, &svc.service_type, action, &args, log);
    log.vlog(format!(
        "{action}: port={requested_port} ok={}",
        body.is_ok()
    ));

    // Some routers refuse ANY finite lease and answer 725 (OnlyPermanentLeasesSupported) — or, less
    // helpfully, 402 (Invalid Args) — for an otherwise valid request. Go retries those two as a
    // permanent lease rather than reporting no mapping (tailscale#9343, tailscale#15223).
    let fault_code = match &body {
        Err(CallError::Fault(code)) if should_retry_permanent(*code) => Some(*code),
        _ => None,
    };
    if let Some(code) = fault_code {
        let permanent = add_port_mapping_args(requested_port, internal, 0);
        body = soap.call(&control_url, &svc.service_type, action, &permanent, log);
        log.vlog(format!(
            "{action}: errcode={code} retried permanently: ok={}",
            body.is_ok()
        ));
    }
    let body = body?;
    let granted_port = granted_external_port(action, &body, requested_port);

    let ext_body = soap.call(
        &control_url,
        &svc.service_type,
        "GetExternalIPAddress",
        &[],
        log,
    )?;
    let reported = first_element(&ext_body, "NewExternalIPAddress").unwrap_or_default();
    let external_ip = validate_external_ip(&reported).map_err(|e| {
        log.log(e.to_string());
        CallError::Transport(e.to_string())
    })?;
    Ok(SocketAddrV4::new(external_ip, granted_port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssdp_search_packets_match_gos_bytes() {
        let all = String::from_utf8(m_search_all_packet()).unwrap();
        assert_eq!(
            all,
            format!(
                "M-SEARCH * HTTP/1.1\r\nHOST: {SSDP_MULTICAST_ADDR}:1900\r\nST: ssdp:all\r\n\
                 MAN: \"ssdp:discover\"\r\nMX: 2\r\n\r\n"
            )
        );
        let igd = String::from_utf8(m_search_igd_packet()).unwrap();
        assert!(
            igd.contains("ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"),
            "the second probe must name IGD explicitly: {igd}"
        );
        assert!(igd.ends_with("MX: 2\r\n\r\n"));
    }

    /// A real Google Wifi discovery response (from Go's `upnp_test.go` corpus).
    const GOOGLE_WIFI_DISCO: &str = "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:2\r\nUSN: uuid:a9708184-a6c0-413a-bbac-11bcf7e30ece::urn:schemas-upnp-org:device:InternetGatewayDevice:2\r\nEXT:\r\nSERVER: Linux/5.4.0-1034-gcp UPnP/1.1 MiniUPnPd/1.9\r\nLOCATION: http://192.168.86.1:5000/rootDesc.xml\r\nOPT: \"http://schemas.upnp.org/upnp/1/0/\"; ns=01\r\n01-NLS: 1\r\nBOOTID.UPNP.ORG: 1\r\nCONFIGID.UPNP.ORG: 1337\r\n\r\n";

    #[test]
    fn parses_a_real_discovery_response() {
        let got = parse_disco_response(GOOGLE_WIFI_DISCO.as_bytes()).expect("must parse");
        assert_eq!(got.location, "http://192.168.86.1:5000/rootDesc.xml");
        assert_eq!(got.server, "Linux/5.4.0-1034-gcp UPnP/1.1 MiniUPnPd/1.9");
        assert_eq!(
            got.usn,
            "uuid:a9708184-a6c0-413a-bbac-11bcf7e30ece::urn:schemas-upnp-org:device:InternetGatewayDevice:2"
        );
    }

    #[test]
    fn header_names_are_matched_case_insensitively() {
        let mixed = "HTTP/1.1 200 OK\r\nLocation: http://192.168.1.1:5000/d.xml\r\nUsn: uuid:x\r\nserver: R/1\r\n\r\n";
        let got = parse_disco_response(mixed.as_bytes()).expect("must parse");
        assert_eq!(got.location, "http://192.168.1.1:5000/d.xml");
        assert_eq!(got.usn, "uuid:x");
        assert_eq!(got.server, "R/1");
    }

    #[test]
    fn refuses_datagrams_that_are_not_http_responses() {
        // Unsolicited SSDP advertisements land on the same socket; they are requests, not replies.
        let notify =
            format!("NOTIFY * HTTP/1.1\r\nHOST: {SSDP_MULTICAST_ADDR}:{DEFAULT_PORT}\r\n\r\n");
        assert_eq!(
            parse_disco_response(notify.as_bytes()),
            Err(DiscoParseError::NotAnHttpResponse)
        );
        assert_eq!(
            parse_disco_response(&[0xff, 0xfe, 0xfd]),
            Err(DiscoParseError::NotText)
        );
    }

    fn disco(location: &str, server: &str, usn: &str) -> DiscoResponse {
        DiscoResponse {
            location: location.to_string(),
            server: server.to_string(),
            usn: usn.to_string(),
        }
    }

    #[test]
    fn duplicate_responses_from_one_device_collapse_to_the_newer_usn() {
        // The same box answers both probes: same location + server, different USN. The IGD:2 USN
        // sorts first (reverse USN order), so that is the one kept.
        let metas = vec![
            disco(
                "http://192.168.1.1:2189/d.xml",
                "MiniUPnPd/2.2.1",
                "uuid:a::urn:schemas-upnp-org:device:InternetGatewayDevice:1",
            ),
            disco(
                "http://192.168.1.1:2189/d.xml",
                "MiniUPnPd/2.2.1",
                "uuid:a::urn:schemas-upnp-org:device:InternetGatewayDevice:2",
            ),
        ];
        let got = process_upnp_responses(metas);
        assert_eq!(got.len(), 1, "one device must not appear twice");
        assert!(
            got[0].usn.ends_with("InternetGatewayDevice:2"),
            "the newer IGD version must win: {:?}",
            got[0]
        );
    }

    #[test]
    fn two_distinct_devices_both_survive_in_a_stable_order() {
        let a = disco(
            "http://192.168.1.1:2189/d.xml",
            "MiniUPnPd/2.2.1",
            "uuid:a::urn:x:1",
        );
        let b = disco(
            "http://192.168.1.2:5000/d.xml",
            "MiniUPnPd/1.9",
            "uuid:b::urn:x:1",
        );
        let one = process_upnp_responses(vec![a.clone(), b.clone()]);
        let other = process_upnp_responses(vec![b, a]);
        assert_eq!(one.len(), 2);
        assert_eq!(one, other, "the order must not depend on arrival order");
    }

    /// A condensed pfSense/MiniUPnPd description: nested devices, an IGD1 WAN IP connection service.
    const PFSENSE_ROOT_DESC: &str = r#"<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0" configId="1337"><specVersion><major>1</major><minor>1</minor></specVersion><device><deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType><friendlyName>FreeBSD router</friendlyName><manufacturer>FreeBSD</manufacturer><serviceList><service><serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType><serviceId>urn:upnp-org:serviceId:L3Forwarding1</serviceId><SCPDURL>/L3F.xml</SCPDURL><controlURL>/ctl/L3F</controlURL><eventSubURL>/evt/L3F</eventSubURL></service></serviceList><deviceList><device><deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType><friendlyName>WANDevice</friendlyName><manufacturer>MiniUPnP</manufacturer><serviceList><service><serviceType>urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1</serviceType><serviceId>urn:upnp-org:serviceId:WANCommonIFC1</serviceId><SCPDURL>/WANCfg.xml</SCPDURL><controlURL>/ctl/CmnIfCfg</controlURL><eventSubURL>/evt/CmnIfCfg</eventSubURL></service></serviceList><deviceList><device><deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType><serviceList><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId><SCPDURL>/WANIPCn.xml</SCPDURL><controlURL>/ctl/IPConn</controlURL><eventSubURL>/evt/IPConn</eventSubURL></service></serviceList></device></deviceList></device></deviceList></device></root>"#;

    #[test]
    fn parses_a_real_device_description() {
        let root = parse_root_device(PFSENSE_ROOT_DESC);
        assert_eq!(root.friendly_name, "FreeBSD router");
        assert_eq!(root.manufacturer, "FreeBSD");
        assert_eq!(root.url_base, None);
        assert_eq!(
            root.services.len(),
            3,
            "every service in the nested device tree must be flattened: {:?}",
            root.services
        );
        let wan = root
            .services
            .iter()
            .find(|s| s.service_type == "urn:schemas-upnp-org:service:WANIPConnection:1")
            .expect("the WAN IP connection service must be found");
        assert_eq!(wan.control_url, "/ctl/IPConn");
        assert_eq!(wan.service_id, "urn:upnp-org:serviceId:WANIPConn1");
    }

    #[test]
    fn a_description_with_no_services_parses_to_an_empty_list() {
        let root =
            parse_root_device("<root><device><friendlyName>Bare</friendlyName></device></root>");
        assert_eq!(root.friendly_name, "Bare");
        assert!(root.services.is_empty());
    }

    #[test]
    fn control_urls_with_escaped_entities_are_decoded() {
        let xml = "<root><serviceList><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><serviceId>id</serviceId><controlURL>/ctl?a=1&amp;b=2</controlURL></service></serviceList></root>";
        let root = parse_root_device(xml);
        assert_eq!(root.services[0].control_url, "/ctl?a=1&b=2");
    }

    #[test]
    fn candidates_are_returned_in_gos_preference_order() {
        let root = RootDevice {
            services: vec![
                Service {
                    service_type: "urn:schemas-upnp-org:service:WANPPPConnection:1".into(),
                    service_id: "ppp".into(),
                    control_url: "/ppp".into(),
                },
                Service {
                    service_type: "urn:dslforum-org:service:WANIPConnection:1".into(),
                    service_id: "legacy".into(),
                    control_url: "/legacy".into(),
                },
                Service {
                    service_type: WAN_IP_CONNECTION_2.into(),
                    service_id: "ip2".into(),
                    control_url: "/ip2".into(),
                },
                Service {
                    service_type: "urn:schemas-upnp-org:service:Layer3Forwarding:1".into(),
                    service_id: "l3f".into(),
                    control_url: "/l3f".into(),
                },
            ],
            ..RootDevice::default()
        };
        let ids: Vec<&str> = candidate_services(&root)
            .iter()
            .map(|s| s.service_id.as_str())
            .collect();
        assert_eq!(
            ids,
            vec!["ip2", "ppp", "legacy"],
            "IGD2 first, then IGD1, then the dslforum legacy URNs; unrelated services are dropped"
        );
    }

    /// A [`ServiceProbe`] answering from a table, keyed by service id, and counting its calls so the
    /// short-circuit can be observed.
    struct FakeProbe {
        connected: Vec<(&'static str, bool)>,
        external: Vec<(&'static str, Ipv4Addr)>,
        calls: std::cell::RefCell<Vec<String>>,
    }

    impl ServiceProbe for FakeProbe {
        fn is_connected(&self, svc: &Service) -> bool {
            self.calls
                .borrow_mut()
                .push(format!("status:{}", svc.service_id));
            self.connected
                .iter()
                .find(|(id, _)| *id == svc.service_id)
                .map(|(_, up)| *up)
                .unwrap_or(false)
        }
        fn external_ip(&self, svc: &Service) -> Option<Ipv4Addr> {
            self.calls
                .borrow_mut()
                .push(format!("extip:{}", svc.service_id));
            self.external
                .iter()
                .find(|(id, _)| *id == svc.service_id)
                .map(|(_, ip)| *ip)
        }
    }

    fn svc(id: &str) -> Service {
        Service {
            service_type: WAN_IP_CONNECTION_2.into(),
            service_id: id.into(),
            control_url: format!("/{id}"),
        }
    }

    #[test]
    fn a_single_candidate_is_chosen_without_probing_it() {
        let only = svc("a");
        let probe = FakeProbe {
            connected: vec![],
            external: vec![],
            calls: Default::default(),
        };
        assert_eq!(select_best_service(&[&only], &probe), Some(&only));
        assert!(
            probe.calls.borrow().is_empty(),
            "ranking one candidate must cost no network requests"
        );
    }

    #[test]
    fn a_connected_device_with_a_public_ip_wins_immediately() {
        let (a, b) = (svc("a"), svc("b"));
        let probe = FakeProbe {
            connected: vec![("a", true), ("b", true)],
            external: vec![
                ("a", Ipv4Addr::new(203, 0, 113, 9)),
                ("b", Ipv4Addr::new(203, 0, 113, 10)),
            ],
            calls: Default::default(),
        };
        assert_eq!(select_best_service(&[&a, &b], &probe), Some(&a));
        assert!(
            !probe.calls.borrow().iter().any(|c| c.ends_with(":b")),
            "the first public-IP device short-circuits: {:?}",
            probe.calls.borrow()
        );
    }

    #[test]
    fn a_private_external_ip_loses_to_a_public_one_even_when_it_comes_first() {
        let (a, b) = (svc("a"), svc("b"));
        let probe = FakeProbe {
            connected: vec![("a", true), ("b", true)],
            // "a" is a second router behind another NAT; "b" is the real gateway.
            external: vec![
                ("a", Ipv4Addr::new(192, 168, 8, 1)),
                ("b", Ipv4Addr::new(203, 0, 113, 9)),
            ],
            calls: Default::default(),
        };
        assert_eq!(select_best_service(&[&a, &b], &probe), Some(&b));
    }

    #[test]
    fn a_private_external_ip_beats_a_device_with_none() {
        let (a, b) = (svc("a"), svc("b"));
        let probe = FakeProbe {
            connected: vec![("a", true), ("b", true)],
            external: vec![("b", Ipv4Addr::new(192, 168, 8, 1))],
            calls: Default::default(),
        };
        assert_eq!(select_best_service(&[&a, &b], &probe), Some(&b));
    }

    #[test]
    fn a_connected_device_beats_a_disconnected_one() {
        let (a, b) = (svc("a"), svc("b"));
        let probe = FakeProbe {
            connected: vec![("a", false), ("b", true)],
            external: vec![],
            calls: Default::default(),
        };
        assert_eq!(select_best_service(&[&a, &b], &probe), Some(&b));
    }

    #[test]
    fn with_nothing_connected_the_first_candidate_is_still_tried() {
        let (a, b) = (svc("a"), svc("b"));
        let probe = FakeProbe {
            connected: vec![],
            external: vec![],
            calls: Default::default(),
        };
        assert_eq!(select_best_service(&[&a, &b], &probe), Some(&a));
    }

    #[test]
    fn no_candidates_is_no_service() {
        let probe = FakeProbe {
            connected: vec![],
            external: vec![],
            calls: Default::default(),
        };
        assert_eq!(select_best_service(&[], &probe), None);
    }

    #[test]
    fn status_strings_that_count_as_connected() {
        assert!(status_is_connected("Connected"));
        assert!(status_is_connected("Up"));
        assert!(!status_is_connected("Disconnected"));
        assert!(!status_is_connected("connected"), "the match is exact");
    }

    #[test]
    fn igd2_uses_add_any_port_mapping_and_igd1_does_not() {
        assert_eq!(map_action_for(WAN_IP_CONNECTION_2), "AddAnyPortMapping");
        assert_eq!(
            map_action_for("urn:schemas-upnp-org:service:WANIPConnection:1"),
            "AddPortMapping"
        );
        assert_eq!(
            map_action_for("urn:dslforum-org:service:WANPPPConnection:1"),
            "AddPortMapping"
        );
    }

    #[test]
    fn a_privileged_or_absent_previous_port_becomes_a_random_high_port() {
        // 0 ("no previous port") must never be sent: the UPnP spec makes it a wildcard that forwards
        // every unmapped external port to us.
        assert_eq!(pick_external_port(0, |_| 0), 1024);
        assert_eq!(pick_external_port(80, |_| 500), 1524);
        assert_eq!(pick_external_port(1023, |n| n - 1), 65534);
        // A usable previous port is kept, so a renewal asks for the port we already had.
        assert_eq!(pick_external_port(41641, |_| 0), 41641);
    }

    #[test]
    fn a_random_external_port_is_never_privileged() {
        for _ in 0..16 {
            assert!(random_external_port() >= 1024);
        }
    }

    #[test]
    fn only_402_and_725_retry_as_a_permanent_lease() {
        assert!(should_retry_permanent(402));
        assert!(should_retry_permanent(725));
        assert!(!should_retry_permanent(718), "ConflictInMappingEntry");
        assert!(!should_retry_permanent(0));
    }

    #[test]
    fn soap_envelope_carries_the_action_service_and_ordered_args() {
        let args = add_port_mapping_args(
            41641,
            SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 42), 41641),
            7200,
        );
        let body = soap_envelope(WAN_IP_CONNECTION_2, "AddAnyPortMapping", &args);
        assert!(body.contains(&format!(
            "<u:AddAnyPortMapping xmlns:u=\"{WAN_IP_CONNECTION_2}\">"
        )));
        assert!(body.contains("<NewProtocol>UDP</NewProtocol>"));
        assert!(body.contains("<NewInternalClient>192.168.1.42</NewInternalClient>"));
        assert!(body.contains("<NewLeaseDuration>7200</NewLeaseDuration>"));
        assert!(body.ends_with("</s:Envelope>\r\n"));
        // Argument ORDER is part of the contract: strict devices reject a reordered body.
        let ext = body.find("<NewExternalPort>").unwrap();
        let int = body.find("<NewInternalPort>").unwrap();
        let lease = body.find("<NewLeaseDuration>").unwrap();
        assert!(ext < int && int < lease, "arguments must keep IGD's order");
    }

    #[test]
    fn a_permanent_lease_is_a_zero_duration() {
        let args = add_port_mapping_args(
            41641,
            SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 42), 41641),
            0,
        );
        assert_eq!(
            args.iter()
                .find(|(k, _)| *k == "NewLeaseDuration")
                .unwrap()
                .1,
            "0"
        );
    }

    #[test]
    fn the_soap_action_header_is_quoted_type_hash_action() {
        assert_eq!(
            soap_action_header(WAN_IP_CONNECTION_2, "AddAnyPortMapping"),
            "\"urn:schemas-upnp-org:service:WANIPConnection:2#AddAnyPortMapping\""
        );
    }

    #[test]
    fn add_any_port_mapping_reports_the_port_the_router_actually_reserved() {
        // The IGD2 action's whole point: the router resolved a conflict and picked a different port.
        let body = "<?xml version=\"1.0\"?><s:Envelope><s:Body><u:AddAnyPortMappingResponse xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:2\"><NewReservedPort>50000</NewReservedPort></u:AddAnyPortMappingResponse></s:Body></s:Envelope>";
        assert_eq!(
            granted_external_port("AddAnyPortMapping", body, 41641),
            50000
        );
    }

    #[test]
    fn add_port_mapping_keeps_the_requested_port() {
        // AddPortMapping's success response is empty — the port we asked for is the port we got.
        let body = "<?xml version=\"1.0\"?><s:Envelope><s:Body><u:AddPortMappingResponse xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\"></u:AddPortMappingResponse></s:Body></s:Envelope>";
        assert_eq!(granted_external_port("AddPortMapping", body, 41641), 41641);
    }

    #[test]
    fn a_soap_fault_yields_its_upnp_error_code() {
        let fault = "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail><UPnPError xmlns=\"urn:schemas-upnp-org:control-1-0\"><errorCode>725</errorCode><errorDescription>OnlyPermanentLeasesSupported</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>";
        assert_eq!(parse_soap_fault_code(fault), Some(725));
        assert!(should_retry_permanent(
            parse_soap_fault_code(fault).unwrap()
        ));
    }

    #[test]
    fn a_body_that_is_not_a_upnp_fault_has_no_error_code() {
        // A plain SOAP fault with no UPnPError detail, and an ordinary success body: neither is a
        // UPnP error code, and treating either as one would trigger a bogus permanent-lease retry.
        let plain = "<s:Envelope><s:Body><s:Fault><faultcode>s:Server</faultcode></s:Fault></s:Body></s:Envelope>";
        assert_eq!(parse_soap_fault_code(plain), None);
        assert_eq!(parse_soap_fault_code("<ok/>"), None);
    }

    #[test]
    fn soap_values_are_read_through_namespace_prefixes() {
        let body = "<s:Envelope><s:Body><u:GetExternalIPAddressResponse xmlns:u=\"urn:x\"><NewExternalIPAddress>203.0.113.9</NewExternalIPAddress></u:GetExternalIPAddressResponse></s:Body></s:Envelope>";
        assert_eq!(
            first_element(body, "NewExternalIPAddress").as_deref(),
            Some("203.0.113.9")
        );
        let status = "<s:Envelope><s:Body><u:GetStatusInfoResponse xmlns:u=\"urn:x\"><NewConnectionStatus>Connected</NewConnectionStatus></u:GetStatusInfoResponse></s:Body></s:Envelope>";
        assert_eq!(
            first_element(status, "NewConnectionStatus").as_deref(),
            Some("Connected")
        );
    }

    #[test]
    fn an_external_ip_of_zero_or_loopback_is_refused() {
        assert_eq!(
            validate_external_ip("203.0.113.9"),
            Ok(Ipv4Addr::new(203, 0, 113, 9))
        );
        assert_eq!(
            validate_external_ip("0.0.0.0"),
            Err(ExternalIpError::Unspecified)
        );
        assert_eq!(
            validate_external_ip("127.0.0.1"),
            Err(ExternalIpError::Loopback)
        );
        assert_eq!(
            validate_external_ip("not-an-ip"),
            Err(ExternalIpError::Unparseable)
        );
        assert_eq!(
            ExternalIpError::Unspecified.to_string(),
            "UPnP returned unspecified external IP"
        );
    }

    #[test]
    fn a_location_pointing_at_another_host_is_repointed_at_the_gateway() {
        // tailscale#5502: the advertised host is not the address we reach the router at.
        let gw = Ipv4Addr::new(192, 168, 1, 1);
        assert_eq!(
            repoint_location_at_gateway("http://192.168.9.9:5000/rootDesc.xml", gw).as_deref(),
            Some("http://192.168.1.1:5000/rootDesc.xml")
        );
        // A location already on the gateway is left exactly as it is.
        assert_eq!(
            repoint_location_at_gateway("http://192.168.1.1:5000/rootDesc.xml", gw).as_deref(),
            Some("http://192.168.1.1:5000/rootDesc.xml")
        );
        assert_eq!(repoint_location_at_gateway("not a url", gw), None);
    }

    #[test]
    fn control_urls_resolve_in_all_three_shapes() {
        let loc = "http://192.168.1.1:2189/rootDesc.xml";
        assert_eq!(
            resolve_control_url(loc, None, "/ctl/IPConn"),
            "http://192.168.1.1:2189/ctl/IPConn"
        );
        assert_eq!(
            resolve_control_url(loc, None, "ctl/IPConn"),
            "http://192.168.1.1:2189/ctl/IPConn"
        );
        assert_eq!(
            resolve_control_url(loc, None, "http://192.168.1.1:49152/ctl"),
            "http://192.168.1.1:49152/ctl"
        );
        // An explicit <URLBase> wins over the description's own URL — including its port, which some
        // devices deliberately move the control endpoint to.
        assert_eq!(
            resolve_control_url(loc, Some("http://192.168.1.1:49152/"), "/ctl/IPConn"),
            "http://192.168.1.1:49152/ctl/IPConn"
        );
        // An empty <URLBase> is ignored rather than producing a hostless URL.
        assert_eq!(
            resolve_control_url(loc, Some("  "), "/ctl/IPConn"),
            "http://192.168.1.1:2189/ctl/IPConn"
        );
    }
}
