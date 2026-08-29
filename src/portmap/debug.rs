//! The `debug portmap` diagnostic: run the port mapper end to end against the current network and
//! narrate what happens — the port of Go's `feature/debugportmapper/debugportmapper.go`
//! (`serveDebugPortmap`, tailscale v1.100.0).
//!
//! This is the operator-facing half of the port mapper. It answers, for one network, the question
//! that decides whether a NAT is traversable without a relay: *does anything here speak NAT-PMP, PCP
//! or UPnP-IGD, and if so what external endpoint does it hand out?* Every step is logged as it
//! happens, because a run that stalls or half-succeeds is as informative as one that works.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use super::{Client, DebugKnobs, Logger, UnknownDebugType, gateway};

/// How long the run may take when the caller does not say (Go: the CLI's `-duration` default).
pub const DEFAULT_DURATION: Duration = Duration::from_secs(5);

/// One `debug portmap` run's options (Go: `local.DebugPortmapOpts` / the endpoint's query
/// parameters).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DebugPortmapOpts {
    /// How long the whole run may take before it is cut off.
    pub duration: Duration,
    /// Which protocol to exercise: empty for all, or `pmp`/`pcp`/`upnp`.
    pub ty: String,
    /// Override the autodetected `(gateway, self)` pair. Both or neither — see
    /// [`parse_gateway_and_self`].
    pub gateway_and_self: Option<(Ipv4Addr, Ipv4Addr)>,
    /// Log every UPnP HTTP request and response.
    pub log_http: bool,
}

impl Default for DebugPortmapOpts {
    fn default() -> Self {
        Self {
            duration: DEFAULT_DURATION,
            ty: String::new(),
            gateway_and_self: None,
            log_http: false,
        }
    }
}

/// Why a `gateway_and_self` override was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GatewayAndSelfError {
    /// The value is not the `gateway/self` pair the endpoint expects.
    NotAPair(String),
    /// One half is not an IPv4 address.
    NotAnIpv4Address(String),
}

impl std::fmt::Display for GatewayAndSelfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAPair(v) => write!(f, "gateway_and_self must be \"gateway/self\", got {v:?}"),
            Self::NotAnIpv4Address(v) => write!(f, "invalid IPv4 address {v:?}"),
        }
    }
}

impl std::error::Error for GatewayAndSelfError {}

/// Parse the endpoint's `gateway_and_self` parameter: the gateway and this host's address, separated
/// by a `/` (Go: `strings.Cut(gwSelf, "/")` in `serveDebugPortmap`).
///
/// DEVIATION from Go, and an intentional one: Go parses both halves with `netip.MustParseAddr`,
/// which **panics** on malformed input — a local-API caller can crash the daemon with
/// `?gateway_and_self=x/y`. Here both halves are parsed fallibly and a bad value is a refusal.
pub fn parse_gateway_and_self(value: &str) -> Result<(Ipv4Addr, Ipv4Addr), GatewayAndSelfError> {
    let (gw, self_ip) = value
        .split_once('/')
        .ok_or_else(|| GatewayAndSelfError::NotAPair(value.to_string()))?;
    let gw: Ipv4Addr = gw
        .parse()
        .map_err(|_| GatewayAndSelfError::NotAnIpv4Address(gw.to_string()))?;
    let self_ip: Ipv4Addr = self_ip
        .parse()
        .map_err(|_| GatewayAndSelfError::NotAnIpv4Address(self_ip.to_string()))?;
    Ok((gw, self_ip))
}

/// Run one `debug portmap`, narrating to `log` (Go: the body of `serveDebugPortmap`).
///
/// Returns an error only when the run could not be *started* — an unknown `--type`. Everything else,
/// including "this network offers nothing", is a normal outcome and is reported through `log`,
/// exactly as Go reports it to the streaming client.
pub async fn run(opts: &DebugPortmapOpts, log: Logger) -> Result<(), UnknownDebugType> {
    let mut knobs = DebugKnobs::for_debug_type(&opts.ty)?;
    knobs.log_http = opts.log_http;
    // The environment kill-switches still apply: an operator who set TS_DISABLE_PORTMAPPER should
    // see this command refuse for that reason rather than quietly probing anyway.
    let knobs = knobs.with_env_overrides(|name| std::env::var(name).ok());

    // Bound the whole run, as Go bounds its handler with `context.WithTimeout(r.Context(), dur)`.
    let outcome = tokio::time::timeout(opts.duration, run_inner(opts, &knobs, &log)).await;
    if outcome.is_err() {
        log.log(format!(
            "debug portmap: context done: context deadline exceeded ({}s)",
            opts.duration.as_secs_f64()
        ));
    }
    Ok(())
}

/// The run itself, without the deadline wrapper.
async fn run_inner(opts: &DebugPortmapOpts, knobs: &DebugKnobs, log: &Logger) {
    let Some((gw, self_ip)) = opts.gateway_and_self.or_else(gateway::gateway_and_self_ip) else {
        // Go: "no gateway or self IP; %v" plus the interface state. There is nothing to ask.
        log.log("no gateway or self IP");
        return;
    };
    log.log(format!("gw={gw}; self={self_ip}"));

    // Go binds a UDP socket and maps ITS port, so the mapping refers to a socket that actually
    // exists for the length of the run; a mapping to a closed port tells the operator nothing about
    // whether traffic would arrive. The socket is held (not dropped) until the run ends.
    let local_sock =
        match tokio::net::UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)).await {
            Ok(s) => s,
            Err(e) => {
                log.log(format!("error binding local UDP socket: {e}"));
                return;
            }
        };
    let local_port = match local_sock.local_addr() {
        Ok(addr) => addr.port(),
        Err(e) => {
            log.log(format!("error reading local UDP port: {e}"));
            return;
        }
    };
    log.log(format!("local port: {local_port}"));

    let mut client = Client::new(gw, self_ip, local_port, *knobs, log.clone());
    let probe = match client.probe().await {
        Ok(res) => res,
        Err(e) => {
            log.log(format!("error in Probe: {e}"));
            return;
        }
    };
    log.log(format!("Probe: {probe}"));

    if !probe.any() {
        log.log("no portmapping services available");
        return;
    }

    match client.create_mapping(&probe).await {
        Ok(mapping) => {
            log.log(format!(
                "mapping: {} (via {}, good for {}s)",
                mapping.external,
                mapping.kind,
                mapping.lifetime.as_secs()
            ));
        }
        Err(e) => {
            log.log(format!("no mapping: {e}"));
        }
    }
    drop(local_sock);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// A logger collecting lines, so a run's transcript can be asserted on.
    fn collecting_logger() -> (Logger, Arc<Mutex<Vec<String>>>) {
        let lines: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = {
            let lines = Arc::clone(&lines);
            Arc::new(move |line: &str| lines.lock().unwrap().push(line.to_string()))
                as super::super::LogSink
        };
        (Logger::new(sink, false), lines)
    }

    #[test]
    fn parses_a_gateway_and_self_override() {
        assert_eq!(
            parse_gateway_and_self("192.168.1.1/192.168.1.42"),
            Ok((
                Ipv4Addr::new(192, 168, 1, 1),
                Ipv4Addr::new(192, 168, 1, 42)
            ))
        );
    }

    #[test]
    fn a_malformed_override_is_refused_rather_than_panicking() {
        // Go's handler calls netip.MustParseAddr here and PANICS on this input.
        assert_eq!(
            parse_gateway_and_self("bogus/192.168.1.42"),
            Err(GatewayAndSelfError::NotAnIpv4Address("bogus".to_string()))
        );
        assert_eq!(
            parse_gateway_and_self("192.168.1.1/nope"),
            Err(GatewayAndSelfError::NotAnIpv4Address("nope".to_string()))
        );
        assert_eq!(
            parse_gateway_and_self("192.168.1.1"),
            Err(GatewayAndSelfError::NotAPair("192.168.1.1".to_string()))
        );
        // An IPv6 pair is refused too: every protocol here maps IPv4.
        assert!(parse_gateway_and_self("fe80::1/fe80::2").is_err());
    }

    #[tokio::test]
    async fn an_unknown_type_refuses_the_run_before_touching_the_network() {
        let (log, lines) = collecting_logger();
        let opts = DebugPortmapOpts {
            ty: "upnpp".to_string(),
            ..DebugPortmapOpts::default()
        };
        let err = run(&opts, log).await.expect_err("a typo must not run");
        assert_eq!(err.to_string(), "unknown portmap debug type");
        assert!(
            lines.lock().unwrap().is_empty(),
            "a refused run must not probe anything: {:?}",
            lines.lock().unwrap()
        );
    }

    #[tokio::test]
    async fn a_run_against_a_gateway_that_answers_nothing_reports_no_services() {
        // The override points at a documentation address on a network that (by construction) has no
        // port-mapping service, so the run reaches the probe and reports the empty result rather
        // than hanging or erroring. This is the shape of a real "this café Wi-Fi offers nothing" run.
        let (log, lines) = collecting_logger();
        let opts = DebugPortmapOpts {
            duration: Duration::from_secs(2),
            gateway_and_self: Some((Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(192, 0, 2, 42))),
            ..DebugPortmapOpts::default()
        };
        run(&opts, log).await.expect("a known type must run");
        let lines = lines.lock().unwrap().clone();
        assert!(
            lines.iter().any(|l| l == "gw=192.0.2.1; self=192.0.2.42"),
            "the run must report the pair it used: {lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|l| l.starts_with("Probe: {PCP:false PMP:false UPnP:")),
            "an unanswered probe must be reported, not swallowed: {lines:?}"
        );
    }

    #[tokio::test]
    async fn the_duration_bounds_the_run() {
        // A 1 ms budget cannot even finish the 250 ms probe, so the run must be cut off and SAY so
        // rather than overrunning the caller's deadline.
        let (log, lines) = collecting_logger();
        let opts = DebugPortmapOpts {
            duration: Duration::from_millis(1),
            gateway_and_self: Some((Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(192, 0, 2, 42))),
            ..DebugPortmapOpts::default()
        };
        let started = std::time::Instant::now();
        run(&opts, log).await.expect("a known type must run");
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "the deadline must actually cut the run short"
        );
        assert!(
            lines
                .lock()
                .unwrap()
                .iter()
                .any(|l| l.contains("context deadline exceeded")),
            "a cut-off run must say it was cut off: {:?}",
            lines.lock().unwrap()
        );
    }
}
