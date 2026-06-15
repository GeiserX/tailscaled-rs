//! Read-only diagnostics and Taildrop file transfer, as free functions over a borrowed engine.
//!
//! `ip_report` / `whois` / `ping` / `file_cp` / `file_list` / `file_get` all take a
//! `&tailscale::Device` (never `Backend` `self`) so the LocalAPI server can run them **off the
//! backend lock**: it clones the engine handle via [`Backend::device_handle`](super::Backend::device_handle)
//! under a brief lock, drops the lock, and only calls these when the handle is `Some`. The
//! device-absent "node is not up" branch therefore lives at the dispatch arm, not here.
//!
//! [`Backend`](super::Backend) keeps thin `pub` shims (`Backend::ip_report` etc.) that delegate to
//! these free functions, so the `server.rs` dispatch call sites (`Backend::file_cp(&dev, ..)`, …)
//! are unchanged by the move.

use std::os::unix::fs::OpenOptionsExt;

use crate::localapi::{ConflictPolicy, FileGotReport, Response, WaitingFileReport, WhoisReport};

/// Report this node's own tailnet addresses (the `tnet ip` / Go `tailscale ip` path).
///
/// Read-only: queries the engine's cheap address accessors and never mutates prefs or bumps the
/// generation. Takes the engine handle as `dev` rather than reading `self.device`, so the LocalAPI
/// server can run it **off the backend lock** (clone the `Arc` via
/// [`device_handle`](super::Backend::device_handle), drop the lock, call here) — the device-absent
/// "node is not up" branch now lives at the caller, which only invokes this when it holds a handle.
///
/// Each family is best-effort: [`ipv4_addr`](tailscale::Device::ipv4_addr) /
/// [`ipv6_addr`](tailscale::Device::ipv6_addr) `Err` before the netmap assigns the address (and
/// IPv6 errs permanently in this v4-only fork), so we map `Err → None` and `Ok → Some(addr)`
/// rather than fail the whole call — a node mid-convergence (or v4-only) reports the addresses it
/// does have and `None` for the rest.
pub(super) async fn ip_report(dev: &tailscale::Device) -> Response {
    // Each family independently: an unassigned (or, for v6, disabled) address errs — that is a
    // normal "not yet / not in this fork" signal, so it yields `None`, not a failed call.
    let ipv4 = dev.ipv4_addr().await.ok().map(|a| a.to_string());
    let ipv6 = dev.ipv6_addr().await.ok().map(|a| a.to_string());
    Response::Ip { ipv4, ipv6 }
}

/// Snapshot the node's client metrics in Prometheus text format (the `tnet metrics` / Go `tailscale
/// metrics` path). Read-only: `Device::metrics` renders the process-global clientmetric registry to
/// text. Takes the engine handle so the LocalAPI server runs it off-lock (the device-absent branch
/// lives at the caller). Infallible at the engine layer — always a `Response::Metrics`.
pub(super) fn metrics(dev: &tailscale::Device) -> Response {
    Response::Metrics {
        text: dev.metrics(),
    }
}

/// Report Tailnet Lock (TKA) status (the `tnet lock status` / Go `tailscale lock status` read-only
/// path). Maps the engine's `Device::tka_status()` → `Option<TkaStatus>` to the wire
/// [`LockReport`](crate::localapi::LockReport): `Some` → enabled with control's authority head +
/// disablement flag; `None` → not enabled (no TKA info for this node). An engine error surfaces as a
/// clear [`Response::Error`]. Read-only — enforcement stays engine-side; this only reports status.
pub(super) async fn lock_status(dev: &tailscale::Device) -> Response {
    match dev.tka_status().await {
        Ok(Some(s)) => Response::Lock(crate::localapi::LockReport {
            enabled: true,
            head: s.head,
            disabled: s.disabled,
        }),
        Ok(None) => Response::Lock(crate::localapi::LockReport {
            enabled: false,
            ..Default::default()
        }),
        Err(e) => Response::Error {
            message: format!("tailnet lock status query failed: {e}"),
        },
    }
}

/// Initialize Tailnet Lock with this node as the sole initial trusted key (the `tnet lock init` / Go
/// `tailscale lock init` single-node path). Hex-decodes the operator-supplied disablement secret and
/// calls [`Device::tka_init`](tailscale::Device::tka_init), which builds + signs the genesis
/// checkpoint (trusting only this node, gated by the secret's Argon2i disablement value) and drives
/// control's two-phase init RPC. Submit-only (the lock reflects locally on the next verified sync),
/// reported as [`Response::Ok`]. A malformed-hex secret fails fast (before any RPC). The engine
/// returns `Unsupported` if the tailnet has other nodes needing (re)signing (multi-node init is a
/// deferred engine follow-up) or a lock already exists — surfaced as a clear [`Response::Error`]. The
/// secret is never logged.
pub(super) async fn lock_init(dev: &tailscale::Device, secret_hex: &str) -> Response {
    let secret = match decode_hex(secret_hex) {
        Some(bytes) => bytes,
        None => {
            return Response::Error {
                message: "invalid disablement secret: expected a hex-encoded value".to_string(),
            };
        }
    };
    match dev.tka_init(secret).await {
        Ok(()) => Response::Ok {
            message: "Tailnet Lock initialized with this node as the sole trusted key (applies on \
                      the next netmap sync; keep the disablement secret safe)"
                .to_string(),
        },
        Err(e) => Response::Error {
            message: format!("tailnet lock init failed: {e}"),
        },
    }
}

/// Co-sign a node key into Tailnet Lock (the `tnet lock sign` / Go `tailscale lock sign` path).
/// Parses the `nodekey:<hex>` string into the engine's [`NodePublicKey`](tailscale::keys::NodePublicKey)
/// and calls [`Device::tka_sign`](tailscale::Device::tka_sign), which submits the signature to control
/// over the TKA mutation RPC (this node must itself be trusted under the current authority). It does
/// NOT mutate the local authority — that advances on the next verified netmap sync — so success means
/// "submitted", which we report as a clear [`Response::Ok`]. A bad node-key string fails fast (before
/// any RPC); an engine/control error (no lock, untrusted signer, transient) surfaces as
/// [`Response::Error`].
pub(super) async fn lock_sign(dev: &tailscale::Device, node_key: &str) -> Response {
    let nk: tailscale::keys::NodePublicKey = match node_key.parse() {
        Ok(k) => k,
        Err(_) => {
            return Response::Error {
                message: format!(
                    "invalid node key {node_key:?}: expected the `nodekey:<hex>` form (as shown by \
                     `tnet status`/`whois`)"
                ),
            };
        }
    };
    match dev.tka_sign(&nk).await {
        Ok(()) => Response::Ok {
            message: "node key signed into Tailnet Lock (applies on the next netmap sync)"
                .to_string(),
        },
        Err(e) => Response::Error {
            message: format!("tailnet lock sign failed: {e}"),
        },
    }
}

/// Disable Tailnet Lock for the tailnet (the `tnet lock disable` / Go `tailscale lock disable` path).
/// Hex-decodes the operator-supplied disablement secret and calls
/// [`Device::tka_disable`](tailscale::Device::tka_disable), which presents it to control against the
/// current authority head. Submit-only (the disablement reflects locally on the next verified sync),
/// reported as [`Response::Ok`]. A malformed-hex secret fails fast (before any RPC); a control
/// rejection (invalid secret, no lock) surfaces as [`Response::Error`]. The secret is never logged —
/// only a generic error is surfaced on failure.
pub(super) async fn lock_disable(dev: &tailscale::Device, secret_hex: &str) -> Response {
    let secret = match decode_hex(secret_hex) {
        Some(bytes) => bytes,
        None => {
            return Response::Error {
                message: "invalid disablement secret: expected a hex-encoded value".to_string(),
            };
        }
    };
    match dev.tka_disable(secret).await {
        Ok(()) => Response::Ok {
            message: "Tailnet Lock disabled for the tailnet (applies on the next netmap sync)"
                .to_string(),
        },
        // Deliberately do NOT echo the secret (or the engine error's inner detail beyond its Display)
        // — `tka_disable`'s error is already coarse and secret-free.
        Err(e) => Response::Error {
            message: format!("tailnet lock disable failed: {e}"),
        },
    }
}

/// Decode a lowercase/uppercase hex string into bytes; `None` on any non-hex char or an odd length.
/// A tiny local helper so the crate takes no `hex` dependency for this one use (mirrors the
/// `hex_encode` on the CLI side).
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// Report the control-pushed MagicDNS configuration (the `tnet dns status` / Go `tailscale dns
/// status` read-only path). Maps the engine's `Device::dns_config()` → `Option<DnsConfig>` to the
/// wire [`DnsStatusReport`](crate::localapi::DnsStatusReport): resolver addresses are pre-rendered
/// to `addr:port` strings via [`udp_addr`](tailscale::DnsResolver::udp_addr) (so the wire DTO stays
/// plain strings and never has to name the engine's `ResolverTransport` enum), the split-DNS routes
/// map its values the same way, and extra records become `(name, addr_string)` pairs; the plain
/// `Vec<String>` fields
/// (search/cert/exit-node-filtered) and the `magic_dns` bool are copied through.
///
/// `Ok(None)` means no netmap has arrived yet (a freshly-up node) — we return a *default*
/// [`DnsStatusReport`] (MagicDNS off, every collection empty) so `dns status` renders cleanly rather
/// than erroring. An engine error surfaces as a clear [`Response::Error`]. Read-only — this only
/// reports the control-pushed config; it changes nothing.
pub(super) async fn dns_status(dev: &tailscale::Device) -> Response {
    match dev.dns_config().await {
        Ok(Some(cfg)) => Response::DnsStatus(crate::localapi::DnsStatusReport {
            magic_dns: cfg.magic_dns,
            search_domains: cfg.search_domains,
            resolvers: cfg
                .resolvers
                .iter()
                .map(|r| r.udp_addr().to_string())
                .collect(),
            routes: cfg
                .routes
                .iter()
                .map(|(suffix, resolvers)| {
                    (
                        suffix.clone(),
                        resolvers.iter().map(|r| r.udp_addr().to_string()).collect(),
                    )
                })
                .collect(),
            fallback_resolvers: cfg
                .fallback_resolvers
                .iter()
                .map(|r| r.udp_addr().to_string())
                .collect(),
            cert_domains: cfg.cert_domains,
            extra_records: cfg
                .extra_records
                .iter()
                .map(|e| (e.name.clone(), e.addr.to_string()))
                .collect(),
            exit_node_filtered_set: cfg.exit_node_filtered_set,
        }),
        // No netmap yet → an empty report renders cleanly (not an error).
        Ok(None) => Response::DnsStatus(crate::localapi::DnsStatusReport::default()),
        Err(e) => Response::Error {
            message: format!("dns config query failed: {e:?}"),
        },
    }
}

/// Resolve `name`/`qtype` through the node's MagicDNS path (the `tnet dns query` / Go `tailscale dns
/// query` path). Calls the engine's [`Device::query_dns`](tailscale::Device::query_dns), which answers
/// tailnet/MagicDNS names authoritatively and forwards the rest exactly as the node itself would,
/// returning the raw DNS response datagram + RCODE + the upstream resolvers consulted.
///
/// Projects the engine's `DnsQueryResult` into the wire [`DnsQueryReport`](crate::localapi::DnsQueryReport):
/// the resolver `SocketAddr`s are pre-rendered to `addr:port` strings (the wire DTO stays plain
/// strings), and the raw response bytes are hex-encoded (the wire stays JSON-clean; the CLI decodes
/// the fixed DNS header from the hex and renders the rest raw — this fork has no answer-record decoder,
/// the honest-omission boundary documented on `DnsQueryReport`). The queried `name`/`qtype` are echoed
/// back for the renderer. An engine error (e.g. the node is down / no live forwarder) surfaces as a
/// clear [`Response::Error`]. Read-only — resolving a name changes nothing.
pub(super) async fn dns_query(dev: &tailscale::Device, name: &str, qtype: u16) -> Response {
    match dev.query_dns(name, qtype).await {
        Ok(result) => Response::DnsQuery(crate::localapi::DnsQueryReport {
            name: name.to_string(),
            qtype,
            rcode: result.rcode,
            resolvers_consulted: result
                .resolvers_consulted
                .iter()
                .map(|a| a.to_string())
                .collect(),
            response_hex: hex_encode(&result.response),
        }),
        Err(e) => Response::Error {
            message: format!("dns query failed: {e:?}"),
        },
    }
}

/// Lowercase-hex-encode a byte slice (for carrying the raw DNS response datagram on the JSON wire).
/// A tiny local helper so the crate takes no `hex` dependency for this one use.
fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Provision (or fetch) a TLS cert+key for `domain` via the tailnet ACME flow (the `tnet cert` / Go
/// `tailscale cert <domain>` path). Calls the engine's `Device::cert_pair`, which issues against the
/// tailnet CA through the live control connection and returns `(cert_pem, key_pem)`.
///
/// **Fail-closed, two layers:**
/// 1. Built WITHOUT the `acme` cargo feature: `Device::cert_pair` does not exist, so this returns a
///    clear "built without acme" [`Response::Error`] (the daemon never fabricates a self-signed cert).
/// 2. WITH `acme`: any ACME/HTTP/validation failure surfaces as a clear error (the engine's
///    `cert_pair` is itself fail-closed — never a partial or self-signed pair).
///
/// `min_validity` is passed as `None` (Go's default: a freshly issued, full-lifetime cert). The key
/// PEM is sensitive: it is carried in [`Response::Cert`] and written `0600` by the CLI; it is never
/// logged here.
pub(super) async fn cert_pair(dev: &tailscale::Device, domain: &str) -> Response {
    #[cfg(feature = "acme")]
    {
        match dev.cert_pair(domain, None).await {
            Ok((cert_pem, key_pem)) => Response::Cert { cert_pem, key_pem },
            Err(e) => Response::Error {
                message: format!("cert issuance for {domain:?} failed: {e}"),
            },
        }
    }
    #[cfg(not(feature = "acme"))]
    {
        // Reference `dev`/`domain` so the non-acme build has no unused-variable warnings.
        let _ = (dev, domain);
        Response::Error {
            message: "this daemon was built without the `acme` feature; rebuild with \
                      `--features acme` to issue TLS certificates"
                .to_string(),
        }
    }
}

/// Report this node's network-conditions report (the `tnet netcheck` / Go `tailscale netcheck`
/// read-only path). Maps the engine's `Device::netcheck()` → `tailscale::NetcheckReport` to the wire
/// [`NetcheckReport`](crate::localapi::NetcheckReport): the preferred DERP region id is copied
/// through, and each per-region latency becomes a [`RegionLatencyView`](crate::localapi::RegionLatencyView)
/// with the `Duration` pre-rendered to milliseconds (so the wire DTO stays plain numbers and never
/// has to name the engine's `Duration`). The engine list is already latency-ascending, so it is
/// emitted in order.
///
/// Unlike [`dns_status`], `netcheck` returns the report **directly** (not an `Option`): the engine
/// defaults to an empty report (no preferred region, empty latency list) before the first
/// measurement, which renders cleanly. An engine error surfaces as a clear [`Response::Error`].
/// HONEST REDUCED SCOPE: this fork's net-report measures only DERP-region latency — Go's
/// UDP/IPv4/IPv6/`MappingVariesByDestIP`/PortMapping flags are not measured, and regions carry no
/// name — see [`NetcheckReport`](crate::localapi::NetcheckReport). Read-only — measures, mutates nothing.
pub(super) async fn netcheck(dev: &tailscale::Device) -> Response {
    match dev.netcheck().await {
        Ok(report) => Response::Netcheck(crate::localapi::NetcheckReport {
            preferred_derp: report.preferred_derp,
            region_latencies: report
                .region_latencies
                .iter()
                .map(|r| crate::localapi::RegionLatencyView {
                    region_id: r.region_id,
                    latency_ms: r.latency.as_secs_f64() * 1000.0,
                })
                .collect(),
        }),
        Err(e) => Response::Error {
            message: format!("netcheck failed: {e:?}"),
        },
    }
}

/// Suggest the best available exit node (the `tnet exit-node suggest` / Go `tailscale exit-node
/// suggest` → `LocalClient.SuggestExitNode` path). Maps the engine's `Device::suggest_exit_node()`:
/// `Ok(Some(s))` → [`Response::ExitNodeSuggestion`] carrying the node's stable id + display name (the
/// CLI prints it with a `--exit-node=<id>` hint); `Ok(None)` → `ExitNodeSuggestion(None)`, an **honest
/// empty result** (no eligible candidate — mirroring Go returning an empty response, NOT an error);
/// an engine error (e.g. no netcheck report yet → no measured preferred DERP region for the
/// latency ranking) → a clear [`Response::Error`]. Read-only — it computes a suggestion, mutates
/// nothing (engaging the node is a separate `set --exit-node`).
pub(super) async fn suggest_exit_node(dev: &tailscale::Device) -> Response {
    match dev.suggest_exit_node().await {
        Ok(Some(s)) => Response::ExitNodeSuggestion {
            suggestion: Some(crate::localapi::ExitNodeSuggestionView {
                id: s.id.0,
                name: s.name,
            }),
        },
        Ok(None) => Response::ExitNodeSuggestion { suggestion: None },
        Err(e) => Response::Error {
            message: format!("exit-node suggest failed: {e:?}"),
        },
    }
}

/// Force the engine to rebind its UDP sockets (the `tnet debug rebind` / Go `tailscale debug rebind`
/// path). A connectivity-recovery knob: it tears down and re-creates magicsock's underlying UDP
/// sockets, which can clear a wedged NAT binding or recover after a network-interface change without
/// a full node restart. A **write** (it mutates live datapath state) — the server gates it like
/// `down`/`logout`. Maps the engine's `Device::rebind()` to a [`Response::Ok`]; an engine error
/// surfaces as a clear [`Response::Error`]. Go pairs this with `restun` ([`re_stun`]) — the lighter
/// knob that re-probes STUN without swapping the socket.
pub(super) async fn rebind(dev: &tailscale::Device) -> Response {
    match dev.rebind().await {
        Ok(()) => Response::Ok {
            message: "rebind: re-created the engine's UDP sockets".to_string(),
        },
        Err(e) => Response::Error {
            message: format!("rebind failed: {e:?}"),
        },
    }
}

/// Force an immediate STUN re-probe / endpoint re-derivation **without** rebinding the socket (the
/// `tnet debug restun` / Go `tailscale debug restun` → magicsock `Conn.ReSTUN("debug")` path).
///
/// Strictly lighter than [`rebind`]: it keeps the existing UDP socket and its NAT mapping and only
/// re-runs the STUN sweep now (re-learning this node's reflexive/public address), instead of waiting
/// out the periodic (~23s, jittered) prober. Reach for it when this node's public endpoint may have
/// changed (e.g. a NAT rebinding) but the socket itself is still fine. A **write** (mutates live
/// datapath endpoint state) — the server gates it like `down`/`logout`. Maps the engine's
/// `Device::re_stun()` to a [`Response::Ok`]; an engine error surfaces as a clear [`Response::Error`].
/// Per the engine, a no-op when the underlay socket failed to bind at startup (DERP-only) or while no
/// peer is configured — that still reports success (the re-probe was issued; there was nothing to do).
pub(super) async fn re_stun(dev: &tailscale::Device) -> Response {
    match dev.re_stun().await {
        Ok(()) => Response::Ok {
            message: "restun: forced a STUN re-probe (socket unchanged)".to_string(),
        },
        Err(e) => Response::Error {
            message: format!("restun failed: {e:?}"),
        },
    }
}

/// Resolve a tailnet IP to the peer that owns it (the `tnet whois` / Go `tailscale whois` path).
///
/// Read-only: a netmap lookup that mutates nothing. Takes the engine handle as `dev` so the
/// LocalAPI server can run it off-lock (clone the `Arc` via [`device_handle`](super::Backend::device_handle),
/// drop the lock, call here); the device-absent "node is not up" branch now lives at the caller.
/// Still fail-closed on bad input (an unparseable `ip`, naming the offending value). The owning node's
/// display name + IPv4 are extracted via [`tailscale::StatusNode::from_node`] — the SAME mapping
/// [`status`](super::Backend::status) uses to render peers (`fqdn`-or-`hostname` name +
/// `tailnet_address.ipv4`), so the two diagnostic surfaces can never drift in how they name a node.
///
/// Maps the engine outcome to the wire [`WhoisReport`](crate::localapi::WhoisReport):
/// - `Ok(Some(w))` → `found: true` with the node name/IPv4, the owner `user` (always `None` in
///   this fork — the domain node model drops the login), and just the capability *names* (the
///   `(cap, args)` args are dropped — too verbose for a whois summary). The flow-scoped peer-cap
///   grants `cap_map` (Go `WhoIsResponse.CapMap`) are also surfaced verbatim — name → raw
///   (JSON-encoded) value strings, which the daemon never parses — distinct from the node-level
///   capability names.
/// - `Ok(None)` → `found: false` (the IP matched no known tailnet node), all fields defaulted.
/// - `Err(e)` → a clear [`Response::Error`] carrying the engine error.
pub(super) async fn whois(dev: &tailscale::Device, ip: &str) -> Response {
    // Parse first so a bad IP fails closed before the engine round-trip — naming the value. (The
    // device-absent "node is not up" branch now lives at the LocalAPI caller, which only reaches
    // here holding a device handle cloned off-lock; see `Backend::device_handle`.)
    let Ok(addr) = ip.parse::<std::net::IpAddr>() else {
        return Response::Error {
            message: format!("invalid IP {ip:?}"),
        };
    };
    // whois resolves by IP only (the engine ignores the port), so a 0 port is fine.
    let sock = std::net::SocketAddr::new(addr, 0);
    match dev.whois(sock).await {
        Ok(Some(w)) => {
            // Reuse `StatusNode::from_node` — the exact name+ipv4 derivation `status` renders
            // peers with — so whois and status agree on a node's identity by construction.
            let node = tailscale::StatusNode::from_node(&w.node);
            // Tags + key-expiry are read off the FULL `Node` (not the `StatusNode` projection): the
            // projection carries name/ipv4/liveness but NOT these two, so without this the daemon
            // would discard them — yet Go surfaces them (tags in `whois` text; key-expiry is a
            // superset this fork also exposes). Read before the `user`/`capabilities` moves below.
            // Expiry → strict RFC3339 (`YYYY-MM-DDTHH:MM:SS+00:00`) via the chrono `DateTime<Utc>`'s
            // inherent `to_rfc3339`, matching Go's `ipnstate`/`apitype` timestamps so a JSON consumer
            // can parse `KeyExpiry`/`LastSeen` (a `.to_string()` Display form — `… UTC`, space-
            // separated — is NOT RFC3339 and mis-parses).
            let tags = w.node.tags.clone();
            let node_key_expiry = w.node.node_key_expiry.map(|t| t.to_rfc3339());
            // Liveness comes off the StatusNode projection (already computed by `from_node`): the
            // same control-connected `online` signal + `last_seen` time that `status` renders per
            // peer. Capture into locals before `node.display_name` is moved below. `online` is a
            // `Copy` bool; `last_seen` → strict RFC3339 (Go-compatible), as above.
            let online = node.online;
            let last_seen = node.last_seen.map(|t| t.to_rfc3339());
            Response::Whois(WhoisReport {
                found: true,
                node_name: Some(node.display_name),
                node_ipv4: Some(node.ipv4.to_string()),
                user: w.user,
                // Keep just the capability names for the summary; drop the verbose args.
                capabilities: w.capabilities.into_iter().map(|(cap, _args)| cap).collect(),
                // Flow-scoped peer-cap grants (Go `WhoIsResponse.CapMap`): surfaced verbatim
                // (name → raw-JSON arg values), distinct from the node-level capability names above.
                cap_map: w.cap_map,
                tags,
                node_key_expiry,
                online,
                last_seen,
            })
        }
        // No tailnet node owns that IP — a clean negative, not an error.
        Ok(None) => Response::Whois(WhoisReport {
            found: false,
            ..Default::default()
        }),
        Err(e) => Response::Error {
            message: format!("whois failed: {e:?}"),
        },
    }
}

/// Ping a tailnet peer over the overlay and report the round-trip time (the `tnet ping` / Go
/// `tailscale ping` path).
///
/// Read-only in the prefs/lifecycle sense: it sends overlay echo traffic but mutates no state and
/// never bumps the generation. Takes the engine handle as `dev` so the LocalAPI server can run it
/// off-lock — important here because the caller-supplied per-attempt timeout (defaulting to 5s when
/// `timeout_ms` is `None`) would otherwise hold the backend lock for its whole duration. The
/// device-absent "node is not up" branch now lives at the caller. Still fail-closed on a bad `ip`
/// (naming the value).
///
/// `Ok(rtt)` → [`Response::Ping`] with the RTT in milliseconds (and the IP echoed for the CLI), plus
/// the direct underlay `endpoint` when one exists (so the CLI can render `via <endpoint>` for a
/// direct path vs `via DERP` for a relayed one, and `--until-direct` knows when to stop);
/// `Err(e)` → a clear [`Response::Error`] (e.g. an unreachable peer, an IPv6 destination in this
/// v4-only fork, or TUN mode where there is no application netstack to ping from).
pub(super) async fn ping(dev: &tailscale::Device, ip: &str, timeout_ms: Option<u64>) -> Response {
    // Parse first so a bad IP fails closed before the engine round-trip — naming the value. (The
    // device-absent "node is not up" branch now lives at the LocalAPI caller, which only reaches
    // here holding a device handle cloned off-lock; see `Backend::device_handle`.)
    let Ok(dst) = ip.parse::<std::net::IpAddr>() else {
        return Response::Error {
            message: format!("invalid IP {ip:?}"),
        };
    };
    let timeout = std::time::Duration::from_millis(timeout_ms.unwrap_or(5000));
    match dev.ping(dst, timeout).await {
        Ok(rtt) => {
            // Classify the path WITHOUT a second network round-trip. The ICMP ping above already
            // traversed the overlay, which is what nudges magicsock to attempt a direct disco
            // upgrade; `direct_path` then reports whether one is currently established as a cached
            // snapshot of the last disco probe (up to one probe interval stale — not a fresh ping).
            // `Some((endpoint, _rtt))` ⇒ direct (render `via endpoint`); `None`/`Err` ⇒ no direct
            // path ⇒ the overlay is DERP-relayed (Go prints `via DERP`). A classification failure is
            // non-fatal: the ping itself succeeded, so degrade to `None` (treated as relayed) rather
            // than turn a good pong into an error.
            //
            // FIDELITY NOTE: the returned `rtt_ms` is the netstack-ICMP RTT, but `endpoint` is the
            // cached disco snapshot — two different measurements. On a peer mid-upgrade the cached
            // snapshot can still read `None` for up to a probe interval after the ICMP pong arrives,
            // so `--until-direct` may overshoot Go (which sources both from one disco round-trip) by
            // a ping or two before it sees the direct path. It still converges. The exact-parity
            // alternative is to drive `dev.ping_disco(dst, timeout)` for both the RTT and the
            // endpoint from a single fresh disco probe (a ping backlog item).
            let endpoint = match dev.direct_path(dst).await {
                Ok(Some((addr, _rtt))) => Some(addr.to_string()),
                Ok(None) | Err(_) => None,
            };
            Response::Ping {
                rtt_ms: rtt.as_secs_f64() * 1000.0,
                ip: ip.to_string(),
                endpoint,
            }
        }
        // Bare cause only (no `ping <ip> failed:` prefix): the `tnet ping` CLI wraps this with its own
        // per-attempt `ping <seq>/<count> failed:` label, so prefixing here too would double it. A
        // non-CLI LocalAPI caller still gets the IP for context via the request it sent.
        Err(e) => Response::Error {
            message: format!("{e:?}"),
        },
    }
}

/// Send a local file to a tailnet peer via Taildrop (the `tnet file cp` / Go `tailscale file cp`
/// path). Streams the file over the encrypted overlay to the peer's peerAPI.
///
/// Takes the engine handle as `dev` so the LocalAPI server can run the (potentially multi-minute,
/// **un-deadlined**) transfer **off the backend lock** — clone the `Arc` via
/// [`device_handle`](super::Backend::device_handle), drop the lock, call here. Holding the lock across the
/// transfer would freeze every concurrent `status`/`up`/`down` for the file's whole duration (a
/// daemon-wide DoS); the device-absent "node is not up" branch now lives at the caller, which only
/// reaches here holding a handle. Still fail-closed on bad input (an unresolvable peer, an
/// unreadable or non-regular-file `path`, or a pathless `path`), each a clear [`Response::Error`]
/// naming the offending value.
///
/// ## Why the daemon opens `path` (same-host assumption)
///
/// The path is opened by the **daemon**, not the CLI — `tnet` and `tailnetd` run on the same host
/// as the same user (the LocalAPI write policy already requires root or the daemon's own UID; see
/// [`crate::auth`]), exactly as Go's `tailscale file cp` has `tailscaled` read the file. So a path
/// the operator can `cp` is one the daemon can open; there is no cross-host or privilege boundary
/// to marshal the bytes across. The send `name` peers see is the path's basename (like Go), so a
/// path with no final component (e.g. `/`) is rejected rather than sent under an empty name.
///
/// ## Path hardening (regular-file-only)
///
/// Because the daemon opens `path` as root, we first `symlink_metadata` it and **refuse anything
/// that is not a regular file** — a symlink (rejected as the link itself, never followed, since
/// `symlink_metadata` does not traverse the final component), device, FIFO, socket, or directory.
/// This is fail-closed defense-in-depth: it stops an infinite-stream device like `/dev/zero` from
/// turning a "send a file" into an unbounded transfer, and stops a symlink from redirecting the
/// root-held open at a file the operator did not name. The subsequent open also uses `O_NOFOLLOW`,
/// closing the stat→open TOCTOU window (a symlink swapped in after the stat fails the open with
/// `ELOOP` rather than being followed) — the same hardening [`debug_capture`] applies. Minimal by
/// design — not a full sandbox.
///
/// Peer resolution mirrors [`whois`]/[`ping`]: a `peer` that parses
/// as an [`IpAddr`](std::net::IpAddr) is looked up by tailnet IP, otherwise by MagicDNS name. The
/// engine derives the destination solely from the resolved peer's own node record, so a raw
/// address can never be targeted directly.
pub(super) async fn file_cp(
    dev: &tailscale::Device,
    path: &str,
    peer: &str,
    name_override: Option<&str>,
) -> Response {
    // Resolve the peer: a bare IP goes by tailnet-IP lookup, anything else by MagicDNS name —
    // the same IP-vs-name split the other peer-addressed commands use.
    let resolved = match peer.parse::<std::net::IpAddr>() {
        Ok(addr) => dev.peer_by_tailnet_ip(addr).await,
        Err(_) => dev.peer_by_name(peer).await,
    };
    let peer_node = match resolved {
        Ok(Some(node)) => node,
        Ok(None) => {
            return Response::Error {
                message: format!("no tailnet peer matches {peer:?}"),
            };
        }
        Err(e) => {
            return Response::Error {
                message: format!("resolve peer {peer:?} failed: {e:?}"),
            };
        }
    };
    // The send name: Go's `--name` override when given, else the path's final component (basename),
    // like Go's `file cp`. A `--name` is itself validated to a single safe component below; a path
    // with no basename (e.g. `/`) and no override has nothing meaningful to name the transfer —
    // reject it.
    let name = match name_override {
        Some(n) => n.to_string(),
        None => {
            let Some(base) = std::path::Path::new(path)
                .file_name()
                .and_then(|n| n.to_str())
                .map(str::to_string)
            else {
                return Response::Error {
                    message: format!("cannot derive a file name from path {path:?}"),
                };
            };
            base
        }
    };
    // The send name must be a single safe component regardless of source (see [`cp_send_name_ok`]).
    if !cp_send_name_ok(&name) {
        return Response::Error {
            message: format!("invalid send name {name:?}: must be a bare file name"),
        };
    }
    // Path hardening (see method doc): the daemon opens `path` as root, so first stat it (via
    // `taildrop_source_ok`, which `symlink_metadata`s WITHOUT following a final-component symlink)
    // and refuse anything that is not a regular file — a symlink, device (e.g. `/dev/zero`, an
    // infinite stream), FIFO, socket, directory, or a missing/unreadable path. Done BEFORE the open
    // so a non-regular target is never opened. This predicate is the stat half; the `O_NOFOLLOW` open
    // below is the TOCTOU-closing second half. The same check is unit-tested directly on the predicate.
    if let Err(message) = taildrop_source_ok(path).await {
        return Response::Error { message };
    }
    // The daemon opens the path (same-host/same-user; see the method doc). A read error here
    // (missing/unreadable file) fails closed, naming the path. `O_NOFOLLOW` closes the stat→open
    // TOCTOU window: the `symlink_metadata` check above already refused an existing symlink, but a
    // symlink swapped in AFTER the stat (the daemon may run as root) would otherwise be followed and
    // its target's contents sent — with O_NOFOLLOW the open fails (ELOOP) instead, so we never read
    // through a planted link. Matches `debug_capture`'s open hardening.
    let file = match tokio::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .await
    {
        Ok(f) => f,
        Err(e) => {
            return Response::Error {
                message: format!("cannot read {path}: {e}"),
            };
        }
    };
    let content_length = match file.metadata().await {
        Ok(m) => m.len(),
        Err(e) => {
            return Response::Error {
                message: format!("cannot stat {path}: {e}"),
            };
        }
    };
    match dev.send_file(&peer_node, &name, content_length, file).await {
        Ok(()) => Response::Ok {
            message: format!("sent {name} ({content_length} bytes) to {peer}"),
        },
        Err(e) => Response::Error {
            message: format!("taildrop send failed: {e:?}"),
        },
    }
}

/// Whether a Taildrop SEND name (`--name` override or a derived basename) is a safe single file-name
/// component. A name carrying a path separator / `.` / `..` / NUL would let the sender dictate a
/// traversal-shaped name the receiver might mishandle — a name is a file name, not a path. The
/// receiver's own engine re-validates, but [`file_cp`] refuses it here too (defense-in-depth,
/// fail-closed). Pure → unit-testable.
fn cp_send_name_ok(name: &str) -> bool {
    !(name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0'))
}

/// List the Taildrop files waiting in this node's receive directory (the `tnet file list` verb).
///
/// Fork-specific: Go v1.100.0 has no inbox-listing verb — bare `tailscale file get` errors, and
/// `file get <dir>` drains the inbox into a directory. This build splits discovery (`list`) from a
/// per-file `get <name> <dest>`; the directory-draining Go model is tracked as a follow-up.
///
/// Read-only. Synchronous because the engine's
/// [`taildrop_waiting_files`](tailscale::Device::taildrop_waiting_files) is a non-blocking store
/// read, not an actor round-trip — so this is **not** part of the lock-across-await DoS the other
/// engine calls have; it would be safe under the lock. It still takes the engine handle as `dev`
/// (rather than reading `self.device`) purely for shape symmetry with the other Taildrop/diagnostic
/// methods, so the LocalAPI dispatch arms are uniform (clone the handle, drop the lock, call). The
/// device-absent "node is not up" branch lives at the caller. When the receive directory is unset
/// (`prefs.taildrop_dir` = `None`), the engine returns an **empty list, not an error** — so an empty
/// `Files` reply simply means "receiving is off, or nothing is waiting", never a failure.
pub(super) fn file_list(dev: &tailscale::Device) -> Response {
    match dev.taildrop_waiting_files() {
        Ok(waiting) => {
            let files = waiting
                .into_iter()
                .map(|w| WaitingFileReport {
                    name: w.name,
                    size: w.size,
                })
                .collect();
            Response::Files { files }
        }
        Err(e) => Response::Error {
            message: format!("list taildrop files failed: {e:?}"),
        },
    }
}

/// List the tailnet peers this node can Taildrop a file *to* (the `tnet file cp --targets` / Go
/// `tailscale file cp --targets` / `file-targets` LocalAPI path).
///
/// Read-only: a thin projection of the engine's [`Device::file_targets`](tailscale::Device::file_targets),
/// which already applies Go's full eligibility filter — a peer qualifies when it advertises a
/// reachable IPv4 peerAPI **and** is either owned by the same user OR carries the file-sharing-target
/// capability, and the whole list is gated on this node holding the file-sharing capability (empty,
/// not an error, when control has not granted it). The engine returns the peers sorted by MagicDNS
/// name, so this preserves that order. Each [`FileTarget`] is mapped to the wire
/// [`FileTargetReport`]: the peer's primary tailnet IPv4, its display name
/// ([`fqdn_opt`](tailscale::Node::fqdn_opt) falling back to the bare hostname — the analogue of Go's
/// `Node.ComputedName`), and its tri-state online status (preserved, never collapsed to `false`).
///
/// Takes the engine handle as `dev` so the LocalAPI server runs it off-lock like the other
/// diagnostics; the device-absent "node is not up" branch lives at the caller.
pub(super) async fn file_targets(dev: &tailscale::Device) -> Response {
    match dev.file_targets().await {
        Ok(targets) => {
            let targets = targets
                .into_iter()
                .map(|t| {
                    let node = t.node;
                    crate::localapi::FileTargetReport {
                        // Primary tailnet IPv4 (Go prints `Node.Addresses[0]`).
                        ip: node.tailnet_address.ipv4.addr().to_string(),
                        // Display name: MagicDNS FQDN when known, else the bare hostname (Go
                        // `Node.ComputedName`). `false` = no trailing dot, matching the status view.
                        name: node
                            .fqdn_opt(false)
                            .unwrap_or_else(|| node.hostname.clone()),
                        // Tri-state online (Go distinguishes online/offline/unknown; do not collapse).
                        online: node.online,
                    }
                })
                .collect();
            Response::FileTargets { targets }
        }
        Err(e) => Response::Error {
            message: format!("listing file targets failed: {e:?}"),
        },
    }
}

/// Fetch a waiting Taildrop file by name, writing it to `dest` (the `tnet file get <name>` verb).
///
/// Fork-specific shape: Go's `tailscale file get <target-directory>` drains the whole inbox into a
/// directory with a `--conflict` policy (default: skip/refuse-overwrite). This per-name fetch instead
/// overwrites `dest`; aligning with Go's directory model + conflict policy is tracked as a follow-up
/// (`bd` `tsd-file-model`).
///
/// Takes the engine handle as `dev` so the LocalAPI server can run it **off the backend lock**
/// (clone the `Arc` via [`device_handle`](super::Backend::device_handle), drop the lock, call here) —
/// the spawn_blocking copy below could be large, and holding the lock across it would freeze every
/// concurrent `status`/`up`/`down`. The device-absent "node is not up" branch now lives at the
/// caller, which only reaches here holding a handle. Still fail-closed on a name that matches no
/// waiting file (naming it) and on a `dest` we must not clobber (see below). The engine returns a
/// plain [`std::fs::File`] handle for the received file; we copy it to `dest` inside
/// [`spawn_blocking`](tokio::task::spawn_blocking) so the synchronous [`std::io::copy`] never
/// stalls the async runtime's worker threads (even though a local file copy is fast).
///
/// ## Dest hardening (no clobber of / no follow into a non-regular file)
///
/// Because the daemon writes `dest` as root, we first `symlink_metadata` it (which does NOT follow
/// a final-component symlink) and, **if it already exists and is not a regular file** — a symlink,
/// device, FIFO, socket, or directory — **refuse** rather than write. This is fail-closed
/// defense-in-depth: it stops a fetch from following a symlink planted at `dest` to overwrite a
/// file the operator did not name, and from writing through a device/dir. A non-existent `dest`
/// (the normal case) passes the check and is created by the copy. The create also uses `O_NOFOLLOW`,
/// closing the stat→create TOCTOU window (a symlink swapped in after the stat fails the open with
/// `ELOOP` rather than being followed) — the same hardening [`debug_capture`] applies. Minimal by
/// design — not a full sandbox.
///
/// With `delete_after` set (the Go default), the received file is removed from the receive
/// directory after a successful copy. A delete failure is logged as a warning but does **not**
/// fail the call — the file was already retrieved to `dest`, which is the operation's success
/// condition; a stale leftover in the receive dir is a lesser problem than reporting a spurious
/// failure for a fetch that did succeed.
pub(super) async fn file_get(
    dev: &tailscale::Device,
    name: &str,
    dest: &str,
    delete_after: bool,
) -> Response {
    // Open the waiting file in the receive store (path-traversal-validated by the engine). A
    // missing/invalid name fails closed, naming it.
    let (mut src, _size) = match dev.taildrop_open_file(name) {
        Ok(pair) => pair,
        Err(e) => {
            return Response::Error {
                message: format!("no waiting file {name:?}: {e:?}"),
            };
        }
    };
    // Dest hardening (see method doc): `taildrop_dest_ok` `symlink_metadata`s `dest` WITHOUT
    // following a final-component symlink, so an existing symlink/device/FIFO/socket/dir is refused
    // rather than followed or clobbered; a `NotFound` is the normal case (we are about to create the
    // file). This predicate is the stat half; the `O_NOFOLLOW` create below is the TOCTOU-closing
    // second half. The same check is unit-tested directly on the predicate.
    if let Err(message) = taildrop_dest_ok(dest).await {
        return Response::Error { message };
    }
    // Copy off the async runtime: `std::io::copy` over `std::fs` handles is blocking, so do it on
    // a blocking thread rather than stall an async worker. The `dest` string is moved in. The create
    // uses `O_NOFOLLOW` to close the stat→create TOCTOU window: the `symlink_metadata` check above
    // already refused an existing symlink, but one swapped in AFTER the stat (the daemon may run as
    // root) would otherwise be followed and the received file written through it to an arbitrary
    // target — with O_NOFOLLOW the open fails (ELOOP) instead. Matches `debug_capture`'s open.
    let dest_owned = dest.to_string();
    let copy_result = tokio::task::spawn_blocking(move || {
        let mut out = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&dest_owned)?;
        std::io::copy(&mut src, &mut out)?;
        Ok::<(), std::io::Error>(())
    })
    .await;
    match copy_result {
        // The blocking task ran and the copy succeeded.
        Ok(Ok(())) => {}
        // The copy itself errored (create/write/read failure) — fail closed, naming dest.
        Ok(Err(e)) => {
            return Response::Error {
                message: format!("cannot write {dest}: {e}"),
            };
        }
        // The blocking task panicked or was cancelled — surface it rather than claim success.
        Err(e) => {
            return Response::Error {
                message: format!("taildrop fetch task failed: {e}"),
            };
        }
    }
    // The fetch succeeded. Optionally consume the inbound file; a delete failure is non-fatal
    // (the file is already saved to `dest`) — warn and still report success.
    if delete_after && let Err(e) = dev.taildrop_delete_file(name) {
        tracing::warn!(
            file = name,
            error = ?e,
            "diag: taildrop file fetched to dest but could not be deleted from the receive directory"
        );
    }
    Response::Ok {
        message: format!("saved {name} to {dest}"),
    }
}

/// Drain the **entire** Taildrop inbox into `dir`, applying `conflict` per file — the faithful
/// analogue of Go's `tailscale file get <target-directory>` (`runFileGetOneBatch` in
/// `cmd/tailscale/cli/file.go`). Returns [`Response::FilesGot`] with one [`FileGotReport`] per
/// attempted file (in inbox order) so the CLI can render Go-style lines and decide its exit code.
///
/// The special `dir == "/dev/null"` **wipes** the inbox (delete every waiting file, write nothing) —
/// Go's `wipeInbox`. Otherwise `dir` must already exist and be a directory (validated here, matching
/// Go's `os.Stat`+`IsDir`); a missing/!dir target is a single fail-closed [`Response::Error`].
///
/// Per file (Go's loop): receive `<dir>/<name>` under the conflict policy → set the quarantine
/// attribute → on success remove it from the inbox (so a re-drain does not re-fetch it). A file that
/// fails to receive is **left in the inbox** and recorded with an `error`; the drain continues to the
/// next file (one bad file never blocks the rest). Like Go we stop early if errors pile up past a
/// sanity bound (a sign everything is broken — e.g. an unwritable target dir).
///
/// Takes the engine handle as `dev` so the LocalAPI server runs it **off the backend lock** (the
/// copies can be large); the device-absent branch lives at the caller. Each file's blocking copy
/// runs on [`spawn_blocking`](tokio::task::spawn_blocking), and the create uses `O_EXCL`/`O_NOFOLLOW`
/// so the daemon (often root) never writes *through* a planted symlink or clobbers under `skip`.
pub(super) async fn file_get_dir(
    dev: &tailscale::Device,
    dir: &str,
    conflict: ConflictPolicy,
) -> Response {
    // `/dev/null` → wipe the inbox (Go `wipeInbox`): delete every waiting file, write nothing.
    if dir == "/dev/null" {
        return wipe_inbox(dev);
    }

    // The target must already exist and be a directory (Go `os.Stat`+`IsDir`). Fail closed otherwise —
    // a typo'd or not-yet-created dir must not silently no-op.
    match tokio::fs::symlink_metadata(dir).await {
        Ok(meta) if meta.is_dir() => {}
        Ok(_) => {
            return Response::Error {
                message: format!("{dir:?} is not a directory"),
            };
        }
        Err(e) => {
            return Response::Error {
                message: format!("{dir:?} is not a directory: {e}"),
            };
        }
    }

    let waiting = match dev.taildrop_waiting_files() {
        Ok(w) => w,
        Err(e) => {
            return Response::Error {
                message: format!("list taildrop files failed: {e:?}"),
            };
        }
    };

    let mut results: Vec<FileGotReport> = Vec::with_capacity(waiting.len());
    let mut error_count = 0usize;
    for wf in waiting {
        // Sanity bound mirroring Go's `len(errs) > 100` batch abort: if this many files have already
        // failed, something systemic is wrong (unwritable dir, full disk) — stop rather than churn
        // through the whole inbox failing every one.
        if error_count > 100 {
            results.push(FileGotReport {
                name: wf.name.clone(),
                error: Some("too many errors draining the inbox; stopping".to_string()),
                ..Default::default()
            });
            break;
        }
        match receive_one(dev, dir, &wf.name, conflict).await {
            // Copied to disk AND removed from the inbox — a clean success.
            ReceiveOutcome::Received { written, size } => {
                results.push(FileGotReport {
                    name: wf.name,
                    size,
                    written: Some(written),
                    error: None,
                });
            }
            // Copied to disk but the inbox delete failed — Go-faithfully an error (a re-drain would
            // re-fetch it forever), but carry `written` so the operator still sees where it landed.
            ReceiveOutcome::NotConsumed {
                written,
                size,
                reason,
            } => {
                error_count += 1;
                results.push(FileGotReport {
                    name: wf.name,
                    size,
                    written: Some(written),
                    error: Some(reason),
                });
            }
            // Could not copy at all — left in the inbox.
            ReceiveOutcome::Failed(reason) => {
                error_count += 1;
                results.push(FileGotReport {
                    name: wf.name,
                    size: 0,
                    written: None,
                    error: Some(reason),
                });
            }
        }
    }

    Response::FilesGot { results }
}

/// Wipe the Taildrop inbox without writing anything (Go `wipeInbox`, the `/dev/null` target). Each
/// deleted file is reported as a zero-byte success with `written: Some("/dev/null")` so the CLI can
/// show what was discarded; a delete failure is recorded as that file's error.
///
/// DELIBERATE DEVIATION from Go: Go's `wipeInbox` returns on the FIRST delete error (fail-fast),
/// stopping the wipe. This instead attempts EVERY file and reports per-file outcomes (report-all),
/// because the `FilesGot` model already gives the operator a full picture and "delete one file
/// failed" should not leave the rest of the inbox un-wiped. The CLI still exits non-zero if any
/// delete failed, so a script sees the failure either way.
fn wipe_inbox(dev: &tailscale::Device) -> Response {
    let waiting = match dev.taildrop_waiting_files() {
        Ok(w) => w,
        Err(e) => {
            return Response::Error {
                message: format!("list taildrop files failed: {e:?}"),
            };
        }
    };
    let results = waiting
        .into_iter()
        .map(|wf| match dev.taildrop_delete_file(&wf.name) {
            Ok(()) => FileGotReport {
                name: wf.name,
                size: 0,
                written: Some("/dev/null".to_string()),
                error: None,
            },
            Err(e) => FileGotReport {
                name: wf.name,
                size: 0,
                written: None,
                error: Some(format!("delete failed: {e:?}")),
            },
        })
        .collect();
    Response::FilesGot { results }
}

/// The outcome of [`receive_one`] for a single inbox file, modelling Go's three end-states so the
/// drain loop can report each faithfully:
/// - `Received { written, size }` — copied to disk AND removed from the inbox. A clean success.
/// - `NotConsumed { written, size, reason }` — copied to disk but the inbox delete FAILED. Go treats
///   this as an error (`deleted` is not incremented and a re-drain would re-fetch the file forever —
///   "persistently stuck files are basically an error"), so the loop records it as an error WHILE
///   still surfacing where the bytes landed.
/// - `Failed(reason)` — could not even copy the file; it is left in the inbox. An error.
enum ReceiveOutcome {
    Received {
        written: String,
        size: u64,
    },
    NotConsumed {
        written: String,
        size: u64,
        reason: String,
    },
    Failed(String),
}

/// Receive ONE inbox file `name` into `dir` under `conflict`. Factored out of the drain loop so the
/// per-file logic (open inbox file → resolve the target path under the conflict policy → copy
/// off-runtime → quarantine → delete-from-inbox) reads linearly. Never returns `Err`: every failure
/// mode maps to a [`ReceiveOutcome`] variant the loop turns into a [`FileGotReport`].
async fn receive_one(
    dev: &tailscale::Device,
    dir: &str,
    name: &str,
    conflict: ConflictPolicy,
) -> ReceiveOutcome {
    // Open the waiting file in the receive store (path-traversal-validated by the engine). The
    // engine reports a size here, but we report the bytes `io::copy` actually wrote below (the
    // ground truth), so the open's size is unused.
    let (mut src, _size) = match dev.taildrop_open_file(name) {
        Ok(pair) => pair,
        Err(e) => return ReceiveOutcome::Failed(format!("opening inbox file {name:?}: {e:?}")),
    };

    // Resolve the on-disk target under the conflict policy and open it. `skip` refuses an existing
    // target (leaving the inbox file); `overwrite` removes-then-exclusive-creates (symlink-safe);
    // `rename` finds the next free `name (N).ext`. Runs on a blocking thread with the copy.
    //
    // QUARANTINE BEFORE BYTES (matches Go's `receiveFile`, which calls `quarantine.SetOnFile` on the
    // open handle BEFORE `io.Copy`): we set the quarantine attribute on the freshly-created, still-
    // EMPTY target before copying any bytes, so the file never exists on disk with content but
    // without the "untrusted/downloaded" marker — closing the window where a crash mid-copy would
    // leave un-quarantined bytes. The quarantine is best-effort (a failure is non-fatal — the marker
    // is defense-in-depth, not a correctness gate), so we capture whether it succeeded and warn after
    // the copy rather than aborting the receive.
    let dir_owned = dir.to_string();
    let name_owned = name.to_string();
    let copy_result =
        tokio::task::spawn_blocking(move || -> std::io::Result<(String, u64, Option<String>)> {
            let (mut out, written_path) =
                open_target_under_policy(&dir_owned, &name_owned, conflict)?;
            // Mark untrusted on the empty file, before any bytes land.
            let quarantine_err = set_quarantine(&written_path).err().map(|e| e.to_string());
            let n = std::io::copy(&mut src, &mut out)?;
            Ok((written_path, n, quarantine_err))
        })
        .await;

    let (written_path, copied, quarantine_err) = match copy_result {
        Ok(Ok(triple)) => triple,
        Ok(Err(e)) => return ReceiveOutcome::Failed(humanize_write_err(dir, name, conflict, &e)),
        Err(e) => return ReceiveOutcome::Failed(format!("receive task failed: {e}")),
    };

    // The quarantine attribute (defense-in-depth: mark the received file untrusted, matching Go's
    // `quarantine.SetOnFile`) is applied inside the blocking copy above, BEFORE the bytes. A failure
    // is non-fatal — the bytes are already written — so warn and still count the file as received.
    if let Some(e) = quarantine_err {
        tracing::warn!(
            file = name,
            path = %written_path,
            error = %e,
            "diag: taildrop file written but quarantine attribute could not be set"
        );
    }

    // Received → remove from the inbox so a re-drain does not re-fetch it (Go deletes after a
    // successful receive, counting `deleted++` only on a successful delete). A delete FAILURE is
    // Go-faithfully an ERROR: the bytes are on disk, but the file is still in the inbox, so the next
    // drain would re-fetch it indefinitely ("persistently stuck files are basically an error"). We
    // surface it as `NotConsumed` — carrying `written` so the operator still sees where it landed,
    // but flagged as an error so the CLI exits non-zero.
    if let Err(e) = dev.taildrop_delete_file(name) {
        tracing::warn!(
            file = name,
            error = ?e,
            "diag: taildrop file received but could not be deleted from the inbox (will re-fetch)"
        );
        return ReceiveOutcome::NotConsumed {
            written: written_path,
            size: copied,
            reason: format!("saved but could not be removed from the inbox: {e:?}"),
        };
    }
    ReceiveOutcome::Received {
        written: written_path,
        size: copied,
    }
}

/// Map a raw write error to a Go-faithful, policy-aware message. Under `skip` an `AlreadyExists`
/// (the `O_EXCL` create hitting an existing file) becomes Go's "refusing to overwrite" wording; other
/// errors are reported with the target for context.
fn humanize_write_err(
    dir: &str,
    name: &str,
    conflict: ConflictPolicy,
    e: &std::io::Error,
) -> String {
    let target = std::path::Path::new(dir).join(name);
    let target = target.display();
    if conflict == ConflictPolicy::Skip && e.kind() == std::io::ErrorKind::AlreadyExists {
        format!("refusing to overwrite {target}: file already exists (left in inbox)")
    } else {
        format!("failed to write {target}: {e}")
    }
}

/// Open the on-disk target for an incoming file `base` in `dir` under `conflict`, returning the open
/// file + the path it will be written to. The analogue of Go's `openFileOrSubstitute`:
///
/// - [`Skip`](ConflictPolicy::Skip): `O_CREATE|O_EXCL|O_NOFOLLOW` at `<dir>/<base>` — an existing
///   file makes the create fail `AlreadyExists` (surfaced as "refusing to overwrite"), so we never
///   clobber.
/// - [`Overwrite`](ConflictPolicy::Overwrite): `remove` the target FIRST (best-effort; ignore
///   `NotFound`), then the same exclusive create. Removing first means we never open-truncate a file
///   an attacker symlinked at `<base>` — the `remove` breaks the link and the exclusive create makes
///   a fresh regular file (Go does exactly this, with the same stated rationale).
/// - [`Rename`](ConflictPolicy::Rename): the plain `<base>` first, then `base (1).ext`, `base (2).ext`
///   … via exclusive create, up to a bounded number of attempts (Chrome-Downloads style).
///
/// All creates use `O_NOFOLLOW` so a symlink at the final component fails the open (`ELOOP`) rather
/// than being followed — the root daemon never writes through a planted link. Synchronous (called
/// from inside `spawn_blocking`).
fn open_target_under_policy(
    dir: &str,
    base: &str,
    conflict: ConflictPolicy,
) -> std::io::Result<(std::fs::File, String)> {
    use std::os::unix::fs::OpenOptionsExt;

    // DEFENSE-IN-DEPTH: reject anything that is not a bare leaf BEFORE joining it onto `dir`. The
    // engine's `validate_base_name` already guarantees inbox names are single components (no `/`,
    // `\`, NUL, `.`, `..`), so this is unreachable today — but it makes this function self-defending
    // rather than relying on an invariant enforced in another crate: a `base` with an embedded
    // separator would otherwise let `Path::join` escape `dir`. Cheap, and the join below is only
    // sound given it. (The `O_NOFOLLOW` create still blocks a symlink write either way.)
    if base.is_empty()
        || base == "."
        || base == ".."
        || base.contains('/')
        || base.contains('\\')
        || base.contains('\0')
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("refusing unsafe taildrop file name {base:?}"),
        ));
    }

    let excl_create = |path: &std::path::Path| -> std::io::Result<std::fs::File> {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true) // O_CREAT|O_EXCL
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
    };

    let target = std::path::Path::new(dir).join(base);
    match conflict {
        ConflictPolicy::Skip => {
            let f = excl_create(&target)?;
            Ok((f, target.to_string_lossy().into_owned()))
        }
        ConflictPolicy::Overwrite => {
            // Remove first so we never write through a symlink planted at the target name; ignore a
            // NotFound (the normal no-conflict case), propagate any other remove error.
            match std::fs::remove_file(&target) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
            let f = excl_create(&target)?;
            Ok((f, target.to_string_lossy().into_owned()))
        }
        ConflictPolicy::Rename => {
            // Try the plain name, then numbered variants. Bounded like Go (it gives up after 100).
            match excl_create(&target) {
                Ok(f) => return Ok((f, target.to_string_lossy().into_owned())),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
            for i in 1..MAX_RENAME_ATTEMPTS {
                let candidate = std::path::Path::new(dir).join(numbered_file_name(base, i));
                match excl_create(&candidate) {
                    Ok(f) => return Ok((f, candidate.to_string_lossy().into_owned())),
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(e) => return Err(e),
                }
            }
            Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!(
                    "could not find a free numbered name for {base:?} after {MAX_RENAME_ATTEMPTS} attempts"
                ),
            ))
        }
    }
}

/// Upper bound on `rename`-policy numbering attempts (Go's `maxAttempts = 100`).
const MAX_RENAME_ATTEMPTS: u32 = 100;

/// Build the Chrome-Downloads-style numbered variant of a base file name: `name (i).ext`, splitting
/// on the FINAL extension (Go's `numberedFileName`: `TrimSuffix(name, ext) + " (i)" + ext`). A name
/// with no `.` just gets ` (i)` appended. Pure → unit-testable.
fn numbered_file_name(base: &str, i: u32) -> String {
    // Match Go's `path.Ext` EXACTLY: it scans back to the LAST '.' in the final path element and
    // returns the suffix from there — with NO special case for a leading dot. So `path.Ext(".bashrc")`
    // is `".bashrc"` (the whole name is the extension; NOT `""` as `os.path.splitext` would give),
    // hence Go's `numberedFileName(".bashrc", 1)` is `" (1).bashrc"` (empty stem + a leading space).
    // We reproduce that verbatim — `rfind('.')` with no `idx > 0` filter. `base` is a validated single
    // path element (the inbox name); `.`/`..` cannot reach here (engine-rejected + the leaf guard in
    // `open_target_under_policy`), so the only leading-dot inputs are real dotfiles like `.bashrc`.
    match base.rfind('.') {
        Some(idx) => {
            let (stem, ext) = base.split_at(idx); // ext includes the leading '.'
            format!("{stem} ({i}){ext}")
        }
        None => format!("{base} ({i})"),
    }
}

/// Set the platform "downloaded from the network, treat as untrusted" quarantine marker on a freshly
/// received Taildrop file (Go's `quarantine.SetOnFile`). Best-effort defense-in-depth; the caller
/// treats a failure as non-fatal (the file is already written).
///
/// - macOS: the `com.apple.quarantine` extended attribute (Gatekeeper reads it). The value format is
///   `<flags>;<timestamp-hex>;<agent>;<uuid>`; we write a minimal well-formed marker (flags `0081` =
///   "quarantined, not yet approved"), with no timestamp/UUID — Gatekeeper only requires the attr to
///   be present to treat the file as quarantined.
/// - Linux/other: there is no OS quarantine concept; this is a no-op success (Go also only sets it on
///   platforms that support it).
#[cfg(target_os = "macos")]
fn set_quarantine(path: &str) -> std::io::Result<()> {
    // `0081` = QTN_FLAG_DOWNLOAD(0x01) | QTN_FLAG_QUARANTINE(0x80)? — Gatekeeper treats any present
    // value as quarantined; we use a minimal marker naming the agent. The semicolons are required
    // field separators even when the timestamp/UUID are empty.
    let value = b"0081;00000000;tailnetd;";
    let c_path = std::ffi::CString::new(path)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has NUL byte"))?;
    let name = c"com.apple.quarantine";
    // SAFETY: `setxattr` reads `c_path`/`name` as NUL-terminated C strings (both valid for the call)
    // and `value`/len as a byte buffer; all are live for the duration. No aliasing or lifetime issue.
    let rc = unsafe {
        libc::setxattr(
            c_path.as_ptr(),
            name.as_ptr(),
            value.as_ptr() as *const libc::c_void,
            value.len(),
            0,
            0,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// No OS quarantine concept off macOS — a no-op success (matches Go setting it only where supported).
#[cfg(not(target_os = "macos"))]
fn set_quarantine(_path: &str) -> std::io::Result<()> {
    Ok(())
}

/// Validate a `debug capture` destination path before the daemon (running as root) creates it:
/// `Ok(())` if the path is missing (the normal fresh-capture case) or an existing **regular file**
/// (overwritten); `Err(reason)` if it EXISTS as anything else — a symlink (refused as the link
/// itself, never followed, since `symlink_metadata` does not traverse the final component), a device,
/// FIFO, socket, or directory. This stops a planted symlink from redirecting the root daemon's write
/// and refuses clobbering a non-file. Pure (just a stat) → unit-testable without a device.
async fn capture_dest_ok(path: &str) -> Result<(), String> {
    match tokio::fs::symlink_metadata(path).await {
        Ok(meta) if meta.file_type().is_file() => Ok(()),
        Ok(_) => Err(format!("refusing to capture to {path}: not a regular file")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("cannot stat {path}: {e}")),
    }
}

/// Validate a `file cp` **source** path before the daemon (running as root) opens it for reading:
/// `Ok(())` only if the path EXISTS and is a **regular file**; `Err(reason)` otherwise — a symlink
/// (refused as the link itself, never followed, since `symlink_metadata` does not traverse the final
/// component), device (e.g. `/dev/zero`, an infinite stream), FIFO, socket, directory, or a
/// missing/unreadable path. Unlike [`capture_dest_ok`]/[`taildrop_dest_ok`] a *missing* path is an
/// ERROR here (there is nothing to send), so the absent case is folded into the same fail-closed
/// message the open would produce. This is the stat half of `file_cp`'s hardening; the open it gates
/// also uses `O_NOFOLLOW` to close the stat→open TOCTOU window. Pure (just a stat) → unit-testable
/// without a device.
async fn taildrop_source_ok(path: &str) -> Result<(), String> {
    match tokio::fs::symlink_metadata(path).await {
        Ok(meta) if meta.file_type().is_file() => Ok(()),
        Ok(_) => Err(format!("refusing to send {path}: not a regular file")),
        // A missing/unreadable source has nothing to send — named the same way as the open error.
        Err(e) => Err(format!("cannot read {path}: {e}")),
    }
}

/// Validate a `file get` **dest** path before the daemon (running as root) creates/overwrites it:
/// `Ok(())` if the path is missing (the normal fresh-fetch case) or an existing **regular file**
/// (overwritten); `Err(reason)` if it EXISTS as anything else — a symlink (refused as the link
/// itself, never followed, since `symlink_metadata` does not traverse the final component), device,
/// FIFO, socket, or directory. Same shape as [`capture_dest_ok`] (a missing dest is allowed and the
/// copy creates it), only the message differs. This is the stat half of `file_get`'s hardening; the
/// create it gates also uses `O_NOFOLLOW` to close the stat→create TOCTOU window. Pure (just a stat)
/// → unit-testable without a device.
async fn taildrop_dest_ok(dest: &str) -> Result<(), String> {
    match tokio::fs::symlink_metadata(dest).await {
        Ok(meta) if meta.file_type().is_file() => Ok(()), // existing regular file → overwrite is fine
        Ok(_) => Err(format!(
            "refusing to write {dest}: exists and is not a regular file"
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()), // does not exist → create below
        Err(e) => Err(format!("cannot write {dest}: {e}")),
    }
}

/// Capture the dataplane's plaintext packets to a pcap file at `path` for `seconds`, then stop (the
/// `tnet debug capture` / Go `tailscale debug capture` path).
///
/// Opens `path` as a [`BufWriter`](std::io::BufWriter) over a fresh `std::fs::File`, hands it to the
/// engine's [`capture_pcap`](tailscale::Device::capture_pcap) (which writes the 24-byte pcap global
/// header on success + installs the dataplane tap), waits `seconds`, then calls
/// [`stop_capture`](tailscale::Device::stop_capture) — which drops the writer, flushing the buffered
/// tail. The daemon does NOT hold the writer (it is moved into the engine and driven inline on the
/// dataplane thread), so the byte count is read back by stat-ing the file after the capture stops.
///
/// **Path hardening:** the daemon writes `path` as its own (root) uid, so — like
/// [`file_get`](file_get) — we `symlink_metadata` it first and refuse anything that EXISTS but is not
/// a regular file (a symlink — never followed — device, FIFO, socket, or directory), so a planted
/// symlink can't redirect the write. A missing path is fine (the common case: a fresh capture file).
///
/// Off the backend lock (the capture runs for `seconds`); the device-absent branch lives at the
/// dispatch arm. Takes `&tailscale::Device` like the other diagnostics.
pub(super) async fn debug_capture(dev: &tailscale::Device, path: &str, seconds: u64) -> Response {
    // Path hardening: refuse an existing non-regular target (symlink/device/FIFO/socket/dir). A
    // missing path is the normal case and is allowed — we create it below.
    if let Err(message) = capture_dest_ok(path).await {
        return Response::Error { message };
    }

    // Create/truncate the file and wrap it buffered. capture_pcap takes a blocking std::io::Write +
    // Send + 'static and MOVES it into the engine, so use a std::fs::File (not tokio's), opened here.
    // `O_NOFOLLOW` closes the stat→open TOCTOU window: capture_dest_ok already refused an existing
    // symlink, but a symlink swapped in AFTER the stat (we run as root) would otherwise be followed by
    // a plain create — with O_NOFOLLOW the open fails (ELOOP) instead, so we never write through a
    // planted link to an arbitrary file. (write+create+truncate, same as File::create otherwise.)
    let file = match std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(f) => f,
        Err(e) => {
            return Response::Error {
                message: format!("cannot create {path}: {e}"),
            };
        }
    };
    let writer = std::io::BufWriter::new(file);

    // Install the tap (writes the global header + starts streaming records into `writer`).
    if let Err(e) = dev.capture_pcap(writer).await {
        // Best-effort cleanup of the (header-less / empty) file so a failed start leaves no stub.
        let _ = tokio::fs::remove_file(path).await;
        return Response::Error {
            message: format!("failed to start capture: {e:?}"),
        };
    }

    // Run for the bounded window, then stop (dropping the engine-held writer flushes the tail).
    tokio::time::sleep(std::time::Duration::from_secs(seconds)).await;
    if let Err(e) = dev.stop_capture().await {
        tracing::warn!(error = ?e, "debug capture: stop_capture failed; the file may be incomplete");
    }

    // The writer was moved into the engine, so read the size back by stat-ing the file.
    let bytes = tokio::fs::metadata(path)
        .await
        .map(|m| m.len())
        .unwrap_or(0);
    Response::Ok {
        message: format!("captured {bytes} bytes to {path} ({seconds}s)"),
    }
}

#[cfg(test)]
mod tests {
    // After the lock-across-await fix (tsd), `ip_report`/`whois`/`ping`/`file_cp`/`file_list`/
    // `file_get` are free fns taking `&tailscale::Device` and the LocalAPI server runs them OFF
    // the backend lock: it clones the engine handle via `device_handle()` under a brief lock, drops
    // the lock, and only calls the method when that handle is `Some`. The "node is not up" branch
    // therefore lives in the dispatch arm (keyed on `device_handle()` being `None`, unit-tested in
    // the `super::super` test module as `device_handle_is_none_without_device`); the bad-IP parse
    // and path-hardening decisions, which require a live `&Device` to reach inside the method
    // (integration territory — no offline `Device` constructor exists), are pinned here via their
    // underlying predicates.

    #[test]
    fn decode_hex_roundtrips_and_rejects_malformed() {
        // The `lock disable` secret arrives hex-encoded; `decode_hex` must round-trip valid hex and
        // reject malformed input (so a bad secret fails fast in the daemon before any control RPC).
        assert_eq!(super::decode_hex("00ff10"), Some(vec![0x00, 0xff, 0x10]));
        assert_eq!(
            super::decode_hex("DEADbeef"),
            Some(vec![0xde, 0xad, 0xbe, 0xef])
        );
        assert_eq!(super::decode_hex(""), Some(vec![]));
        // Odd length → None (a hex byte is 2 chars).
        assert_eq!(super::decode_hex("abc"), None);
        // Non-hex chars → None.
        assert_eq!(super::decode_hex("zz"), None);
        assert_eq!(super::decode_hex("00gg"), None);
    }

    #[test]
    fn diagnostic_bad_ip_parse_is_rejected() {
        // `whois`/`ping` reject an unparseable IP before any engine round-trip via this exact parse;
        // the rejection now lives behind a `&Device` (integration), so pin the parse predicate it
        // relies on: the offending values fail `IpAddr::from_str` (so the method's bad-input arm
        // fires), while a well-formed tailnet IP parses (so a good input reaches the engine).
        assert!(
            "not-an-ip".parse::<std::net::IpAddr>().is_err(),
            "a non-IP whois/ping argument must fail to parse → method returns the bad-input Error"
        );
        assert!(
            "999.999.999.999".parse::<std::net::IpAddr>().is_err(),
            "an out-of-range IP must fail to parse → method returns the bad-input Error"
        );
        assert!(
            "100.64.0.1".parse::<std::net::IpAddr>().is_ok(),
            "a well-formed tailnet IP must parse → reaches the engine call"
        );
    }

    #[tokio::test]
    async fn capture_dest_hardening() {
        use super::capture_dest_ok;
        let base = std::env::temp_dir().join(format!("tailnetd-cap-dest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();

        // A fresh (missing) path is OK — the common case (capture creates it).
        let fresh = base.join("fresh.pcap");
        assert!(capture_dest_ok(fresh.to_str().unwrap()).await.is_ok());

        // An existing regular file is OK (overwritten).
        let reg = base.join("old.pcap");
        std::fs::write(&reg, b"x").unwrap();
        assert!(capture_dest_ok(reg.to_str().unwrap()).await.is_ok());

        // A directory is refused (can't be tricked into writing into / through a non-file).
        assert!(capture_dest_ok(base.to_str().unwrap()).await.is_err());

        let _ = std::fs::remove_dir_all(&base);
    }

    // --- Taildrop path hardening (file_cp source / file_get dest) — fail-closed regular-file rule --
    //
    // Because the daemon opens the `file_cp` source and writes the `file_get` dest AS ROOT, both
    // refuse anything that is not a regular file (a symlink — never followed — device, FIFO, socket,
    // or directory). That stat-check half is now an extracted pure predicate that the production
    // methods CALL — `taildrop_source_ok` (file_cp: source must EXIST as a regular file) and
    // `taildrop_dest_ok` (file_get: dest must be a regular file OR absent) — mirroring how
    // `debug_capture` calls `capture_dest_ok`. These tests therefore exercise the SAME code the
    // methods run (no re-implementation), over real temp paths: a regular file is accepted, a symlink
    // is rejected as the link itself (never traversed), a directory is refused, and the absent case
    // differs by predicate (source → error, dest → ok). The `O_NOFOLLOW` open that closes the
    // stat→open TOCTOU window is the load-bearing SECOND half, pinned separately below.

    #[tokio::test]
    async fn taildrop_source_ok_accepts_regular_rejects_dir_and_missing() {
        // `file_cp` source rule, via the production predicate: a regular file → Ok; a directory →
        // Err; a missing path → Err (nothing to send). This is the exact check `file_cp` now calls.
        use super::taildrop_source_ok;
        let base = std::env::temp_dir().join(format!("tailnetd-src-ok-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();

        let file = base.join("regular.bin");
        std::fs::write(&file, b"hello").unwrap();
        assert!(
            taildrop_source_ok(file.to_str().unwrap()).await.is_ok(),
            "a regular file must be accepted as a file_cp source"
        );

        // A directory is refused (can't be sent / can't be tricked into reading through a non-file).
        assert!(
            taildrop_source_ok(base.to_str().unwrap()).await.is_err(),
            "a directory must be refused as a file_cp source"
        );

        // A missing source is an error (unlike a dest, there is nothing to send).
        let missing = base.join("does-not-exist.bin");
        assert!(
            taildrop_source_ok(missing.to_str().unwrap()).await.is_err(),
            "a missing source must be refused (nothing to send)"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn taildrop_source_ok_rejects_symlink_without_following() {
        // A symlink at the source must be refused as the LINK itself (not followed to its target),
        // EVEN when it points at a regular file — `symlink_metadata` does not traverse the final
        // component. Pinned through the production predicate `file_cp` calls.
        use super::taildrop_source_ok;
        let base = std::env::temp_dir().join(format!("tailnetd-src-sym-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let target = base.join("target.bin");
        std::fs::write(&target, b"data").unwrap();
        let link = base.join("link.bin");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        assert!(
            taildrop_source_ok(link.to_str().unwrap()).await.is_err(),
            "a symlink source must be refused as the link itself, never followed to its target"
        );
        // The target must be untouched — the predicate only stats, never reads through the link.
        assert_eq!(std::fs::read(&target).unwrap(), b"data");

        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn taildrop_dest_ok_accepts_regular_and_missing_rejects_dir() {
        // `file_get` dest rule, via the production predicate: a missing dest → Ok (the copy creates
        // it — the normal case), an existing regular file → Ok (overwritten), a directory → Err.
        // This is the exact check `file_get` now calls (same shape as `capture_dest_ok`).
        use super::taildrop_dest_ok;
        let base = std::env::temp_dir().join(format!("tailnetd-dest-ok-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();

        // The normal fresh-fetch case: a non-existent dest passes (created by the copy).
        let missing = base.join("does-not-exist.bin");
        assert!(
            taildrop_dest_ok(missing.to_str().unwrap()).await.is_ok(),
            "a non-existent dest must be allowed (file_get creates it)"
        );

        // An existing regular file is OK (overwritten).
        let reg = base.join("old.bin");
        std::fs::write(&reg, b"x").unwrap();
        assert!(
            taildrop_dest_ok(reg.to_str().unwrap()).await.is_ok(),
            "an existing regular-file dest must be allowed (overwrite)"
        );

        // A directory is refused (can't clobber / write through a non-file).
        assert!(
            taildrop_dest_ok(base.to_str().unwrap()).await.is_err(),
            "a directory dest must be refused"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn taildrop_dest_ok_rejects_existing_symlink_without_following() {
        // An EXISTING symlink at the dest must be refused as the link itself (not followed/clobbered),
        // even when it points at a regular file. Pinned through the production predicate `file_get` calls.
        use super::taildrop_dest_ok;
        let base = std::env::temp_dir().join(format!("tailnetd-dest-sym-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let target = base.join("target.bin");
        std::fs::write(&target, b"data").unwrap();
        let link = base.join("link.bin");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        assert!(
            taildrop_dest_ok(link.to_str().unwrap()).await.is_err(),
            "an existing symlink dest must be refused as the link itself, never followed/clobbered"
        );
        // The target must be untouched — the predicate only stats, never writes through the link.
        assert_eq!(std::fs::read(&target).unwrap(), b"data");

        let _ = std::fs::remove_dir_all(&base);
    }

    #[cfg(unix)]
    #[test]
    fn o_nofollow_open_refuses_a_symlink() {
        // The SECOND line of defense (the stat→open TOCTOU closure): even if a symlink is swapped in
        // at the path AFTER the `symlink_metadata` check passes, the actual open uses `O_NOFOLLOW`, so
        // it fails with `ELOOP` rather than following the link. `file_cp` (read) and `file_get`
        // (write+create) both now open this way (matching `debug_capture`). Pin the exact mechanism:
        // an `O_NOFOLLOW` open of a symlink fails, for BOTH the read and the write+create open shapes.
        use std::os::unix::fs::OpenOptionsExt;
        let base = std::env::temp_dir().join(format!("tailnetd-nofollow-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let target = base.join("target.bin");
        std::fs::write(&target, b"data").unwrap();
        let link = base.join("link.bin");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        // Read open (the `file_cp` source shape): O_NOFOLLOW → refused.
        let read_res = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&link);
        assert!(
            read_res.is_err(),
            "O_NOFOLLOW read-open of a symlink must fail (ELOOP), never follow it"
        );
        assert_eq!(
            read_res.err().unwrap().raw_os_error(),
            Some(libc::ELOOP),
            "the refusal must be ELOOP (the O_NOFOLLOW signal), not some other error"
        );

        // Write+create+truncate open (the `file_get` dest / `debug_capture` shape): also refused.
        let write_res = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&link);
        assert!(
            write_res.is_err(),
            "O_NOFOLLOW write-open of a symlink must fail (ELOOP), never write through it"
        );
        assert_eq!(
            write_res.err().unwrap().raw_os_error(),
            Some(libc::ELOOP),
            "the refusal must be ELOOP"
        );
        // The target's contents were never read or clobbered through the link.
        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"data",
            "the symlink target must be untouched by the refused opens"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn timestamps_emit_strict_rfc3339_not_display_form() {
        // `whois`/`status` render peer `last_seen` / `node_key_expiry` via `DateTime::to_rfc3339`
        // (Go-`ipnstate`-compatible), NOT chrono's `Display` (`2026-06-11 05:19:14 UTC`, which a
        // JSON consumer mis-parses). Pin the exact shape for a known instant so a refactor back to
        // `.to_string()` is caught. This is the format the three emission sites use (diag::whois ×2,
        // ipn::status peer projection).
        use chrono::{TimeZone, Utc};
        let t = Utc.with_ymd_and_hms(2026, 6, 11, 5, 19, 14).unwrap();
        let rfc = t.to_rfc3339();
        assert_eq!(rfc, "2026-06-11T05:19:14+00:00", "must be strict RFC3339");
        // Guard against the Display form ever sneaking back in.
        assert!(rfc.contains('T') && !rfc.contains(" UTC"));
        assert_ne!(
            rfc,
            t.to_string(),
            "to_rfc3339 must differ from the Display form"
        );
    }

    #[test]
    fn cp_send_name_ok_accepts_bare_names_rejects_pathlike() {
        use super::cp_send_name_ok;
        // Bare file names (override or derived basename) are fine.
        assert!(cp_send_name_ok("report.pdf"));
        assert!(cp_send_name_ok(".bashrc"));
        assert!(cp_send_name_ok("a b (1).txt"));
        // Path-shaped / traversal / NUL names are refused (a name is not a path).
        assert!(!cp_send_name_ok(""));
        assert!(!cp_send_name_ok("."));
        assert!(!cp_send_name_ok(".."));
        assert!(!cp_send_name_ok("a/b.txt"));
        assert!(!cp_send_name_ok("../escape"));
        assert!(!cp_send_name_ok("a\\b"));
        assert!(!cp_send_name_ok("a\0b"));
    }

    #[test]
    fn numbered_file_name_matches_go_path_ext() {
        use super::numbered_file_name;
        // Splits on the FINAL extension: stem + " (i)" + ext (Go numberedFileName + path.Ext).
        assert_eq!(numbered_file_name("report.pdf", 1), "report (1).pdf");
        assert_eq!(numbered_file_name("a.b.txt", 3), "a.b (3).txt");
        assert_eq!(
            numbered_file_name("archive.tar.gz", 1),
            "archive.tar (1).gz"
        );
        // No '.' at all → just append " (i)".
        assert_eq!(numbered_file_name("README", 2), "README (2)");
        // A leading-dot dotfile: Go's path.Ext(".bashrc") == ".bashrc" (the WHOLE name, NOT "" —
        // Go has no leading-dot special case, unlike Python splitext). So the stem is empty and the
        // result is " (1).bashrc" (a leading space). Verified against `go run` upstream.
        assert_eq!(numbered_file_name(".bashrc", 1), " (1).bashrc");
    }

    #[test]
    fn open_target_skip_refuses_existing_leaves_it_intact() {
        use super::{ConflictPolicy, open_target_under_policy};
        let base = std::env::temp_dir().join(format!("tailnetd-skip-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let dir = base.to_str().unwrap();

        // Pre-existing file with known contents.
        let existing = base.join("f.bin");
        std::fs::write(&existing, b"OLD").unwrap();

        // skip → AlreadyExists, and the existing file is untouched.
        let err = open_target_under_policy(dir, "f.bin", ConflictPolicy::Skip).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(
            std::fs::read(&existing).unwrap(),
            b"OLD",
            "skip must not clobber"
        );

        // A NON-conflicting name under skip succeeds.
        let (_f, path) = open_target_under_policy(dir, "new.bin", ConflictPolicy::Skip).unwrap();
        assert_eq!(path, base.join("new.bin").to_string_lossy());

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn open_target_overwrite_replaces_and_is_symlink_safe() {
        use super::{ConflictPolicy, open_target_under_policy};
        use std::io::Write;
        let base = std::env::temp_dir().join(format!("tailnetd-ow-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let dir = base.to_str().unwrap();

        // (a) Plain overwrite of an existing regular file: we get a fresh, empty, writable handle.
        let existing = base.join("f.bin");
        std::fs::write(&existing, b"OLD").unwrap();
        let (mut f, path) =
            open_target_under_policy(dir, "f.bin", ConflictPolicy::Overwrite).unwrap();
        f.write_all(b"NEW").unwrap();
        drop(f);
        assert_eq!(path, existing.to_string_lossy());
        assert_eq!(
            std::fs::read(&existing).unwrap(),
            b"NEW",
            "overwrite must replace contents"
        );

        // (b) Symlink-safety: a symlink planted at the target name must NOT be written through —
        // overwrite removes the link first then exclusive-creates, so the link's target is untouched.
        let outside = base.join("outside-secret");
        std::fs::write(&outside, b"SECRET").unwrap();
        let link = base.join("link.bin");
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        let (mut f, _p) =
            open_target_under_policy(dir, "link.bin", ConflictPolicy::Overwrite).unwrap();
        f.write_all(b"FROM_TAILDROP").unwrap();
        drop(f);
        assert_eq!(
            std::fs::read(&outside).unwrap(),
            b"SECRET",
            "overwrite must not write through a planted symlink to its target"
        );
        // `link.bin` is now a fresh regular file (the link was removed + recreated), not a symlink.
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_file(),
            "the target name must now be a regular file, not the symlink"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn open_target_rename_creates_numbered_variants() {
        use super::{ConflictPolicy, open_target_under_policy};
        let base = std::env::temp_dir().join(format!("tailnetd-rn-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let dir = base.to_str().unwrap();

        // First rename call with no conflict → the plain name.
        let (_f0, p0) = open_target_under_policy(dir, "doc.txt", ConflictPolicy::Rename).unwrap();
        assert_eq!(p0, base.join("doc.txt").to_string_lossy());
        // Second → "doc (1).txt"; third → "doc (2).txt".
        let (_f1, p1) = open_target_under_policy(dir, "doc.txt", ConflictPolicy::Rename).unwrap();
        assert_eq!(p1, base.join("doc (1).txt").to_string_lossy());
        let (_f2, p2) = open_target_under_policy(dir, "doc.txt", ConflictPolicy::Rename).unwrap();
        assert_eq!(p2, base.join("doc (2).txt").to_string_lossy());

        let _ = std::fs::remove_dir_all(&base);
    }
}
