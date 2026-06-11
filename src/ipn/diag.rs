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

use crate::localapi::{Response, WaitingFileReport, WhoisReport};

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
///   `(cap, args)` args are dropped — too verbose for a whois summary).
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
            Response::Whois(WhoisReport {
                found: true,
                node_name: Some(node.display_name),
                node_ipv4: Some(node.ipv4.to_string()),
                user: w.user,
                // Keep just the capability names for the summary; drop the verbose args.
                capabilities: w.capabilities.into_iter().map(|(cap, _args)| cap).collect(),
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
/// `Ok(rtt)` → [`Response::Ping`] with the RTT in milliseconds (and the IP echoed for the CLI);
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
        Ok(rtt) => Response::Ping {
            rtt_ms: rtt.as_secs_f64() * 1000.0,
            ip: ip.to_string(),
        },
        Err(e) => Response::Error {
            message: format!("ping {ip} failed: {e:?}"),
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
/// root-held open at a file the operator did not name. Minimal by design — not a full sandbox.
///
/// Peer resolution mirrors [`whois`]/[`ping`]: a `peer` that parses
/// as an [`IpAddr`](std::net::IpAddr) is looked up by tailnet IP, otherwise by MagicDNS name. The
/// engine derives the destination solely from the resolved peer's own node record, so a raw
/// address can never be targeted directly.
pub(super) async fn file_cp(dev: &tailscale::Device, path: &str, peer: &str) -> Response {
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
    // Derive the send name from the path's final component (basename), like Go's `file cp`. A
    // path with no basename (e.g. `/`) has nothing meaningful to name the transfer — reject it.
    let Some(name) = std::path::Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .map(str::to_string)
    else {
        return Response::Error {
            message: format!("cannot derive a file name from path {path:?}"),
        };
    };
    // Path hardening (see method doc): the daemon opens `path` as root, so first `symlink_metadata`
    // it (which does NOT follow a final-component symlink) and refuse anything that is not a regular
    // file — a symlink, device (e.g. `/dev/zero`, an infinite stream), FIFO, socket, or directory.
    // Done BEFORE the open so a non-regular target is never opened. `symlink_metadata` failing
    // (missing/unreadable path) falls through here too, named the same way as the open error below.
    match tokio::fs::symlink_metadata(path).await {
        Ok(meta) if meta.file_type().is_file() => {}
        Ok(_) => {
            return Response::Error {
                message: format!("refusing to send {path}: not a regular file"),
            };
        }
        Err(e) => {
            return Response::Error {
                message: format!("cannot read {path}: {e}"),
            };
        }
    }
    // The daemon opens the path (same-host/same-user; see the method doc). A read error here
    // (missing/unreadable file) fails closed, naming the path.
    let file = match tokio::fs::File::open(path).await {
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

/// List the Taildrop files waiting in this node's receive directory (the `tnet file list` / Go
/// `tailscale file get` no-arg path).
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

/// Fetch a waiting Taildrop file by name, writing it to `dest` (the `tnet file get <name>` / Go
/// `tailscale file get <name>` path).
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
/// (the normal case) passes the check and is created by the copy. Minimal by design — not a full
/// sandbox.
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
    // Dest hardening (see method doc): `symlink_metadata` does not follow a final-component
    // symlink, so an existing symlink/device/FIFO/socket/dir at `dest` is refused rather than
    // followed or clobbered. A `NotFound` is the normal case (we are about to create the file).
    // Any other stat error fails closed, naming `dest`.
    match tokio::fs::symlink_metadata(dest).await {
        Ok(meta) if meta.file_type().is_file() => {} // existing regular file → overwrite is fine
        Ok(_) => {
            return Response::Error {
                message: format!("refusing to write {dest}: exists and is not a regular file"),
            };
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {} // does not exist → create below
        Err(e) => {
            return Response::Error {
                message: format!("cannot write {dest}: {e}"),
            };
        }
    }
    // Copy off the async runtime: `std::io::copy` over `std::fs` handles is blocking, so do it on
    // a blocking thread rather than stall an async worker. The `dest` string is moved in.
    let dest_owned = dest.to_string();
    let copy_result = tokio::task::spawn_blocking(move || {
        let mut out = std::fs::File::create(&dest_owned)?;
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
            "taildrop file fetched to dest but could not be deleted from the receive directory"
        );
    }
    Response::Ok {
        message: format!("saved {name} to {dest}"),
    }
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
    // or directory): `file_cp` always, `file_get` only when `dest` already exists (a fresh dest is
    // created). The full methods need a live `&Device`, so these tests pin the load-bearing predicate
    // directly — `symlink_metadata(p).file_type().is_file()` over real temp paths — proving a regular
    // file is accepted, a directory is refused, and a symlink reads as NOT a regular file (so it is
    // rejected as the link itself, never traversed). This is the exact check both methods perform.

    #[test]
    fn path_hardening_accepts_regular_file_rejects_dir() {
        // A regular file → accepted; a directory → refused. This is the `file_cp` source rule and the
        // `file_get` existing-dest rule, exercised through the same `symlink_metadata` + `is_file`
        // predicate the methods use.
        let base = std::env::temp_dir().join(format!("tailnetd-hard-reg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let file = base.join("regular.bin");
        std::fs::write(&file, b"hello").unwrap();

        let fmeta = std::fs::symlink_metadata(&file).unwrap();
        assert!(
            fmeta.file_type().is_file(),
            "a regular file must satisfy the regular-file check (accepted)"
        );
        let dmeta = std::fs::symlink_metadata(&base).unwrap();
        assert!(
            !dmeta.file_type().is_file(),
            "a directory must NOT satisfy the regular-file check (refused)"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    #[cfg(unix)]
    #[test]
    fn path_hardening_rejects_symlink_without_following() {
        // A symlink must read as NOT a regular file via `symlink_metadata` (which does not traverse
        // the final component), EVEN when it points at a regular file — so `file_cp`/`file_get` reject
        // the link itself rather than following it to a target the operator did not name. This is the
        // symlink-trick defense both methods rely on.
        let base = std::env::temp_dir().join(format!("tailnetd-hard-sym-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let target = base.join("target.bin");
        std::fs::write(&target, b"data").unwrap();
        let link = base.join("link.bin");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let lmeta = std::fs::symlink_metadata(&link).unwrap();
        assert!(
            lmeta.file_type().is_symlink(),
            "symlink_metadata must see the link itself, not its target"
        );
        assert!(
            !lmeta.file_type().is_file(),
            "a symlink must NOT satisfy the regular-file check → it is refused, never followed"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn file_get_dest_nonexistent_is_allowed() {
        // The normal `file_get` case: a `dest` that does not exist passes the hardening check (the
        // copy then creates it). Pin the `NotFound`-means-create branch the method keys on.
        let base = std::env::temp_dir().join(format!("tailnetd-hard-dest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let missing = base.join("does-not-exist.bin");
        match std::fs::symlink_metadata(&missing) {
            Err(e) => assert_eq!(
                e.kind(),
                std::io::ErrorKind::NotFound,
                "a non-existent dest must stat as NotFound → file_get creates it"
            ),
            Ok(_) => panic!("the dest must not exist for this test"),
        }
    }
}
