//! Engine [`tailscale::Config`] construction from persisted [`Prefs`].
//!
//! This is the single seam where the daemon's reconfigurable *intent* ([`Prefs`] + the on-disk key
//! file) becomes the engine's *immutable* construction config. Split out of [`super`] as a free
//! function ([`build_config`]) that reads only `prefs` + `key_path` (no `Backend` `self`), so it is
//! straightforward to read and test in isolation; [`Backend::build_config`](super::Backend) is a
//! thin shim over it so the internal callers (`begin_up` / `begin_set` / `drive_set` preflight) are
//! unchanged.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};

use crate::prefs::Prefs;

/// Translate [`Prefs`] + the on-disk key file into a [`tailscale::Config`] for the engine. This is
/// the single seam where the daemon's reconfigurable intent becomes the engine's immutable
/// construction config (Phase-3 platform config will grow here), so `up` stays a thin orchestrator
/// over it.
///
/// Control-server precedence (highest wins): `prefs.control_url` > `TS_CONTROL_URL` > engine
/// default (real Tailscale). The base is built from [`tailscale::Config::default_from_env`] so
/// the env var is honored, then the node key is loaded in (mirroring
/// `Config::default_with_key_file`, which is just `{ key_state: load_key_file(..), ..default() }`
/// over the *non*-env default), then prefs override hostname/ephemeral/accept_routes, and finally
/// `prefs.control_url` overrides the control server last so an explicit pref always wins over the
/// environment.
pub(super) async fn build_config(
    prefs: &Prefs,
    key_path: &Path,
    listen_port: Option<u16>,
) -> Result<tailscale::Config> {
    // Start from the env-aware default so `TS_CONTROL_URL` (and the other `TS_*` vars) are
    // honored, then fold in the persisted node key — `default_with_key_file` does the same
    // `load_key_file` but over the plain (non-env) default, which would silently ignore the env.
    let mut config = tailscale::Config::default_from_env();
    config.key_state = tailscale::config::load_key_file(key_path, Default::default())
        .await
        .map_err(|e| anyhow!("load key file {}: {e:?}", key_path.display()))?;
    config.requested_hostname = prefs.hostname.clone();
    // Ephemeral defaults to `false` (persistent), matching Go `tailscaled` — a persistent node keeps
    // its registration across reboots and resumes from its key alone. The operator opts INTO an
    // ephemeral node with `tnet up --ephemeral` (short-lived CI/containers); control then GCs it
    // shortly after disconnect, so an ephemeral node will NOT rejoin after a reboot without a fresh
    // auth key — `tailnetd`'s auto-start logging surfaces that honestly. Either way it is a
    // registration-time *intent* carried verbatim from prefs, never flipped silently by the daemon.
    config.ephemeral = prefs.ephemeral;
    config.accept_routes = prefs.accept_routes;
    // Accept-MagicDNS (Go `CorpDNS` / `--accept-dns`, default-on): gate the engine's MagicDNS
    // responder on the control-pushed DNS config. `false` ignores the pushed config.
    config.accept_dns = prefs.accept_dns;
    // Shields-up (Go `ShieldsUp`): block inbound peer connections terminating on this node. The
    // engine wraps the live packet filter in its `ShieldsUpFilter` when this is set.
    config.block_incoming = prefs.shields_up;
    // Exit node: prefs store the raw selector string; parse it into the engine's
    // `ExitNodeSelector`. `FromStr` is infallible (a bare IP → `Ip`, anything else → `Name`),
    // so the parse cannot fail — `Err` is `core::convert::Infallible` and `unwrap` here is
    // unreachable, not a fallible-result-swallow. `None` leaves `config.exit_node` at its
    // default (no exit node = direct egress).
    if let Some(s) = &prefs.exit_node {
        let sel: tailscale::ExitNodeSelector = s.parse().unwrap();
        config.exit_node = Some(sel);

        // LEAK-SAFETY POSTURE (tsd-iqq.3). An exit node is leak-free ONLY when the OS-wide
        // traffic + DNS actually traverse it. The two modes differ, and this is the one place
        // both are visible, so surface the posture here rather than let an operator assume:
        //
        // - TUN mode (`tun_enabled`): the engine captures OS-wide traffic AND takes over the OS
        //   resolver (points it at the in-datapath MagicDNS responder on `100.100.100.100` and
        //   delegates recursive resolution to the *exit node's* peerAPI DoH over the overlay —
        //   never a host socket, v4-only). So OS-wide exit is leak-safe: no real-origin-IP DNS
        //   leak. Nothing for the daemon to add — the engine's `ts_host_net` does it (and only
        //   in TUN mode; see `ts_runtime::tun_actor`).
        // - Netstack mode (default, no TUN): the OS default route and resolver are UNTOUCHED, so
        //   exit-node selection only affects traffic that apps send *through the daemon* (via
        //   LocalAPI/loopback). It is NOT OS-wide and has no OS-level DNS-leak surface — but an
        //   operator expecting "all my machine's traffic now exits residential" will NOT get
        //   that without TUN. Warn so the expectation gap is visible, not silent.
        if !prefs.tun_enabled {
            tracing::warn!(
                "config: exit node configured in netstack mode (TUN off): only traffic routed THROUGH \
                 this daemon uses the exit — the OS default route and resolver are untouched, \
                 so this is NOT machine-wide egress. Enable TUN (`--tun`, root) for OS-wide, \
                 DNS-leak-free exit."
            );
        }
    }
    config.advertise_exit_node = prefs.advertise_exit_node;
    // Advertised subnet routes: prefs store raw CIDR strings; parse each into `ipnet::IpNet`.
    // A malformed CIDR FAILS LOUDLY (mirroring the `control_url` parse above) rather than being
    // silently dropped — naming the bad value — because an operator who asked to advertise a
    // route and instead got it silently discarded would have a confusing, hard-to-notice gap.
    // (The engine itself is v4-only: it drops any IPv6 prefix internally after this point, so a
    // v6 CIDR is *accepted and parsed* here, then dropped by the engine with no error — we do
    // NOT pre-filter v6, matching the engine's "accept-then-drop" contract.)
    let advertise_routes = prefs
        .advertise_routes
        .iter()
        .map(|s| {
            s.parse::<ipnet::IpNet>()
                .with_context(|| format!("invalid advertise route {s:?}"))
        })
        .collect::<Result<Vec<ipnet::IpNet>>>()?;
    config.advertise_routes = advertise_routes;
    // ACL tags requested at registration (Go `--advertise-tags`). Stored as raw `tag:<name>` strings
    // in prefs (validated at the `up`/`set` boundary), mapped verbatim to the engine's
    // `requested_tags`. Empty = a user-owned node.
    config.requested_tags = prefs.advertise_tags.clone();
    // Apply a custom control server when prefs carry one; this wins over `TS_CONTROL_URL` and
    // the engine default. A malformed URL fails loudly rather than silently falling back —
    // pointing at the wrong control plane must never be silent. Only `http`/`https` are accepted
    // (defense-in-depth: the value is operator-trusted, but rejecting a stray scheme is cheap).
    if let Some(s) = &prefs.control_url {
        let url = url::Url::parse(s).with_context(|| format!("invalid control_url {s:?}"))?;
        match url.scheme() {
            "http" | "https" => {}
            other => {
                return Err(anyhow!(
                    "invalid control_url {s:?}: scheme {other:?} is not http or https"
                ));
            }
        }
        // Allow the unauthenticated `/key` bootstrap to use plain http when (and only when) the
        // control URL is itself `http://`. The engine defaults `allow_http_key_fetch` to `false`,
        // which force-upgrades the `GET /key` fetch to `https` even for an `http://` control server —
        // so a plain-http control plane (a self-hosted Headscale on `http://host:port` with no TLS,
        // common on a LAN / NodePort) fails registration with a TLS error against the plaintext
        // listener. Go's client honors the control URL's scheme for the key fetch, so this matches
        // upstream. It is scoped to an operator-configured `http://` URL (an explicit, deliberate
        // choice) and has NO effect on the normal `https://` path; an `https://` control URL leaves
        // the fail-closed default in place. (Setting it for `https` would be a harmless no-op, but we
        // gate on the scheme so the relaxation is visible and never silently applies to https.)
        config.allow_http_key_fetch = url.scheme() == "http";
        config.control_server_url = url;
    }
    // TUN-mode data path. Default is the engine's userspace netstack (unprivileged); TUN hands
    // packets to a real kernel interface, which needs (a) a daemon built with the `tun` cargo
    // feature [`tailscale/tun`] and (b) root / CAP_NET_ADMIN. We preflight both and FAIL LOUDLY
    // — never silently downgrade to netstack, because the operator asked for OS-wide
    // connectivity and a silent fallback would be a confusing, hard-to-notice half-working state.
    if prefs.tun_enabled {
        #[cfg(not(feature = "tun"))]
        {
            return Err(anyhow!(
                "TUN mode requested (tun_enabled) but this daemon was built without the `tun` \
                 feature; rebuild with `cargo build --features tun` (and run as root) to use it"
            ));
        }
        #[cfg(feature = "tun")]
        {
            // Privilege preflight: the engine's TUN transport errors `RootUserRequired` without
            // root; surface that here with actionable context before the handshake starts.
            #[cfg(unix)]
            // SAFETY: geteuid() is infallible (no args, no preconditions).
            if unsafe { libc::geteuid() } != 0 {
                return Err(anyhow!(
                    "TUN mode requires root / CAP_NET_ADMIN to create the kernel TUN interface, \
                     but the daemon is not running as root. Run tailnetd as root (the packaged \
                     systemd/launchd units do) or use the default userspace-networking mode"
                ));
            }
            // Select the kernel-TUN transport. The engine (v0.6.7+) re-exports `TransportMode`
            // and `TunConfig` from the facade, so the daemon can construct the value directly.
            //
            // Interface name: when the operator did not pass `--tun-name`, we must pick a
            // platform-appropriate default rather than let the engine apply its own. The engine
            // defaults a `None` name to `"tailscale0"` (Linux-style), but on macOS the kernel
            // requires utun interfaces to be named `utun*` — `tailscale0` is rejected by `tun-rs`
            // with "device name must start with utun", and the device (hence the whole overlay
            // data path) fails to come up. So on macOS we default to bare `"utun"`, which the
            // kernel treats as "assign the next free utunN". On Linux we leave `None` so the
            // engine's `tailscale0` default stands. (The real fix belongs in the engine's
            // platform-aware default; tracked as an engine ask — until then this keeps TUN
            // working cross-platform.)
            let tun_name = prefs
                .tun_name
                .clone()
                .or_else(super::state::default_tun_name);
            config.transport_mode = tailscale::TransportMode::Tun(tailscale::TunConfig {
                name: tun_name,
                mtu: prefs.tun_mtu,
            });
        }
    }
    // Tailscale SSH server preflight. Unlike TUN, SSH is NOT an engine `Config` knob — the server
    // is a daemon-spawned task (see `spawn_ssh_task`), so `ssh_enabled` sets NO field on
    // `config`. It only gates the spawn, plus these two fail-loud preflights mirroring TUN's, so
    // an impossible `--ssh` fails the bring-up here rather than silently doing nothing:
    // (a) built without the `ssh` cargo feature → there is no server to spawn; and
    // (b) running as non-root → the engine's `listen_ssh` must drop privileges to the
    //     policy-mapped local user, which requires root, so the session would fail closed.
    // Both fail loudly here (never a silent no-SSH node when SSH was explicitly requested).
    if prefs.ssh_enabled {
        #[cfg(not(feature = "ssh"))]
        {
            return Err(anyhow!(
                "SSH requested (ssh_enabled) but this daemon was built without the `ssh` \
                 feature; rebuild with `cargo build --features ssh` (and run as root) to use it"
            ));
        }
        #[cfg(feature = "ssh")]
        {
            // Privilege preflight: the engine's `listen_ssh` drops privileges to the
            // policy-mapped local user and so requires root; surface that here with actionable
            // context before the handshake starts.
            #[cfg(unix)]
            // SAFETY: geteuid() is infallible (no args, no preconditions).
            if unsafe { libc::geteuid() } != 0 {
                return Err(anyhow!(
                    "Tailscale SSH server requires root to drop privileges to the policy-mapped \
                     local user, but the daemon is not running as root. Run tailnetd as root \
                     (the packaged systemd/launchd units do) to use --ssh"
                ));
            }
        }
    }
    // Taildrop receive directory. `Some(dir)` enables RECEIVING (the engine builds its receive
    // store under this path and accepts inbound `PUT /v0/put/<name>` transfers from peers);
    // `None` leaves `config.taildrop_dir` at its default of `None`, where the engine is
    // **fail-closed** — `taildrop_waiting_files` returns an empty list and inbound transfers are
    // refused. Sending (`file_cp`) does NOT depend on this; only receiving does. The raw pref
    // string maps straight to the engine's `Option<PathBuf>` (no parse can fail).
    config.taildrop_dir = prefs.taildrop_dir.as_ref().map(PathBuf::from);
    // WireGuard/disco UDP listen port (Go `tailscaled --port` / `PORT`). A daemon-startup setting, not
    // a pref — it is fixed for the process lifetime, so it is threaded in here rather than stored in
    // `Prefs`. `None` (the default + Go's `0`) lets the OS pick an ephemeral port; `Some(p)` pins the
    // magicsock bind to `p` so the node's UDP endpoint is stable across restarts (what a fixed-pinhole
    // firewall needs). The engine falls back to an ephemeral port if `p` is already taken at startup
    // (a collision must not fail bring-up), so this is a *preference*, not a hard requirement.
    config.wireguard_listen_port = listen_port;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prefs::Prefs;

    /// A `build_config` over a throwaway key path with the given control_url override. The key file
    /// is created on first read, so each call gets a unique temp path to stay parallel-safe.
    async fn config_for_control_url(control_url: Option<&str>) -> tailscale::Config {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let key_path = std::env::temp_dir().join(format!(
            "tailnetd-cfgtest-{}-{}.key",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let prefs = Prefs {
            control_url: control_url.map(String::from),
            ..Default::default()
        };
        let cfg = build_config(&prefs, &key_path, None)
            .await
            .expect("build_config should succeed for a valid control_url");
        let _ = std::fs::remove_file(&key_path);
        cfg
    }

    /// Run `build_config` with the given `listen_port` over a throwaway key path (the port path does
    /// not touch control, so default prefs suffice). Returns the built engine config.
    async fn config_for_listen_port(listen_port: Option<u16>) -> tailscale::Config {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let key_path = std::env::temp_dir().join(format!(
            "tailnetd-portcfgtest-{}-{}.key",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let cfg = build_config(&Prefs::default(), &key_path, listen_port)
            .await
            .expect("build_config should succeed");
        let _ = std::fs::remove_file(&key_path);
        cfg
    }

    #[tokio::test]
    async fn listen_port_none_is_ephemeral_some_is_pinned() {
        // `--port`/`PORT` threads through to the engine's wireguard_listen_port: None (default) leaves
        // the OS-chosen ephemeral port; Some(p) pins the magicsock bind. Pin both so a refactor that
        // drops the threading (or maps it to the wrong field) is caught.
        let ephemeral = config_for_listen_port(None).await;
        assert_eq!(
            ephemeral.wireguard_listen_port, None,
            "no --port → ephemeral (None), matching Go's port 0"
        );
        let pinned = config_for_listen_port(Some(41641)).await;
        assert_eq!(
            pinned.wireguard_listen_port,
            Some(41641),
            "--port 41641 must pin the engine's WireGuard listen port"
        );
    }

    #[tokio::test]
    async fn http_control_url_enables_plaintext_key_fetch() {
        // The bug this guards: a plaintext `http://` control server (self-hosted Headscale, no TLS)
        // could never register because the engine force-upgraded the unauthenticated `/key` bootstrap
        // to https. An `http://` control_url must set `allow_http_key_fetch` so the key fetch honors
        // the scheme (matching Go).
        let cfg = config_for_control_url(Some("http://localhost:8080")).await;
        assert!(
            cfg.allow_http_key_fetch,
            "an http:// control_url must allow the plain-http /key bootstrap"
        );
        assert_eq!(cfg.control_server_url.scheme(), "http");
    }

    #[tokio::test]
    async fn https_control_url_keeps_failclosed_key_fetch() {
        // An `https://` control URL must leave the fail-closed default in place (no relaxation): the
        // key fetch stays over TLS, as it should for a real control plane.
        let cfg = config_for_control_url(Some("https://hs.example.com")).await;
        assert!(
            !cfg.allow_http_key_fetch,
            "an https:// control_url must NOT relax the /key bootstrap"
        );
        assert_eq!(cfg.control_server_url.scheme(), "https");
    }
}
