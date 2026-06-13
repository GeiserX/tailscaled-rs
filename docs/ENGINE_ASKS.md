# What the daemon needs from the `tailscale-rs` engine

This lists the changes the downstream daemon (`tailscaled-rs`) needs from the `tailscale-rs`
library to unblock end-to-end features. Each ask is self-contained, additive, and
backward-compatible. The daemon pins engine rev `f3793636` (`v0.31.0`); individual asks
note the rev they were verified against (older "verified vs `e126bba`/v0.6.9" / `81446f88`/v0.28.2
/ `6035651b`/v0.29.1 notes below predate the current pin and are kept as historical context — the
SHIPPED markers reflect what the pin provides).

> **Pin bump 6035651b (v0.29.1) → f3793636 (v0.31.0), 2026-06-13.** Clean bump — full gate green
> (194 lib + 97 tnet + 9 integ; clippy ±`identity-federation`; fmt). The one breaking change
> (`feat(ts_tunnel)!`: `Psk` drops `Copy` for zeroize-on-drop) does **not** touch the daemon's surface
> (the daemon consumes `tailscale::Device`, not `ts_tunnel::Psk`), confirmed by a clean probe-compile.
> **Unblocks `#15 query_dns`**: the engine now exposes `Device::query_dns` through the live MagicDNS
> forwarder (#152) → `tnet dns query` is now daemon-fixable (was engine-gated). Also **confirms the
> TUN peer-AllowedIPs host-route fix** landed (#127, the ask filed with the live `ip route` repro).
> Pulls a large batch of crypto/robustness fixes for free: WG symmetric-key zeroize-on-drop (#164),
> TKA `Aum::sign` + KAT (#163 — a step toward #17 enforcement, NOT enough yet), magicsock pong-source
> + best-addr hysteresis (#160/#135), mid-session re-auth URL surfacing (#134), and ~15 panic→graceful
> hardening fixes across netstack/derp/disco/control/netcheck/ffi. NEXT to consume: wire `tnet dns
> query` over `Device::query_dns`.

> **Pin bump 81446f88 (v0.28.2) → 6035651b (v0.29.1), 2026-06-12 (PR #125).** This bump SHIPPED +
> CONSUMED three asks: **#14 `accept_dns`** (Config field + `set_accept_dns`; wired daemon-side in
> PR #126 — supersedes the "did NOT land" note below), **#16 `cert_pair`** (PEM cert+key export;
> consumed by `tnet cert` PR #127), and **#19** (the TUN peer-AllowedIPs host-route bug; consumed for
> free — engine owns routing). Still OPEN: **#15 `query_dns`** (→ `tnet dns query`), **#17 TKA
> mutation** (→ `tnet lock` write-ops), **#18** Windows host-net, **#20** Taildrop file-arrival bus
> signal (→ `tnet file get --wait`/`--loop`), plus #8/#9/#13 (minor). v0.29.2
> (engine-internal MagicDNS qtype fix) is intentionally NOT pinned — taken on the next meaningful bump.

> **Pin bump f42eb70e (v0.21.2) → 81446f88 (v0.28.2), 2026-06-12.** API-surface diff (both revs'
> `src/lib.rs` + `ts_runtime` types compared) confirmed the engine surface is **purely additive across
> all 28 commits — zero breaking/changed/removed public items**, so the bump is build-safe. Newly
> consumable as `tailscale::*` (no new dep): `Device::watch_ipn_bus(NotifyWatchOpt) -> IpnBusWatcher`
> streaming `Notify { state, net_map, browse_to_url }` (unblocks interactive `tnet login` —
> `browse_to_url` merges registration auth-URL + running-node PopBrowserURL); `set_hostname`,
> `set_accept_routes`, `set_advertise_exit_node`, `accept_routes()` getter (runtime pref toggles);
> `ping_disco` (true on-demand RTT); `StatusNode.relay` now populated (DERP region for the status
> table); `WhoIs.cap_map` (flow-scoped cap-grants). **`accept_dns` (ask #14) did NOT land** — code
> search = 0 hits, no `Config.accept_dns` field at v0.28.2; it remains an open, explicit ask, not a
> passive wait.

Ranked by leverage: #1 converts ~115 lines of already-written, CI-built, feature-gated daemon code
into a working feature with a one-line change downstream.

---

## 1. (BLOCKER) Re-export `TransportMode` and `TunConfig` from the crate facade

**Why:** The daemon has the entire TUN-mode data path plumbed (prefs → wire → CLI `--tun/--no-tun`
→ `tun` cargo feature → root preflight), and the engine's `tun` feature compiles. The one missing
piece: a downstream crate that depends only on `tailscale` **cannot construct** the value to select
TUN, because the type isn't re-exported.

- `Config.transport_mode: ts_control::TransportMode` is **public** (`src/config.rs:174`), but
- the facade (`src/lib.rs`) does **not** `pub use` `TransportMode`/`TunConfig`, and `ts_control` is
  not a direct dependency of downstream crates — so `TransportMode::Tun(TunConfig { name, mtu })` is
  unnameable downstream.

**Ask (one line, in `src/lib.rs` next to the other `pub use ts_control::{…}` re-exports):**

```rust
pub use ts_control::{TransportMode, TunConfig};
```

`TransportMode` (enum: `Netstack` default, `Tun(TunConfig)`) and `TunConfig { name: Option<String>,
mtu: Option<u16> }` are already `pub` in `ts_control::config` — this only surfaces them through the
facade.

**Optional ergonomic extra (nice, not required):** a builder on `Config`:

```rust
impl Config {
    /// Select the kernel-TUN transport. `name` = desired interface (None → OS picks), `mtu` = None
    /// uses the transport default (overlay MTU 1280).
    pub fn use_tun(&mut self, name: Option<String>, mtu: Option<u16>) {
        self.transport_mode = TransportMode::Tun(TunConfig { name, mtu });
    }
}
```

**Downstream effect once landed:** the daemon's `build_config()` replaces its "TUN not yet wirable"
error with `config.transport_mode = TransportMode::Tun(TunConfig { name: self.prefs.tun_name.clone(),
mtu: self.prefs.tun_mtu })` — a one-line change — and `tsd-tth` (TUN data path) ships.

---

## 2. ✅ FIXED in engine v0.8.0 — `Device::new_with_secret(Option<SecretString>)`

> **DONE.** The engine shipped `Device::new_with_secret(config, auth_key: Option<secrecy::SecretString>)`
> in **v0.8.0** (`bf07c25`, engine takes a `secrecy = "0.10"` dep matching the daemon's). The daemon's
> `build_device` now passes the `SecretString` straight in — no more `.expose_secret().to_string()`
> last-inch plaintext copy in daemon memory. Tracks `tsd-tnv` (now closeable). The original ask:

## 2. Accept `Option<secrecy::SecretString>` for the pre-auth key on `Device::new`

**Why:** The daemon holds the pre-auth key as `secrecy::SecretString` end-to-end (zeroized on drop,
never logged) and is forced to `.expose_secret().to_string()` into a plain `String` for the last
inch — `Device::new(&Config, auth_key: Option<String>)`. That plaintext `String` then lives,
un-zeroized, inside the engine (`Config.auth_key` and the resolve path). It defeats the daemon's
secret hygiene at the boundary.

**Ask:** offer a secret-typed entry point. Either:
- add `secrecy` as a dep and change the signature to `auth_key: Option<secrecy::SecretString>`
  (breaking — bump minor), **or** (back-compat preferred)
- add an alternative constructor, e.g.
  `Device::new_with_secret(config: &Config, auth_key: Option<secrecy::SecretString>)`, and have the
  existing `new` wrap a `String` into a `SecretString` internally.

Engine does not currently depend on `secrecy` (verified). Tracks downstream bead `tsd-tnv`.

---

## 3. Zeroize-on-drop for the private-key types

**Why:** `MachinePrivateKey` / `NodePrivateKey` / `DiscoPrivateKey` (and the WG static / PSK) derive
`Copy` with **no `Drop`/`Zeroize`** (`ts_keys/src/macros.rs:7` etc.), so key bytes are bit-copied on
every read and never wiped — despite `PersistState` docs implying zeroize-on-drop. A VPN's key
material should not linger in freed heap.

**Ask:** drop `Copy` on the private-key newtypes and add `zeroize::ZeroizeOnDrop` (keep the
`zerocopy` derives for the wire representation, but gate raw-byte access behind an explicit
`expose`/`as_bytes` method rather than free `Copy`). This is a security-hardening change; it will
ripple through call sites that rely on `Copy`. Tracks downstream bead `tsd-c3d`.

**✅ SHIPPED (engine v0.11.0).** Private keys are now `ZeroizeOnDrop` + no-`Copy`; `public_key()`
widened to `&self`. **Daemon impact: NONE** — the daemon never holds a raw private key (auth keys
flow as `secrecy::SecretString` via `Device::new_with_secret`; the persisted node key is read by
`&self` in `has_persisted_node_key`, no hot-path clone). Bead `tsd-c3d` closed. Rides in on the
v0.12.0 pin bump.

---

## 4. (Lower priority) A network-change / rebind hook

**Why:** A real `tailscaled` re-binds sockets and re-derives endpoints on link change (Wi-Fi
switch, sleep/wake). The engine exposes no `rebind()` / link-change entry point the daemon can call,
so a Rust daemon is sluggish/broken across network changes on laptops (fine for a static cloud
node). Tracks downstream bead `tsd-94d`.

**Ask (either, whichever fits the engine's design):**
- a `Device::network_changed()` / `Device::rebind()` method the daemon can call when it detects a
  link change, **or**
- internal `netmon`-driven rebind inside the runtime so the daemon doesn't have to.

This one needs engine design input — listed for awareness, not as a precise patch.

**✅ SHIPPED (engine v0.12.0, `Device::rebind(&self) -> Result<(), Error>`).** The engine took the
explicit-method option (the daemon owns *when*; `rebind` does the socket work: re-bind preferring the
same local port, clear reflexive/confirmed-direct paths → re-probe + DERP-relay until a path
re-confirms, IPv4-only invariant preserved, no-op if DERP-only). Daemon work now unblocked: build the
link-change monitor (`tsd-94d`) that calls `Device::rebind()` on Wi-Fi switch / sleep-wake. Rides in
on the v0.12.0 pin bump.

**✅ CONSUMED (daemon, `tsd-94d`).** The link-change monitor (`ipn::linkmon` + the device-bound
`spawn_link_monitor` task) now polls the host's interface addresses and calls `Device::rebind()` on a
network-path change — the first daemon-robustness feature beyond the static netstack. This ask is
fully closed end-to-end.

---

## Already sufficient — no engine change needed (noted to avoid redundant asks)

- **Interactive login**: `DeviceState::NeedsLogin(url::Url)` + `Device::watch_state()` /
  `device_state()` are exposed and already used downstream. Done.
- **Terminal-failure surfacing**: `DeviceState::Failed(RegistrationError)` is exposed and
  `RegistrationError::is_permanent()` is **public** — the daemon can already distinguish a permanent
  failure (bad/expired key) from interactive-login. No engine change needed; this is downstream work
  (bead `tsd-bml`).
- **Status without blocking**: `device_state()` is a non-blocking `watch` borrow — sufficient. Done.

---

## Suggested PR shape for the engine

#1 alone (the two-name re-export) is a tiny, safe, immediately-useful PR — do that first; it unblocks
a shipped feature. #2 and #3 are security-hardening and warrant their own reviewed PRs. #4 needs
design discussion. After #1 lands and the engine cuts a release, the daemon bumps its pinned
`rev`/version and flips TUN on in one line.

---

## 5. (BLOCKER for macOS TUN) Platform-aware default TUN interface name

**Why:** `ts_runtime::tun_actor::tun_config_from_control` defaults a `None` interface name to
`"tailscale0"` (Linux-style). On macOS the kernel requires utun interfaces to be named `utun*`, so
`tun-rs`'s `DeviceBuilder::name("tailscale0").build_async()` fails with **"device name must start
with utun"**, the TUN device is never created, and the overlay data path fails closed (the node
reaches Running on the control plane but has no working tunnel).

**Verified:** engine v0.6.7, `ts_runtime/src/tun_actor.rs:138` (`name: cfg.name.clone()
.unwrap_or_else(|| "tailscale0".to_owned())`) → `ts_transport_tun/src/async_tokio.rs:34`
(`DeviceBuilder::new().name(&config.name)`). On Linux `tailscale0` is fine; on macOS it is rejected.

**Ask:** make the default name platform-aware in `tun_config_from_control` (or wherever the `None`
name is resolved):
- Linux/BSD: `"tailscale0"` (unchanged).
- macOS: `"utun"` (bare prefix → the kernel assigns the next free `utunN`), or accept an empty/None
  name through to `tun-rs` so it auto-picks.

**Downstream note:** the daemon currently works around this by defaulting `tun_name` to `"utun"` on
macOS itself (`tailscaled-rs` `ipn::default_tun_name`). Once the engine picks a platform-correct
default, the daemon workaround can be removed (it becomes a redundant no-op).

---

## 6. ✅ FIXED in engine v0.6.10 — `ROUTE_BIN` was the Linux path `/usr/sbin/route`; on macOS `route` is `/sbin/route`

> **DONE.** The engine shipped the one-line fix in **v0.6.10** (`ts_host_net/src/macos.rs`:
> `const ROUTE_BIN: &str = "/sbin/route";`, commit `f0277391`). The daemon bumped its pin to that
> rev and **re-verified the fix live on the released engine**: `tnet up --tun` reaches `Running`
> with a tailnet `/32`, the log hits `TUN device created`, and there is **zero `os error 2`** (the
> fatal fail-closed string is gone); clean RAII teardown. Daemon bead `tsd-tth` closed. The section
> below is retained as the diagnostic record.
>
> **Original RESOLVED note (proven end-to-end live against a locally-patched v0.6.9, e126bba).**
> This supersedes BOTH earlier theories (the v6 `/128`, then the vaguer "host-route
> programming order is off"). The actual bug was a single wrong constant.

**Root cause (one line).** `ts_host_net/src/macos.rs:26`:
```rust
const ROUTE_BIN: &str = "/usr/sbin/route";   // ← Linux/iproute2 path. WRONG on macOS.
```
On macOS, `route(8)` ships at **`/sbin/route`** — there is **no** `/usr/sbin/route` (that path is
Linux). So `apply_routes` → `run_route` → `Command::new("/usr/sbin/route").args(argv).status()?`
returns `Err(ENOENT)`, which `?`-propagates out of `apply_routes` and is rendered as
**"No such file or directory (os error 2)"** — the exact fatal string in the trace. The TunActor
treats that `Err` as fatal and fail-closes (`host route programming failed; TUN idle`), tearing the
interface down. (`scutil` is fine — it really is at `/usr/sbin/scutil`. Only `ROUTE_BIN` is wrong.)

**The `code 49 AddrNotAvailable` is a RED HERRING — not fatal, not the engine's route shellout.** It
is logged by *tun-rs's own* associated-route helper, which is a `log::warn!`, not an error return
(`tun-rs-2.8.1/src/platform/macos/device.rs:85-87`):
```rust
if let Err(err) = siocaifaddr(ctl()?.as_raw_fd(), &req) { return Err(io::Error::from(err)); } // address assign — SUCCEEDS
if let Err(e) = self.add_route(addr.into(), mask.into(), associate_route) { log::warn!("{e:?}"); } // ← code 49, SWALLOWED as warn
```
tun-rs assigns the interface `/32` via `SIOCAIFADDR` successfully (it would `return Err` otherwise),
then its *own* `route_manager` `RTM_ADD` for the on-link `/32` warns `EADDRNOTAVAIL` and is ignored.
The device is created fine. This warn is unrelated to the fatal `os error 2`.

**The fix (one line):**
```rust
/// `route(8)` binary path. On macOS `route` lives in `/sbin`, NOT `/usr/sbin`.
const ROUTE_BIN: &str = "/sbin/route";
```

**Proof it is correct — verified live on this macOS box (Darwin 25.x), engine v0.6.9 patched to
`/sbin/route`, real tailnet:**
- `command -v route` → `/sbin/route`; `/usr/sbin/route` → does not exist (ENOENT).
- Direct OS check, current (broken) path: `sudo /usr/sbin/route … add …` → `command not found`.
- Direct OS check, fixed path: `sudo /sbin/route -n get -inet 100.100.100.100` → exit 0.
- With the patched engine, `tnet up --tun --tun-name utun11`:
  - `state: Running`, self `100.99.101.81`, 19 peers.
  - log reaches `ts_runtime::tun_actor: TUN device created prefix=100.99.101.81/32` — that line is
    the **last** statement in the StateUpdate handler (`tun_actor.rs:759`), only reached **after**
    `apply_routes` returns `Ok`. **No `os error 2`, no `host route programming failed`, no
    fail-closed teardown.** The exact pre-fix failure is gone.
  - the `route(8)` invocation now actually runs (its own stdout `add net 100.100.100.100: gateway
    utun11` appears in the log — proof the binary was found and executed).
  - `ifconfig utun11` → `inet 100.99.101.81 --> 100.99.101.81 netmask 0xffffffff`, MTU 1280.
  - clean RAII teardown on `tnet down`: utun11 removed, zero leftover routes.

**`route add` on an already-present route is NOT a second bug.** macOS `/sbin/route -n -q add` returns
**exit 0 even when it prints "File exists"** (EEXIST) — verified directly (`add` twice → both exit 0).
So `run_route`'s `status.success()` check passes whether the route is new or pre-existing; no extra
EEXIST tolerance is needed in `apply_routes`. (`expand_routes` already handles the `/0` EEXIST case
separately; the per-`/32` adds are naturally idempotent at the `route(8)` exit-code level.)

**Answer to the engine lane's earlier question (where the daemon builds the TUN Config / the prefix):**
the daemon does **NOT** construct `ts_transport_tun::Config` and supplies **no prefix** — it sets the
facade `transport_mode = TransportMode::Tun(TunConfig { name, mtu })` (only `name` + `mtu`, no prefix
field). Every prefix/route is derived inside the engine from `node.tailnet_address` /
`node.accepted_routes`. So this was never a daemon-side issue — confirming your instinct not to patch
blind. It's the one wrong constant above.

**Repro for the engine lane (to re-confirm after patching):** macOS, root, `--features tun`,
`tnet up --tun --tun-name utunNN` with `TAILNETD_LOG='info,ts_runtime::tun_actor=trace,ts_host_net=trace,tun_rs=debug'`.
Pre-fix: dies at `host route programming failed … os error 2`. Post-fix: reaches `TUN device created`
and `Running`. NOTE: if you test on a box that **already runs real Tailscale**, the host's existing
`utun` owns the whole `100.x` CGNAT range, so a *second* node's peer `/32`s lose the route race and
end-to-end ping won't traverse the new utun — that's a test-host artifact, not an engine bug. Test on
a box with no other Tailscale, or just assert the bring-up reaches Running + `TUN device created`
without the `os error 2`.

**Ask:** change `ROUTE_BIN` from `/usr/sbin/route` to `/sbin/route` in `ts_host_net/src/macos.rs`.
That's the entire fix. (Optional hardening, not required: resolve `route` via `PATH`/both-paths
fallback so it's robust to layout differences — but the absolute `/sbin/route` matches what Go
`tailscaled`'s `router_darwin` and `wireguard-apple` use, so a bare constant is fine.)

**Downstream:** daemon-side is complete (name fix #5 landed; daemon supplies no prefix). After this
lands + a release is cut, the daemon drops the temporary local `paths` override and bumps the pin.
**Linux TUN** uses bare `ip`/`resolvectl` (PATH-resolved) — unaffected by this; still untested from
this lane but has no analogous hardcoded-path trap.

---

## 7. ✅ PARTIALLY FIXED in engine v0.7.3 — SSH session-recording enforcement (engine bead `tsr-0h2`)

> **UPDATE:** the engine shipped the **session-recording enforcement** half in **v0.7.3** (`dd4b33e`,
> PR #25): `recorders` / `on_recording_failure` are no longer dropped in the domain conversion, and
> the SSH server now **fails closed** — when a matched rule requires recording but no recorder
> transport is available, the session is refused. That closes the silent-bypass. The daemon bumped
> its pin to v0.7.3 to pick this up. **Still open:** the interactive **check-mode**
> (`HoldAndDelegate`) just-in-time control round-trip, and the recorder *transport* itself — both
> deferred by the engine; the daemon's SSH server honors a record-required policy by refusing, the
> correct fail-closed posture until the recorder transport lands.

The daemon now runs the engine's turnkey `Device::listen_ssh` (Tailscale SSH server, tsd-46c,
shipped daemon v0.5.0). Base parity works live: policy accept/reject + privilege-drop login shell.
**Gap:** `ts_control/src/ssh_policy.rs:82-83` PARSES `recorders` / `on_recording_failure` and the
interactive check path off the netmap but **drops them before evaluation** — so:

- A policy with `action: "check"` (`HoldAndDelegate`) is not honored — there's no just-in-time
  control round-trip (`DoNoiseRequest` poll until Accept/Reject, with `OnPolicyChange` revocation).
- A policy that says "record this session or refuse" (`on_recording_failure: terminate/reject`) is
  **silently ignored** — a real policy bypass (the operator believes sessions are recorded; they
  aren't).

**Ask:** implement check-mode (the `HoldAndDelegate` round-trip) and enforce session-recording per
`OnRecordingFailure`, OR — if deferred — make the daemon-visible surface report that they're
unenforced so the daemon can warn loudly. This is engine-side (policy eval + the control noise
channel live in the engine). Daemon impact: until this lands, `tnet up --ssh` ships base server
parity only; the daemon documents the gap. Mirrors Go `tailssh`'s `evaluatePolicy` +
`fetchSSHAction` + `sessionrecording`.

## 8. Exit-node DNS path for forwarded clients — advertise side (engine bead `tsr-c39`)

When THIS node advertises itself as an exit node (`advertise_exit_node`, shipped daemon v0.4.0) and
egress is enabled, traffic forwarded **through** it has no DNS handling — the overlay router only
loopbacks MagicDNS (`100.100.100.100`) for the **local** node. Go's model expects the exit node to
also be the DNS path for its clients.

**Ask:** confirm whether forwarded-client DNS is in scope for the engine's forwarder (and if so, that
it stays v4-only + leak-free), or document that it's strictly the client-side daemon's concern. Filed
so the daemon doesn't wrongly assume the engine handles it. (The USE side is already leak-safe — see
ask #6 / the daemon's leak-safety invariant; this is specifically the ADVERTISE side.)

## 9. Document the live-set surface (engine bead `tsr-89s`)

The daemon's `tnet set` (shipped v0.5.0) applies `exit_node` **live** via `Device::set_exit_node`
(no reconnect) and **rebuilds** the device for every other pref (hostname / accept_routes /
advertise_* / ssh), because the engine `Config` is immutable per-construction.

**Ask (doc-only if the setters already exist):** publish the COMPLETE list of prefs the engine can
change **live** on a running `Device` (no rebuild) vs those that require reconstruction. Today the
daemon only knows `set_exit_node` is live; if `set_serve_config` / `listen_funnel` / others are also
live, the daemon's `set` can widen its seamless fast-path instead of triggering a brief reconnect.
No new engine code needed if the live setters already exist — just the contract.

## 10. `block_incoming` / shields-up Config field (engine bead — to file)

> ✅ **SHIPPED in engine v0.21.2** (pin bumped 2026-06-11). The engine grew the shields-up knob; the
> daemon-side `--shields-up` pref + CLI wiring is a future in-repo batch (no further engine work).

Go `tailscale up --shields-up` / `set --shields-up` drops all inbound connections from peers (the
node still reaches out). The daemon wants to surface this pref (`tsd-iqq.4`), but the engine `Config`
has no `block_incoming` / `shields_up` field and no packetfilter posture knob for it.

**Ask:** add `Config.block_incoming: bool` (default false) that, when set, makes the engine refuse
inbound peer connections (the local packetfilter / accept path drops them) while leaving outbound
intact — mirroring Go's `ShieldsUp` (`ipn.Prefs.ShieldsUp` → `filter` "shields up" mode). Daemon
then wires a `shields_up` pref + `--shields-up`/`--no-shields-up` like the other tri-state flags.

## 11. Surface the pushed DNS config on `Device` (engine bead — to file)

> ✅ **SHIPPED in engine v0.21.2** (`Device::dns_config()`, pin bumped 2026-06-11). `tnet dns status`
> is now a future in-repo batch.

For `tnet dns status` (Go `tailscale dns status`) the daemon needs to read the control-pushed DNS
config. The engine has `ts_control::DnsConfig { magic_dns, search_domains, resolvers }` internally,
but the `Device` facade exposes no accessor (no `Device::dns_config()` and `Status` carries no DNS).

**Ask:** add `Device::dns_config(&self) -> Option<ts_control::DnsConfig>` (or fold a DNS summary into
`Status`) so the daemon can render MagicDNS state + search domains + resolvers read-only. Pure
read-surface; no behavior change. Unblocks the DNS half of `tsd-ioh` (the `accept-dns` *pref* is
already wirable via the existing Config; this is only the status/diagnostics read).

## 12. Surface a netcheck / net-report on `Device` (engine bead — to file)

> ✅ **SHIPPED in engine v0.21.2** (`Device::netcheck()`, pin bumped 2026-06-11). `tnet netcheck` is
> now a future in-repo batch.

For `tnet netcheck` (Go `tailscale netcheck`) the daemon needs the node's network conditions — DERP
latencies, preferred DERP region, NAT/port-mapping detection (UPnP/PMP/PCP), UDP/IPv4/IPv6
reachability. The engine runs netcheck internally (DERP latency measurement is in the runtime), but
the `Device` facade exposes no accessor.

**Ask:** add `Device::netcheck(&self) -> Result<NetcheckReport, Error>` (or expose the last
net-report) summarizing DERP region latencies + preferred region + NAT/mapping flags, so the daemon
can render it read-only. `tnet ip`/`whois`/`ping` already shipped (engine had those accessors);
`netcheck` is the one diagnostic still missing an engine read-surface. Mirrors tsnet's netcheck.

## 13. Re-export the Funnel types at the engine crate root (facade completeness)

`Device::listen_funnel(&self, cfg: &ts_control::ServeConfig, opts: ts_control::FunnelOptions) ->
Result<ts_runtime::funnel::FunnelAcceptedReceiver, ts_control::FunnelError>` is public, but its
parameter/return types are NOT re-exported at the `tailscale` crate root. The facade re-exports
`ServeConfig`/`ServeState`/`ServeTarget`/`CertError` (from `ts_control`) but omits `FunnelOptions`,
`FunnelError`, and `ts_runtime::funnel::{FunnelAccepted, FunnelAcceptedReceiver}`. Result: an external
crate cannot name the `opts` argument's type, so `listen_funnel` is effectively uncallable through the
facade alone — exactly the gap the existing `TransportMode`/`TunConfig` re-export comment calls out.

**Workaround in use (daemon side):** a direct `geiserx_ts_control` dep pinned to the SAME rev as
`geiserx_tailscale`, so `ts_control::FunnelOptions` unifies to the identical type; the receiver type
is left inferred (the accept loop is inlined, never naming it).

**Ask:** add `pub use ts_control::{FunnelError, FunnelOptions, MISSING_FUNNEL_RELAY};` and
`pub use ts_runtime::funnel::{FunnelAccepted, FunnelAcceptedReceiver};` to `src/lib.rs` (alongside the
existing serve re-exports). Pure re-export, no behavior change. Lets the daemon drop the extra
`ts_control` dep and name the funnel accept loop's type in a free function.

## 14. `accept_dns` / CorpDNS Config gate (engine bead — to file)

The daemon wants `tnet up --accept-dns` / `--no-accept-dns` (Go `tailscale up --accept-dns`, the
`CorpDNS` pref: accept the tailnet's MagicDNS config onto the host resolver). This is the last
high-use `up`/`set` flag still unmodeled, and it is engine-blocked **only by a missing Config field** —
the OS-DNS machinery it gates **already exists**: `ts_host_net::apply_dns` (scutil on macOS,
resolvectl on Linux) programs the system resolver in TUN mode, called from `ts_runtime/tun_actor.rs`
when control pushes MagicDNS=on, and an **empty `nameservers` list is already a clean no-op** on both
platforms (`macos.rs` / `linux.rs` early-return). So `accept_dns=false` just needs to route into that
existing skip path — a thin gate, NOT greenfield resolver work.

**Ask (mirrors the `accept_routes` threading end-to-end):**
1. `ts_control/src/config.rs`: add `pub accept_dns: bool` (sibling of `accept_routes`), **default
   `true`** (Go's CorpDNS is default-on); add to the `Default` impl. `#[serde(default)]` for wire
   back-compat.
2. `ts_runtime/src/env.rs`: thread `accept_dns` through `ForwarderConfig`/`Env` + `from_control_config`
   (exactly as `accept_routes` is threaded).
3. `ts_runtime/src/tun_actor.rs`: the **one consume site** — where `magic_dns` is computed
   (`msg.dns_config…d.magic_dns`) and `host_dns_from_dns_config` is called, AND in `env.accept_dns` so
   that `accept_dns=false` forces the **DNS-apply** path to empty nameservers (the in-netstack
   100.100.100.100 responder itself stays untouched; also keep the quad-100/32 route-steer consistent
   with the gated decision so it isn't routed into the TUN when DNS isn't accepted). Do NOT put this in
   `HostRouteGating` — that gates routes; DNS is a separate decision in the StateUpdate handler.

Suggested engine test: assert `accept_dns=false` ⇒ empty nameservers even with `magic_dns=true`
(mirror `host_dns_nameservers_point_at_magic_dns_when_enabled`).

**Daemon side once landed (no engine help needed):** `Prefs.accept_dns` (default true) → `build_config`
maps it onto `Config.accept_dns` → `up`/`set --accept-dns`/`--no-accept-dns` tri-state + the
revert-guard lockstep + `get`/`status` surfacing (the `tnet status`/`dns status` "Use Tailscale DNS"
placeholder lines are already present to replace). **Only observable in `--tun` mode** (netstack mode
never programs the host resolver), so the daemon pref + guard are offline-testable but the actual
scutil/resolvectl effect wants the live Mac-Mini TUN gate.

> Posted as a heads-up on the engine lane's `docs/COORDINATE.md` board (active engine session,
> iter36/37). The daemon consumes it via a pin bump after it lands — no blocking; the daemon proceeds
> with in-lane work meanwhile.

## 15. `Device::query_dns(name, qtype)` — a real forwarder DNS query (for a faithful `tnet dns query`)

The daemon wants `tnet dns query <name> [type]` (Go `tailscale dns query`), which resolves a name
**through the node's DNS path** and prints the answer records, the RCODE, and which resolver(s)
answered. The engine's only resolution primitive today is `Device::resolve()` (verified at pin
f42eb70e, `src/lib.rs:500`): an **in-process netmap `dnsMap` lookup** — MagicDNS names only, IPv4
only, no upstream/forwarder query, no record types, no RCODE, no resolver info, `Ok(None)` for any
non-tailnet name. Building `dns query` on `resolve()` would ship a command that *looks like* a DNS
query but silently isn't (no A/AAAA/CNAME/MX/TXT/…, no split-DNS forwarding, no RCODE) — a
low-fidelity facsimile that violates the honest-omission discipline this daemon holds to. So `dns
query` is **deferred**, not faked.

**Ask:** add `Device::query_dns(&self, name: &str, qtype: …) -> Result<…wire response + resolvers…>`
that runs an actual query through the engine's DNS forwarder (the 100.100.100.100 path), returning the
parsed answer records + RCODE + the resolver(s) consulted — the analogue of Go's `localClient.QueryDNS`
(`cmd/tailscale/cli/dns-query.go`). Once it lands, the daemon adds `tnet dns query` as a faithful
read (the `whois`/`id-token` plumbing pattern) consumed via a pin bump. No rush — filed so the gap is
recorded, not forgotten.

## 16. `Device::cert_pair(name, min_validity)` — PEM cert **and private key** (for a faithful `tnet cert`)

The daemon wants `tnet cert <domain>` (Go `tailscale cert`), which writes BOTH `<domain>.crt` and
`<domain>.key` PEM files to disk (the key at mode `0600`) — Go's `localClient.CertPairWithValidity`
returns `(certPEM, keyPEM)` (`cmd/tailscale/cli/cert.go:123`). The engine's only cert accessor at the
current pin (v0.28.2) is `Device::get_certificate(name) -> CertifiedKey` (`src/lib.rs:1471/1478`),
which returns a `rustls::sign::CertifiedKey` (`ts_control/src/cert.rs:80`): the certificate **chain**
is recoverable as PEM (DER → re-encode), but the **private key is consumed into an opaque `rustls`
`SigningKey`** and is not retrievable as PEM — `issue_certificate` (`ts_control/src/acme.rs`) returns
only the assembled `CertifiedKey`. So the daemon could write a usable `.crt` but **not** the `.key` —
a half-feature the honest-omission discipline forbids. So `cert` is **deferred**, not faked.

**Ask:** add `Device::cert_pair(&self, name: &str, min_validity: Option<Duration>) -> Result<(cert_pem:
String, key_pem: String)>` (the analogue of Go's `CertPairWithValidity`) — surface the ACME-issued
leaf private key as PEM alongside the chain, so the daemon can write the Go-faithful `.crt` + `.key`
pair. Once it lands, the daemon adds `tnet cert` (consumed via a pin bump). Tracked in the daemon as
bead `tsd-xkq`.

## 17. TKA mutation — `Device::tka_{init,sign,disable,…}` (for `tnet lock` write-ops)

The daemon ships `tnet lock status` (read-only) faithfully, but the **write half** of Go's
`tailscale lock` (`init` / `add` / `remove` / `sign` / `disable` / `local-disable` / `revoke-keys` —
`cmd/tailscale/cli/tailnet-lock.go`) has no engine surface. At v0.28.2 the only TKA primitive is
`Device::tka_status() -> Option<TkaStatus>` (`src/lib.rs:1129`), a **read-only carrier**: `TkaStatus`
(`ts_control/src/tka.rs`) exposes only the authority head + disablement signal, and the module doc
states the actual signature/verification logic lives in the `ts_tka` crate with **no `Device` method
to sign an AUM, initialize the authority, or mutate the trusted-key set**. Building the write-ops on
the current surface is impossible without faking the cryptographic signing — forbidden.

**Ask:** add the TKA mutation methods to `Device` (init the authority, sign/co-sign an AUM, add/remove
a trusted key, disable/local-disable, revoke keys) — the analogues of Go's `localClient.NetworkLock*`
calls — backed by the `ts_tka` crate's signing. Once they land, the daemon adds `tnet lock`
init/sign/add/remove/disable/revoke (consumed via a pin bump). Tracked in the daemon as bead
`tsd-1r6` (the enforcement epic). No rush — filed so the frontier is recorded.

## 18. Windows host route/DNS programming in `ts_host_net` (for `--tun` parity on Windows)

The engine's `ts_host_net` (the TUN-mode host route/DNS chokepoint, wired into
`ts_runtime/tun_actor.rs`) ships `linux.rs` + `macos.rs` but **no `windows.rs`** (verified at pin
`81446f88`). So a `--tun` node on Windows brings up the wintun interface but `host_net()` returns
`Unsupported` — no OS routing table / DNS programming, i.e. no transparent connectivity. This is the
engine-side analogue of Go's `wgengine/router/router_windows.go` + the Windows DNS manager.

**Why it's an engine ask, not daemon work:** as with the macOS/Linux routers (daemon beads `tsd-jys`
/ `tsd-5u2`, both closed as engine-absorbed), the daemon has **no routing seam** — the facade exposes
no `host_net`, and routing lives inside `ts_runtime` gated on `TransportMode::Tun`. The daemon's only
Windows-TUN role would be wintun-name selection + the privilege preflight (the analogue of the
macOS `lowest_free_utun` + root check it already does). The routing/DNS itself must be engine-side.

**Ask (LOW priority — Windows is daemon bead `tsd-1yw` P3, no consumer needs it yet):** add
`ts_host_net/src/windows.rs` mirroring Go `router_windows.go` (route table via the Windows routing
API / `netsh`, DNS via the NRPT or per-interface resolver). Filed so the gap is recorded; the daemon
consumes it for free (it's automatic in the TUN datapath) once it lands. No rush. — daemon lane

## 19. (BUG — TUN mode has no peer connectivity) `host_routes_from_node` omits peer AllowedIPs

**Severity: HIGH for `--tun` mode** (TUN-mode nodes can reach MagicDNS but NOT their tailnet peers).
**Found via a live Linux TUN end-to-end on a fresh ARM64 VM (2026-06-12)** — the first live `--tun`
drive of the daemon (userspace mode was the only path previously verified).

**Repro (Linux ARM64, Ubuntu 24.04, engine pin 81446f88 / v0.28.2):** `tailnetd` (root) +
`tnet up --tun` joins the tailnet and reaches `Running`, `TUN: True`, self `100.64.0.1` (illustrative
CGNAT addr). The kernel `tailscale0` iface is created and carries `inet 100.64.0.1/32` (✅ device +
self-addr work). But:
- `ip -4 route show` has **only** `100.100.100.100 dev tailscale0` (the MagicDNS /32). **No per-peer
  `100.x/32` routes** — even though `tnet status --json` shows peers online with e.g.
  `AllowedIPs: ['100.64.0.2/32']`.
- `ip route get 100.64.0.2` → `via <gateway> dev <eth>` (the **physical** iface, not the TUN).
- `ping -c3 100.64.0.2` → 100% loss. TUN-mode peer connectivity is broken.

**Root cause (read `ts_runtime/src/tun_actor.rs` `host_routes_from_node` @ 81446f88):** the host route
set is built **solely from `node.accepted_routes`** (the subnet-routes-this-node-accepts set, gated on
`--accept-routes`) + the MagicDNS `/32`. It **never adds the peers' AllowedIPs** (the per-peer tailnet
`/32`s). Go `tailscaled` feeds the router `Config.Routes` = the **union of every peer's AllowedIPs**
(`wgengine` → `router.Set`), so each peer's `100.x/32` is routed via the tailscale iface. Our engine
omits that union entirely, so the OS has no route to any peer over the TUN — traffic falls through to
the default (physical) route.

**Ask (the Go-parity fix):** in `host_routes_from_node`, ALSO install each peer's AllowedIPs (the
per-peer `100.x/32` + any peer-advertised subnet the node accepts) as routes `dev <tun>` — the union
Go's `wgengine` passes to the router. The peer set is in the netmap the `tun_actor` already holds
(the same source `status` reads peers + AllowedIPs from). Keep IPv4-only + the self-`/32` exclusion +
the `/0`-only-if-exit-node gating as-is; this is purely ADDING the peer-AllowedIPs union that's
currently missing. Suggested test: a TUN node with ≥1 peer ⇒ `ip route` has a `dev <tun>` route for
that peer's `/32`, and `ip route get <peer_v4>` selects the TUN.

**Daemon impact:** none on the daemon side (the daemon just selects TUN; the engine owns route
programming, ask #18 / the closed router beads). The daemon consumes the fix via a pin bump and the
Linux TUN e2e (this repro) then passes A4 (peer connectivity). Filed with full live evidence; the
daemon's Phase-3 "transparent OS-wide connectivity" claim is blocked on this for the peer-reachability
half (the device/self-addr/MagicDNS half already works). — daemon lane

## 20. A Taildrop **file-arrival** signal on the IPN bus (for `tnet file get --wait` / `--loop`)

**Why:** Go's `tailscale file get` has `--wait` (block until ≥1 file arrives if the inbox is empty)
and `--loop` (drain forever, receiving files as they come in). Both rest on Go's `waitForFile`, which
long-polls the LocalAPI `IPNBusWatcher` for an `IncomingFiles` notification and returns when the inbox
becomes non-empty. The daemon shipped the inbox **drain** (`tnet file get <dir>` + `--conflict`, PR
#136) over the engine's existing `taildrop_waiting_files`/`open_file`/`delete_file` primitives — but
`--wait`/`--loop` are **deferred** because the engine's `watch_ipn_bus` (verified at pin `6035651`,
`src/lib.rs:1405`) carries only `state` / `net_map` / `browse_to_url` in its `Notify` — there is **no**
`IncomingFiles` / file-arrival event. A daemon-side poll loop (re-list every N seconds) is possible but
wasteful and racy, so it's not built; the feature waits on an honest signal.

**Ask:** surface a Taildrop file-arrival notification — either (a) add an `incoming_files:
Option<Vec<WaitingFile>>` field to the existing `watch_ipn_bus` `Notify` (the Go shape — Go's
`ipn.Notify.IncomingFiles`), fired whenever the receive store gains a file; or (b) a dedicated
`Device::watch_incoming_files() -> watch::Receiver<Vec<WaitingFile>>` analogous to `watch_netmap`. Once
it lands, the daemon adds `--wait` (await the first non-empty signal, then drain once) and `--loop`
(drain on every signal) to `tnet file get`, consumed via a pin bump. No rush — recorded so the gap is
not forgotten; the drain itself is already faithful without it. — daemon lane

## 21. Engine `Config` fields for the ~12 missing Go `up`/`set` pref flags

**Why:** Go's `tailscale up`/`set` (v1.100.0 `up.go:99-148`, `set.go:76-122`) expose ~15 pref flags;
this fork's `up`/`set` faithfully cover the ten that map to existing engine `Config` fields
(`hostname`, `accept-routes`, `accept-dns`, `shields-up`, `exit-node`, `advertise-exit-node`,
`advertise-routes`, `advertise-tags`, `ssh`, `tun`). The remainder are **not daemon-fixable today**
because the pinned engine `Config` (rev `6035651`, `src/config.rs`) has **no field** to carry them, and
the honest-omission rule forbids shipping a flag that parses but silently does nothing (the historical
`accept_dns` inert-flag trap). Confirmed by reading the authoritative `Config` struct: its fields end
at `audience`, with nothing for any of the flags below.

**Ask — add the engine `Config` fields (Go pref name → suggested field), so the daemon can wire each
faithfully (a wire `Up`/`Set` field + pref mapping + the revert-guard/`--reset` lockstep + a
`get_settings` row):**

- `--operator <user>` → `operator_user: Option<String>` (also the substrate for the operator-GID
  LocalAPI authz matrix the daemon's THREAT_MODEL notes as a later phase).
- `--exit-node-allow-lan-access <bool>` → `exit_node_allow_lan_access: bool` (Go
  `Prefs.ExitNodeAllowLANAccess`; only meaningful with an exit node selected).
- `--nickname <name>` → `nickname: Option<String>` (Go `Prefs.ProfileName`-adjacent / node nickname).
- `--report-posture <bool>` → `posture_checking: bool` (Go `Prefs.PostureChecking`).
- `--auto-update <bool>` / `--update-check <bool>` → `auto_update: { apply: Option<bool>, check:
  Option<bool> }` (Go `Prefs.AutoUpdate`). *(Caveat: the daemon also lists self-update as a NON-GOAL —
  see DESIGN §"Non-goals". If the engine carries the pref purely as state to report to control, the
  daemon can wire the flag as a pref without implementing an updater; flagging the tension.)*
- `--advertise-connector <bool>` → an app-connector pref/field (Go `Prefs.AppConnector`). Distinct from
  the existing `advertise_services` (that is service-advertise, not the app-connector role).
- `--webclient <bool>` → `run_web_client: bool` (Go `Prefs.RunWebClient`). *(Also a daemon NON-GOAL as
  a UI; same caveat as auto-update — pref-state only, no embedded server.)*
- Linux subnet-router knobs: `--snat-subnet-routes`, `--stateful-filtering`, `--netfilter-mode`,
  `--unattended` → the engine's router/netfilter layer (Go `Prefs.NoSNAT` / `NoStatefulFiltering` /
  `NetfilterMode` / `Unattended`). These ride on the Linux OS-router (daemon bead tsd-m8s) and are
  lower priority.

**Workload-identity flags** (`--client-id`/`--client-secret`/`--id-token`/`--audience`) are a SEPARATE
case: the engine `Config` **already has** `client_id`/`client_secret`/`id_token`/`audience`, but they
are behind the engine's **`identity-federation` cargo feature**, which this fork's engine dep does NOT
enable — so wiring them today would also be inert. **Sub-ask:** confirm whether enabling
`identity-federation` on the engine dep is supported/compiles; if so the daemon can wire those four
flags immediately (they need no new engine field, only the feature on). Tracked in daemon bead
tsd-1m9, which is BLOCKED on this ask. — daemon lane
