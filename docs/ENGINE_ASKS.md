# What the daemon needs from the `tailscale-rs` engine

This lists the changes the downstream daemon (`tailscaled-rs`) needs from the `tailscale-rs`
library to unblock end-to-end features. Each ask is self-contained, additive, and
backward-compatible. The daemon pins engine rev `35e5db22` (`v0.41.0`); individual asks
note the rev they were verified against (older "verified vs `e126bba`/v0.6.9" / `81446f88`/v0.28.2
/ `6035651b`/v0.29.1 / `f3793636`/v0.31.0 / `575104b1`/v0.32.0 / `f8192568`/v0.33.0 / `1694d208`/v0.34.2
/ `faf46b34`/v0.35.8 notes below predate the current pin and are kept as historical context — the SHIPPED
markers reflect what the pin provides). Bumps since v0.33.0: → v0.34.2 (tka chokepoint, cap parity, taildrop
length-verify) → v0.35.3 (control-runner unbounded mailbox, tka rotation-drop, tunnel/derp fixes) →
v0.35.8 (netcheck hysteresis, dataplane ACL, magicsock STUN, derp wire keys, taildrop symlink-refuse) →
v0.39.0 → v0.40.0 → v0.41.0 (current pin) — all transparent except the `DeviceState` growth noted in the
v0.40.0 header below, each clippy+test-verified.

> **Pin bump fe86ca00 (v0.40.0) → 35e5db22 (v0.41.0), 2026-06-16.** Probe-compiled first (against the
> pre-tag HEAD `73f56b1e`): CLEAN — no breaking change, purely additive. **SHIPS + CONSUMES ask #24**:
> the engine now exposes `Device::suggest_exit_node() -> Result<Option<ExitNodeSuggestion>, Error>`
> (#267, mirroring Go `LocalClient.SuggestExitNode`), where `ExitNodeSuggestion { id: StableNodeId,
> name: String }`, `Ok(None)` = no eligible candidate (an honest empty result, NOT an error), and `Err`
> = no usable netcheck report yet (no measured preferred DERP region for the latency ranking). Consumed
> as `tnet exit-node suggest` (the consuming change rides this bump): a new read-only `SuggestExitNode`
> LocalAPI verb → off-lock `Device::suggest_exit_node` → prints the suggested node + a `tnet set
> --exit-node=<id>` hint (or a clear "no suggestion available" notice). Also pulls the `ts_netmon` crate
> publish fix (#264) for free (workspace-release plumbing, no daemon surface).

> **Pin bump 3e81d862 (v0.39.0) → fe86ca00 (v0.40.0), 2026-06-15.** Probe-compiled first; the ONE
> breaking change was caught + handled there: the engine's `#[non_exhaustive]` `DeviceState` grew two
> reachable variants — `NeedsMachineAuth` (registered, awaiting admin approval, no auth URL) and
> `Reauthenticating` (auto non-interactive re-auth on node-key expiry in progress). The daemon's
> `state_from_device` (src/ipn/state.rs) now maps `NeedsMachineAuth → State::NeedsMachineAuth` (finally
> *producing* the previously-parity-only ipn.State — this is the engine half of bead **tsd-ccv**, now
> unblocked) and `Reauthenticating → State::Starting` (transient, no action), plus a forward-compat
> `_ => Starting` wildcard. **SHIPS + CONSUMES three asks** (all via #263 "add engine surface for
> daemon"): **#22** `Config.wireguard_listen_port: Option<u16>` (→ `tailnetd --port`/`PORT`), **#23**
> `StatusNode.ssh_host_keys: Vec<String>` in known_hosts format (→ a faithful `tnet ssh` with pinned
> host-key verification), **#26** `Device::re_stun()` (→ `tnet debug restun`, lighter than rebind). Also
> pulls for free: auto re-auth on key expiry (#260), opt-in network-monitor auto-rebind (#261), zstd
> map-response decode (#257), hostinfo Container/Env detection (#255), admin-approval polling instead of
> dying (#262). NEXT to consume: wire `tailnetd --port`, `tnet ssh`, `tnet debug restun` (separate PRs
> after this bump lands), and surface NeedsMachineAuth's "approve this device" hint.

> **Pin bump 575104b1 (v0.32.0) → f8192568 (v0.33.0), 2026-06-13.** Clean bump — full gate green;
> probe-compile clean (no breaking surface). **Completes the Tailnet Lock surface**: the engine now
> exposes `Device::tka_init(disablement_secret)` (#175, "epic complete") — initialize the lock with
> this node as the sole initial trusted key (Go `tailscale lock init`, single-node case). Consumed as
> `tnet lock init <disablement-secret>` (the consuming change rides this bump). So `tnet lock` now has
> the full verb set: `status` (read), `init`, `sign`, `disable`. NOTE the engine's `tka_init` is
> **single-node only** — a multi-node tailnet (other nodes needing re-signing under the new lock) gets
> `Unsupported`; multi-node init is a deferred engine follow-up (file an ask if/when wanted).

> **Pin bump f3793636 (v0.31.0) → 575104b1 (v0.32.0), 2026-06-13.** Clean bump — full gate green;
> probe-compile clean (no breaking surface). **Unblocks `#17` Tailnet Lock enforcement / write-ops**:
> the engine now exposes the `Device`-level TKA drivers — `Device::tka_sign(&NodePublicKey)` (#169,
> co-sign a node key into the lock = Go `NetworkLockSign`) and `Device::tka_disable(Vec<u8>)` (#170,
> present the disablement secret = Go `NetworkLockDisable`), over the new control TKA mutation RPC
> (#168). Previously only `Aum::sign` (a primitive) + read-only `tka_status` existed (v0.31.0), so
> `tnet lock` was read-only; now `tnet lock sign`/`tnet lock disable` are daemon-fixable (the
> consuming PR follows this bump). Also newly available: `Device::http_connector` (#165, HTTP over
> the tailnet — a possible future slice). NOTE `Device::tka_init` (#175, `tnet lock init`) landed on
> engine main AFTER the v0.32.0 tag → it rides the next bump (v0.33.0).

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

> ✅ **RESOLVED (current pin v0.35.8).** The engine now exposes — and the daemon's `tnet set` calls —
> **six** in-place live setters (no reconnect): `Device::set_exit_node`, `set_hostname`,
> `set_accept_routes`, `set_accept_dns`, `set_advertise_routes`, `set_advertise_exit_node`. The
> remaining `set`-able prefs are rebuild-only because the engine has no live setter for them:
> `shields_up` (immutable `Config.block_incoming`), `advertise_tags` (registration-time
> `Config.requested_tags`), `ssh` (device-lifecycle task). The daemon's `SetOptions::needs_rebuild()`
> encodes exactly this split and is now structurally drift-guarded by
> `set_options_live_vs_rebuild_classification_no_silent_drift` (an exhaustive `SetOptions` destructure
> forces every new field into a conscious Live/Rebuild decision at compile time). So the original ask
> — "publish the complete live-vs-rebuild contract" — is satisfied; the contract lives in
> `SetOptions::needs_rebuild`'s doc + that test. (Historical: at v0.5.0 only `set_exit_node` was live
> and every other pref rebuilt; the v0.28.2 engine added the other five live setters.)

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

## 21. ✅ MOSTLY SHIPPED — Engine `Config` fields for the missing Go `up`/`set` pref flags

> ✅ **SHIPPED at the current pin (`9d847a6`, engine v0.43.0)** for eight of the flags below, and the
> daemon wired them in `tsd-1m9`: `--operator` (`Config.operator_user`), `--nickname`
> (`node_nickname`), `--report-posture` (`posture_checking`), `--advertise-connector`
> (`advertise_app_connector`), `--webclient` (`run_web_client`), `--exit-node-allow-lan-access`
> (`exit_node_allow_lan_access`), `--auto-update` (`auto_update_apply`, an `Option<bool>` mirroring
> Go's `opt.Bool`) and `--update-check` (`auto_update_check`). Each is threaded on to
> `ts_control::Config`. Two of them genuinely reach control — the engine folds
> `advertise_app_connector` into `Hostinfo.AppConnector` and `auto_update_apply == Some(true)` into
> `Hostinfo.AllowsUpdate`, at registration and on every map request — so `tnet set` rebuilds the
> device for those two (they are construction-time fields with no runtime setter). The other six are
> CARRIED prefs: the engine stores them and never acts on or sends them, and the daemon does not act
> on them either yet, so `tnet set` only persists them (no reconnect). Each flag's `tnet` help and
> `Prefs` doc says exactly what is and is not implemented.
>
> **Still open:** the Linux subnet-router knobs at the end of the ask list (`--snat-subnet-routes`,
> `--stateful-filtering`, `--netfilter-mode`, `--unattended`), which need the engine's router/netfilter
> layer and ride the Linux OS-router work (`tsd-m8s`). The original ask is kept below for that
> residue and as the record of what was requested.
>
> **Follow-ups the daemon still owes (each its own bead, none required for the flags to be faithful):**
> consuming `operator_user` in the LocalAPI authorization matrix (today it is recorded, and the write
> policy is still root/same-euid — THREAT_MODEL already scopes this as a later phase). Unifying
> `node_nickname` with the per-profile display name in `profiles.json` that `tnet switch --list`
> shows — which Go drives from the same `Prefs.ProfileName` — is **done**: `set --nickname` now also
> renames the current profile, so `nickname` is carried by the ENGINE but not inert locally.

**Why — the rationale AS FILED, against pin `6035651`. Superseded for eight of the flags; kept as
the record of what was asked for and why.** Go's `tailscale up`/`set` (v1.100.0 `up.go:99-148`,
`set.go:76-122`) expose ~15 pref flags; this fork's `up`/`set` faithfully covered only the ten that
mapped to existing engine `Config` fields (`hostname`, `accept-routes`, `accept-dns`, `shields-up`,
`exit-node`, `advertise-exit-node`, `advertise-routes`, `advertise-tags`, `ssh`, `tun`). The remainder
were **not daemon-fixable at that pin** because the engine `Config` (rev `6035651`, `src/config.rs`)
had **no field** to carry them, and the honest-omission rule forbids shipping a flag that parses but
silently does nothing (the historical `accept_dns` inert-flag trap). That was confirmed by reading the
authoritative `Config` struct: its fields ended at `audience`, with nothing for any of the flags below.

**Why it still stands, at pin `9d847a6` — for the Linux router knobs only.** The engine has since
added a field for eight of the flags and the daemon wired them (banner above), so "no field to carry
them" now describes `--snat-subnet-routes`, `--stateful-filtering`, `--netfilter-mode` and
`--unattended` alone: for those four the reasoning above is unchanged and they stay unshipped rather
than parse-and-do-nothing. The list below is marked per entry — ✅ SHIPPED at `9d847a6` (the daemon
carries the pref today), ⬜ STILL OPEN (no engine field; this is the live ask).

**Ask — add the engine `Config` fields (Go pref name → suggested field), so the daemon can wire each
faithfully (a wire `Up`/`Set` field + pref mapping + the revert-guard/`--reset` lockstep + a
`get_settings` row):**

- ✅ SHIPPED — `--operator <user>` → `operator_user: Option<String>` (also the substrate for the
  operator-GID LocalAPI authz matrix the daemon's THREAT_MODEL notes as a later phase).
- ✅ SHIPPED — `--exit-node-allow-lan-access <bool>` → `exit_node_allow_lan_access: bool` (Go
  `Prefs.ExitNodeAllowLANAccess`; only meaningful with an exit node selected).
- ✅ SHIPPED — `--nickname <name>` → `nickname: Option<String>` (Go `Prefs.ProfileName`-adjacent /
  node nickname).
- ✅ SHIPPED — `--report-posture <bool>` → `posture_checking: bool` (Go `Prefs.PostureChecking`).
- ✅ SHIPPED — `--auto-update <bool>` / `--update-check <bool>` → `auto_update: { apply:
  Option<bool>, check: Option<bool> }` (Go `Prefs.AutoUpdate`). *(Caveat: the daemon also lists
  self-update as a NON-GOAL — see DESIGN §"Non-goals". If the engine carries the pref purely as
  state to report to control, the daemon can wire the flag as a pref without implementing an
  updater; flagging the tension.)*
- ✅ SHIPPED — `--advertise-connector <bool>` → an app-connector pref/field (Go
  `Prefs.AppConnector`). Distinct from the existing `advertise_services` (that is service-advertise,
  not the app-connector role).
- ✅ SHIPPED — `--webclient <bool>` → `run_web_client: bool` (Go `Prefs.RunWebClient`). *(Also a
  daemon NON-GOAL as a UI; same caveat as auto-update — pref-state only, no embedded server.)*
- ⬜ STILL OPEN — Linux subnet-router knobs: `--snat-subnet-routes`, `--stateful-filtering`,
  `--netfilter-mode`, `--unattended` → the engine's router/netfilter layer (Go `Prefs.NoSNAT` /
  `NoStatefulFiltering` / `NetfilterMode` / `Unattended`). These ride on the Linux OS-router (daemon
  bead tsd-m8s) and are lower priority.

**Workload-identity flags** (`--client-id`/`--client-secret`/`--id-token`/`--audience`) are a SEPARATE
case: the engine `Config` **already has** `client_id`/`client_secret`/`id_token`/`audience`, but they
are behind the engine's **`identity-federation` cargo feature**, which this fork's engine dep does NOT
enable — so wiring them today would also be inert. **Sub-ask:** confirm whether enabling
`identity-federation` on the engine dep is supported/compiles; if so the daemon can wire those four
flags immediately (they need no new engine field, only the feature on). Tracked in daemon bead
tsd-1m9, which is BLOCKED on this ask. — daemon lane

## 22. A configurable WireGuard/disco listen port on `Config` (for `tailnetd --port` / `PORT`)

**Why:** Go `tailscaled` takes `--port` (and `PORT=` via its systemd/openrc `EnvironmentFile`, default
`41641`) — the UDP port magicsock binds for WireGuard + disco. Operators behind a firewall that only
forwards/pinholes a fixed UDP port need to pin it; a node that binds an ephemeral port can't be
reached for direct (non-DERP) connectivity through such a firewall. The daemon already shipped the
rest of the `tailnetd` flag plane (`--statedir`/`--socket`/`--verbose`/`--version`/`--config`, PR
#139/#140), but **`--port` cannot be wired faithfully**: verified at the current pin (`f3793636`,
`v0.31.0`, `src/config.rs`) the engine `Config` has **no** WireGuard/disco listen-port field — only
the inbound-forwarder `forward_tcp_ports`/`forward_udp_ports` (a different concept), and there is no
`Device` listen-port setter (`src/lib.rs` has no `set_port`/`listen_port`). So a `tailnetd --port`
today would be an inert flag — refused under the honest-omission rule (the `accept_dns` trap).

**Ask:** add a configurable listen port for the magicsock UDP socket — either a
`Config.wireguard_listen_port: Option<u16>` (`None` = ephemeral, as today; `Some(p)` binds `p`),
matching Go `tailscaled`'s `--port` semantics (and Go's `0` = "pick any", which maps to `None`). If
the engine prefers a runtime setter, a `Device::set_listen_port`/rebind is also fine, but the
construction-time `Config` field is the closest match to Go (the port is fixed at daemon start).

**Daemon impact once landed:** `tailnetd` adds `--port <PORT>` + the `PORT` env (Go's
`EnvironmentFile` convention), threads it into `build_config` as the new field, and the packaged
systemd unit can set `PORT=41641`. Low-to-medium priority — it matters specifically for
fixed-firewall-pinhole deployments; an ephemeral port is fine for the common NAT-traversal case.
Tracked in daemon bead tsd-k7s (the one remaining engine-gated item there). — daemon lane

## 23. Per-peer SSH host keys in `StatusNode` (for `tnet ssh`)

**Why:** Go's `tailscale ssh [user@]<host>` resolves the peer via the daemon status, writes a
`known_hosts` file from each peer's **SSH host keys** (`genKnownHosts` reads `ps.SSH_HostKeys`), and
execs the system `ssh` with `StrictHostKeyChecking=yes` + that `UserKnownHostsFile` — so `ssh`
verifies the peer's host key **pinned from the netmap** (no TOFU prompt, no MITM window). The daemon
has everything else needed (`peerStatusFromArg` resolution over the peer name/IP, the `-o` flag set,
the `ProxyCommand` via `tnet nc`, the exec) — but the engine's `StatusNode`
(`ts_runtime/src/status.rs`) carries **no SSH-host-keys field**, so we cannot build a faithful
`known_hosts`. Shipping a degraded version (skip the file / `StrictHostKeyChecking=accept-new`) would
be a *less secure* facsimile of Go's pinned-key posture — refused under the honest-omission rule.

**Ask:** surface each peer's SSH host keys in the status. Add `ssh_host_keys: Vec<String>` to
`StatusNode` (the netmap already carries the peers' `Hostinfo.SSH_HostKeys` — this just projects them
into the status the daemon reads), matching Go's `ipnstate.PeerStatus.SSH_HostKeys` (a slice of
`known_hosts`-format public-key lines).

**Daemon impact once landed:** the daemon adds `tnet ssh` — `peerStatusFromArg` resolve → write
`<state_dir>/ssh_known_hosts` from the new field → exec `ssh` with Go's exact `-o` options +
`ProxyCommand`. Consumed via a pin bump. Tracked in daemon bead tsd-dy5. — daemon lane

## 24. `Device::suggest_exit_node()` — best-available exit node (for `tnet exit-node suggest`)

**Why:** Go's `tailscale exit-node suggest` calls `LocalClient.SuggestExitNode`, which asks the
daemon to pick the best available exit-node peer (by DERP-region proximity / latency / priority) and
prints its name with "run `tailscale set --exit-node=…`". The daemon has the peer list (`status()`)
but **no suggestion logic + no engine method** that reproduces Go's selection algorithm
(`ipnlocal.SuggestExitNode`, which weighs region latency + a deterministic tiebreak). Hand-rolling a
*different* heuristic daemon-side would silently diverge from Go's choice (a fidelity gap), and the
inputs Go uses (per-peer DERP region + measured latency + capability weighting) are not all surfaced
on `NodeInfo`/`Status` today.

**Ask:** add `Device::suggest_exit_node() -> Result<Option<ExitNodeSuggestion>, Error>` reproducing
Go's `SuggestExitNode` selection (region-latency-weighted, deterministic tiebreak), returning the
chosen peer's `StableNodeId` + name (Go's `apitype.ExitNodeSuggestionResponse`). Verbatim parity with
Go's algorithm is the point — a different heuristic is worse than none.

**Daemon impact once landed:** `tnet exit-node suggest` → `Response::ExitNodeSuggestion` → print the
name + the `set --exit-node` hint (Go's exact wording), "no suggestion" when none. Read-only.
Consumed via a pin bump. Tracked in daemon bead tsd-jz2. — daemon lane

## 25. TKA key-set mutation + AUM log — `Device::tka_{add,remove,log}` (for `tnet lock add/remove/log`)

> ✅ **PART (b) SHIPPED — `Device::tka_log(limit) -> Result<Vec<TkaLogEntry>, Error>` is on the facade
> at the current pin** (documented there as the Rust analog of Go `LocalClient.NetworkLockLog`;
> `TkaLogEntry` re-exported at the engine root, defined in `ts_runtime/src/tka_sync.rs`). It reads the
> node's already-synced + verified AUM chain **locally** — head-first, carrying the AUM hash, the
> change kind (`add-key`/`remove-key`/`checkpoint`/…), the signer key ids and the raw CBOR — with no
> control round-trip. **CONSUMED**: `tnet lock log [--limit N]` ships (bead `tsd-qeu`), so `log` is no
> longer part of this ask. One residual daemon-side gap, deliberate and documented at the renderer: Go
> decodes each update's raw AUM to print the per-kind key detail; the daemon has no AUM decoder, so a
> stanza prints hash + change kind + signer key ids and `--json` carries the raw CBOR for out-of-band
> decoding.
>
> **Part (a) — `tka_add`/`tka_remove` — remains outstanding**, and is the whole of what is left here:
> the engine has no key-set mutation entry point (no `tka_add`/`tka_remove`/`tka_modify`, no AddKey /
> RemoveKey AUM builder in `ts_tka`, and no public accessor for the live verified `Authority`), so the
> daemon cannot assemble and sign the AUM itself. `tnet lock add`/`remove` stay blocked (bead
> `tsd-nee`).

**Why:** `tnet lock` already ships `init`/`status`/`sign`/`disable` over the engine's
`tka_{init,status,sign,disable}`. Go additionally has `lock add <key…>` / `lock remove <key…>` (add or
remove trusted signing keys from the tailnet-lock key authority) and `lock log` (print the AUM
update-chain history). At the time of writing the engine exposed **no** `tka_add`/`tka_remove`
(key-set mutation) and **no** AUM-log reader, so none of the three verbs could be built faithfully —
and a tailnet-lock key-set change is a high-stakes trust operation that must NOT be approximated. (The
AUM-log reader has since landed; see the marker above.)

**Ask:** add (a) `Device::tka_add(keys)` / `Device::tka_remove(keys)` to mutate the lock's trusted-key
set (Go `NetworkLockModify`), submitting a signed AUM through control like `tka_sign` does; and (b)
`Device::tka_log(limit) -> Vec<TkaLogEntry>` returning the AUM chain (Go `NetworkLockLog` —
`ipnstate.NetworkLockUpdate` entries: AUM hash, kind, signer). All gated behind the existing TKA
plumbing.

**Daemon impact once landed:** `tnet lock add/remove` (WRITES — gated root/owner-uid like the other
lock mutations). `tnet lock log` (read) already shipped off part (b). Consumed via a pin bump. Tracked
in daemon bead tsd-lq8. — daemon lane

---

## 26. `Device::re_stun()` — force a STUN re-probe (for `tnet debug restun`)

**Why:** `tnet debug rebind` already ships over the engine's `Device::rebind()` (re-creates the UDP
sockets). Go's magicsock debug surface pairs `rebind` with **`restun`** — a lighter knob that forces a
fresh STUN/endpoint re-probe *without* tearing down the sockets (`tailscale debug restun` →
`magicsock.Conn.ReSTUN`). The engine exposes `rebind()` but **no** `re_stun()`, so `debug restun`
can't be built faithfully. It's a strictly weaker/safer operation than `rebind` (no socket churn), so
an operator diagnosing endpoint/NAT issues reaches for it first.

**Ask:** add `Device::re_stun(&self) -> Result<(), Error>` that triggers an immediate STUN re-probe /
endpoint re-derivation on the running magicsock conn (Go `Conn.ReSTUN("debug")`), without rebinding
sockets. No netmap/control round-trip — purely the local endpoint-discovery refresh.

**Daemon impact once landed:** `tnet debug restun` (WRITE — gated root/owner-uid like `debug rebind`),
a thin sibling of the existing `debug rebind` handler. Consumed via a pin bump. Tracked in daemon bead
tsd-rst. — daemon lane

---

## 27. `Device::tka_local_disable()` — disable tailnet lock for THIS node only (for `tnet lock local-disable`)

**Why:** `tnet lock` ships `init`/`status`/`sign`/`disable` over the engine's `tka_{init,status,sign,disable}`.
Go additionally has `lock local-disable` (`tailscale lock local-disable` → `NetworkLockForceLocalDisable`):
turn tailnet lock off for **this node only** (a local escape hatch when the node is locked out and can't
get a co-signature), distinct from the tailnet-wide `disable <secret>`. The engine exposes no
force-local-disable entrypoint, so the verb can't be built. `disablement-kdf` (the offline Argon2i value
derivation) IS shipped daemon-side (it needs no engine state — bead tsd-iqq.14 / PR #213); only
`local-disable` is blocked.

**Ask:** add `Device::tka_local_disable(&self) -> Result<(), Error>` (Go `ipnlocal.NetworkLockForceLocalDisable`)
— force-disable the local TKA state for this node (drop the local authority + stop enforcing), without a
control round-trip or affecting the tailnet's authority. Gated behind the existing TKA plumbing.

**Daemon impact once landed:** `tnet lock local-disable` (WRITE — gated root/owner-uid like the other lock
mutations), a thin LocalAPI verb + dispatch. Consumed via a pin bump. Tracked in daemon bead tsd-iqq.14
(the local-disable half). — daemon lane

---

## 28. Incremental peer deltas on the IPN bus — `Notify.PeerChangedPatch` / `PeersChanged` / `PeersRemoved` (for WatchNotifications peer-delta parity)

**Why:** the daemon's WatchNotifications feed (`tnet`'s masked `Watch` → `Response::Notify`, bead
tsd-iqq.11) is built on `Device::watch_ipn_bus`. At the current engine the bus's `Notify.net_map` is the
**full** peer `Vec<StatusNode>` on every netmap change (`ts_runtime/src/ipn_bus.rs` clones the whole peer
set), whereas Go's `ipn.Notify` carries **incremental** peer deltas — `PeerChangedPatch` (per-peer field
patches), `PeersChanged`, `PeersRemoved` — so a watcher applies a small diff instead of re-ingesting the
whole netmap each time. For a large tailnet this is a real efficiency gap (full-set re-broadcast per change
vs a one-peer patch). The daemon already ships the full-set push (Phase 1/3), which is correct but not
delta-efficient.

**Ask:** add an incremental peer-change channel to the runtime + surface it on `Notify` — e.g.
`Notify.peers_changed: Option<Vec<StatusNode>>` / `peers_removed: Option<Vec<StableNodeId>>` (or a
`PeerChangedPatch`-style per-field patch), emitted on a netmap delta instead of (or alongside) the full
`net_map`. Mirrors Go's `ipnlocal` netmap-diff path.

**Daemon impact once landed:** `NotifyView` grows `peers_changed`/`peers_removed` fields; `stream_notify`
forwards them. Until then the daemon's full-`net_map` push is the faithful (if less efficient) behavior — an
honest reduction, not a fake. Tracked in daemon bead tsd-iqq.11 (Phase 3). — daemon lane

---

## 29. Web-client session auth + owner identity — for the over-Tailscale management web UI (Go `ManageServerMode`)

**Why:** Go's `tailscale web` has two faces. The loopback CLI server (`LoginServerMode`) is read-only + a
login link — the daemon ships that faithfully (`tnet web` / `status --web`, incl. the login affordance, bead
tsd-bvc). The FULL mutating UI is Go's **`ManageServerMode`**, hosted by the daemon on the node's tailnet
IP:5252 (Go `RunWebClient` pref / `tailscale set --webclient`), reachable **over Tailscale only**, behind a
**browser session cookie** completed through the control server's webclient auth-URL flow
(`client/web/web.go serveTailscaleAuth` → Noise round-trips to control `…/machine/webclient/init|wait`).
Adding mutation to the daemon's UNAUTHENTICATED loopback server would *exceed* Go (it bypasses the LocalAPI
`SO_PEERCRED` write-gate — any local user / a CSRF'd browser could reconfigure the node), so web mutation
faithfully belongs in ManageServerMode. But its auth model is engine-gated here:

1. **A web-client session-auth flow** — Go `serveTailscaleAuth`: mint + confirm a browser session via a
   Noise round-trip to control's webclient auth URL. The engine exposes no such primitive.
2. **Owner identity on whois/self** — `WhoisReport.user` is **always `None` in this fork** (the engine
   doesn't retain the owning login/email), so authz can't be bound to the node owner like Go does.

**Ask:** surface (1) a control-backed webclient session mint/confirm on `Device`, and (2) the owning user
identity on the whois/self netmap projection.

**Daemon impact once landed:** promote `RunWebClient` from warn-only (currently a documented non-goal) to
honored; host a second server inside `tailnetd` bound to the tailnet IP(s):5252, refusing non-Tailscale
requests + requiring an authorized session, exposing the full mutating surface via the existing LocalAPI
verbs + a `csrfProtect` same-origin guard. Until then the loopback read+login UI is the faithful subset (NOT
a weaker any-tailnet-peer gate, which would *exceed* Go's permissiveness). Tracked in daemon bead tsd-bvc
(the ManageServerMode half). — daemon lane

## 30. (BUG — serve path mux uses substring match, not segment-boundary) `serve_path` `path.starts_with(prefix)` over-matches

**Severity: MEDIUM** (a request can be routed to the WRONG serve handler — e.g. an unauthenticated path
bleeds into a mount intended for a different, possibly sensitive, prefix). **Found by reading the engine
source while triaging daemon bead tsd-k4q** (verified against the pinned engine rev `3e81d862` / v0.39.0).

**The bug (`ts_runtime/src/serve.rs`, `serve_path`, pinned rev `3e81d862`):** the Path-mux handler
selection is a raw string prefix test —

```rust
// Longest-matching prefix wins.
let matched = handlers
    .iter()
    .filter(|(prefix, _)| path.starts_with(prefix.as_str()))   // <-- substring, not segment-aware
    .max_by_key(|(prefix, _)| prefix.len())
    .map(|(_, target)| target);
```

`str::starts_with` is a byte-substring test, so a mount registered at `/api` **also matches a request to
`/apifoo`** (and `/api-internal`, `/apixyz`, …). It should match only `/api` exactly and `/api/<subpath>`.
A handler mounted at a sensitive prefix can therefore be reached by an unintended sibling path, and the
longest-prefix tiebreak doesn't save it (there may be no more-specific mount).

**Go's behavior (primary source, `ipn/ipnlocal/serve.go` `getServeHandler` @ v1.100.0):** matching is
**segment-based**, not substring. Go first tries an exact `Handlers().GetOk(r.URL.Path)`, then walks up
**path segments** via `path.Clean` + `path.Dir`, probing `pth + "/"` then `pth` at each level until `/`.
Because `path.Dir("/apifoo")` is `/` (it never yields `/api`), a `/api` mount matches **only** `/api` and
`/api/...` — `/apifoo` matches neither. (The matched mount is then `http.StripPrefix(TrimSuffix(mountPoint,
"/"))`-ed off before proxying.)

**Ask:** make the `serve_path` prefix test segment-aware so it matches Go. Minimal fix: a mount `prefix`
matches `path` iff `path == prefix` **or** `path` starts with `prefix` followed by a `/` boundary (taking
the trailing slash on the mount into account, as Go does), rather than a bare `path.starts_with(prefix)`.
Equivalently, port Go's exact-then-walk-up-segments loop. Keep the longest-match tiebreak (Go effectively
prefers the most-specific / trailing-slash mount). A regression test: mounts `{"/api": A, "/": B}`, request
`/apifoo` ⇒ must route to `B` (root), NOT `A`; request `/api/x` ⇒ `A`; request `/api` ⇒ `A`.

**Daemon impact once landed:** none in the daemon — the daemon only *builds* the `ServeTarget::Path`
handler map (`src/ipn/serve.rs` `handler_to_target`/`http_handler_to_target`); the request-time mux is
entirely engine-owned, so this fix is transparent to the daemon (no wiring change). Tracked in daemon bead
tsd-k4q. — daemon lane

## 31. Taildrop **send-path** parity — unknown-length bodies, a byte-progress signal, and a target-eligibility reason (for a Go-faithful `tnet file cp`)

**Why:** Go's `tailscale file cp` (v1.100.0 `cmd/tailscale/cli/file.go`) does three things on the send
path that this fork cannot express against the pinned engine (`9d847a6e` / v0.43.0). The daemon-side
wiring for each is small and ready; the primitive is missing. Read while triaging daemon bead
**tsd-52k** — the full drift map is in [`FILE_CP_PARITY.md`](FILE_CP_PARITY.md). — daemon lane

**(a) An unknown-length (chunked) send, for `file cp -` (stdin).** Go pushes stdin with
`contentLength = -1`, so `PushFile` omits `Content-Length` and the peerAPI `PUT` body is
chunked-encoded; the size of a pipe is not knowable up front. The engine's
`Device::send_file(peer, name, content_length: u64, reader)` (`src/lib.rs:1116`) takes a **required**
`u64`, and `ts_runtime::taildrop_send::send_file` unconditionally writes
`Content-Length: {content_length}` into the request head (`ts_runtime/src/taildrop_send.rs:188`). The
only daemon-side workaround is to spool all of stdin to disk or memory to learn its length first —
not streaming, and an unbounded local-resource surface on a root-run daemon, so `tnet file cp` rejects
`-` outright today rather than fake it.

*Ask:* let the declared length be optional — e.g. `content_length: Option<u64>` (or a sibling
`send_file_streaming`), where `None` emits `Transfer-Encoding: chunked` and chunk-frames the body
instead of `Content-Length`. The receiving half already tolerates it in Go's peerAPI; keep the
existing `u64` behavior byte-identical when `Some`.

**(b) A send-progress signal (bytes pulled toward the peerAPI).** Go arms a 3-second timer on the
first file and disarms it on the first `OutgoingFile.Sent > 0` seen on the IPN bus
(`file.go:230`/`file.go:289`); if it fires it warns `# warning: %s is reportedly offline; trying
anyway` or `# warning: %s is not replying; trying anyway`. Go is explicit that the trigger is bytes
actually moving, **not** the netmap `Online` bit (which lags) and **not** the client's own write count
(which completes as soon as the body is buffered locally). The engine streams the body inside
`taildrop_send::send_file` with no callback and publishes no outgoing-file event, so "not replying" is
unobservable here; a CLI-local timer with nothing to disarm it would fire on every healthy transfer
longer than three seconds, so the warning is honestly omitted instead. The same signal is what Go's
`--verbose` and `--update-interval` progress line are built on.

*Ask:* surface bytes-written progress for an in-flight send — either (a) an optional
`on_progress: impl Fn(u64)` / `mpsc::Sender<u64>` argument on `Device::send_file`, or (b) an
`outgoing_files: Option<Vec<OutgoingFile>>` field on the `watch_ipn_bus` `Notify` (the Go shape, and
the natural sibling of ask **#20**'s incoming-file signal). Option (a) is the smaller change: because
`send_file` already takes the body as an `AsyncRead` and pulls from it only as it writes to the
overlay, a counter at that read point already has Go's semantics.

**(c) A Taildrop target-eligibility classification, with a reason.** Go's `getTargetStableID`
(`file.go:440`) refuses **before** opening any file and says why, switching on the daemon-computed
`ipnstate.PeerStatus.TaildropTarget` enum (ten values). Five of those reasons are visible to this
daemon today (available / no peerAPI / offline / IPN state not running / no netmap), but three are
not: `OwnedByOtherUser` — the engine applies `peer.user_id == self_user_id` *inside*
`build_file_targets` (`ts_runtime/src/status.rs`) and exposes neither the self user id nor the
per-peer verdict; `MissingCap` — the node-level file-sharing gate makes `file_targets` return an
**empty list**, indistinguishable from "no eligible peers"; and `UnsupportedOS` — `ts_control::Node`
carries no `Hostinfo.OS` field at all. So the daemon can only report "not a Taildrop target", never
Go's specific sentence.

*Ask:* either (a) a `Device::taildrop_target(&NodeInfo) -> TaildropTarget` returning a reason enum
mirroring Go's, or (b) the ingredients, which are individually useful elsewhere: the self node's
`user_id`, a `Node::os` from `Hostinfo`, and a way to distinguish "this node lacks the file-sharing
capability" from "no peer qualifies" (e.g. `file_targets` returning that as a typed error rather than
an empty vec — note the current empty-vec-not-error behavior is deliberate and documented, so this
would want a separate accessor rather than a semantic change).

**Daemon impact once landed:** (a) unblocks `tnet file cp -` (plus the `stdin<ext>` naming, which is
pure daemon-side work); (b) unblocks the not-replying warning and a `--verbose`/progress line;
(c) upgrades the pre-send refusal from a post-hoc `taildrop send failed: BadRequest` to Go's specific
message. None of the three is a blocker for the daemon-buildable half of tsd-52k, which lands without
a pin bump.

---

## 32. Expose the detected `Hostinfo` — `Device::host_info()` (for `tnet debug hostinfo`)

**Why:** Go's `tailscale debug hostinfo` prints the `Hostinfo` the client advertises to control
(`hostinfo.New()`, marshalled to JSON). It is one of the first things asked for in a support thread,
because it is exactly the block control sees: OS + OS version, arch/machine, the advertised client
version, distro, container/managed-environment detection.

This one is worth stating precisely, because the daemon-side bead (`tsd-b15`) previously recorded it
as blocked on "netmap fields the engine doesn't surface" — that diagnosis was wrong. The engine
**already computes the entire struct**: `ts_control::hostinfo::HostInfoData::detect()` is a
field-by-field mirror of Go's `hostinfo.New()` (`ipn_version`, `os`, `os_version`, `go_arch`,
`go_version`, `machine`, `distro`/`distro_version`/`distro_code_name`, `container`, `env`), and it is
what the register + map-poll paths send. The only thing missing is reachability: `ts_control/src/lib.rs`
declares `mod hostinfo;` (private) and neither `ts_control` nor the `tailscale` facade re-exports
`HostInfoData`, so a downstream crate cannot name the type — verified against pin `9d847a6e`/v0.43.0.

The daemon deliberately does **not** work around this by re-detecting the host itself. A second,
independent detector would drift from the engine's, and `debug hostinfo` would then print something
subtly different from what the node actually sends to control — which is precisely the failure the
command exists to rule out. A wrong answer here is worse than no answer.

**Ask:** either (a) `pub use hostinfo::HostInfoData;` from `ts_control` (plus `pub mod hostinfo` or a
facade re-export) so the daemon can call `HostInfoData::detect()`, or — better, because it reports the
*live* node rather than a fresh detection — (b) `Device::host_info(&self) -> HostInfoData` returning the
instance the running node is actually advertising. (b) also covers the fields Go fills that are not
part of `detect()` today (`Hostname`, `Package`/`PACKAGE_TSNET`, `RoutableIPs`, `Services`,
`SSHHostKeys`), which only the live node knows.

**Daemon impact once landed:** `tnet debug hostinfo` (READ) — with (a) a pure-local print like the
existing `debug env`/`debug build-info`; with (b) a thin read-only LocalAPI verb. Consumed via a pin
bump. Tracked in daemon bead tsd-b15. — daemon lane

---

## 33. Expose the DERP map — `Device::derp_map()` (for full-strength captive-portal detection)

**Why:** Go's captive-portal detector (`net/captivedetection/endpoints.go`, `availableEndpoints`)
builds its probe list from the DERP map: for every non-`Avoid`, non-`NoMeasureNoHome` region it takes
each node's **IPv4** with `CanPort80` set and probes `http://<ip>/generate_204`. Two properties make
those the good endpoints, and neither is reproducible without the map:

- **They are addressed by IP, not hostname.** A captive portal almost always hijacks DNS too, so a
  hostname probe measures the portal's resolver rather than the network path. Go probes DERP by
  literal IPv4 for exactly this reason.
- **They answer a challenge.** A DERP server echoes the request's `X-Tailscale-Challenge: ts_<host>`
  back as `X-Tailscale-Response: response ts_<host>`. That closes the hole where a portal answers a
  bare `204` to look innocent — a portal cannot synthesize the echo. Only DERP nodes implement it;
  the generic `generate_204` endpoints do not.

Verified against pin `9d847a6e`/v0.43.0: `Device::netcheck()` returns a `NetcheckReport` carrying only
region **ids** and measured latencies (`ts_runtime::status::NetcheckReport`), and neither
`ts_control` nor the `tailscale` facade re-exports the `ts_control_serde::derp_map` types, so the
daemon cannot reach a node hostname, IPv4 or `CanPort80` flag. The DERP map is otherwise fully modelled
inside the engine (`ts_control_serde/src/derp_map.rs` already carries the `Avoid`, `NoMeasureNoHome`
and port-80 fields this needs, the last one documented there as being for "captive portal checks").

Go's fallback when the map is empty is its baked-in `dnsfallback` static DERP map. The daemon
deliberately does **not** ship a hard-coded copy of that: a stale list of somebody else's server IPs
compiled into this fork would rot silently and probe addresses that may no longer be Tailscale's.

**Ask:** `Device::derp_map(&self) -> Option<DerpMap>` (or any read-only projection carrying, per
region, the region id, `avoid`/`no_measure_no_home`, and per node the IPv4 literal + `can_port80`),
plus a facade re-export of the type. A `preferred_derp` on the existing netcheck report already gives
the region ranking, so nothing else is needed.

**Daemon impact once landed:** captive-portal detection (`src/ipn/captive.rs`) gains the DERP-node
endpoints and the challenge/response check. The port is already written and unit-tested against
synthetic regions — `available_endpoints(regions, preferred_region_id)` — so consuming this is a
one-argument change at the single call site in `ipn::captive_portal_loop`. Until then detection runs on
the two Tailscale endpoints Go always appends (`controlplane`/`login`), which need no map but are
status-code-only. Tracked in daemon bead tsd-iqq.5. — daemon lane

---

## 34. A peer-relay server (listen port + static endpoints) and a config-sync kill switch — for the last four Go `set` pref flags

**Why:** Go's `tailscale set` (`cmd/tailscale/cli/set.go` @ `53a0d659afa51835dd7a9283873cca44261454f8`)
registers four pref flags this fork models no pref for. Three of them are engine-gated; the fourth is
listed here only so nobody files it as an ask by mistake.

- **`--relay-server-port <PORT>`** (Go `Prefs.RelayServerPort *uint16`) — the UDP port a **peer relay
  server** binds on all interfaces; `0` means "pick a random unused port", and the flag's empty value
  means "disable relay-server functionality". A peer relay is a node that forwards disco + WireGuard
  frames between two peers that cannot reach each other directly, without the round trip to a DERP
  region.
- **`--relay-server-static-endpoints <IP:PORT,…>`** (Go `Prefs.RelayServerStaticEndpoints
  []netip.AddrPort`) — static endpoints to advertise as candidates for relay connections, for a relay
  behind a firewall pinhole whose reflexive address discovery will not find the right candidate. Go
  documents them as "only relevant when RelayServerPort is non-nil".
- **`--sync`** (Go `Prefs.Sync opt.Bool`, unset = true) — whether the node actively syncs its
  configuration from the control plane. `--sync=false` is Go's kill switch, and its stated purpose is
  testing: "to verify that netmap caching and offline operation work correctly".

Verified against pin `9d847a6e`/v0.43.0. The engine can **read** a peer's relay role —
`ts_control::node` carries `peer_relay` (Go `Hostinfo.PeerRelay`) and `NodeInfo::is_peer_relay()` —
but there is nothing on the **serving** side: `ts_control::Config` has no relay listen port and no
static-endpoint list (its fields run from `server_url` to `allow_http_key_fetch`), `ts_control::hostinfo`
never sets `peer_relay` for this node, so our own `Hostinfo` cannot advertise the role, and
`ts_magicsock` has no relay listener to bind. There is likewise no way to suspend the map poll while
the node stays up, so `--sync=false` has nothing to switch off.

**Ask:**

1. `Config.relay_server_port: Option<u16>` — `None` disables (today's behaviour), `Some(0)` binds a
   random unused port, `Some(p)` binds `p` on all interfaces. This is the same construction-time shape
   as the already-shipped `wireguard_listen_port` (ask #22), and it matches Go, where the port is a
   pref read at engine reconfigure.
2. `Config.relay_server_static_endpoints: Vec<SocketAddr>` — advertised as relay candidates; ignored
   when `relay_server_port` is `None`, mirroring Go.
3. Set `Hostinfo.PeerRelay` for THIS node when a relay port is configured, so control and peers learn
   the role — the read side (`NodeInfo::is_peer_relay`) already exists, and without the advertise side
   a bound listener is unreachable.
4. The magicsock UDP relay path itself: accept relayed disco/WireGuard frames on the bound port and
   forward between the two peers. This is the substantial half; (1)–(3) are plumbing around it.
5. Separately and much smaller: a way to stop syncing configuration from control without bringing the
   node down — `Config.sync: bool` or a `Device::set_sync(bool)` — so `--sync=false` can exercise
   netmap caching and offline operation the way Go's does.

(1)–(4) are one feature and can land together; (5) is independent and is the cheap one.

**NOT asked for: `--remote-config`** (Go `Prefs.RemoteConfig`, new since v1.100.0). It delegates full
remote control of the node's prefs **and its LocalAPI** to the tailnet admin via the control plane,
bypassing Tailscale's per-feature double opt-in — "a single client-side 'I trust the tailnet admin'
switch", in Go's own words. This daemon's authorization model is local (THREAT_MODEL §4.1: every
LocalAPI write is gated on the caller's peer UID — root or the daemon's owner — and the control plane
is a peer whose input is validated, never a principal that may rewrite prefs or invoke local
endpoints). Adopting `RemoteConfig` would add a second,
remote write path into both, so this fork **declines the behaviour** rather than deferring it. Please do
not build it on this daemon's account; if the engine ever wants it for another consumer, it should be a
feature the embedder opts into explicitly, never a default.

**Daemon impact once landed:** `tnet set --relay-server-port` / `--relay-server-static-endpoints`
already parse (with Go's own `ParseUint`/`ParseAddrPort` validation, dedup and `AddrPort.Compare`
ordering) and are refused by name in `check_unmodelled_set_flags`; wiring them is a wire `Set` field +
pref + `get_settings` row, and the refusal is deleted. `--sync`/`--no-sync` is the same shape.
`--remote-config` keeps its refusal permanently. Tracked in daemon bead tsd-re94825b. — daemon lane

## 35. Proxied-flow `whois` — a `(proto, ip:port) → node` lookup (for `tnet whois --proto`)

**Why:** Go's `whois` is a *flow* lookup, not an address lookup. `cmd/tailscale/cli/whois.go` @
`53a0d659afa51835dd7a9283873cca44261454f8` takes `ip[:port]` and a `--proto` selector (`protocol; one
of "tcp" or "udp"; empty means both`) and calls `LocalClient.WhoIsProto`, which reaches
`LocalBackend.WhoIs(proto, ipp)`. That method resolves by IP first (`cn.NodeByAddr`) and consults the
protocol **only** in its fallback: when the address matches no node in the netmap and the port is
non-zero, it asks `b.sys.ProxyMapper().WhoIsIPPort(proto, ipp)` — for `""` it tries `"tcp"` then
`"udp"` — to map a locally-proxied flow (a `127.0.0.1:port` socket tailscaled itself proxied) back to
the tailnet IP behind it, then resolves that. So the same `ip:port` really can belong to different
sessions per protocol, but only for flows the daemon proxies.

Verified against pin `9d847a6e`/v0.43.0. The engine has no such table and no port dimension at all:
`Device::whois(SocketAddr)` (`src/lib.rs`) forwards to `ts_runtime`, whose `peer_tracker::whois_opt`
calls `status::whois_addr(addr)` — the whole body of which is `addr.ip()` — and then
`peer_by_tailnet_ip_opt`. There is no proxy-map type anywhere in the workspace, so nothing records
which local socket belongs to which peer, and a protocol has nothing to select within.

**Ask:**

1. A proxied-flow registry in the engine, the analogue of Go's `proxymap.Mapper`: the netstack /
   userspace-proxy paths record `(proto, local ip:port) → peer tailnet IP` when they proxy a
   connection, and drop the entry when it closes.
2. `Device::whois_proto(proto: Option<Proto>, addr: SocketAddr) -> Result<Option<WhoIs>, Error>` (or
   a `proto` parameter on the existing `whois`): resolve by IP as today, and on a miss with a
   non-zero port, consult (1) — trying `tcp` then `udp` when `proto` is `None`, which is Go's
   empty-means-both order — and resolve the mapped tailnet IP.

(1) is the substantial half; (2) is the surface over it. Both are additive: today's `whois(addr)` is
(2) with `proto: None` and a port of 0.

**Daemon impact once landed:** `tnet whois [--proto tcp|udp] ip[:port]` already parses Go's arguments
in full, and the LocalAPI `Request::Whois` already carries `port` and `proto` through to
`diag::whois`, which hands the port to the engine and can only record the protocol. Wiring it is one
call-site change in `diag::whois` plus deleting the "recorded, cannot select" notes on the flag help
and the wire docs. Until then a proxied flow that Go attributes to a peer is reported here as owned by
no node, with or without the flag. Tracked in daemon bead tsd-re4d7624. — daemon lane

## 36. Tailnet-lock init with a trusted-key set, several disablements, and this node's own lock key (for `tnet lock init`)

**Why:** Go's `lock init` initializes the authority the operator describes, not a fixed one.
`cmd/tailscale/cli/tailnet-lock.go` @ `53a0d659afa51835dd7a9283873cca44261454f8` takes
`[--gen-disablement-for-support] --gen-disablements N <trusted-key>...`, where the positionals are the
tailnet lock **public keys** (`tlpub:<hex>`, optionally `<key>?<votes>`) initially trusted to sign
nodes — plus any pre-computed `disablement:<hex>` values — mints `N` disablement secrets itself,
optionally mints one more that is transmitted to the coordination server for support, and calls
`LocalClient.TailnetLockInit(ctx, keys, disablementValues, supportDisablement)`. Before any of that it
refuses when `st.Enabled`, and refuses when the current node's own lock key is not among the trusted
keys (`st.PublicKey`, from `NetworkLockStatus`) — "the tailnet lock key of the current node must be
one of the trusted keys during initialization".

Verified against pin `9d847a6e`/v0.43.0. The engine's init is a fixed single-node genesis:
`Device::tka_init(disablement_secret: Vec<u8>)` (`src/lib.rs`) → `ts_runtime`'s `tka_init_run`
(`control_runner.rs`), whose body builds `AumKey { kind: Ed25519, votes: 1, public:
keys.network_lock_keys.public }` as the **sole** trusted key and `vec![disablement_value(&secret)]` as
the **single** disablement value, then submits init/begin → init/finish. Three consequences:

1. **No key set.** There is no parameter for one, so a tailnet cannot be locked with a second signing
   node trusted from the start — the case Go's help is written around ("run `tailscale lock` on that
   node, and copy the node's tailnet lock key").
2. **No way to read this node's lock key.** `TkaStatus` (`ts_control/src/tka.rs`) carries only `head`
   and `disabled` — no analogue of Go's `NetworkLockStatus.PublicKey` — and nothing else on `Device`
   exposes `network_lock_keys.public`. So Go's self-key refusal cannot be *evaluated* here, and the
   operator cannot obtain the key that Go's grammar requires them to pass.
3. **The support disablement is unconditional.** `tka_init_run` sets
   `TkaInitFinishRequest.support_disablement = disablement_secret` — the one secret it was given — so
   the operator's disablement secret always reaches the coordination server. Upstream sends a
   *separate*, purpose-minted secret there, and only when `--gen-disablement-for-support` is passed.

**Ask** (extends #17 `tka_init` and #25's key-set half):

1. `Device::tka_init(keys: Vec<AumKey>, disablement_values: Vec<Vec<u8>>, support_disablement:
   Option<Vec<u8>>)` — the genesis built from the caller's trusted-key set and disablement values,
   with the support secret sent only when it is `Some`. Today's call is that with the node's own key,
   one derived value, and the secret repeated as the support disablement.
2. This node's tailnet lock public key on the read path — a field on `TkaStatus` (Go's
   `NetworkLockStatus.PublicKey`) or a `Device::tka_public_key()` — so the CLI can print it for the
   operator to copy and can check Go's "current node must be among the trusted keys" refusal.

**Daemon impact once landed:** `tnet lock init` already parses Go's whole positional grammar
(`parse_lock_args`, a port of upstream's `parseTLArgs`, including `<key>?<votes>` and both
`disablement:` prefixes) and already runs Go's `--confirm` two-step, its already-enabled refusal and
its secret minting. Wiring is: pass the parsed keys and values to the new `tka_init`, delete the
"this daemon cannot …" refusals in `plan_lock_init`, replace the placeholder trusted-key line with
Go's `- tlpub:%x (%s key)` list, restore Go's self-key check against (2), and drop the
support-disablement note the command prints today. Until then the fork initializes only the subset the
engine has — this node as the sole trusted key, one disablement secret — and says so where the
operator hits it. Tracked in daemon bead tsd-reb2dfc1. — daemon lane

## 37. Per-peer `Location` (and `Active`) on `StatusNode` — for `exit-node list`'s country/city columns and `--filter`

**Why:** Go's `exit-node list` is a *location* browser. `cmd/tailscale/cli/exitnode.go` @
`53a0d659afa51835dd7a9283873cca44261454f8` runs the exit-node peers through
`filterFormatAndSortExitNodes`, which buckets them by `Location.CountryCode` then `Location.CityCode`,
keeps only the highest-`Location.Priority` node per city (plus whichever is the active exit node),
synthesises an `Any` city row holding the country's best node when a country has more than one city,
sorts countries and cities by name, and honours `--filter` ("filter exit nodes by country") with a
case-insensitive match against `Location.Country`. It then prints five columns — IP, HOSTNAME,
COUNTRY, CITY, STATUS.

Verified against pin `9d847a6e`/v0.43.0. The **wire** type is already there and already parsed:
`ts_control_serde::Location` (`ts_control_serde/src/location.rs`) carries `country`, `country_code`,
`city`, `city_code`, `latitude`, `longitude` and `priority`, and `HostInfo.location:
Option<Location<'a>>` (`ts_control_serde/src/host_info.rs`) decodes it off the netmap. It is dropped
one layer up: `impl From<..> for Node` (`ts_control/src/node.rs`) projects `host_info.services`,
`host_info.net_info.preferred_derp` and `host_info.peer_relay` into the domain `Node` but not
`host_info.location`, so `ts_control::Node` has no location field, `StatusNode`
(`ts_runtime/src/status.rs`) has none either, and neither does the daemon's `PeerReport`. Nothing
between the decoder and the CLI can group, sort or filter by country.

`StatusNode` is also missing Go's `PeerStatus.Active` (traffic seen in the last couple of minutes),
which `peerStatus` consults before `Online` when it picks the STATUS wording.

**Ask:**

1. Retain the decoded location on the domain node — `Node::location: Option<Location>` (an owned
   analogue of `ts_control_serde::Location`), projected in `From<..> for Node` next to the other
   `host_info` fields it already keeps, `None` when the peer declared none (never fabricated).
2. Surface it on the status view — `StatusNode::location: Option<Location>`, the analogue of Go's
   `ipnstate.PeerStatus.Location`. `priority` is the field the per-city reduction needs, so it has to
   ride along with the names and codes.
3. `StatusNode::active: bool` — Go's `PeerStatus.Active`, true when traffic has been seen for the peer
   recently. Independent of (1) and (2) and useful to `tnet status` as well.

All three are additive: today's behaviour is (1)/(2) always `None` and (3) always `false`.

**Daemon impact once landed:** `tnet exit-node list` already prints Go's five columns, sorts by DNS
name, ports Go's `peerStatus` and both of its error paths (`no exit nodes found`, `no exit nodes found
for %q`), and accepts `--filter`. What it cannot do is *group*: with no `Location`, every peer takes
Go's own no-location path — one unnamed country, one unnamed city, no priority reduction, no `Any`
row, `-` printed for country and city — and any non-empty `--filter` can only reach the "found for %q"
error. Wiring is: carry `location` through `peer_report_from_status_node` into `PeerReport`, then port
`filterFormatAndSortExitNodes` itself (the country/city buckets, the priority reduction, the `Any`
row, the two name sorts) and match `--filter` against the real country. (3) removes the last deviation
in the STATUS column, where an idle-but-online selected exit node currently reads `selected` and Go
says `selected but offline`. Tracked in daemon bead tsd-red57f03. — daemon lane

## 38. Selectable ping types and a ping size — `Device::ping_typed` (for Go `ping --tsmp` / `--peerapi` / `--size`)

**Why:** Go's `tailscale ping` (`cmd/tailscale/cli/ping.go` @
`53a0d659afa51835dd7a9283873cca44261454f8`) does not have one probe, it has four, and the operator
picks between them. `pingType()` maps `--tsmp`/`--icmp`/`--peerapi` onto a `tailcfg.PingType`
(defaulting to `PingDisco`) and hands it, together with `--size`, to `LocalClient.PingWithOpts`. The
four measure genuinely different things:

- **disco** (`PingDisco`, the default) — a magicsock-level probe between the two endpoints. Answers
  "is there a direct path, and how fast is it".
- **ICMP** (`PingICMP`) — an ICMP echo injected into the tunnel, answered by the peer's *host OS
  stack*. Answers "is the peer's OS reachable through WireGuard".
- **TSMP** (`PingTSMP`) — through WireGuard, answered by the peer's *tailscaled*, neither host OS
  stack involved. Answers "is the peer's daemon alive and does the packet filter admit me". Go
  returns after the first pong for TSMP and ICMP alike.
- **peerAPI** (`PingPeerAPI`) — not a ping: an HTTP hit on the peer's peerAPI server, printed as
  `hit peerapi of %s (%s) at %s in %s` (node IP, node name, peerAPI URL, latency).

`--size` ("size of the ping message (disco pings only). 0 for minimum size.") pads the disco probe,
which is how an operator finds a path MTU problem.

Verified against pin `9d847a6e`/v0.43.0. The engine has **two** of the four, but no way to choose
between them and no size knob:

- `Device::ping(dst, timeout) -> Result<Duration, PingError>` — "an ICMPv4 echo … from this device's
  own tailnet IPv4 over the overlay netstack — never a host socket", answered by the peer's own OS
  stack. That is Go's `PingICMP`, and it is what the daemon sends for every `tnet ping` today.
- `Device::ping_disco(dst, timeout) -> Result<Option<(SocketAddr, Duration)>, Error>` — a fresh
  disco probe returning the endpoint that answered and the RTT. That is Go's `PingDisco`.
- **TSMP: nothing.** `ts_dataplane` admits IP protocol 99 past the ACL on the way in (Go's `case
  ipproto.TSMP: return Accept`), and `ts_capabilityversion` records the version at which TSMP ping
  became a thing, but no crate constructs a TSMP message and none answers one. A TSMP probe sent
  today would never be replied to.
- **peerAPI: a client, but not a probe.** `Device::push_file` reaches a peer's peerAPI over
  `NodeInfo::peerapi_addr`, so the transport exists; there is no call that hits the peer's peerAPI
  and reports its URL plus a latency.
- **Size: no parameter.** Both ping calls take a destination and a timeout and choose the packet
  themselves.

**Ask:**

1. A single typed entry point, so the caller selects the probe instead of the engine choosing for
   it — e.g.

   ```rust
   pub enum PingKind { Disco, Icmp, Tsmp, PeerApi }

   pub struct PingOpts { pub kind: PingKind, pub size: Option<usize>, pub timeout: Duration }

   pub struct PingOutcome {
       pub latency: Duration,
       /// The direct endpoint that answered, when the probe went direct.
       pub endpoint: Option<SocketAddr>,
       /// `PingKind::PeerApi` only: the peer's peerAPI base URL that was hit.
       pub peerapi_url: Option<String>,
       /// The peer's node name, for Go's `pong from <name> (<ip>)` line.
       pub node_name: Option<String>,
   }

   pub async fn ping_typed(&self, dst: IpAddr, opts: PingOpts) -> Result<PingOutcome, PingError>;
   ```

   `Disco` and `Icmp` are re-exports of the two calls that already exist, so those two arms are
   plumbing.
2. **TSMP, both halves.** Construct and send a TSMP ping over the tunnel, and answer an inbound one
   from this node's own daemon rather than only admitting it past the ACL. This is the substantial
   piece; it is also the one that makes `tailscale ping --tsmp` against a Rust node work *from a Go
   node*, which is a two-way interop gap today, not just a missing CLI flag.
3. **A peerAPI probe** — a `GET` on the peer's peerAPI base returning `(url, latency)`, reusing the
   client `push_file` already has.
4. **`size` on the disco probe**, padding the disco payload; ignored for the other kinds, exactly as
   Go documents it ("disco pings only").
5. Nice to have with (1): the peer's node name in the outcome, so `pong from <name> (<ip>)` can carry
   the name Go prints instead of the IP standing in for it.

(2) and (3) are independent of each other; (1) and (4) are small once either lands, and (1) alone —
with `Tsmp`/`PeerApi` returning `Unsupported` — is already useful, because it lets the daemon report
"not implemented" from the engine instead of refusing at the CLI.

**Related, and worth fixing before any of this: the default probe is the wrong one.** Go's default is
`PingDisco`; the daemon's `Request::Ping` calls `Device::ping` (ICMP) and then reads the direct-path
endpoint from `Device::direct_path`, a cached snapshot of the last periodic disco probe. So `tnet
ping` today reports an ICMP RTT next to a disco endpoint that can be up to one probe interval stale,
and `--until-direct` can overshoot Go by a ping or two before it notices the upgrade. That needs no
engine change — `Device::ping_disco` already returns both halves from one fresh probe — and is
tracked as a daemon-side follow-up, noted here so the two are not confused.

**Daemon impact once landed:** `tnet ping --tsmp`/`--peerapi`/`--size` already parse and are refused
by name in `ping_probe_refusal` (`src/bin/tnet.rs`); wiring them is a ping-kind + size field on the
`Ping` wire request, the `ipn::diag::ping` call, and Go's `hit peerapi of …` line for the peerAPI
arm — then the refusal is deleted. `--icmp` is already honoured (it names the probe the daemon
sends) and needs nothing. — daemon lane

## 39. App-connector route learning + a `RouteInfo` readback (for `tnet appc-routes`)

**Why:** the daemon already ships the *advertise* half of the app connector. `tnet up/set
--advertise-connector` sets `Config.advertise_app_connector`, the engine folds it into
`Hostinfo.AppConnector` at registration and on every map request, and control sees the node
offering the role. Nothing behind that advertisement exists, in the daemon or the engine.

Go's connector (`appc.AppConnector`, driven from `ipnlocal`) is three pieces the engine would own,
because all three sit on the data plane:

- **The configured domain set.** Control pushes it in the netmap capability map — the
  `tailscale.com/app-connectors` cap (`appctype.AppConnectorAttr`: `domains`, wildcards, and
  predetermined `routes`). The engine parses the netmap; the daemon never sees the capmap.
- **DNS observation.** For each configured domain (`example.com`, or `*.example.com` matched
  against the wildcard list) the connector watches the answers flowing through its own resolver and
  records the addresses it sees. That is a tap on the MagicDNS forwarder — engine-side.
- **Route advertisement.** Each newly observed address becomes a /32 or /128 the node advertises,
  appended to the advertised-route set and re-sent to control.

Verified against pin `9d847a6e`/v0.43.0: `Config.advertise_app_connector` is a plain bool the
register/map-poll paths read, and nothing else in the engine references app connectors. There is no
domain observation, no learned-route accumulation, and no store — so there is nothing for a readback
verb to return.

**Ask:** the learning path above, plus one read-only accessor over what it accumulated —
`Device::app_connector_route_info(&self) -> Option<RouteInfo>` where `RouteInfo` mirrors Go's
`appctype.RouteInfo` (`types/appctype/appconnector.go`): `control: Vec<IpNet>` (routes from the
policy's `routes` field), `domains: BTreeMap<String, Vec<IpAddr>>` (addresses learned per domain),
`wildcards: Vec<String>` (the configured `*.` domains with the `*.` stripped — the watch list, not
what the watching found: Go's `updateDomains` fills it from the control-pushed `domains` list alone,
and `NewAppConnector` seeds a restarting connector's wildcard set straight back from it). `None`
when the node is not advertising the role, so the caller can tell "not a connector" from "a
connector that has learned nothing", which are different answers. The routes themselves should keep
flowing through the existing advertised-route path rather than a second one.

Split it if that is easier to land: the accessor is useless without the learning, but the *learning*
alone is already the feature — a node that actually connects. The readback is how an operator
confirms it.

**Daemon impact once landed:** an `AppcRouteInfo` LocalAPI verb (read-only, the shape of
`GetPrefs`) → `Device::app_connector_route_info`, consumed by `tnet appc-routes`. The CLI is already
ported and its flag surface is settled: `appc_routes_shape` in `src/bin/tnet.rs` resolves Go's
`-n` > `--map` > `--all` > summary precedence, and `appc_routes_output` answers the two prefs-only
shapes today (Go's `not a connector`, and `-n`'s advertised-route count) while the other three
return `appc_routes_refusal` — replace that arm with the three renderers ported from Go's
`getAllOutput` / `getSummarizeLearnedOutput` and the command is complete. Until then
`--advertise-connector` documents the limit at every place it appears (`tnet up`/`set --help`,
`Prefs::advertise_app_connector`, README). Tracked in daemon bead tsd-ree961df. — engine lane
