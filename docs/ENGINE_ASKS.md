# What the daemon needs from the `tailscale-rs` engine

This lists the changes the downstream daemon (`tailscaled-rs`) needs from the `tailscale-rs`
library to unblock end-to-end features. Each ask is self-contained, additive, and
backward-compatible. Verified against the pinned engine rev `e126bba` (released `v0.6.9`).

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

## 6. (BLOCKER for macOS TUN — ROOT-CAUSED + FIX PROVEN) `ROUTE_BIN` is the Linux path `/usr/sbin/route`; on macOS `route` is `/sbin/route`

> **RESOLVED to a one-line root cause and proven end-to-end live (engine v0.6.9, e126bba).**
> This supersedes BOTH earlier theories (the v6 `/128`, then the vaguer "host-route
> programming order is off"). The actual bug is a single wrong constant.

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
