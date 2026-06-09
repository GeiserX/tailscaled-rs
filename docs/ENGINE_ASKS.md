# What the daemon needs from the `tailscale-rs` engine

This lists the changes the downstream daemon (`tailscaled-rs`) needs from the `tailscale-rs`
library to unblock end-to-end features. Each ask is self-contained, additive, and
backward-compatible. Verified against the pinned engine rev `afa970c` (released `v0.6.6`).

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

## 6. (BLOCKER for macOS TUN) IPv6 /128 assigned to the utun interface even with IPv6 off → macOS EADDRNOTAVAIL

**Why:** In TUN mode on macOS, the node registers and reaches Running, but the overlay data path
fails closed at interface-address assignment. The engine's `route_updater` iterates ALL
`accepted_routes` — including the node's IPv6 `/128` (e.g. `fd7a:115c:a1e0::.../128`) — and tries to
assign each to the utun. macOS rejects the v6 assignment with **EADDRNOTAVAIL (os error 49, "Can't
assign requested address")**, which surfaces as `tun_actor: host route programming failed; TUN idle
(fail-closed)` and the utun is torn down. Net: Running on the control plane, no working tunnel.

**Verified (engine v0.6.7, debug log of a live root run on macOS):**
```
route_updater: populating accepted routes accepted_routes=[100.112.2.94/32, fd7a:115c:a1e0::.../128]
tun_rs::platform::macos::device: Os { code: 49, kind: AddrNotAvailable, ... }
tun_actor: host route programming failed; TUN idle (fail-closed) error=os error 2
```

**Inconsistency:** `ts_runtime/src/tun_actor.rs:150-175` documents and applies an "IPv4-only by
construction: every IPv6 prefix in accepted_routes is dropped" invariant for *host routes* — but the
`route_updater.rs:391-416` path that assigns addresses to the interface does NOT drop the v6 prefix,
so the v6 /128 still reaches the macOS utun and fails. The daemon already runs IPv6-off by default
(`enable_ipv6 = false`), yet the engine still derives and tries to bind the /128.

**Ask:** in TUN mode (at least on macOS, and consistent with the v4-only host-route invariant), do
not assign IPv6 prefixes to the utun when IPv6 is not enabled — drop v6 from the
interface-address-assignment path the same way `tun_actor` already drops it from host routes. Or, if
v6 is intended, bring the utun's IPv6 up before assigning (macOS needs the interface v6-ready first).

**Downstream:** the daemon cannot work around this (it already has IPv6 off and the /128 is derived
inside the engine from the netmap self-node). macOS TUN is blocked on this engine fix. Linux TUN is
likely unaffected (Linux accepts the v6 assignment); the daemon-side name fix (#5) + this (#6) are
the two macOS-specific TUN blockers.
