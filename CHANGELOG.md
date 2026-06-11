# Changelog

All notable changes to **tailscaled-rs** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Pre-1.0, experimental.** This is a from-scratch Rust system daemon — `tailnetd`
> (the daemon) plus `tnet` (a thin CLI) — built on the `tailscale-rs` engine, adding
> the layer the embeddable engine omits: an IPN-style state machine, persisted
> preferences, and a LocalAPI over a Unix domain socket. The engine refuses to run
> unless `TS_RS_EXPERIMENT=this_is_unstable_software` is set, and so does this daemon.
> Interfaces (LocalAPI, prefs schema, CLI flags) are unstable and may change without
> notice while we are below 1.0. Not affiliated with, endorsed by, or sponsored by
> Tailscale Inc.; "Tailscale" and "WireGuard" are used nominatively only.

## Versioning policy

Releases are driven by [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` → **minor** bump.
- `fix:` → **patch** bump.
- `chore:` / `docs:` / `style:` / `refactor:` / `test:` → no release on their own.
- Because the project is **pre-1.0**, breaking changes may land in a **minor** bump
  (and are called out under **Changed**) rather than forcing a major bump. The major
  version stays at `0` until the LocalAPI, prefs schema, and CLI are declared stable.

## [0.29.0](https://github.com/GeiserX/tailscaled-rs/compare/v0.28.0...v0.29.0) (2026-06-11)


### Features

* **whois:** surface ACL tags and node-key expiry ([#85](https://github.com/GeiserX/tailscaled-rs/issues/85)) ([a9a1426](https://github.com/GeiserX/tailscaled-rs/commit/a9a1426ffe5c8b826b9fa8aaa099d3b51bff5b3b))

## [0.28.0](https://github.com/GeiserX/tailscaled-rs/compare/v0.27.0...v0.28.0) (2026-06-11)


### Features

* **up:** add --timeout to wait for the node to reach Running ([#83](https://github.com/GeiserX/tailscaled-rs/issues/83)) ([e3c542f](https://github.com/GeiserX/tailscaled-rs/commit/e3c542fcc0c6225ed38eb8ecb1e1dfbd86fb4fad))

## [0.27.0](https://github.com/GeiserX/tailscaled-rs/compare/v0.26.0...v0.27.0) (2026-06-11)


### Features

* **up:** add --force-reauth to force a fresh re-registration ([#81](https://github.com/GeiserX/tailscaled-rs/issues/81)) ([17e081c](https://github.com/GeiserX/tailscaled-rs/commit/17e081c7efcfac316c79d1934c17570cc2452d2e))

## [0.26.0](https://github.com/GeiserX/tailscaled-rs/compare/v0.25.0...v0.26.0) (2026-06-11)


### Features

* **install:** tnet install / uninstall — system-daemon bootstrap ([#79](https://github.com/GeiserX/tailscaled-rs/issues/79)) ([9743f2c](https://github.com/GeiserX/tailscaled-rs/commit/9743f2c1cc0fe81a73928e94d06caaee9acaba25))

## [0.25.0](https://github.com/GeiserX/tailscaled-rs/compare/v0.24.0...v0.25.0) (2026-06-11)


### Features

* **daemon:** link-change monitor → Device::rebind() (laptop-grade re-homing) ([#77](https://github.com/GeiserX/tailscaled-rs/issues/77)) ([ee8f82f](https://github.com/GeiserX/tailscaled-rs/commit/ee8f82f84be3b55e8f14e019f74af8795e0b555a))

## [0.24.0](https://github.com/GeiserX/tailscaled-rs/compare/v0.23.0...v0.24.0) (2026-06-11)


### Features

* **prefs:** --shields-up — block inbound peer connections (up + set) ([#75](https://github.com/GeiserX/tailscaled-rs/issues/75)) ([a616e0b](https://github.com/GeiserX/tailscaled-rs/commit/a616e0b2e7f3d207311d044dd37810ca4d022700))

## [0.23.0](https://github.com/GeiserX/tailscaled-rs/compare/v0.22.0...v0.23.0) (2026-06-11)


### Features

* **netcheck:** tnet netcheck — DERP-latency net report ([#73](https://github.com/GeiserX/tailscaled-rs/issues/73)) ([15396ba](https://github.com/GeiserX/tailscaled-rs/commit/15396ba1f45fb8372dbc04ac873f48db4589bc23))

## [0.22.0](https://github.com/GeiserX/tailscaled-rs/compare/v0.21.0...v0.22.0) (2026-06-11)


### Features

* **dns:** tnet dns status — render the control-pushed MagicDNS config ([#71](https://github.com/GeiserX/tailscaled-rs/issues/71)) ([280ff2b](https://github.com/GeiserX/tailscaled-rs/commit/280ff2bf4f0eb149ec985e7bf0200a5bec399f29))

## [0.21.0](https://github.com/GeiserX/tailscaled-rs/compare/v0.20.0...v0.21.0) (2026-06-11)


### Features

* **status:** engine bump v0.21.2 + enrich tnet status (relay/direct, last-seen, allowed-routes, active-exit) ([#69](https://github.com/GeiserX/tailscaled-rs/issues/69)) ([eb6c187](https://github.com/GeiserX/tailscaled-rs/commit/eb6c1877258b82b870da670da14989e3c147fa21))

## [0.20.0](https://github.com/GeiserX/tailscaled-rs/compare/v0.19.0...v0.20.0) (2026-06-11)


### Features

* **debug:** tnet debug capture — packet capture to a pcap file ([#67](https://github.com/GeiserX/tailscaled-rs/issues/67)) ([e30ee03](https://github.com/GeiserX/tailscaled-rs/commit/e30ee0386853e9eb9b27e010166abe49f704f8d4))

## [0.19.0](https://github.com/GeiserX/tailscaled-rs/compare/v0.18.0...v0.19.0) (2026-06-11)


### Features

* **funnel:** tnet funnel &lt;port&gt; {on|off} via engine listen_funnel ([#65](https://github.com/GeiserX/tailscaled-rs/issues/65)) ([54803b2](https://github.com/GeiserX/tailscaled-rs/commit/54803b20b88c617cfd43bdcc2396f0fba7bf205e))

## [0.18.0](https://github.com/GeiserX/tailscaled-rs/compare/v0.17.0...v0.18.0) (2026-06-11)


### Features

* **serve:** rich web handlers — text, --set-path mounts, redirect ([#63](https://github.com/GeiserX/tailscaled-rs/issues/63)) ([2f5f86c](https://github.com/GeiserX/tailscaled-rs/commit/2f5f86ca5c5629f34fac4e1e86e8eeeebdb79aea))

## [0.17.0](https://github.com/GeiserX/tailscaled-rs/compare/v0.16.0...v0.17.0) (2026-06-11)


### Features

* **serve:** HTTPS/HTTP web serve via engine delegation ([#61](https://github.com/GeiserX/tailscaled-rs/issues/61)) ([7b458e6](https://github.com/GeiserX/tailscaled-rs/commit/7b458e6003c3bebaefdbb8053f2361e560fb9a66))

## [0.16.0](https://github.com/GeiserX/tailscaled-rs/compare/v0.15.0...v0.16.0) (2026-06-11)


### Features

* **serve:** ServeConfig model + persistence + tnet serve tcp/status/reset ([#58](https://github.com/GeiserX/tailscaled-rs/issues/58)) ([63d8aa5](https://github.com/GeiserX/tailscaled-rs/commit/63d8aa5ccbf51aefe5cc63f7eceb370ab17c6985))
* **serve:** TCP-forward accept loops (serve --tcp now serves traffic) ([#60](https://github.com/GeiserX/tailscaled-rs/issues/60)) ([0e65d1d](https://github.com/GeiserX/tailscaled-rs/commit/0e65d1d779c5ddca7d381ea7f1aac208958ba548))

## [0.15.0](https://github.com/GeiserX/tailscaled-rs/compare/v0.14.0...v0.15.0) (2026-06-10)


### Features

* **nc:** tnet nc &lt;host&gt; &lt;port&gt; — overlay netcat (Go parity) ([#56](https://github.com/GeiserX/tailscaled-rs/issues/56)) ([3c5bc9e](https://github.com/GeiserX/tailscaled-rs/commit/3c5bc9e9f365b14b1638f2d7c98381435ac144e0))

## [0.14.0](https://github.com/GeiserX/tailscaled-rs/compare/v0.13.0...v0.14.0) (2026-06-10)


### Features

* **ping:** tnet ping -c &lt;count&gt; (Go parity) ([#53](https://github.com/GeiserX/tailscaled-rs/issues/53)) ([92cfdd6](https://github.com/GeiserX/tailscaled-rs/commit/92cfdd6cc824867ecbc6c001408be050e616a991))


### Bug Fixes

* **tags,ping:** tighten tag validation to Go CheckTag + pace ping -c ([#55](https://github.com/GeiserX/tailscaled-rs/issues/55)) ([61d3068](https://github.com/GeiserX/tailscaled-rs/commit/61d3068f7f3b6c13ac2959a53265ea6201165d78))

## [0.13.0](https://github.com/GeiserX/tailscaled-rs/compare/v0.12.0...v0.13.0) (2026-06-10)


### Features

* **bugreport:** tnet bugreport — local diagnostic marker (Go parity, honest) ([#52](https://github.com/GeiserX/tailscaled-rs/issues/52)) ([7348a16](https://github.com/GeiserX/tailscaled-rs/commit/7348a168262ca8e6d805dab86d77854a8460da3b))
* **up,set:** advertise-tags pref (Go --advertise-tags parity) ([#50](https://github.com/GeiserX/tailscaled-rs/issues/50)) ([7b04fe7](https://github.com/GeiserX/tailscaled-rs/commit/7b04fe72d8b85fbe1f80fb33e13ecdef0445ac90))

## [0.12.0](https://github.com/GeiserX/tailscaled-rs/compare/v0.11.0...v0.12.0) (2026-06-10)


### Features

* **cli:** tnet metrics, lock status, exit-node list (Go parity) ([#48](https://github.com/GeiserX/tailscaled-rs/issues/48)) ([56d0ff9](https://github.com/GeiserX/tailscaled-rs/commit/56d0ff9a8c7c8be039834ce3e8c94850ea585e2c))

## [0.11.0](https://github.com/GeiserX/tailscaled-rs/compare/v0.10.0...v0.11.0) (2026-06-10)


### Features

* **ip:** tnet ip -4/-6/-1 and [peer] (Go parity) ([#45](https://github.com/GeiserX/tailscaled-rs/issues/45)) ([1868ac7](https://github.com/GeiserX/tailscaled-rs/commit/1868ac74cf45ce0d1ff9e8591d25708d7b1b9a99))
* **profiles:** multi-profile state + tnet switch (Go parity) ([#46](https://github.com/GeiserX/tailscaled-rs/issues/46)) ([fc5aa7e](https://github.com/GeiserX/tailscaled-rs/commit/fc5aa7e5b6d24875f2a7f5d26a8393518eec9b5e))
* **status:** --active / --no-peers / --no-self filters (Go parity) ([#44](https://github.com/GeiserX/tailscaled-rs/issues/44)) ([9fc2826](https://github.com/GeiserX/tailscaled-rs/commit/9fc28261d553da133c320ab32160305ca285c1dd))
* **status:** tnet status --json (Go ipnstate.Status-shaped subset) ([#42](https://github.com/GeiserX/tailscaled-rs/issues/42)) ([46447e3](https://github.com/GeiserX/tailscaled-rs/commit/46447e30e2ab4fdbbec3ba65e8962f579e477c6c))


### Bug Fixes

* **profiles:** commit in-memory switch only after persisted writes succeed ([#47](https://github.com/GeiserX/tailscaled-rs/issues/47)) ([12069a4](https://github.com/GeiserX/tailscaled-rs/commit/12069a46cba0c703a85f44f2739f5b20f74d362f))

## [0.10.0](https://github.com/GeiserX/tailscaled-rs/compare/v0.9.0...v0.10.0) (2026-06-10)


### Features

* **get:** tnet get — show current prefs (Go parity) ([#39](https://github.com/GeiserX/tailscaled-rs/issues/39)) ([1b64d6b](https://github.com/GeiserX/tailscaled-rs/commit/1b64d6b35b09a1fc8b05942cca73cddf4928208e))
* **version:** tnet version (+ --daemon, --json) — Go parity ([#38](https://github.com/GeiserX/tailscaled-rs/issues/38)) ([8f3b711](https://github.com/GeiserX/tailscaled-rs/commit/8f3b711bc0af8b52067b97130d96f80cc9988cac))
* **wait,whoami:** tnet wait + whoami (Go parity) ([#40](https://github.com/GeiserX/tailscaled-rs/issues/40)) ([407993c](https://github.com/GeiserX/tailscaled-rs/commit/407993ce86b056349761f95a79ba18dfb77931e3))


### Bug Fixes

* **up,logout:** drift-proof the revert guard + crash-safe logout key wipe ([#36](https://github.com/GeiserX/tailscaled-rs/issues/36)) ([78c50a3](https://github.com/GeiserX/tailscaled-rs/commit/78c50a32bbf1f31890b47a70efe44964bfd36189))

## [0.9.0](https://github.com/GeiserX/tailscaled-rs/compare/v0.8.0...v0.9.0) (2026-06-10)


### Features

* **logout:** tnet logout — deregister + discard key (Go parity) ([#33](https://github.com/GeiserX/tailscaled-rs/issues/33)) ([0d5170d](https://github.com/GeiserX/tailscaled-rs/commit/0d5170d1df9e0575af17c7a4e524a11869907fa4))

## [0.8.0](https://github.com/GeiserX/tailscaled-rs/compare/v0.7.0...v0.8.0) (2026-06-10)


### Features

* **up:** Go-faithful REPLACE semantics via accidental-revert guard + --reset ([#32](https://github.com/GeiserX/tailscaled-rs/issues/32)) ([aa2b3b4](https://github.com/GeiserX/tailscaled-rs/commit/aa2b3b46b103a6600b01d1fbff111d3adbc4e93a))


### Bug Fixes

* **localapi:** run read/file engine calls off-lock + harden Taildrop paths ([#28](https://github.com/GeiserX/tailscaled-rs/issues/28)) ([10432e8](https://github.com/GeiserX/tailscaled-rs/commit/10432e81f9121f84af45ef80b3889e78ada8c1aa))
* **nits:** consistent clear-flag naming, tun resolver helper, comment cleanup ([#31](https://github.com/GeiserX/tailscaled-rs/issues/31)) ([63fa6c7](https://github.com/GeiserX/tailscaled-rs/commit/63fa6c7edc2470db68fd333f004c3564b0da1f71))

## [0.7.0](https://github.com/GeiserX/tailscaled-rs/compare/v0.6.0...v0.7.0) (2026-06-10)


### Features

* **security:** use engine Device::new_with_secret + bump to v0.8.0 (tsd-tnv) ([#26](https://github.com/GeiserX/tailscaled-rs/issues/26)) ([9a8a703](https://github.com/GeiserX/tailscaled-rs/commit/9a8a703b592ed5ca1bcbc311b69855deeef7243a))

## [0.6.0](https://github.com/GeiserX/tailscaled-rs/compare/v0.5.0...v0.6.0) (2026-06-10)


### Features

* **diag:** tnet ip / whois / ping diagnostics (tsd-iqq.2 part 1) ([#23](https://github.com/GeiserX/tailscaled-rs/issues/23)) ([9903696](https://github.com/GeiserX/tailscaled-rs/commit/9903696be97de6f7ef623530c38620b6952728e5))
* **file:** Taildrop send/receive (tsd-qw8) ([#24](https://github.com/GeiserX/tailscaled-rs/issues/24)) ([016e072](https://github.com/GeiserX/tailscaled-rs/commit/016e0728cb800a2610d735f99316c3d45404c2ec))
* **status:** surface configured posture in status (tsd-iqq.4 part 1) ([#21](https://github.com/GeiserX/tailscaled-rs/issues/21)) ([34ca3a5](https://github.com/GeiserX/tailscaled-rs/commit/34ca3a55cc238d011aa6efc6b4997d73a2520a6b))

## [0.5.0](https://github.com/GeiserX/tailscaled-rs/compare/v0.4.0...v0.5.0) (2026-06-09)


### Features

* **exit:** leak-safety guard + documented invariant (tsd-iqq.3) ([#19](https://github.com/GeiserX/tailscaled-rs/issues/19)) ([53bbd22](https://github.com/GeiserX/tailscaled-rs/commit/53bbd220aee2a837381b1748f9b9b3eda7d90e9b))
* **set:** tnet set — live pref mutation without up/down (tsd-iqq.1) ([#15](https://github.com/GeiserX/tailscaled-rs/issues/15)) ([c918cc1](https://github.com/GeiserX/tailscaled-rs/commit/c918cc15fd4baf820d7df79c08e1e7d8bd9801ad))
* **ssh:** Tailscale SSH server (tsd-46c) ([#17](https://github.com/GeiserX/tailscaled-rs/issues/17)) ([3b17972](https://github.com/GeiserX/tailscaled-rs/commit/3b1797280afa651199dfa3e5fa536030a18f58de))


### Bug Fixes

* **set:** preflight rebuilt config before tearing down the live device ([#18](https://github.com/GeiserX/tailscaled-rs/issues/18)) ([ee1f6b0](https://github.com/GeiserX/tailscaled-rs/commit/ee1f6b01f882d7e32031302253a342d2bc152f28))

## [0.4.0](https://github.com/GeiserX/tailscaled-rs/compare/v0.3.1...v0.4.0) (2026-06-09)


### Features

* **routing:** exit-node + advertise-exit-node + advertise-routes (tsd-hob, tsd-cmi) ([#13](https://github.com/GeiserX/tailscaled-rs/issues/13)) ([ceb8ec3](https://github.com/GeiserX/tailscaled-rs/commit/ceb8ec3c5bfe0b311a52b56dd8b71774d58afbfc))

## [0.3.1](https://github.com/GeiserX/tailscaled-rs/compare/v0.3.0...v0.3.1) (2026-06-09)


### Miscellaneous Chores

* release 0.3.1 ([#11](https://github.com/GeiserX/tailscaled-rs/issues/11)) ([295360f](https://github.com/GeiserX/tailscaled-rs/commit/295360f335cac2534124fef711cc46ea1c50c13c))

## [0.3.0](https://github.com/GeiserX/tailscaled-rs/compare/v0.2.2...v0.3.0) (2026-06-09)


### Features

* **status:** surface terminal registration failure distinctly (tsd-bml) ([#7](https://github.com/GeiserX/tailscaled-rs/issues/7)) ([46fe77d](https://github.com/GeiserX/tailscaled-rs/commit/46fe77d15da76f0aafd4aad6118b145ae098f204))


### Bug Fixes

* gate terminal-failure on is_permanent + harden installer symlinks ([#9](https://github.com/GeiserX/tailscaled-rs/issues/9)) ([8cef416](https://github.com/GeiserX/tailscaled-rs/commit/8cef4165bbe83eeb3d7cfa9bbd21552e36261af9))

## [0.2.2](https://github.com/GeiserX/tailscaled-rs/compare/v0.2.1...v0.2.2) (2026-06-09)


### Bug Fixes

* **release:** auto-dispatch the binary build when a release is cut ([#5](https://github.com/GeiserX/tailscaled-rs/issues/5)) ([b3b1cb5](https://github.com/GeiserX/tailscaled-rs/commit/b3b1cb50285bd0767694a42686f4ce9765520833))

## [0.2.1](https://github.com/GeiserX/tailscaled-rs/compare/v0.2.0...v0.2.1) (2026-06-09)


### Bug Fixes

* **release:** emit clean v* tags so the binary build fires ([#3](https://github.com/GeiserX/tailscaled-rs/issues/3)) ([03f0cd9](https://github.com/GeiserX/tailscaled-rs/commit/03f0cd97697976edc2edef8c503868a360649c14))

## [0.2.0](https://github.com/GeiserX/tailscaled-rs/compare/tailscaled-rs-v0.1.0...tailscaled-rs-v0.2.0) (2026-06-09)


### Features

* **login:** interactive/browser login — surface the control auth URL (tsd-8j2) ([862a708](https://github.com/GeiserX/tailscaled-rs/commit/862a708824e19f5eb10610128a8c52588fdcb9ca))
* **status:** 'tnet status --watch' streaming over LocalAPI (tsd-c3p) ([c93e492](https://github.com/GeiserX/tailscaled-rs/commit/c93e49266bfaa840f1613556e55206ae4d4faaed))
* **tun:** Phase-3 TUN-mode plumbing (daemon-ready; blocked on one engine export) ([9275693](https://github.com/GeiserX/tailscaled-rs/commit/92756939d211d5032ff6832a607be911feff282c))
* **tun:** wire kernel-TUN transport on engine v0.6.7 (tsd-tth) ([a86fb3b](https://github.com/GeiserX/tailscaled-rs/commit/a86fb3b5e189c3275738e2d6aba86761c54ad7cb))


### Bug Fixes

* bump engine to v0.6.9 + correct macOS-TUN engine ask [#6](https://github.com/GeiserX/tailscaled-rs/issues/6) ([3f9675c](https://github.com/GeiserX/tailscaled-rs/commit/3f9675cbce0261fcb49d052be8ff306d8525d163))
* **ci:** gate the utun-name test to macOS so Linux+tun compiles ([eb6fee3](https://github.com/GeiserX/tailscaled-rs/commit/eb6fee3fddbbdd8b464d42b8c83596549a392db7))
* **review:** bound status() netmap query + drop vestigial param ([a85c324](https://github.com/GeiserX/tailscaled-rs/commit/a85c324a1fa07916281f32ccdea9a7ef18ec892a))
* **review:** off-lock SIGHUP reload, --no-tun, boot-attempt guard, hardening ([814ccef](https://github.com/GeiserX/tailscaled-rs/commit/814ccefb02c70757f581aede9e34f14ecbcb3547))
* **tun:** default macOS TUN name to utun (engine default tailscale0 is rejected) ([7b4c41d](https://github.com/GeiserX/tailscaled-rs/commit/7b4c41dd23cb7d11afb6fbde800b744db84ed6c1))

## [Unreleased]

_Nothing yet._

## [0.1.0] - 2026-06-08

The initial MVP of the standalone daemon, hardened and reviewed.

### Added

- **MVP daemon (`tailnetd`) + CLI (`tnet`).** A from-scratch, BSD-3-Clause Rust
  system daemon built on the `tailscale-rs` engine, supplying the daemon layer the
  embeddable engine omits: an IPN-style state machine, persisted preferences, and a
  LocalAPI over a Unix domain socket. In MVP (Phase 1, userspace networking) it joins
  a tailnet with a pre-auth key, reaches `Running`, and answers `status`/`up`/`down`.
  Verified end-to-end against a live tailnet.
- **Pre-auth-key handling that keeps keys out of argv/history.** `tnet` gains
  `--authkey-file` and `$TS_AUTH_KEY` (precedence: file > flag > env).
- **SO_PEERCRED authorization on the LocalAPI socket.** Reads are open; writes
  (`up`/`down`) require root or the daemon's owner, and authorization fails closed if
  the peer-credential lookup errors. Computed per-connection before the stream split.
- **Control-plane URL override.** A `control_url` from prefs/CLI is parsed and applied
  to the engine config on `up()`; a malformed URL fails loudly instead of silently
  falling back to the default control plane.
- **Extended IPN state parity.** `NeedsMachineAuth` / `InUseOtherUser` added to the
  state model with honest LIMITATION docs (the engine surfaces no machine-auth signal —
  documented, not fabricated); `derive_state` extracted as a pure, unit-tested helper.
- **Secure state directory.** `ensure_state_dir_secure` enforces `0700` on the state
  directory before any key file is written.
- **Tests.** LocalAPI integration tests over a real UDS plus a state-machine matrix;
  39 tests pass, `clippy -D warnings` clean.

### Changed

- **Crate renamed to `tailscaled-rs`** (imported as `tailscaled_rs`); the installed
  binaries deliberately stay `tailnetd` + `tnet` so they never collide on `PATH` with a
  real Tailscale install. Added repository metadata. No behavior change.
  > Publishing to crates.io remains blocked until the `tailscale-rs` engine is
  > published there (`cargo publish` rejects the git dependency).
- **`control_url` precedence made explicit.** The engine config is now built from
  `Config::default_from_env()` so `TS_CONTROL_URL` is honored, with `prefs.control_url`
  overriding last (precedence: **prefs > env > default**). HTTP/HTTPS scheme validation
  added; a `control_url.rs` test pins the parse + scheme contract.
- **Authorization model simplified.** Collapsed `Permissions{read,write}` (a dead field)
  into a 2-variant `Access` enum; introduced an `AuthPolicy` built once at startup (the
  operator-GID seam) instead of a per-call euid lookup; made `current_euid` private. A
  pure `authorize(&Request, Access) -> Result<(), Denied>` was extracted so the
  security-critical deny path is unit-tested directly.
- **Prefs are forward/backward compatible** via a container-level `#[serde(default)]` on
  `prefs.json`.
- **LICENSE made canonically detectable.** `LICENSE` is now the verbatim BSD-3-Clause
  template (GitHub auto-detect); the upstream-derivation explanation and trademark
  notices moved to `NOTICE`, with both copyright holders in the copyright line and
  Tailscale Inc. attribution retained per clause 1.

### Fixed

- **`ever_configured` survives restart.** It now derives from prefs-file existence, so
  the `NoState` vs `Stopped` distinction holds across a restart (previously an
  up→down→restart wrongly reported `NoState`; now reports `Stopped`).
- **Engine status errors are logged, not swallowed.** `status()` errors are logged
  instead of silently downgrading `Running` → `Starting`.
- **Empty pre-auth keys are ignored consistently.** An empty `TS_AUTH_KEY` is filtered in
  the daemon auto-start path, matching the CLI.

### Security

- **Peercred-gated writes (fail-closed).** `up`/`down` require root or the daemon owner
  via `SO_PEERCRED`; a credential-lookup error denies the request.
- **Secrets handled as `secrecy::SecretString` end-to-end** (CLI, daemon, auto-start),
  exposed only at serialization and the engine call, never logged; a Debug-redaction
  test pins this.
- **`0700` enforced on the socket's parent directory** inside `serve()` rather than
  trusting the caller.
- **LocalAPI server hardening:** request line length capped at 64 KiB (anti-OOM);
  in-flight connections drained via a `JoinSet` with a 2 s bound on shutdown; concurrent
  connections capped with a `Semaphore`.

[Unreleased]: https://github.com/GeiserX/tailscaled-rs/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/GeiserX/tailscaled-rs/releases/tag/v0.1.0
