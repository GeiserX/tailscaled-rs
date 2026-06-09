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
