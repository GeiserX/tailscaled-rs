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

## [0.42.0](https://github.com/GeiserX/tailscaled-rs/compare/v0.41.0...v0.42.0) (2026-06-13)


### Features

* **cli:** add `tnet lock sign` / `tnet lock disable` (Tailnet Lock write-ops) ([#163](https://github.com/GeiserX/tailscaled-rs/issues/163)) ([fd9040a](https://github.com/GeiserX/tailscaled-rs/commit/fd9040a0c83400ebce80b196b05c74198413d6db))

## [0.41.0](https://github.com/GeiserX/tailscaled-rs/compare/v0.40.1...v0.41.0) (2026-06-13)


### Features

* **cli:** add `tnet cert` (Go tailscale cert), consuming engine [#16](https://github.com/GeiserX/tailscaled-rs/issues/16) ([#127](https://github.com/GeiserX/tailscaled-rs/issues/127)) ([2dbb124](https://github.com/GeiserX/tailscaled-rs/commit/2dbb124637e2cc7785a22180d7fce982f2bd305d))
* **cli:** add `tnet debug prefs` (Go `tailscale debug prefs`) ([#143](https://github.com/GeiserX/tailscaled-rs/issues/143)) ([367d0c5](https://github.com/GeiserX/tailscaled-rs/commit/367d0c5dd29e9388050a0cef11afba887f83eb10))
* **cli:** add `tnet dns query` (Go `tailscale dns query`) ([#158](https://github.com/GeiserX/tailscaled-rs/issues/158)) ([4735a8a](https://github.com/GeiserX/tailscaled-rs/commit/4735a8af2240f83214474ea4a8dc5225d32a0286))
* **cli:** add `tnet licenses` (Go `tailscale licenses`) ([#142](https://github.com/GeiserX/tailscaled-rs/issues/142)) ([87f2dfb](https://github.com/GeiserX/tailscaled-rs/commit/87f2dfb8b51b6949ae02ce37d4ab19bd9ac27222))
* **cli:** add `tnet metrics print` subcommand (Go `tailscale metrics print`) ([#144](https://github.com/GeiserX/tailscaled-rs/issues/144)) ([3be6310](https://github.com/GeiserX/tailscaled-rs/commit/3be6310b3e523a1dd0931760e84c718a3ee28d86))
* **cli:** add workload-identity-federation up flags (--client-id/--client-secret/--id-token/--audience) ([#154](https://github.com/GeiserX/tailscaled-rs/issues/154)) ([3df6101](https://github.com/GeiserX/tailscaled-rs/commit/3df61016e4879d6000e8468f3baf46962feca2b9))
* **cli:** tnet wait/up --timeout confirms the kernel TUN interface carries the IP ([#155](https://github.com/GeiserX/tailscaled-rs/issues/155)) ([388df12](https://github.com/GeiserX/tailscaled-rs/commit/388df1264b6e255a21e69f1bd8df584298bac500))
* **cli:** wire accept-dns (Go --accept-dns / CorpDNS), consuming engine [#14](https://github.com/GeiserX/tailscaled-rs/issues/14) ([#126](https://github.com/GeiserX/tailscaled-rs/issues/126)) ([06640b8](https://github.com/GeiserX/tailscaled-rs/commit/06640b8b71a1f6b72692046290c8e8a68c23ccbd))
* **file:** Go cp colon-target syntax + variadic files + --targets (closes tsd-x4i) ([#137](https://github.com/GeiserX/tailscaled-rs/issues/137)) ([1807be3](https://github.com/GeiserX/tailscaled-rs/commit/1807be3b7390b6cfaafd28d104101800a6871ecb))
* **file:** Go-faithful `file get <dir>` inbox drain + --conflict (fixes silent-overwrite data loss) ([#136](https://github.com/GeiserX/tailscaled-rs/issues/136)) ([77c037e](https://github.com/GeiserX/tailscaled-rs/commit/77c037ecf404a96c6e8b9da50aa25588fc61f1c4))
* **get:** add `get --set-flags` (Go `tailscale get --set-flags`) ([#149](https://github.com/GeiserX/tailscaled-rs/issues/149)) ([6cbaa58](https://github.com/GeiserX/tailscaled-rs/commit/6cbaa5804ed79c4335c00954e79ecc7a96b11565))
* **get:** surface hostname in `tnet get` (Go parity) + fix flaky conffile test temp path ([#148](https://github.com/GeiserX/tailscaled-rs/issues/148)) ([1180b43](https://github.com/GeiserX/tailscaled-rs/commit/1180b43c296d5558bfa962c5590d0f0223df64d9))
* **install:** TUN-relaxed systemd unit for tun-feature builds (tsd-9qm) ([#138](https://github.com/GeiserX/tailscaled-rs/issues/138)) ([eb8e522](https://github.com/GeiserX/tailscaled-rs/commit/eb8e5229700d496af6fe7b15468ce99b65b168af))
* **ping:** --until-direct + Go-faithful -c default + direct/DERP path reporting ([#135](https://github.com/GeiserX/tailscaled-rs/issues/135)) ([9c83b56](https://github.com/GeiserX/tailscaled-rs/commit/9c83b56db138c4c2f276d6c9d8e57264c0e8fa12))
* **serve:** model Go's top-level ServeConfig.Web map (tsd-6p4 stage A) ([#129](https://github.com/GeiserX/tailscaled-rs/issues/129)) ([30d7522](https://github.com/GeiserX/tailscaled-rs/commit/30d7522fe5de6623cef2184641a4970c8621cd4d))
* **serve:** serve + render the Go ServeConfig.Web map (tsd-6p4 stage B, read side) ([#130](https://github.com/GeiserX/tailscaled-rs/issues/130)) ([0f1c7ca](https://github.com/GeiserX/tailscaled-rs/commit/0f1c7ca468fa00cb04a1b9a607e53bb3b737a942))
* **serve:** serve TLS-terminated raw-TCP forwards (Go --tls-terminated-tcp) ([#128](https://github.com/GeiserX/tailscaled-rs/issues/128)) ([6787ad8](https://github.com/GeiserX/tailscaled-rs/commit/6787ad8dc3d891cd5c33faa1ed657b515f15df0f))
* **serve:** tnet serve authors the Go Web map (tsd-6p4 stage B2, write side) ([#131](https://github.com/GeiserX/tailscaled-rs/issues/131)) ([33ad18a](https://github.com/GeiserX/tailscaled-rs/commit/33ad18ae70ecd329875ade61b7a842eb1a757570))
* **tailnetd:** --config declarative config file (Go ipn.ConfigVAlpha, closes tsd-bin) ([#140](https://github.com/GeiserX/tailscaled-rs/issues/140)) ([8e72b0c](https://github.com/GeiserX/tailscaled-rs/commit/8e72b0cd897a5f66b9f87647adef27a864e3e9aa))
* **tailnetd:** Go-style CLI flags (--statedir/--socket/--verbose/--version) ([#139](https://github.com/GeiserX/tailscaled-rs/issues/139)) ([f7c5d3c](https://github.com/GeiserX/tailscaled-rs/commit/f7c5d3cce28cdea362f11ea5826c3a3d2e4ea0d4))


### Bug Fixes

* **cli:** align netcheck/serve/get diagnostic output with Go v1.100.0 ([#122](https://github.com/GeiserX/tailscaled-rs/issues/122)) ([f0788e3](https://github.com/GeiserX/tailscaled-rs/commit/f0788e39deae438aeaa36d83389426e247ca4f5c))
* **cli:** byte-match Go's lock-status wording + correct file-command doc miscites ([#123](https://github.com/GeiserX/tailscaled-rs/issues/123)) ([1a65ea5](https://github.com/GeiserX/tailscaled-rs/commit/1a65ea5ce4c016e6551b594d475ab395e3822d56))
* **cli:** neutralize column/row injection from control-supplied names in terminal output ([#152](https://github.com/GeiserX/tailscaled-rs/issues/152)) ([51b5d30](https://github.com/GeiserX/tailscaled-rs/commit/51b5d30e605c70344df3d7e30dc1d5e1c44862dc))
* **cli:** reset SIGPIPE to default so broken output pipes exit cleanly (not a panic) ([#151](https://github.com/GeiserX/tailscaled-rs/issues/151)) ([2fb9130](https://github.com/GeiserX/tailscaled-rs/commit/2fb9130f74a76fe71771c448c111b9e25c6553ee))
* **cli:** sanitize control-supplied diagnostic output + correct netcheck JSON claims ([#124](https://github.com/GeiserX/tailscaled-rs/issues/124)) ([19a4273](https://github.com/GeiserX/tailscaled-rs/commit/19a4273c848fcd5195c5f975d285a44ea4e7a39c))
* **exit-node:** reject `auto:` selector instead of silently breaking exit routing ([#119](https://github.com/GeiserX/tailscaled-rs/issues/119)) ([27cd239](https://github.com/GeiserX/tailscaled-rs/commit/27cd23931547947d01717821e869c8b9d32e6dc6))
* **file:** wire `cp --name` to the actual transfer (was silently a no-op) ([#141](https://github.com/GeiserX/tailscaled-rs/issues/141)) ([2b178ba](https://github.com/GeiserX/tailscaled-rs/commit/2b178baf7419d00d19870bfd348742caadc19ad2))
* **ipn:** gate Stopped on a persisted node key (Go hasNodeKeyLocked) + honest dns-status --json doc ([#121](https://github.com/GeiserX/tailscaled-rs/issues/121)) ([8556063](https://github.com/GeiserX/tailscaled-rs/commit/85560635e1021538e6c80f4cc63dc63748a1e9e4))
* **ipn:** persist has_logged_in on set-rebuild + clear it on logout (review follow-ups) ([#161](https://github.com/GeiserX/tailscaled-rs/issues/161)) ([c29128d](https://github.com/GeiserX/tailscaled-rs/commit/c29128d8338b771a233e497069d3edad1d25d582))
* **ipn:** revert-guard fresh-node exemption keys on has-logged-in, not prefs-file existence ([#156](https://github.com/GeiserX/tailscaled-rs/issues/156)) ([14dbde7](https://github.com/GeiserX/tailscaled-rs/commit/14dbde7ee12015b47a6b99c7b79a78b49cb69296))
* **release:** ship a full-featured daemon (tun,ssh,acme) — released binaries were feature-less ([#133](https://github.com/GeiserX/tailscaled-rs/issues/133)) ([b09fa10](https://github.com/GeiserX/tailscaled-rs/commit/b09fa1028a5889bc808771a6538b19321019cf8f))
* **status:** emit RFC3339 timestamps (Go-ipnstate-compatible), not chrono Display ([#147](https://github.com/GeiserX/tailscaled-rs/issues/147)) ([6476b1b](https://github.com/GeiserX/tailscaled-rs/commit/6476b1ba28b07ced17d3c017cd63d20b6bc3e017))
* **up:** default to a persistent node + add --ephemeral/--no-ephemeral (Go parity, tsd-4qt) ([#134](https://github.com/GeiserX/tailscaled-rs/issues/134)) ([d46bbee](https://github.com/GeiserX/tailscaled-rs/commit/d46bbee68b86bc85fda1a8e11dec67e68b76c42f))

## [0.40.1](https://github.com/GeiserX/tailscaled-rs/compare/v0.40.0...v0.40.1) (2026-06-12)


### Bug Fixes

* **taildrop:** O_NOFOLLOW on file_cp/file_get opens + file engine asks [#16](https://github.com/GeiserX/tailscaled-rs/issues/16)/[#17](https://github.com/GeiserX/tailscaled-rs/issues/17) ([#112](https://github.com/GeiserX/tailscaled-rs/issues/112)) ([86e86c8](https://github.com/GeiserX/tailscaled-rs/commit/86e86c80525655686b8950cbe63df2c57dc485f5))

## [0.40.0](https://github.com/GeiserX/tailscaled-rs/compare/v0.39.0...v0.40.0) (2026-06-12)


### Features

* **set:** apply hostname/accept-routes/advertise-* live (no reconnect) ([#110](https://github.com/GeiserX/tailscaled-rs/issues/110)) ([9290e0c](https://github.com/GeiserX/tailscaled-rs/commit/9290e0cac4858c14f5844cffbeff83d604d20813))

## [0.39.0](https://github.com/GeiserX/tailscaled-rs/compare/v0.38.0...v0.39.0) (2026-06-12)


### Features

* **whois:** surface flow-scoped cap-grants (WhoIsResponse.CapMap) ([#108](https://github.com/GeiserX/tailscaled-rs/issues/108)) ([f5d7e11](https://github.com/GeiserX/tailscaled-rs/commit/f5d7e11ad26b90ff30918a2f41797dcf93cd3121))

## [0.38.0](https://github.com/GeiserX/tailscaled-rs/compare/v0.37.0...v0.38.0) (2026-06-12)


### Features

* **status:** add --web (embedded HTML status server) ([#105](https://github.com/GeiserX/tailscaled-rs/issues/105)) ([047a025](https://github.com/GeiserX/tailscaled-rs/commit/047a025f9a4b72200c90901208b6c6939435110e))

## [0.37.0](https://github.com/GeiserX/tailscaled-rs/compare/v0.36.0...v0.37.0) (2026-06-12)


### Features

* **status:** surface Version + TUN (+HaveNodeKey) in status --json ([#103](https://github.com/GeiserX/tailscaled-rs/issues/103)) ([0e4edb7](https://github.com/GeiserX/tailscaled-rs/commit/0e4edb7dadb56bb8b69fd95fa02cd85f2d08ee00))

## [0.36.0](https://github.com/GeiserX/tailscaled-rs/compare/v0.35.0...v0.36.0) (2026-06-12)


### Features

* **risk:** enforce lose-ssh on an SSH-server toggle over Tailscale SSH (completes the risk) ([#101](https://github.com/GeiserX/tailscaled-rs/issues/101)) ([e9db2b8](https://github.com/GeiserX/tailscaled-rs/commit/e9db2b8f3bb1c083052946ba84131232c56e7369))

## [0.35.0](https://github.com/GeiserX/tailscaled-rs/compare/v0.34.1...v0.35.0) (2026-06-12)


### Features

* **up:** --accept-risk + enforce lose-ssh on force-reauth over Tailscale SSH ([#99](https://github.com/GeiserX/tailscaled-rs/issues/99)) ([c30c1d8](https://github.com/GeiserX/tailscaled-rs/commit/c30c1d821289d8b37348d3db27d7a3c886fe3047))

## [0.34.1](https://github.com/GeiserX/tailscaled-rs/compare/v0.34.0...v0.34.1) (2026-06-12)


### Bug Fixes

* **auth:** gate `metrics` as a write (Go PermitWrite), not a read ([#97](https://github.com/GeiserX/tailscaled-rs/issues/97)) ([2dcd3e3](https://github.com/GeiserX/tailscaled-rs/commit/2dcd3e3bb5d317a402296b3e38996dcb199f27ff))

## [0.34.0](https://github.com/GeiserX/tailscaled-rs/compare/v0.33.0...v0.34.0) (2026-06-12)


### Features

* **id-token:** tnet id-token &lt;audience&gt; — fetch an OIDC id-token for the node ([#95](https://github.com/GeiserX/tailscaled-rs/issues/95)) ([2103a6f](https://github.com/GeiserX/tailscaled-rs/commit/2103a6f0e0229a2ca25b7456819f1d6638ae1f53))

## [0.33.0](https://github.com/GeiserX/tailscaled-rs/compare/v0.32.0...v0.33.0) (2026-06-11)


### Features

* **version:** version.Meta JSON shape (incl. cap) + bugreport [note] + version --upstream stub ([#93](https://github.com/GeiserX/tailscaled-rs/issues/93)) ([56b2236](https://github.com/GeiserX/tailscaled-rs/commit/56b223633929aca2ad2bb1f9e2ab42012e1f3f46))

## [0.32.0](https://github.com/GeiserX/tailscaled-rs/compare/v0.31.0...v0.32.0) (2026-06-11)


### Features

* **up:** refuse a control-server change on a running node without --force-reauth ([#91](https://github.com/GeiserX/tailscaled-rs/issues/91)) ([8035ba4](https://github.com/GeiserX/tailscaled-rs/commit/8035ba4129f2075082b863d99237fdf4c451e29a))

## [0.31.0](https://github.com/GeiserX/tailscaled-rs/compare/v0.30.0...v0.31.0) (2026-06-11)


### Features

* **wait:** fail fast on a terminal registration error ([#89](https://github.com/GeiserX/tailscaled-rs/issues/89)) ([e818397](https://github.com/GeiserX/tailscaled-rs/commit/e8183978d36d4bb38e5da6ceae3902d17d55af92))

## [0.30.0](https://github.com/GeiserX/tailscaled-rs/compare/v0.29.0...v0.30.0) (2026-06-11)


### Features

* **whois:** surface online state and last-seen time ([#87](https://github.com/GeiserX/tailscaled-rs/issues/87)) ([8a4156d](https://github.com/GeiserX/tailscaled-rs/commit/8a4156d64b3abf9af61cd5073a8e112ef674d3fc))

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
