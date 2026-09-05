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

## [0.54.3](https://github.com/GeiserX/tailscaled-rs/compare/v0.54.2...v0.54.3) (2026-09-05)


### Bug Fixes

* **portmap:** stop an abandoned debug run and defuse its log lines ([#368](https://github.com/GeiserX/tailscaled-rs/issues/368)) ([566984a](https://github.com/GeiserX/tailscaled-rs/commit/566984ae1dabc2e0a62592b4cfda396abb9dd09e))

## [0.54.2](https://github.com/GeiserX/tailscaled-rs/compare/v0.54.1...v0.54.2) (2026-09-05)


### Bug Fixes

* **audit:** restate the totals the re-derived parity audit dropped ([#364](https://github.com/GeiserX/tailscaled-rs/issues/364)) ([1cda69d](https://github.com/GeiserX/tailscaled-rs/commit/1cda69dcde2ca5bf5fc4bdcebddc15f8c13b6f8b))

## [0.54.1](https://github.com/GeiserX/tailscaled-rs/compare/v0.54.0...v0.54.1) (2026-09-03)


### Bug Fixes

* **cli:** print Go's own reload-config lines so scripts still match ([#354](https://github.com/GeiserX/tailscaled-rs/issues/354)) ([bd471fa](https://github.com/GeiserX/tailscaled-rs/commit/bd471faa9fa91a979ddb0c981d60155a75b24d14))

## [0.54.0](https://github.com/GeiserX/tailscaled-rs/compare/v0.53.0...v0.54.0) (2026-09-03)


### Features

* **appc-routes:** tell the operator the app connector advertises but never learns a route ([#341](https://github.com/GeiserX/tailscaled-rs/issues/341)) ([3d274d4](https://github.com/GeiserX/tailscaled-rs/commit/3d274d43cc4751ef695fe5e4d9e56592d8fbdcb6))
* **configure:** adopt Go's macOS `sysext`/`mac-vpn`, rule the host-integration set out of scope ([#303](https://github.com/GeiserX/tailscaled-rs/issues/303)) ([73859c8](https://github.com/GeiserX/tailscaled-rs/commit/73859c867d520225267fc466c8f52e3c5aa131ef))
* **debug:** port `debug resolve`, the one lookup that needs no daemon ([#304](https://github.com/GeiserX/tailscaled-rs/issues/304)) ([fe65d46](https://github.com/GeiserX/tailscaled-rs/commit/fe65d46efb343c0b9fdedf3b515015f931760d87))
* **service:** let this build see the Tailscale Services (VIPs) a node can reach ([#309](https://github.com/GeiserX/tailscaled-rs/issues/309)) ([7dec267](https://github.com/GeiserX/tailscaled-rs/commit/7dec267124636249220453da7d742affd700dd81))
* **set:** carry Go's last four `set` pref flags so a ported command line says what is missing ([#310](https://github.com/GeiserX/tailscaled-rs/issues/310)) ([1973cf9](https://github.com/GeiserX/tailscaled-rs/commit/1973cf95b8f6718570964e326ec29c9837fc0e12))
* **syspolicy:** let an admin supply policy with `tailnetd --syspolicy-file` ([#308](https://github.com/GeiserX/tailscaled-rs/issues/308)) ([a6c3cef](https://github.com/GeiserX/tailscaled-rs/commit/a6c3cefc8bdf3392dab08d3ee46e4ca4b4db9796))
* **tailnetd:** diagnose a node that never comes up, without a running daemon ([#324](https://github.com/GeiserX/tailscaled-rs/issues/324)) ([a515d4a](https://github.com/GeiserX/tailscaled-rs/commit/a515d4ac18604fe83bad8662e72acfe9617a23ca))
* **tailnetd:** refuse Go's two TPM flags by name, and record the state-at-rest decision ([#325](https://github.com/GeiserX/tailscaled-rs/issues/325)) ([054224c](https://github.com/GeiserX/tailscaled-rs/commit/054224c908f8cbef983b38c6f61cce0cb12d412e))
* **tailnetd:** take Go's `--tun`, the flag every unit file passes ([#344](https://github.com/GeiserX/tailscaled-rs/issues/344)) ([9f6c2cb](https://github.com/GeiserX/tailscaled-rs/commit/9f6c2cb79193c0e38be84ff5889c820774950a35))
* **tnet:** give `down` Go's `--reason` and its lose-SSH refusal ([#336](https://github.com/GeiserX/tailscaled-rs/issues/336)) ([02d4d93](https://github.com/GeiserX/tailscaled-rs/commit/02d4d9331aabf6b2a1d2a985752b25ee34d29538))
* **tnet:** give `exit-node list` Go's columns, `--filter` and refusals ([#331](https://github.com/GeiserX/tailscaled-rs/issues/331)) ([e3da1da](https://github.com/GeiserX/tailscaled-rs/commit/e3da1dac5abce5e2742d784fb574bf4814a67f5a))
* **tnet:** let `ping` take the peer name you already know it by ([#337](https://github.com/GeiserX/tailscaled-rs/issues/337)) ([8dd1ca5](https://github.com/GeiserX/tailscaled-rs/commit/8dd1ca50de2b0ff1f24fd7390a32326b7e87ebfe))
* **tnet:** make `bugreport` carry evidence, not just a bare marker ([#330](https://github.com/GeiserX/tailscaled-rs/issues/330)) ([2d333c2](https://github.com/GeiserX/tailscaled-rs/commit/2d333c2e9ba8e32c357734f5606af72b696219b9))
* **tnet:** take `dns status --all`, and stop printing it by default ([#333](https://github.com/GeiserX/tailscaled-rs/issues/333)) ([95a3c81](https://github.com/GeiserX/tailscaled-rs/commit/95a3c81d7862ab1aeacf07e998cfc5c1008a891a))
* **tnet:** take Go's whois flow arguments, so `whois --proto=tcp ip:port` runs ([#327](https://github.com/GeiserX/tailscaled-rs/issues/327)) ([1329596](https://github.com/GeiserX/tailscaled-rs/commit/1329596f889119f61fc98cf75a06fc88c94a8f43))
* **up:** take Go's own `up` flag spellings so a ported command line runs ([#313](https://github.com/GeiserX/tailscaled-rs/issues/313)) ([09627e5](https://github.com/GeiserX/tailscaled-rs/commit/09627e5c404039c3dee8e13a207785b5f6b77bf4))
* **web:** let a reverse-proxied or CGI-served web UI state the URL it is really reached at ([#326](https://github.com/GeiserX/tailscaled-rs/issues/326)) ([12f170a](https://github.com/GeiserX/tailscaled-rs/commit/12f170a8a062c7a8f94ff9c7d16e647717016a87))


### Bug Fixes

* bound demo cert fetches and name the API `down --reason` needs ([#349](https://github.com/GeiserX/tailscaled-rs/issues/349)) ([593192b](https://github.com/GeiserX/tailscaled-rs/commit/593192bc6b0298a9de416f74ec39780379bcadb3))
* **captive:** probe the running node, not the one still coming up ([#340](https://github.com/GeiserX/tailscaled-rs/issues/340)) ([842a5db](https://github.com/GeiserX/tailscaled-rs/commit/842a5dbcb17b633fbba2e309dc4310d415f887d6))
* **cert:** take Go's --serve-demo command line, which carries no domain ([#345](https://github.com/GeiserX/tailscaled-rs/issues/345)) ([075b24b](https://github.com/GeiserX/tailscaled-rs/commit/075b24b753757f073214828016530be03c608b21))
* **config:** stop `--config` silently dropping prefs this daemon already has ([#323](https://github.com/GeiserX/tailscaled-rs/issues/323)) ([771f55d](https://github.com/GeiserX/tailscaled-rs/commit/771f55d610c48c07d93d8b8308462dd8268ef141))
* **debug:** ask the daemon for its state dir instead of guessing from the CLI's environment ([#338](https://github.com/GeiserX/tailscaled-rs/issues/338)) ([b64d2cc](https://github.com/GeiserX/tailscaled-rs/commit/b64d2ccd254b71d7a68fe9fd7f9c6043dabe2df9))
* **file:** report the stuck-inbox `moved 0/N files` failure without `--verbose` ([#300](https://github.com/GeiserX/tailscaled-rs/issues/300)) ([370b9fa](https://github.com/GeiserX/tailscaled-rs/commit/370b9fab05bd80441b642b63a26ca829f8585880))
* **ip:** refuse the `-1`/`-4`/`-6` combinations Go refuses, instead of answering them with an empty set ([#319](https://github.com/GeiserX/tailscaled-rs/issues/319)) ([72d0519](https://github.com/GeiserX/tailscaled-rs/commit/72d051959f5a405c84c05a9345ceef431a844a86))
* **set:** a failed `--nickname` rename no longer skips the engine reconcile ([#297](https://github.com/GeiserX/tailscaled-rs/issues/297)) ([f3ca6e6](https://github.com/GeiserX/tailscaled-rs/commit/f3ca6e6ef2e7356eca9ff27c9b43253b6f1c547a))
* **ssh:** let ssh_config decide the login user when the target omits `user@` ([#305](https://github.com/GeiserX/tailscaled-rs/issues/305)) ([ede83c3](https://github.com/GeiserX/tailscaled-rs/commit/ede83c3182849df06f5dc44f5ba0dc355d67f193))
* **switch:** match Go's `switch remove` on the current profile, and its first-hit name matching ([#301](https://github.com/GeiserX/tailscaled-rs/issues/301)) ([172435b](https://github.com/GeiserX/tailscaled-rs/commit/172435bee4759281978a889d29619617df99365d))
* **tailnetd:** `--config` takes a source, so `optional:vm:user-data` boots instead of dying ([#306](https://github.com/GeiserX/tailscaled-rs/issues/306)) ([d57cc6a](https://github.com/GeiserX/tailscaled-rs/commit/d57cc6a9fca13210b676d5f39da7e3d09bf8a9a9))
* **tailnetd:** refuse `--bird-socket` by name instead of dying on an unknown argument ([#302](https://github.com/GeiserX/tailscaled-rs/issues/302)) ([2038aeb](https://github.com/GeiserX/tailscaled-rs/commit/2038aebb53a41fde148ef2a5e356394164d8b8be))
* **tailnetd:** stop `debug --get-url` faking a DNS failure for an IPv6 literal ([#335](https://github.com/GeiserX/tailscaled-rs/issues/335)) ([6aa85d3](https://github.com/GeiserX/tailscaled-rs/commit/6aa85d3b4f7053298a539c4919abd4ce1f4c723c))
* **tnet:** stop `lock init` treating a public key as the lock's secret ([#329](https://github.com/GeiserX/tailscaled-rs/issues/329)) ([aba3502](https://github.com/GeiserX/tailscaled-rs/commit/aba3502ebc197139d1591bc9658555fce8f717da))
* **tnet:** stop `lock log` succeeding on a lock-disabled node ([#339](https://github.com/GeiserX/tailscaled-rs/issues/339)) ([a68f1df](https://github.com/GeiserX/tailscaled-rs/commit/a68f1df756eb88807f5d7aa31624dbe52b04bf04))
* **tnet:** stop a mistyped tailnet-lock key aborting the process ([#346](https://github.com/GeiserX/tailscaled-rs/issues/346)) ([250955f](https://github.com/GeiserX/tailscaled-rs/commit/250955fc7d1dbbd47c943cfd6ec886cf0bba16a7))

## [0.53.0](https://github.com/GeiserX/tailscaled-rs/compare/v0.52.2...v0.53.0) (2026-08-30)


### Features

* **cli:** accept the six Go flags a ported command line still died on ([#289](https://github.com/GeiserX/tailscaled-rs/issues/289)) ([a92d513](https://github.com/GeiserX/tailscaled-rs/commit/a92d5139113ae59037f3c3065aa332b3e3efa4e4))
* **configure:** emit the kubeconfig kubectl accepts, over http or https ([#288](https://github.com/GeiserX/tailscaled-rs/issues/288)) ([32719b6](https://github.com/GeiserX/tailscaled-rs/commit/32719b60f5e8baa549fc60a7fdcc7e6876571053))
* **health:** say when a captive portal is what's blocking the node ([#290](https://github.com/GeiserX/tailscaled-rs/issues/290)) ([ea567a3](https://github.com/GeiserX/tailscaled-rs/commit/ea567a3b6e9746ee5888b04650884332c50714f7))
* **packaging:** install tailnetd + tnet with Homebrew, and keep the formula honest ([#292](https://github.com/GeiserX/tailscaled-rs/issues/292)) ([12c941c](https://github.com/GeiserX/tailscaled-rs/commit/12c941cfd45ad4e40c88ff3a6d211dcf048ac7dd))
* **reload-config:** report whether the reload is live or waits for the next up ([#285](https://github.com/GeiserX/tailscaled-rs/issues/285)) ([d5eee15](https://github.com/GeiserX/tailscaled-rs/commit/d5eee155ffc64724c300dadcbada7a6fa890c56b))
* **serve:** take Go's serve/funnel flag grammar so ported commands run unedited ([#274](https://github.com/GeiserX/tailscaled-rs/issues/274)) ([358ab21](https://github.com/GeiserX/tailscaled-rs/commit/358ab219bd84ba1f583d6a54d765a5d9239cbe29))
* **tailnetd:** clean up macOS routes and DNS a hard-killed daemon left behind ([#278](https://github.com/GeiserX/tailscaled-rs/issues/278)) ([3d393c8](https://github.com/GeiserX/tailscaled-rs/commit/3d393c83dcc9c3fb5dfc131236023562cd20d65f))
* **tnet:** accept the Go up/set pref flags the engine can now carry ([#269](https://github.com/GeiserX/tailscaled-rs/issues/269)) ([9a49710](https://github.com/GeiserX/tailscaled-rs/commit/9a49710c1cec23b1d730631c2461b0c57153dc3f))
* **tnet:** add file get --verbose for Go-style Taildrop drain progress ([#276](https://github.com/GeiserX/tailscaled-rs/issues/276)) ([67456e5](https://github.com/GeiserX/tailscaled-rs/commit/67456e58d71efd7b5630ef925d500261317c3bad))
* **tnet:** make tnet report which state dir it picked, and which build it is ([#273](https://github.com/GeiserX/tailscaled-rs/issues/273)) ([1b8c977](https://github.com/GeiserX/tailscaled-rs/commit/1b8c9771bfde7a79dba500afd915452e85c35b84))
* **tnet:** point kubectl at a cluster fronted by a Tailscale auth proxy ([#262](https://github.com/GeiserX/tailscaled-rs/issues/262)) ([578d652](https://github.com/GeiserX/tailscaled-rs/commit/578d6522c649b1fa693b7ad9edc8f0c1f7c7c673))
* **tnet:** read the tailnet-lock update chain with `tnet lock log` ([#275](https://github.com/GeiserX/tailscaled-rs/issues/275)) ([ab19f18](https://github.com/GeiserX/tailscaled-rs/commit/ab19f183457354bf7aa11e2bf055317120d418cb))


### Bug Fixes

* **cli:** refuse `up --exit-node-allow-lan-access` with no exit node, and let `--nickname` rename the profile ([#294](https://github.com/GeiserX/tailscaled-rs/issues/294)) ([ca7c528](https://github.com/GeiserX/tailscaled-rs/commit/ca7c52836c4051f88df07ea607cf9fac6cec38d0))
* **configure:** merge into the user's kubeconfig instead of emitting one ([#296](https://github.com/GeiserX/tailscaled-rs/issues/296)) ([14a2b26](https://github.com/GeiserX/tailscaled-rs/commit/14a2b26f1df322e1d4cc37fb8118d94936e1930e))
* **serve:** give a ported serve command line Go's refusal, not "unsupported" ([#293](https://github.com/GeiserX/tailscaled-rs/issues/293)) ([a1ad4f5](https://github.com/GeiserX/tailscaled-rs/commit/a1ad4f54eb2e15cea5afa5dd7baa024924be0da3))
* **serve:** redirect targets are sent verbatim, not variable-expanded ([#287](https://github.com/GeiserX/tailscaled-rs/issues/287)) ([6d3d7a3](https://github.com/GeiserX/tailscaled-rs/commit/6d3d7a3060a55fcba25cb98450eaaff55745c6bc))
* **switch:** don't report a switch or a removal that never happened ([#279](https://github.com/GeiserX/tailscaled-rs/issues/279)) ([fa38b33](https://github.com/GeiserX/tailscaled-rs/commit/fa38b33e4a2b0ed745b80a792d94ebdc8f6d65d5))
* **taildrop:** resolve and vet the directory `file get` writes into, not just the leaf ([#286](https://github.com/GeiserX/tailscaled-rs/issues/286)) ([17f326e](https://github.com/GeiserX/tailscaled-rs/commit/17f326e6a443a87ca518b5f98bb07fa10fa24886))

## [0.52.2](https://github.com/GeiserX/tailscaled-rs/compare/v0.52.1...v0.52.2) (2026-08-12)


### Bug Fixes

* **deps:** bump engine rev to pull russh 0.62.6 (4 security advisories) ([#256](https://github.com/GeiserX/tailscaled-rs/issues/256)) ([602bfc7](https://github.com/GeiserX/tailscaled-rs/commit/602bfc7c652d8cee05f0f43533a7b9c68e911d76))

## [0.52.1](https://github.com/GeiserX/tailscaled-rs/compare/v0.52.0...v0.52.1) (2026-07-20)


### Bug Fixes

* **clippy:** drop redundant `advertise_tags: _` wildcard before `..` ([#249](https://github.com/GeiserX/tailscaled-rs/issues/249)) ([33c3285](https://github.com/GeiserX/tailscaled-rs/commit/33c3285f63bef0e16ce3561fe2258ac16532cbeb))

## [0.52.0](https://github.com/GeiserX/tailscaled-rs/compare/v0.51.0...v0.52.0) (2026-06-15)


### Features

* **tailnetd:** emit sd_notify(READY=1) + flip systemd units to Type=notify ([#233](https://github.com/GeiserX/tailscaled-rs/issues/233)) ([2dd488d](https://github.com/GeiserX/tailscaled-rs/commit/2dd488d51f627faf30c013f49a551eb90fa8abb7))
* **tnet:** add switch --list --json (Go tailscale switch --list --json) ([#235](https://github.com/GeiserX/tailscaled-rs/issues/235)) ([069d9eb](https://github.com/GeiserX/tailscaled-rs/commit/069d9ebbfd78c5c88826b98e74057c6807d5494a))
* **tnet:** exit-node suggest + bump engine v0.40.0 → v0.41.0 (ask [#24](https://github.com/GeiserX/tailscaled-rs/issues/24)) ([#239](https://github.com/GeiserX/tailscaled-rs/issues/239)) ([024d85b](https://github.com/GeiserX/tailscaled-rs/commit/024d85bb05464537ff6bbfc2d7021ed82b898b7b))
* **tnet:** is_ssh_over_tailscale reads /proc session-leader environ under sudo ([#238](https://github.com/GeiserX/tailscaled-rs/issues/238)) ([cd1f0da](https://github.com/GeiserX/tailscaled-rs/commit/cd1f0da7e354fb6c3be67b5c9431e45839017a51))


### Bug Fixes

* **tnet:** reject `file get <name> -` clearly instead of writing a file named "-" ([#236](https://github.com/GeiserX/tailscaled-rs/issues/236)) ([3bd97dc](https://github.com/GeiserX/tailscaled-rs/commit/3bd97dc05d44e15b154b5bde7104a06c67b50c77))

## [0.51.0](https://github.com/GeiserX/tailscaled-rs/compare/v0.50.0...v0.51.0) (2026-06-15)


### Features

* **install:** wire systemd ExecStopPost=--cleanup and operator EnvironmentFile ([#225](https://github.com/GeiserX/tailscaled-rs/issues/225)) ([8a1bf4c](https://github.com/GeiserX/tailscaled-rs/commit/8a1bf4cc2ed0a5553a73f1cd6cd1ef4bf1ea22db))
* **tailnetd:** add --port / PORT — consume Config.wireguard_listen_port ([#231](https://github.com/GeiserX/tailscaled-rs/issues/231)) ([62ea1c9](https://github.com/GeiserX/tailscaled-rs/commit/62ea1c9ed2511431fb50d0bcdb5fc97dd3b243df))
* **tnet:** add debug local-creds + debug stat (Go tailscale debug parity) ([#227](https://github.com/GeiserX/tailscaled-rs/issues/227)) ([2e09b7f](https://github.com/GeiserX/tailscaled-rs/commit/2e09b7f00e8b1017010b677ac923934843b7ae77))
* **tnet:** add debug restun (Go tailscale debug restun) — consume Device::re_stun ([#230](https://github.com/GeiserX/tailscaled-rs/issues/230)) ([b423e3a](https://github.com/GeiserX/tailscaled-rs/commit/b423e3a7797931056b66eebfc0e1119c00741099))
* **tnet:** add ssh — host-key-pinned ssh over the tailnet (v0.40.0) ([#232](https://github.com/GeiserX/tailscaled-rs/issues/232)) ([97e411a](https://github.com/GeiserX/tailscaled-rs/commit/97e411a206471e764d4400502a103d922d77a2e3))
* **tnet:** web UI login affordance — surface the auth URL ([#223](https://github.com/GeiserX/tailscaled-rs/issues/223)) ([f07fbc3](https://github.com/GeiserX/tailscaled-rs/commit/f07fbc3c4d2e6ab80f9adda221f06538542aeeea))

## [0.50.0](https://github.com/GeiserX/tailscaled-rs/compare/v0.49.0...v0.50.0) (2026-06-15)


### Features

* **daemon:** add --debug HTTP server exposing GET /debug/metrics (tsd-iqq.9) ([#215](https://github.com/GeiserX/tailscaled-rs/issues/215)) ([11ec005](https://github.com/GeiserX/tailscaled-rs/commit/11ec00569c89e81cb68c4b3991113998ffd2bc71))
* **localapi:** WatchNotifications phase 1 — masked Notify stream (tsd-iqq.11) ([#220](https://github.com/GeiserX/tailscaled-rs/issues/220)) ([16679dc](https://github.com/GeiserX/tailscaled-rs/commit/16679dc815a6b195e2c239c7a8606d27a0c31967))
* **localapi:** WatchNotifications phase 2 — prefs-change broadcast ([#221](https://github.com/GeiserX/tailscaled-rs/issues/221)) ([aba1a44](https://github.com/GeiserX/tailscaled-rs/commit/aba1a448a1e1f020a299dcc26738df77285ab44b))
* **tnet:** add up --json (Go tailscale up --json) ([#219](https://github.com/GeiserX/tailscaled-rs/issues/219)) ([539a99a](https://github.com/GeiserX/tailscaled-rs/commit/539a99aece22c7ff71696955420025b39e5c74c4))
* **tnet:** netcheck --format json|json-line + --every (tsd-iqq.13) ([#218](https://github.com/GeiserX/tailscaled-rs/issues/218)) ([6f31097](https://github.com/GeiserX/tailscaled-rs/commit/6f31097d3c6a085797612bfc0df9acb311c23061))


### Bug Fixes

* **tnet:** ping &lt;own-ip&gt; prints "is local Tailscale IP" + exit 0 (tsd-rqa) ([#222](https://github.com/GeiserX/tailscaled-rs/issues/222)) ([2843d65](https://github.com/GeiserX/tailscaled-rs/commit/2843d6523ce5ccb42a9f7c91b6295320a7cbe80c))

## [0.49.0](https://github.com/GeiserX/tailscaled-rs/compare/v0.48.0...v0.49.0) (2026-06-15)


### Features

* **localapi:** add check-ip-forwarding + check-prefs verbs (tsd-iqq.8) ([#208](https://github.com/GeiserX/tailscaled-rs/issues/208)) ([68c48b3](https://github.com/GeiserX/tailscaled-rs/commit/68c48b31faad668ea6ae8c915ef625b4378f0018))
* **tnet:** add ip --assert and whois --json (CLI-flag parity, tsd-iqq.13) ([#209](https://github.com/GeiserX/tailscaled-rs/issues/209)) ([5ce4f65](https://github.com/GeiserX/tailscaled-rs/commit/5ce4f6570e2bf29b098097f1ab93c8cff8c22604))
* **tnet:** add reload-config LocalAPI verb + running-config adoption (tsd-iqq.7) ([#214](https://github.com/GeiserX/tailscaled-rs/issues/214)) ([16b1fe5](https://github.com/GeiserX/tailscaled-rs/commit/16b1fe512def4871013f306325b37661193082ab))


### Bug Fixes

* **cli:** neutralize U+2028/U+2029 + bidi overrides in terminal sanitizers (tsd-ct5) ([#212](https://github.com/GeiserX/tailscaled-rs/issues/212)) ([a9783c8](https://github.com/GeiserX/tailscaled-rs/commit/a9783c8ae59b68556f8ae90d71a716452d25640c))
* **funnel:** warn on non-loopback backend; correct stale CI runner comment ([#211](https://github.com/GeiserX/tailscaled-rs/issues/211)) ([1bec62a](https://github.com/GeiserX/tailscaled-rs/commit/1bec62a7f23ccd8a6ea9c43275927127a56b159b))

## [0.48.0](https://github.com/GeiserX/tailscaled-rs/compare/v0.47.1...v0.48.0) (2026-06-15)


### Features

* **daemon:** add --cleanup, --no-logs-no-support, and rich --version ([#201](https://github.com/GeiserX/tailscaled-rs/issues/201)) ([9140508](https://github.com/GeiserX/tailscaled-rs/commit/91405081fc43ef02ad1848f7ec527a4a51767548))
* **tnet:** add `debug rebind` (force engine UDP socket rebind) ([#203](https://github.com/GeiserX/tailscaled-rs/issues/203)) ([f102544](https://github.com/GeiserX/tailscaled-rs/commit/f1025442566fcd94ba0156c1192687b17cdcf64d))
* **tnet:** add `debug via` for 4via6 route encode/decode ([#202](https://github.com/GeiserX/tailscaled-rs/issues/202)) ([badfd03](https://github.com/GeiserX/tailscaled-rs/commit/badfd0357ddf38378b0ce5dd0a3febf443746df9))


### Bug Fixes

* **conffile:** match Go ConfigVAlpha wire keys; drop non-Go AdvertiseTags ([#205](https://github.com/GeiserX/tailscaled-rs/issues/205)) ([1379087](https://github.com/GeiserX/tailscaled-rs/commit/1379087a48ca8d09dadd86665f8cc02a2b517967))
* **httpproxy:** bound and harden the Tailscale-Connect-Error header ([#204](https://github.com/GeiserX/tailscaled-rs/issues/204)) ([afb707f](https://github.com/GeiserX/tailscaled-rs/commit/afb707f6f9327470cbd042fe7f44c4c171d43967))
* **serve:** atomic config save + funnel-off clears stale-host key ([#207](https://github.com/GeiserX/tailscaled-rs/issues/207)) ([8ae6ea5](https://github.com/GeiserX/tailscaled-rs/commit/8ae6ea59807ae42a682e0eb683e603dabdef2bc9))
* **status:** Go-faithful exit-node ID, --watch json/filters, peer IPv6 ([#206](https://github.com/GeiserX/tailscaled-rs/issues/206)) ([0d3eb90](https://github.com/GeiserX/tailscaled-rs/commit/0d3eb90a614eeee533994b2314222e2d6a39592c))
* **up:** wipe key before --reset mutates in-memory prefs ([#199](https://github.com/GeiserX/tailscaled-rs/issues/199)) ([497fd19](https://github.com/GeiserX/tailscaled-rs/commit/497fd19c1f32532b818d31e3a4e2bf6afa06012d))

## [0.47.1](https://github.com/GeiserX/tailscaled-rs/compare/v0.47.0...v0.47.1) (2026-06-14)


### Bug Fixes

* **cert:** write the private key atomically (temp+fsync+rename), guard the filename ([#195](https://github.com/GeiserX/tailscaled-rs/issues/195)) ([fa0a045](https://github.com/GeiserX/tailscaled-rs/commit/fa0a045c5cb5d0d57c7c4e274225c8861812fdb6))
* **conffile:** validate --config fields before persisting; warn on Locked ([#198](https://github.com/GeiserX/tailscaled-rs/issues/198)) ([08a72da](https://github.com/GeiserX/tailscaled-rs/commit/08a72daedd62fbb6db2491467911e8054591128d))
* **localapi:** separate cap + timeouts for long-lived Watch/Nc streams (DoS) ([#197](https://github.com/GeiserX/tailscaled-rs/issues/197)) ([cad049c](https://github.com/GeiserX/tailscaled-rs/commit/cad049c2157f1233976838629ecdf41464c3929e))

## [0.47.0](https://github.com/GeiserX/tailscaled-rs/compare/v0.46.0...v0.47.0) (2026-06-14)


### Features

* **daemon:** outbound HTTP proxy over the tailnet (--outbound-http-proxy-listen) ([#191](https://github.com/GeiserX/tailscaled-rs/issues/191)) ([848c1ca](https://github.com/GeiserX/tailscaled-rs/commit/848c1ca6f51f083dd2064710f9925f805fbaf496))
* **daemon:** SOCKS5 proxy that dials over the tailnet (--socks5-server) ([#189](https://github.com/GeiserX/tailscaled-rs/issues/189)) ([3fa605b](https://github.com/GeiserX/tailscaled-rs/commit/3fa605baf9c463f99d279083e4b2f6aad6ecda21))
* **debug:** add `tnet debug env` and `tnet debug metrics` (Go parity) ([#192](https://github.com/GeiserX/tailscaled-rs/issues/192)) ([e341b99](https://github.com/GeiserX/tailscaled-rs/commit/e341b99924379cb626fdbca87a23ec834ec3651f))


### Bug Fixes

* **proxy:** bound the SOCKS5/HTTP handshake + dial with a timeout (slowloris) ([#193](https://github.com/GeiserX/tailscaled-rs/issues/193)) ([c64402e](https://github.com/GeiserX/tailscaled-rs/commit/c64402eb7c4b831beb3169f6bf062a2251140e32))

## [0.46.0](https://github.com/GeiserX/tailscaled-rs/compare/v0.45.0...v0.46.0) (2026-06-14)


### Features

* **switch:** resolve `tnet switch <target>` by profile name, not just id ([#184](https://github.com/GeiserX/tailscaled-rs/issues/184)) ([e9fb0cd](https://github.com/GeiserX/tailscaled-rs/commit/e9fb0cd7ada42edf5b58ad2fa6338c3b2131bc1d))


### Bug Fixes

* **funnel:** resolve the splice backend from the Web map, not just tcp_forward ([#181](https://github.com/GeiserX/tailscaled-rs/issues/181)) ([b5881d7](https://github.com/GeiserX/tailscaled-rs/commit/b5881d78ee02bda32470ce1dbe522389f44d334b))
* **revert-guard:** correct ephemeral exemption docs + enforce UpOptions↔guard lockstep ([#185](https://github.com/GeiserX/tailscaled-rs/issues/185)) ([c82e43a](https://github.com/GeiserX/tailscaled-rs/commit/c82e43a41f73854b280135c471886010cb7bbce0))
* **taildrop:** set the quarantine attribute BEFORE copying received bytes ([#183](https://github.com/GeiserX/tailscaled-rs/issues/183)) ([53f84a3](https://github.com/GeiserX/tailscaled-rs/commit/53f84a3c33fc8df547250096779ff3652d56002c))

## [0.45.0](https://github.com/GeiserX/tailscaled-rs/compare/v0.44.1...v0.45.0) (2026-06-13)


### Features

* **cli:** add tnet syspolicy list / reload ([#175](https://github.com/GeiserX/tailscaled-rs/issues/175)) ([b390892](https://github.com/GeiserX/tailscaled-rs/commit/b390892e45d0eb44abb24b233a3f183b4ca28c76))


### Bug Fixes

* **control:** allow plaintext /key bootstrap for http:// control servers ([#178](https://github.com/GeiserX/tailscaled-rs/issues/178)) ([4fe80c8](https://github.com/GeiserX/tailscaled-rs/commit/4fe80c8c40b88f95b2e86d34daf2a2605f479046))

## [0.44.1](https://github.com/GeiserX/tailscaled-rs/compare/v0.44.0...v0.44.1) (2026-06-13)


### Bug Fixes

* **update:** harden the self-replace path (decompression-bomb cap, O_EXCL temp, explicit oversize) ([#172](https://github.com/GeiserX/tailscaled-rs/issues/172)) ([6442a15](https://github.com/GeiserX/tailscaled-rs/commit/6442a15c94b0bde8a3dc8648735ee8c076874f59))

## [0.44.0](https://github.com/GeiserX/tailscaled-rs/compare/v0.43.0...v0.44.0) (2026-06-13)


### Features

* **cli:** add `tnet update` (Go `tailscale update`) — version-check + verified self-install ([#169](https://github.com/GeiserX/tailscaled-rs/issues/169)) ([b7adb4d](https://github.com/GeiserX/tailscaled-rs/commit/b7adb4dd7a547961f2c9e868a704941ca7082e75))
* **cli:** add `tnet web` (Go `tailscale web`) — read-only status web UI ([#171](https://github.com/GeiserX/tailscaled-rs/issues/171)) ([e6132ca](https://github.com/GeiserX/tailscaled-rs/commit/e6132cada71e6e8cb8dd5264e5333bc644ef471d))

## [0.43.0](https://github.com/GeiserX/tailscaled-rs/compare/v0.42.0...v0.43.0) (2026-06-13)


### Features

* **cli:** add `tnet login` + reframe DESIGN scope to full Go parity (no "non-goals") ([#165](https://github.com/GeiserX/tailscaled-rs/issues/165)) ([7914e8b](https://github.com/GeiserX/tailscaled-rs/commit/7914e8b899df46b6e044bd8ed38b5cc9fc6aea7a))
* **cli:** bump engine v0.32.0 → v0.33.0 + add `tnet lock init` (complete the lock surface) ([#168](https://github.com/GeiserX/tailscaled-rs/issues/168)) ([bf0e58e](https://github.com/GeiserX/tailscaled-rs/commit/bf0e58ef356502bec5454fb32598c92734eb1b84))

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
