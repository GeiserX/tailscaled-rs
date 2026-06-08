<p align="center">
  <img src="docs/images/banner.svg" alt="tailscaled-rs" width="100%">
</p>

<h1 align="center">tailscaled-rs</h1>

<p align="center">
  <a href="https://github.com/GeiserX/tailscaled-rs/actions/workflows/ci.yml"><img src="https://github.com/GeiserX/tailscaled-rs/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-BSD--3--Clause-blue.svg" alt="License: BSD-3-Clause"></a>
  <img src="https://img.shields.io/badge/edition-2024-blue.svg" alt="Rust edition 2024">
  <img src="https://img.shields.io/badge/status-experimental-orange.svg" alt="Status: experimental">
</p>

An independent, from-scratch **Rust system daemon** that joins a WireGuard-based mesh
overlay network by speaking the Tailscale control protocol — the long-running, IPC-controlled
*daemon* layer (a `tailscaled`-shaped process) built on top of the embeddable
[`tailscale-rs`](https://github.com/GeiserX/tailscale-rs) engine library.

Where `tailscale-rs` is an **embeddable library** (you link it into your own program, the way
Go's `tsnet` works), `tailscaled-rs` is the **daemon**: a persistent background service with a
reconcilable state machine, persisted preferences, and a local control socket that a thin CLI
(`tnet`) talks to. That daemon layer is exactly what an embeddable library leaves out, and it is
what this project adds.

> [!WARNING]
> **Experimental. Not for production.** This is early-days software. The underlying engine
> contains unaudited cryptography and carries no stability or compatibility guarantees, and the
> daemon layer here is a young MVP. Do not rely on it for data privacy yet.

## What works today (MVP)

- **Joins a real tailnet** non-interactively with a pre-auth key, obtains a tailnet IP, and
  reaches `Running` over DERP-relayed connectivity.
- **IPN-style state machine** — `NoState → NeedsLogin → Starting → Running → Stopped`, with the
  reported state *derived* from live engine/netmap reality (never stored, so it can't drift).
- **Persisted preferences** — the node's intent (`up`/`down`, hostname, accept-routes) survives a
  restart.
- **LocalAPI over a Unix domain socket** — the daemon (`tailnetd`) serves a local control surface;
  the CLI (`tnet up` / `down` / `status`) is a thin client over it.

## Not yet (the road to a full daemon)

TUN-mode by default and per-OS routing/DNS programming, interactive (browser) login,
`netmon`-driven endpoint re-binding on network change, service installation
(systemd/launchd/Windows), MagicDNS OS integration, exit-node/subnet-router operation, Tailscale
SSH / Serve / Funnel, and Tailnet Lock enforcement. The MVP runs in **userspace-networking** mode
(no TUN, no OS routing/DNS changes) — applications reach the tailnet via the daemon rather than
the kernel. See [`docs/DESIGN.md`](docs/DESIGN.md) for the full architecture and phased plan.

## Quick start

```bash
# Build
cargo build --release

# The engine requires an explicit acknowledgement that it is experimental:
export TS_RS_EXPERIMENT=this_is_unstable_software

# Run the daemon (foreground)
./target/release/tailnetd

# In another shell: join a tailnet with a pre-auth key, then check status
./target/release/tnet up --authkey tskey-auth-XXXX --hostname my-node
./target/release/tnet status
./target/release/tnet down
```

State (node keys + prefs) lives in `$XDG_STATE_HOME/tailnetd` (override with `TAILNETD_STATE_DIR`);
the control socket is `<state-dir>/tailnetd.sock` (override with `TAILNETD_SOCKET`).

## Architecture

```mermaid
flowchart LR
    CLI["tnet (CLI)"] -->|"up / down / status<br/>over Unix socket"| D
    subgraph D["tailnetd (daemon)"]
        IPN["IPN state machine<br/>+ persisted Prefs"]
        API["LocalAPI server"]
        API --> IPN
        IPN -->|"build Config,<br/>bring up / tear down"| ENG
        ENG["tailscale-rs engine<br/>(control · magicsock · DERP · WireGuard · netstack)"]
    end
    ENG <-->|"Noise control protocol"| CTRL["Control server"]
    ENG <-->|"WireGuard / DERP"| PEERS["Tailnet peers"]
```

The daemon owns the **lifecycle and intent**; the engine owns the **cryptography and data plane**.
See [`docs/DESIGN.md`](docs/DESIGN.md) for the component graph, the state machine, and what each
layer is responsible for.

## Developing against a local engine

`tailscaled-rs` depends on a pinned revision of `tailscale-rs` (see `Cargo.toml`), and `Cargo.lock`
is committed so every build is reproducible. If you are co-developing the engine, point Cargo at a
local checkout with a **gitignored** `.cargo/config.toml`:

```toml
# .cargo/config.toml  (gitignored — never committed)
paths = ["/path/to/your/tailscale-rs"]
```

Cargo transparently substitutes the local source when its version matches the pinned one — edit the
engine, rebuild the daemon, no manifest change. To bump the pinned engine deliberately, update the
`rev` in `Cargo.toml` and run `cargo update -p tailscale-rs`.

## Relationship to Tailscale and WireGuard

This is an **independent, unofficial** project. It is **not affiliated with, endorsed by, or
sponsored by Tailscale Inc.** "Tailscale" is a trademark of Tailscale Inc.; this project uses the
name only nominatively, to describe the protocol it is compatible with. "WireGuard" is a registered
trademark of Jason A. Donenfeld; this project implements/speaks the WireGuard protocol and is not an
official WireGuard project.

The bulk of Tailscale's own client is open source (BSD-3-Clause), and this project is offered in the
same spirit: a permissively-licensed, community contribution that anyone — including upstream — is
free to use, study, and build on.

## License

[BSD-3-Clause](LICENSE). Portions derived from or interoperating with `tailscale-rs` retain the
original Tailscale Inc. copyright notice, as required.
