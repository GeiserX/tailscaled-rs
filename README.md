<p align="center">
  <img src="https://raw.githubusercontent.com/GeiserX/tailscaled-rs/main/docs/images/banner.svg" alt="tailscaled-rs" width="100%">
</p>

<h1 align="center">tailscaled-rs</h1>

<p align="center">
  <a href="https://github.com/GeiserX/tailscaled-rs/releases"><img src="https://img.shields.io/github/v/release/GeiserX/tailscaled-rs" alt="Release"></a>
  <a href="https://github.com/GeiserX/tailscaled-rs/actions/workflows/ci.yml"><img src="https://github.com/GeiserX/tailscaled-rs/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/GeiserX/tailscaled-rs" alt="License"></a>
  <a href="docs/how-it-works.md#status"><img src="https://img.shields.io/badge/status-experimental-orange.svg" alt="Status: experimental"></a>
</p>

An independent, from-scratch **Rust system daemon** that joins a WireGuard-based mesh
overlay network by speaking the Tailscale control protocol — the long-running, IPC-controlled
*daemon* layer (a `tailscaled`-shaped process) built on top of the embeddable
[`tailscale-rs`](https://github.com/GeiserX/tailscale-rs) engine library.

Where `tailscale-rs` is an **embeddable library** (you link it into your own program, the way
Go's `tsnet` works), `tailscaled-rs` is the **daemon**: a persistent background service with a
reconcilable state machine, persisted preferences, and a local control socket that a thin CLI
(`tnet`) talks to.

> [!WARNING]
> **Experimental. Not for production.** This is early-days software. The underlying engine
> contains unaudited cryptography and carries no stability or compatibility guarantees, and the
> daemon layer here is a young MVP. Do not rely on it for data privacy yet.

## Features

- Joins a real tailnet non-interactively with a pre-auth key and reaches `Running`.
- An IPN-style state machine whose reported state is derived from the live engine, so it can't drift.
- Persisted preferences, and a LocalAPI over a Unix socket that the `tnet` CLI drives (`up`, `down`, `status`, `set`, `switch`).
- `tnet` accepts the flag spellings Go's `tailscale` uses, and validates exit nodes and advertised routes the way Go does.
- Declarative `--config` for headless and Kubernetes nodes, and a daemon-less `tailnetd debug` for nodes that won't come up.
- Optional kernel-TUN mode, Tailscale SSH server and ACME certificates (`--features tun,ssh,acme`; the release binaries ship with all three).
- `tnet install` sets it up as a systemd or launchd service; a Homebrew formula is ready.

## Quick start

Rust 1.95 or newer, on macOS or Linux, from a checkout of this repository:

```bash
cargo build --release
TS_RS_EXPERIMENT=this_is_unstable_software ./target/release/tailnetd
./target/release/tnet up --authkey tskey-auth-XXXX --hostname my-node   # in another shell
```

`tnet status` shows the node, and `tnet status --web` serves a live status page. [Usage](docs/usage.md) covers every flag, and [Getting started](docs/getting-started.md) installs it as a service.

## Documentation

- [Getting started](docs/getting-started.md): Homebrew, `tnet install`, the systemd and launchd units
- [Usage](docs/usage.md): `tailnetd` flags, `tailnetd debug`, and what each `tnet` command and flag does
- [How it works](docs/how-it-works.md): what works, what doesn't yet, and how the daemon and engine split
- [Development](docs/development.md): building against a local `tailscale-rs` checkout, and the three test tiers
- Design notes: [design](docs/DESIGN.md), [threat model](docs/THREAT_MODEL.md), [engine asks](docs/ENGINE_ASKS.md)

## Legal

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
