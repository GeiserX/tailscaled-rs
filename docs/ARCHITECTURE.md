# Status and architecture

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
the kernel. See [`docs/DESIGN.md`](DESIGN.md) for the full architecture and phased plan.

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
See [`docs/DESIGN.md`](DESIGN.md) for the component graph, the state machine, and what each
layer is responsible for.
