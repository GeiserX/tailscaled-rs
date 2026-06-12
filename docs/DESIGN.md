# Design: a Rust `tailscaled`

This document describes what `tailscaled-rs` is, how it is layered on the
[`tailscale-rs`](https://github.com/GeiserX/tailscale-rs) engine, and the phased plan from the
current MVP toward a full system daemon. It is the condensed, public design rationale; the
implementation is the source of truth.

## The two-layer split

A Tailscale-style node divides cleanly into two layers with very different shapes:

| Layer | Responsibility | Where it lives |
|---|---|---|
| **Engine** | Cryptography + data plane: the Noise control handshake, the network-map client, magicsock (direct UDP + disco NAT traversal), DERP relay, the WireGuard tunnel, the userspace netstack, packet filtering, and — in TUN mode — the **host route/DNS programming** (`ts_host_net`: the OS routing table + system resolver, the analogue of Go's `wgengine/router` + DNS manager). | `tailscale-rs` (an embeddable library) |
| **Daemon** | Lifecycle + intent + control surface: a state machine, persisted preferences, a local IPC socket, a CLI, service install (systemd/launchd), and the TUN-mode *selection* (transport mode + privilege preflight + interface-name default). The per-OS routing/DNS *mechanism* itself lives in the engine (above), not here — the daemon has no routing seam. | **this project** |

The engine is `tsnet`-shaped: you construct an immutable node from a config and it runs in-process.
The daemon is `tailscaled`-shaped: a long-running service you reconfigure at runtime and control
over a socket. `tailscaled-rs` is the second layer, and it treats the engine as a dependency.

## Component graph

```mermaid
flowchart TB
    subgraph client["Client"]
        CLI["tnet — thin CLI"]
    end
    subgraph daemon["tailnetd — the daemon"]
        API["LocalAPI server<br/>(Unix domain socket)"]
        IPN["IPN state machine<br/>(owns Prefs + lifecycle)"]
        PREFS["Prefs store<br/>(persisted intent)"]
        API --> IPN
        IPN <--> PREFS
    end
    subgraph engine["tailscale-rs engine"]
        DEV["Device"]
        CTRLC["control client + Noise"]
        MS["magicsock (UDP + disco)"]
        DERP["DERP client"]
        WG["WireGuard tunnel"]
        NS["smoltcp netstack"]
        DEV --> CTRLC & MS & WG & NS
        MS --> DERP
    end
    CLI -->|"up / down / status"| API
    IPN -->|"build Config, new() / shutdown()"| DEV
    CTRLC <-->|"Noise control protocol"| CONTROL["Control server"]
    MS <-->|"UDP / disco"| PEERS["Tailnet peers"]
    DERP <--> DERPSRV["DERP relays"]
```

**Control flow (downward):** a CLI command hits the LocalAPI, which mutates Prefs and drives the
state machine; the state machine builds a fresh engine `Config` from current Prefs and brings the
`Device` up or tears it down.

**Data flow (inside the engine):** application/overlay packets traverse the netstack → WireGuard →
magicsock (direct UDP when disco finds a path, else DERP relay) → peer, and the reverse. This loop
is entirely the engine's; the daemon never touches packets.

## The state machine (the spine)

The reported state is **derived** from `(is the engine up?, has a netmap arrived?, what do Prefs
say?)` rather than stored — so it can never drift from reality.

```mermaid
stateDiagram-v2
    [*] --> NoState
    NoState --> Starting: up (engine constructed)
    NoState --> NeedsLogin: up but registration fails
    Starting --> Running: first netmap + self address
    Running --> Stopped: down (WantRunning=false)
    Stopped --> Starting: up
    Running --> NeedsLogin: auth lost / key expired
```

All seven Go `ipn.State` variants now exist as `ipn::State` for wire/API parity:
`NoState`, `NeedsLogin`, `NeedsMachineAuth`, `InUseOtherUser`, `Starting`, `Running`, `Stopped`
(`ipn::State::as_str` is the authoritative list). Two of them are **parity-only and not yet
reachable** from a live status snapshot: because the MVP is pre-auth-key only with no interactive
login, `NeedsMachineAuth` (node registered, awaiting admin approval) and `InUseOtherUser`
(node key already bound to another user/profile) are never produced — those conditions currently
surface as `NeedsLogin`/error instead. They are kept so the state name set never has to change
when interactive login lands.

## Minimal Viable Daemon — in / out

**In (the smallest useful closed loop):** pre-auth-key registration, obtaining a tailnet IP,
DERP-relayed connectivity, the IPN state machine, persisted Prefs, the LocalAPI socket
(`status`/`up`/`down`), and the thin CLI. Runs in **userspace-networking** mode.

**Out (explicitly deferred):** TUN data path + OS routing + OS DNS programming, MagicDNS OS
integration, exit nodes / subnet routers, interactive/browser login, Tailscale SSH / Serve /
Funnel / Taildrop, Tailnet Lock enforcement, fine-grained operator authorization, and Windows
service packaging.

## Phased plan

| Phase | Goal | Milestone |
|---|---|---|
| **1 — MVP** *(done)* | userspace-networking node: authkey join, `status`/`up`/`down` over LocalAPI, `SO_PEERCRED` LocalAPI authorization (read for all, write for root/same-UID), persisted prefs in a `0700` state dir, zeroized secret handling | A node joins a tailnet and answers `status` |
| **2 — Daemonize** | service install (systemd/launchd), `netmon`-driven re-bind on network change, Linux OS-DNS | Survives reboot + link-change as a managed service |
| **3 — Platform breadth** | TUN-mode selection + privilege preflight + per-OS interface-name defaults (the daemon's part); the per-OS **host route/DNS programming itself is engine-owned** (`ts_host_net`, Linux + macOS shipped, wired into the TUN datapath — the daemon has no routing seam by design); port mapping | Transparent OS-wide connectivity (Linux/macOS done via the engine; Windows host-net is an engine gap) |
| **4 — Feature parity** | MagicDNS, exit/subnet routing, Serve/Funnel, SSH, Tailnet Lock enforcement | Approaches `tailscaled` feature parity |

## Hard problems (tracked honestly)

- **The control protocol is a moving target** defined by the upstream Go source, not a frozen spec;
  the daemon pins a capability version and must track upstream deliberately.
- **disco / NAT traversal** is the subtlest surface; "works but never leaves DERP" is a silent
  failure mode, not a crash.
- **Per-OS routing and DNS** is an irreducible platform matrix and is the largest body of net-new
  work in Phases 2–3.
- **Unaudited cryptography** in the engine gates any production claim on an independent audit.

## Security posture

See [`../SECURITY.md`](../SECURITY.md). In short: experimental, **unaudited crypto** — do not rely
on it for data privacy until independently audited.

Several local-host protections that an earlier draft listed as "do it yourself" are now **shipped**:

- **`0700` state directory.** The daemon creates and `chmod`s its state dir to `0700` on startup
  (it holds unencrypted key material), and re-tightens the socket's parent dir in `serve` itself —
  it doesn't trust the launcher to have done it.
- **Zeroized secret handling.** Auth keys are carried as `secrecy::SecretString` (zeroized on drop,
  no `Debug`/serialize), exposed exactly once at the engine registration call and never stored on
  the backend or logged.
- **`SO_PEERCRED` LocalAPI authorization.** Every control-socket connection is authorized by its
  peer process credentials, mirroring Tailscale's `ipnauth` model: anyone who can reach the socket
  may **read** (`status`), but only **root or the daemon's own UID may write** (`up`/`down`). The
  `0700` dir is the first gate; peer-cred is the second — it still denies writes even if the socket
  is ever reachable by another user.

```mermaid
flowchart LR
    PEER["LocalAPI client<br/>(connects to Unix socket)"] -->|"peer_cred()"| AUTH{"uid == 0<br/>or uid == owner?"}
    AUTH -->|"yes"| RW["ReadWrite<br/>(status / up / down)"]
    AUTH -->|"no (or lookup fails)"| RO["ReadOnly<br/>(status only)"]
```

Not yet done (honest scope): the richer Tailscale "operator user" GID matrix is a later phase —
the seam exists (the policy is built once at startup and threaded per-connection, and the peer's
`gid` is already read) but is not enforced; and the crypto remains unaudited.
