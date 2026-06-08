# Contributing

Thanks for your interest! `tailscaled-rs` is an independent, experimental project and contributions
are welcome.

## Ground rules

- **License:** by contributing, you agree your work is licensed under [BSD-3-Clause](LICENSE).
- **Conventional commits:** `feat:`, `fix:`, `docs:`, `chore:`, etc.
- **Keep the trademark hygiene intact:** don't use the Tailscale or WireGuard logos, and don't
  imply official affiliation. Nominative "compatible with the Tailscale protocol" phrasing is fine.

## Local setup

```bash
cargo build
export TS_RS_EXPERIMENT=this_is_unstable_software   # required by the engine
cargo test
```

To co-develop against a local `tailscale-rs` checkout, add a **gitignored** `.cargo/config.toml`:

```toml
paths = ["/path/to/your/tailscale-rs"]
```

## Before opening a PR

The CI gates are, in order:

```bash
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo build --release --bins
```

Run them locally first — a failing format or clippy step gates the whole pipeline. Keep changes
surgical and add focused tests for new logic where practical.

## Scope

See [`docs/DESIGN.md`](docs/DESIGN.md) for the architecture and the phased plan. The daemon layer
(state machine, LocalAPI, CLI, OS integration) lives here; the cryptographic/networking engine
lives in [`tailscale-rs`](https://github.com/GeiserX/tailscale-rs) — engine-level changes belong
there.
