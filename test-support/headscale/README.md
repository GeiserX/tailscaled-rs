# Headscale test control server (Tier B)

A minimal, self-hosted [Headscale](https://github.com/juanfont/headscale) control server for
exercising the `tailscaled-rs` daemon's **real** join → netmap → down flow **without touching
production Tailscale** (no ToS or rate-limit exposure). This is "Tier B" in
[`../../docs/TESTING.md`](../../docs/TESTING.md), which is the canonical reference — this file is the
quick loop kept next to the compose stack.

## Files

- [`docker-compose.yml`](./docker-compose.yml) — runs `headscale/headscale:0.28.0` (a real, recent
  **stable** tag — never `:latest`), publishing the HTTP control port on `localhost:8080`.
- [`config.yaml`](./config.yaml) — the smallest config that boots a single tailnet: sqlite,
  auto-generated noise key, `100.64.0.0/10` address pool, embedded DERP region (0.28.0 refuses to
  boot with an empty DERPMap), no update check.

## The loop

```bash
export TS_RS_EXPERIMENT=this_is_unstable_software   # the engine requires this

# 1. Start the control server.
docker compose -f test-support/headscale/docker-compose.yml up -d

# 2. Create a user and a reusable pre-auth key (auth-key is the daemon's only login path).
docker compose -f test-support/headscale/docker-compose.yml exec headscale \
    headscale users create test
# In 0.28.0 `preauthkeys --user` is the numeric user ID, not the name, so resolve it first:
UID=$(docker compose -f test-support/headscale/docker-compose.yml exec -T headscale \
    headscale users list -o json | python3 -c "import sys,json; print(next(u['id'] for u in json.load(sys.stdin) if u['name']=='test'))")
docker compose -f test-support/headscale/docker-compose.yml exec -T headscale \
    headscale preauthkeys create --user "$UID" --reusable --expiration 24h
#   → prints a pre-auth key (hskey-auth-…)

# 3. Point the daemon at it (either of these works):
TS_CONTROL_URL=http://localhost:8080 ./target/release/tnet up --authkey <key> --hostname hs-smoke
#   or:
./target/release/tnet up --control-url http://localhost:8080 --authkey <key>
./target/release/tnet status     # expect: Running, with a 100.64.x.x address
./target/release/tnet down

# …or run the gated integration test instead of the CLI:
export TAILNETD_HS_URL=http://localhost:8080
export TAILNETD_HS_AUTHKEY=<key>
cargo test --test headscale_e2e -- --ignored --nocapture

# 4. Tear it down (-v also drops the sqlite/noise-key volumes).
docker compose -f test-support/headscale/docker-compose.yml down -v
```

## Notes

- **Keep the pre-auth key in the environment only** — never paste it into a committed file. Node
  state (sqlite db, noise key) lives in named docker volumes, not in the repo tree.
- **Green here is not full Tailscale compatibility.** Headscale lags upstream's capability version,
  so this tier proves the daemon works against *Headscale's* understanding of the protocol, not the
  genuine control plane. See [`../../docs/TESTING.md`](../../docs/TESTING.md) and
  [`../../docs/ENGINE.md`](../../docs/ENGINE.md) for the capver / fidelity-gap discipline.
