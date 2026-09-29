# Usage

How to build and run `tailnetd` and drive it with `tnet`, and what each `tnet` flag does and does not do. Installing it as a system service is in [INSTALLATION.md](INSTALLATION.md).

## Build and run

```bash
# Build (lean default: userspace networking, no TLS-cert/SSH-server/TUN).
cargo build --release
# …or build a FULL-featured daemon (what the released binaries ship) — adds kernel-TUN mode,
# the Tailscale SSH server, and ACME cert issuance for `cert`/`serve --https`/`funnel`. Each still
# gates at runtime (TUN/SSH need root; cert/funnel need a SaaS tailnet):
#   cargo build --release --features tun,ssh,acme
# (Prebuilt release downloads are already built with all three.)

# The engine requires an explicit acknowledgement that it is experimental:
export TS_RS_EXPERIMENT=this_is_unstable_software

# Run the daemon (foreground)
./target/release/tailnetd

# tailnetd accepts flags (Go `tailscaled`-style) that override the TAILNETD_* env vars:
#   --statedir <dir>   state directory      (overrides TAILNETD_STATE_DIR)
#   --socket <path>    LocalAPI socket path (overrides TAILNETD_SOCKET)
#   --verbose <0|1|2>  log verbosity        (overrides TAILNETD_LOG; 0=info,1=debug,2=trace)
#   --config <source>  declarative config source (Go --config / ipn.ConfigVAlpha) — set prefs up
#                      front without an interactive `tnet up` (headless/k8s). e.g.:
#                        {"version":"alpha0","Enabled":true,"Hostname":"node-a",
#                         "AuthKey":"file:/run/secrets/ts-authkey","acceptRoutes":true}
#                      AuthKey may be a literal or "file:<path>". Merged over persisted prefs.
#                      <source> is a path, or "vm:user-data" (the VM's user-data via the cloud
#                      instance metadata service — recognized, but this build has no metadata
#                      client, so it reports the source as absent). Prefix either with
#                      "optional:" to boot UNCONFIGURED when the source is absent instead of
#                      failing to start; a source that is present but invalid still fails.
#   --version          print version and exit;  --help  full usage
# e.g.  ./target/release/tailnetd --statedir /var/lib/tailnetd --verbose 1
#
# tailnetd also takes a `debug` SUBCOMMAND (Go `tailscaled debug`) — daemon-less diagnostics for
# when the node will not come up at all, which is exactly when `tnet` (which talks to a running
# daemon over its socket) cannot help. It needs no daemon, no socket and no TS_RS_EXPERIMENT:
#   tailnetd debug --ifconfig            dump the host's network state once, as JSON (on stderr)
#   tailnetd debug --monitor             …and re-dump it on every link change, until interrupted
#   tailnetd debug --get-url <url>       fetch a URL with a connection trace ("login" = the
#                                        default control plane's login URL)
# (Go's --derp and --portmap are declared and refused BY NAME: a DERP round-trip test needs a
# standalone DERP client this daemon does not own, and port mapping does not exist in the engine.)
#
# NOTE: --statedir also moves the default socket to <dir>/tailnetd.sock. Since `tnet` has no
# --statedir, point the client at it explicitly:  tnet --socket /var/lib/tailnetd/tailnetd.sock status
# (or export TAILNETD_SOCKET). The packaged service uses the default /var/lib/tailnetd, so this only
# matters when you relocate state on a manual/non-root run.

# In another shell: join a tailnet with a pre-auth key, then check status
./target/release/tnet up --authkey tskey-auth-XXXX --hostname my-node
./target/release/tnet status
./target/release/tnet down

# Force a fresh login (re-register from scratch, keeping your settings):
./target/release/tnet up --force-reauth

# Bring up and wait (up to 30s) for the node to reach Running — handy in scripts:
./target/release/tnet up --authkey tskey-auth-XXXX --timeout 30 && echo connected

# Serve a live HTML status page (default http://127.0.0.1:8384; opens a browser):
./target/release/tnet status --web            # add --no-browser / --listen ADDR to customize

# Adjust policy prefs on a running node — applied live, no reconnect:
./target/release/tnet set --hostname my-node --accept-routes
```

`tnet up --timeout <SECONDS>` (Go `tailscale up --timeout`) waits for the node to reach the Running
state after bringing it up, exiting non-zero on timeout — useful to gate a follow-up step on
connectivity. Omit it to return as soon as the daemon accepts the up; `0` waits forever.

`tnet up --force-reauth` (Go `tailscale up --force-reauth`) discards this node's key and registers
fresh, surfacing a new login URL — handy to re-authenticate without changing any settings. It may
briefly bring the connection down while it re-registers, so avoid running it over a remote SSH/RDP
session you could lock yourself out of.

`tnet up` also answers to the spellings Go's `tailscale up` uses, so a command line copied from Go
runs unedited: `--auth-key` is an alias of `--authkey` (and, like Go, a value of `file:<path>` under
either spelling reads the key from that file), and `--login-server` is an alias of `--control-url`.
Go's hidden `--host-routes` is accepted and does nothing — it has had to be `true` since Tailscale
1.67, and this build's userspace netstack installs no host routes at all — while `--host-routes=false`
is refused with Go's own "only 'true' is allowed". `up --nickname` is refused by name, pointing at
`tnet set --nickname`: no `up` names a login profile, in this fork or in Go, which registers
`--nickname` on `set` and `login` only. Both refusals exit **2**, the status Go's flag package gives
a parse failure: upstream decides both inside `flag.Parse`, so neither ever reaches `runUp`. The
`--host-routes=false` sentence is Go's own, byte for byte, down to the one-dash `-host-routes` Go's
flag package prints whichever spelling was typed. The `--nickname`
sentence is this fork's, and it is longer than Go's on purpose — where Go stops at "flag provided but
not defined", this one names the commands that do take a profile name. Neither refusal prints the
usage block Go's parser appends to both, for the same reason no other refusal here prints one: the
message already says what to run.

`tnet set` (Go `tailscale set`) adjusts policy prefs on an already-running node. Changing
`--exit-node`, `--hostname`, `--accept-routes`, `--advertise-routes`, or `--advertise-exit-node`
applies **live** — in place, with no reconnect (matching Go's `set`). `--shields-up`, `--ssh`,
`--advertise-tags`, `--advertise-connector` and `--auto-update` briefly rebuild the connection (they
have no in-place engine setter, and the last two are re-advertised to control on every map request).
`--auto-update` is additionally **refused** on an installation that could never apply an update — one
a package manager owns (`brew upgrade` is the update path there), or a platform with no published
release artifact — because the pref is advertised to control as `Hostinfo.AllowsUpdate`, so accepting
it would tell the tailnet admin that a remote update trigger will be honoured by a node that cannot
honour one. Declining (`--no-auto-update`) is accepted everywhere. As in Go, the rule is asked of the
prefs a write would LEAVE BEHIND rather than of the flags it names, so an opt-in already stored keeps
failing later `set`s until `--no-auto-update` withdraws it. The same refusal is applied to the
declarative path — a config file's `"AutoUpdate": {"Apply": true}` fails the load on such an
installation, because the claim reaching control is the same one whether a command or a file made it.
That last part is a deliberate divergence, not a port: upstream's config loader does not run this
check (see `Config::apply_to_prefs`), but a `--config` node is exactly the deployment with nobody
reading command output, so the claim would otherwise be made silently and forever.
`--operator`, `--report-posture`, `--webclient`, `--update-check` and
`--exit-node-allow-lan-access` are **carried prefs**: they are persisted and reported (`tnet get`),
but nothing in this build acts on them yet — each flag's `--help` says exactly what it does and does
not do. `--nickname` is the exception among them: like Go, it also renames the current login profile,
so the name you pick is what `tnet switch --list` shows and what `tnet switch <name>` resolves
against. `set` never re-authenticates and never changes whether the node is up or down.

`--exit-node` is **resolved before it is stored**, on `up`, `set` and `check-prefs` alike, the way Go
resolves the argument in its CLI (`exitNodeIPOfArg`). This machine's own tailnet address is refused
("cannot use … as an exit node as it is a local IP address to this machine; did you mean
`--advertise-exit-node`?"), and once the node is `Running`, so are an IP no peer holds ("no node found
in netmap with IP …") and a peer that never advertised a default route ("node … is not advertising an
exit node"). A name is matched against every peer's base name and FQDN, case-insensitively, and is
refused when no peer answers to it ("invalid value … must be IP or peer hostname") or when more than
one does ("ambiguous exit node name …"); before the first netmap a name is refused outright ("cannot
resolve exit node by hostname while Tailscale is starting up; please use its Tailscale IP address
instead"), because there is no peer list to resolve it against — pass the exit node's tailnet IP
there. Without this the engine's selector parse accepts *every* string, so a typo, this node's own
address, or a peer that offers no exit was stored as a working pref and then routed nothing, with no
command saying why.

`--advertise-routes` is validated as a **set**, together with `--advertise-exit-node`, the way Go's
`netutil.CalcAdvertiseRoutes` validates the two (on `up`, `set`, `check-prefs` and a `--config` file
alike). Besides the long-standing masking rule ("route … has non-address bits set; expected …"), a
**default route must be advertised in both families or in neither**: `--advertise-routes 0.0.0.0/0`
on its own is refused with "0.0.0.0/0 advertised without its IPv6 counterpart, please also advertise
::/0", and `::/0` on its own with the mirror of that. A node advertising only the v4 default is a
*half* exit node — it takes its clients' IPv4 traffic while their IPv6 traffic leaves straight out
their own link, a leak neither end can see. `--advertise-exit-node` **is** those two default routes,
so it satisfies the rule by itself and satisfies it for a route list that names one default; turning
it off while the routes still name one is refused for the same reason. A 4via6 prefix is also checked
as one (Go `ValidateViaPrefix`): it must sit in `fd7a:115c:a1e0:b1a::/64`, be at least a `/96`, and
embed a site id of `0xffff` or less — otherwise it would be advertised as an ordinary IPv6 route that
decodes to no IPv4 CIDR at all. Use `tnet debug via <site-id> <ipv4-cidr>` to produce a well-formed
one.

`tnet switch <target>` only ever *selects* a profile that exists: a target matching no profile by id
or nickname is refused, exactly as Go's `tailscale switch` refuses it (`No profile named ...`), so a
typo can no longer disconnect the node into an empty profile. Creating one is its own request —
`tnet switch --new <id>`, a flag with no upstream counterpart, standing in for the interactive
`tailscale login` this fork does not have yet. The new profile starts empty and logged out; run
`tnet up` to register it.

Four of Go's `set` flags are **parsed but not modelled**, so a command line ported from Go reaches a
refusal that names the gap instead of dying at the parser. For each, the value asking for the state
this daemon is currently in is accepted, and the other is refused: `--relay-server-port=` and
`--relay-server-static-endpoints=` (disable / advertise none) are fine, but a port or an endpoint
list is refused — this build runs no peer relay server; `--sync` is fine and `--no-sync` (Go
`--sync=false`) is refused — there is no way to stop the map poll while staying up. Those three are
engine-gated (`docs/ENGINE_ASKS.md` §34). The fourth, `--remote-config`, is refused **by choice and
permanently**: it hands the tailnet admin full remote control of this node's prefs and LocalAPI,
bypassing the per-feature double opt-in, which this daemon's local authorization model
(`docs/THREAT_MODEL.md` §4.1) does not grant to the control plane. `--no-remote-config`, Go's
default, is what this build always does.

**App connector: the advertise half only.** `tnet up/set --advertise-connector` really does reach
control — the engine sets `Hostinfo.AppConnector` from the pref at registration and on every map
request, so the admin console sees the node offering the role. What this build does **not** have is
the connector's data path: it never receives the connector domain list, never watches DNS lookups to
learn a domain's addresses, and so never appends a learned route to `--advertise-routes`. An
advertising node therefore serves no connector traffic. `tnet appc-routes` (Go `tailscale
appc-routes`) reports exactly what follows from that — `not a connector` when the pref is off, and
`-n`'s count of the routes you advertise — and refuses `--map`, `--all` and the default per-domain
summary with that reason, rather than printing an empty map that would read as "learned nothing
yet". Advertise the role only if something else in your tailnet is doing the connecting.

State (node keys + prefs) lives in `$XDG_STATE_HOME/tailnetd` (override with `TAILNETD_STATE_DIR`);
the control socket is `<state-dir>/tailnetd.sock` (override with `TAILNETD_SOCKET`).

**Crash cleanup (macOS).** In kernel-TUN mode the daemon programs host routes and a scoped MagicDNS
resolver; both are reversed on a clean shutdown. A `SIGKILL`/panic skips that teardown, so on macOS
they can outlive the daemon — a `scutil` resolver dictionary pointing at a MagicDNS server that is no
longer listening, and routes blackholing into a `utun` that no longer exists. `tailnetd` therefore
reaps that leftover state at startup, before it brings the node up: it removes its own `scutil` key
and any of its static routes whose `utun` device is gone, and touches nothing else. Set
`TAILNETD_NO_REAP=1` to skip the pass.
