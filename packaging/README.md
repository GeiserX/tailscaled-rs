# Packaging — running `tailnetd` as a service

Service definitions and install docs for running the `tailnetd` daemon as an always-on
background service:

- **Linux** — systemd unit: [`systemd/tailnetd.service`](systemd/tailnetd.service)
- **macOS** — launchd `LaunchDaemon`: [`launchd/cloud.tailscaled-rs.tailnetd.plist`](launchd/cloud.tailscaled-rs.tailnetd.plist)

Both run `tailnetd` from `/usr/local/bin/tailnetd`, set the required experiment opt-in
(`TS_RS_EXPERIMENT=this_is_unstable_software`), point the daemon at a private state directory,
and restart it on failure.

> [!WARNING]
> **Experimental, unaudited software — not for production.** The underlying engine contains
> unaudited cryptography and the daemon layer is a young MVP. Installing one of these units is
> you opting in, on purpose, to running experimental software. Do not rely on it for data
> privacy yet. See the [repository README](../README.md) and [`SECURITY.md`](../SECURITY.md).

## Install flow

```mermaid
flowchart TD
    BUILD["cargo build --release"] --> BIN["install target/release/tailnetd<br/>→ /usr/local/bin/tailnetd"]
    BIN --> OS{Which OS?}
    OS -->|Linux| SD["cp tailnetd.service<br/>→ /etc/systemd/system/"]
    SD --> SDEN["systemctl daemon-reload<br/>systemctl enable --now tailnetd"]
    OS -->|macOS| LD["cp cloud.tailscaled-rs.tailnetd.plist<br/>→ /Library/LaunchDaemons/"]
    LD --> LDEN["launchctl bootstrap system<br/>/Library/LaunchDaemons/cloud.tailscaled-rs.tailnetd.plist"]
    SDEN --> UP["tnet up --authkey-file /path/to/key<br/>(then tnet status)"]
    LDEN --> UP
```

## 1. Install the binary

Build the release binary and place it where the units expect it:

```bash
cargo build --release
sudo install -m 0755 target/release/tailnetd /usr/local/bin/tailnetd
# Optional: the CLI client, for `tnet up/down/status`.
sudo install -m 0755 target/release/tnet /usr/local/bin/tnet
```

(If you put the binary elsewhere, edit `ExecStart=` in the unit / `ProgramArguments` in the
plist accordingly.)

## 2a. Linux (systemd)

```bash
sudo cp systemd/tailnetd.service /etc/systemd/system/tailnetd.service
sudo systemctl daemon-reload
sudo systemctl enable --now tailnetd
```

`enable --now` starts it immediately and on every boot. The unit creates and locks
`/var/lib/tailnetd` to `0700` (via `StateDirectory=`; the daemon re-checks `0700` itself), and
already sets `TS_RS_EXPERIMENT` so the engine will start.

> [!NOTE]
> The unit's `After=/Wants=network-online.target` only delays startup until the network is
> routable if a wait service is actually enabled (e.g. `systemctl enable systemd-networkd-wait-online`
> or NetworkManager's `NetworkManager-wait-online.service`). Without one, `network-online.target` is
> reached early and the daemon may start before the network is up — harmless, since it retries.

Check it came up:

```bash
systemctl status tailnetd
```

## 2b. macOS (launchd)

### Scripted install (macOS)

The quickest path is the bundled installer, which automates every manual step below (install
the binary, drop in the plist with `root:wheel`/`0644`, create the `0700` state dir, pre-create
the non-world-readable log files, and `launchctl bootstrap` the daemon). It is idempotent —
re-running it updates the binary + plist and reloads the service cleanly:

```bash
# Build first (see "1. Install the binary"), then:
sudo packaging/macos/install.sh                       # uses ./target/release/tailnetd
# …or point it at a binary explicitly:
sudo packaging/macos/install.sh /path/to/tailnetd
```

```mermaid
flowchart LR
    INST["sudo packaging/macos/install.sh<br/>[path-to-tailnetd]"] --> B["install → /usr/local/bin/tailnetd"]
    B --> P["plist → /Library/LaunchDaemons<br/>(root:wheel 0644)"]
    P --> S["mkdir /usr/local/var/tailnetd<br/>(0700 root:wheel)"]
    S --> L["launchctl bootstrap system …<br/>(legacy: launchctl load -w)"]
    L --> UP["sudo tnet up --authkey-file …"]
```

To remove the service later, run the matching uninstaller. It boots the daemon out and removes
the plist + binary, but **leaves the state dir** (`/usr/local/var/tailnetd`, the node's keys +
prefs) in place; it prints the `rm -rf` command to purge the node identity if you want to:

```bash
sudo packaging/macos/uninstall.sh
```

The manual steps below remain the documented fallback and explain exactly what the script does.

```bash
sudo cp launchd/cloud.tailscaled-rs.tailnetd.plist /Library/LaunchDaemons/
sudo chown root:wheel /Library/LaunchDaemons/cloud.tailscaled-rs.tailnetd.plist
sudo chmod 0644 /Library/LaunchDaemons/cloud.tailscaled-rs.tailnetd.plist

# Create the state dir the plist references and give it a root-owned parent.
# launchd starts the daemon as root, but /usr/local is typically owned by the
# Homebrew user — so chown the state dir (which holds unencrypted key material)
# to root:wheel rather than leaving the daemon's key dir under a non-root parent.
# (The daemon also re-checks/enforces 0700 on this dir itself.)
sudo mkdir -p /usr/local/var/tailnetd
sudo chown root:wheel /usr/local/var/tailnetd
sudo chmod 0700 /usr/local/var/tailnetd

# Pre-create the log files mode 0640 root:wheel so they are NOT world-readable.
# launchd honours pre-existing file permissions, so creating them up front keeps
# logs (which can contain node identifiers) off other local users' eyes.
sudo install -m 0640 -o root -g wheel /dev/null /var/log/tailnetd.log
sudo install -m 0640 -o root -g wheel /dev/null /var/log/tailnetd.err.log

# Load it (modern launchctl):
sudo launchctl bootstrap system /Library/LaunchDaemons/cloud.tailscaled-rs.tailnetd.plist
# Legacy launchctl (older macOS) equivalent:
#   sudo launchctl load -w /Library/LaunchDaemons/cloud.tailscaled-rs.tailnetd.plist
```

State lives under `/usr/local/var/tailnetd`; logs are written to
`/var/log/tailnetd.log` and `/var/log/tailnetd.err.log`.

## Talking to the daemon: `tnet` and the LocalAPI socket

The daemon serves its LocalAPI on a Unix socket inside its state directory
(`<state-dir>/tailnetd.sock`). `tnet` resolves the same path automatically **as long as it runs
with the same view of the state directory as the daemon** — so when you run `tnet` with `sudo`
(as root), it picks up the system path the service uses and the socket lines up on its own:

```bash
sudo tnet up --authkey-file /path/to/key   # resolves the system socket as root — no --socket needed
sudo tnet status
```

Concretely, when run as **root** the state dir defaults to `/var/lib/tailnetd` (Linux) /
`/usr/local/var/tailnetd` (macOS) unless `TAILNETD_STATE_DIR` is set — matching the packaged
units — so `sudo tnet up` / `sudo tnet status` Just Work against the running daemon.

> [!NOTE]
> If you run `tnet` as a **non-root** user, a non-root shell resolves a *per-user* state path by
> default, so it will look for the socket in the wrong place. Point it at the daemon's socket
> explicitly:
> ```bash
> tnet --socket /var/lib/tailnetd/tailnetd.sock status         # Linux
> tnet --socket /usr/local/var/tailnetd/tailnetd.sock status   # macOS
> ```
> Reads (`status`) succeed for anyone who can reach the socket; writes (`up`/`down`) are still
> restricted to root or the daemon's own user (see [`SECURITY.md`](../SECURITY.md)).

## 3. Join a tailnet (set an auth key safely)

The service starts the daemon, but the node still needs a pre-auth key to register. **Prefer
`tnet up --authkey-file`** — it reads the key from a file you control and never puts the secret
in argv, shell history, or the service definition:

```bash
# Write the key to a root-only file, then hand the path to `tnet up`:
umask 077
printf '%s' 'tskey-auth-XXXXXXXX' | sudo tee /var/lib/tailnetd/authkey >/dev/null   # Linux
# (macOS: use /usr/local/var/tailnetd/authkey)
sudo chmod 0600 /var/lib/tailnetd/authkey

sudo tnet up --authkey-file /var/lib/tailnetd/authkey --hostname my-node
sudo tnet status
```

Once the node has registered, the prefs persist, so on later boots the daemon auto-starts and
reconnects. You can delete the key file afterward.

### Alternative: `TS_AUTH_KEY` drop-in (not recommended)

The daemon also reads `TS_AUTH_KEY` from its environment for non-interactive re-registration.
You *can* supply it via a service override, but this writes the secret into a config file on
disk:

- **systemd:** `sudo systemctl edit tailnetd` and add
  ```ini
  [Service]
  Environment=TS_AUTH_KEY=tskey-auth-XXXXXXXX
  ```
  which is stored at `/etc/systemd/system/tailnetd.service.d/override.conf`.
- **launchd:** add a `TS_AUTH_KEY` entry to the plist's `EnvironmentVariables` dict.

> [!CAUTION]
> The drop-in / plist approach leaves the auth key in plaintext in a unit/override file (and it
> can leak via `systemctl show`). Prefer `tnet up --authkey-file`. If you do use a drop-in,
> `chmod 0600` the override file and rotate/revoke the key after first use.

## 4. View logs

```bash
# Linux (systemd journal):
journalctl -u tailnetd -f
# Increase daemon verbosity if needed (the daemon honours TAILNETD_LOG, e.g. =debug):
#   sudo systemctl edit tailnetd   →   [Service]\nEnvironment=TAILNETD_LOG=debug

# macOS (plist log paths):
sudo tail -f /var/log/tailnetd.log /var/log/tailnetd.err.log
```

## 5. Uninstall

**Linux:**

```bash
sudo systemctl disable --now tailnetd
sudo rm /etc/systemd/system/tailnetd.service
sudo systemctl daemon-reload
# Remove state (node keys + prefs) — this forgets the node entirely:
sudo rm -rf /var/lib/tailnetd
sudo rm -f /usr/local/bin/tailnetd /usr/local/bin/tnet
```

**macOS:**

```bash
sudo launchctl bootout system /Library/LaunchDaemons/cloud.tailscaled-rs.tailnetd.plist
# Legacy equivalent: sudo launchctl unload -w /Library/LaunchDaemons/cloud.tailscaled-rs.tailnetd.plist
sudo rm /Library/LaunchDaemons/cloud.tailscaled-rs.tailnetd.plist
sudo rm -rf /usr/local/var/tailnetd
sudo rm -f /var/log/tailnetd.log /var/log/tailnetd.err.log
sudo rm -f /usr/local/bin/tailnetd /usr/local/bin/tnet
```

Logging out of the tailnet before removing state is good hygiene (`sudo tnet down`, and revoke
the node from your control server / Headscale admin).
