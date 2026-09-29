# Getting started

## Install as a system service

On macOS or Linux with [Homebrew](https://brew.sh), the tap installs both binaries and registers the
service in one step (it builds from source — the release workflow publishes Linux tarballs only):

```bash
brew tap GeiserX/tailscaled-rs
brew install tailscaled-rs
sudo brew services start tailscaled-rs      # sets TS_RS_EXPERIMENT for the daemon
```

> [!NOTE]
> The tap repository is not published yet — the formula is ready ahead of it. Until then it installs
> from a checkout: `brew install --build-from-source packaging/homebrew/tailscaled-rs.rb`.

See [`packaging/homebrew/README.md`](https://github.com/GeiserX/tailscaled-rs/blob/main/packaging/homebrew/README.md) for what the formula builds, where
state and logs go, and how the tap is refreshed for a release. Otherwise, install the daemon
straight from a checkout (systemd on Linux, launchd on macOS):

```bash
# Build, then install the system service (one command; requires root)
cargo build --release
sudo ./target/release/tnet install

# …and to remove it later (leaves your node state in place)
sudo ./target/release/tnet uninstall
```

`sudo tnet install` does three things: it copies the running `tailnetd` binary to
`/usr/local/bin/tailnetd`, installs the service unit, and enables it to start at boot. Then check
`tnet status` (or `sudo tnet status` — as root the CLI resolves the same system state dir).

| | Linux (systemd) | macOS (launchd) |
| --- | --- | --- |
| Service unit | `/etc/systemd/system/tailnetd.service` | `/Library/LaunchDaemons/cloud.tailscaled-rs.tailnetd.plist` |
| Enable / load | `systemctl enable --now tailnetd` | `launchctl bootstrap system <plist>` |
| State dir | `/var/lib/tailnetd` | `/usr/local/var/tailnetd` |

> [!NOTE]
> The installed unit sets `TS_RS_EXPERIMENT=this_is_unstable_software` for you — **enabling the
> service is you opting in to running experimental, unaudited software on purpose** (the daemon does
> not set that opt-in for itself). Other OSes are not supported; `tnet install` there exits with a
> clear error.

> [!NOTE]
> On Linux, `tnet install` picks the systemd unit that matches how the daemon was **built**. A
> default (userspace-networking) build installs a fully-sandboxed unit (no capabilities, no
> `/dev/net/tun`). A build with the `tun` feature (`--features tun`, kernel-TUN data path) installs a
> unit relaxed *only* as much as a kernel `tun` interface needs — `CAP_NET_ADMIN` (to create/configure
> the interface and program routes), `/dev/net/tun` (allowlisted read-write, device cgroup otherwise
> closed), and the syscall surface for the `ip`/`resolvectl` helpers it execs — while keeping every
> key-protection directive intact. The
> installed binary and its unit therefore always agree, so a TUN build is never silently broken by a
> sandbox that hides its device, and a userspace build is never needlessly granted `CAP_NET_ADMIN`.

`tnet uninstall` disables/unloads the service and removes the unit, but **deliberately leaves the
state dir** (it holds your node's key material), so a later `tnet install` resumes the same node.
To purge the node entirely, remove the state dir for your OS (above) by hand after uninstalling.
