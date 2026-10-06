# `tnet configure` vs Go `tailscale configure` — the scope ruling

Scope: bead **`tsd-recff472`**. Upstream's `configure` tree is mostly *host integration*: commands
that configure a machine — a Synology NAS, a JetKVM, a Proxmox host, a Mac — around Tailscale Inc.'s
own packages and images. This fork ships none of those packages, and had only `configure kubeconfig`.
Every parity sweep therefore re-found the rest as absences, because nobody had written down whether
they were missing or *declined*. This document is that decision, command by command, so the sweep can
stop asking.

**Sources read.** Go `tailscale` at the pinned ref **`53a0d659afa51835dd7a9283873cca44261454f8`**:
`cmd/tailscale/cli/configure.go` (the tree and its `ccall` platform gating),
`configure_apple.go` + `configure_apple-all.go` (`sysext`, `mac-vpn`, `requiresStandalone`,
`requiresGUI`), `configure-synology.go` (`synology`, `configure-host`),
`configure-synology-cert.go` (`synology-cert`), `configure-jetkvm.go` (`jetkvm`),
`configure-flash-appliance.go` and `configure-pve-appliance.go` (the appliance pair),
`configure_linux.go` (`systray`). This fork at the current tree: `src/bin/tnet.rs`
(`ConfigureCmd`, `run_configure_sysext`, `run_configure_mac_vpn`, `run_configure_kubeconfig`).

---

## 1. Verdicts at a glance

| Go subcommand | Where Go registers it | Verdict here |
| --- | --- | --- |
| `kubeconfig` | everywhere | **ported** (`tsd-37m`/`tsd-k47`) |
| `sysext` (`activate`/`deactivate`/`status`) | darwin only | **adopted as the refusal Go itself serves** |
| `mac-vpn` (`install`/`uninstall`) | darwin only | **adopted as the refusal Go itself serves** |
| `synology` | linux **and** `distro.Synology` | **out of scope** — DSM package plumbing |
| `configure-host` (hidden top-level alias) | only when `synology` exists | **out of scope** — follows `synology` |
| `synology-cert` | linux **and** `distro.Synology` | **out of scope** — DSM certificate store |
| `jetkvm` | linux, arm, **and** `distro.JetKVM` | **out of scope** — boots Go's `tailscaled` |
| `flash-appliance` | everywhere but Windows | **out of scope** — flashes Tailscale's signed image |
| `pve-appliance` | linux (+ a live `/etc/pve`) | **out of scope** — same image, into a PVE VM |
| `systray` | linux, `!ts_omit_systray` | **out of scope** — already ruled: this repo ships no GUI |

The distinction that decides all of it: **`kubeconfig`, `sysext` and `mac-vpn` configure something
about *this* node's own daemon or its client; the other six configure a host around software Tailscale
Inc. distributes.** A fork that ships no `.spk`, no appliance image and no macOS app cannot do the
second kind honestly — it can only pretend to.

---

## 2. Adopted: `sysext` and `mac-vpn`

These two look like macOS platform glue, and in the GUI client they are. But in the **open-source CLI
build** — which is what this fork's `tnet` is the analogue of — Go ships them as pure refusals:

```go
func requiresStandalone(ctx context.Context, args []string) error {
	return errors.New("unsupported command: requires the Standalone (.pkg installer) GUI build of the client")
}

func requiresGUI(ctx context.Context, args []string) error {
	return errors.New("unsupported command: requires a GUI build of the macOS client")
}
```

Every `sysext` verb, every `mac-vpn` verb, and both bare parent commands route to one of those. The
Swift GUI intercepts the command line before it reaches the CLI; when there is no GUI, the CLI's whole
job is to say so. **That job this fork can do exactly, and honestly** — it ships no macOS app, no
system extension and no VPN profile, so the refusal is not a stub standing in for missing work. It is
the finished behaviour.

Ported in `src/bin/tnet.rs` as `ConfigureCmd::{Sysext, MacVpn}` with Go's verb sets, both parents
accepting the bare form as Go does, and `sysext_refusal` / `mac_vpn_refusal` building the message:
Go's `unsupported command:` opening and Go's reason, then a sentence naming what this fork offers
instead (`tnet install`, which registers `tailnetd` as a launchd/systemd service). Exit status is 1,
matching Go's returned `error` — and, more to the point, distinguishable from the exit 2 an
unregistered subcommand would produce, which explains nothing.

Two deliberate departures, both in the direction of saying more rather than less:

- **The verb is named in the message** (`configure sysext status: unsupported command: …`). Go's text
  is verb-independent; the fork's other refusals all lead with the command path, and a user who typed
  three words deserves to see which one was refused.
- **The commands are registered on Linux too**, where Go leaves them `nil`. Go's own idiom for a
  registered-but-off-platform command is an explanatory error (`flash-appliance` on Windows:
  *"flash-appliance is not supported on Windows yet"*; `pve-appliance` off Linux: *"the pve-appliance
  subcommand is only available on Linux"*), and that is the shape used here: off macOS the reason
  becomes the platform (`Go registers 'configure sysext' on darwin only`) rather than the missing GUI
  build. The alternative — `cfg`-gating the variants to darwin — would match Go's registration exactly
  but leave the code uncompiled and untested on the Linux CI runner, which is a worse trade for a pair
  of commands whose entire behaviour is a sentence.

Unknown verbs are still parse errors: `configure sysext enable` exits 2, because pretending to
understand a verb Go does not have would be a different kind of lie.

---

## 3. Out of scope, and why

### 3.1 `synology`, `configure-host`, `synology-cert`

`configure synology` runs at boot as root on a DSM device: it creates `/dev/net/tun` with `mknod`,
chmods it `0666`, and — on DSM 7 — `setcap cap_net_admin,cap_net_raw+eip` on
`/var/packages/Tailscale/target/bin/tailscaled`, the path *inside Tailscale's `.spk` package*. It
refuses outright unless `distro.Get() == distro.Synology`, and Go does not even register the command
elsewhere. `configure-host` is a hidden top-level compatibility alias for it, and exists only when it
does. `configure synology-cert` is the same shape for TLS: it fetches the tailnet certificate and
uploads it into the DSM certificate store through `/usr/syno/bin/synowebapi`, so DSM's own web server
serves it.

**Out of scope.** All three configure a Synology *package* this fork does not build, publish or
install, and the DSM 7 half is literally a `setcap` on a hard-coded path inside it. There is no
honest version of "grant permissions to the Tailscale package" for a daemon that is not that package.
If this repo ever ships a DSM package, the command becomes buildable in the same commit as the
package, and not before. The certificate half has a working analogue today: `tnet cert` obtains the
tailnet certificate; what stays undone is only the DSM-specific installation of it.

### 3.2 `jetkvm`

Writes `/userdata/init.d/S22tailscale`, a busybox init script that launches
`/userdata/tailscale/tailscaled`, and symlinks `/userdata/tailscale/tailscale` to `/bin/tailscale`.
Registered only on `linux && arm && distro.JetKVM`.

**Out of scope.** It is a boot script for *Go's* binaries at *Go's* install paths on one device. The
generic form of what it does — "make the daemon start at boot" — is already this fork's `tnet install`,
which writes a systemd unit or a launchd job for `tailnetd`. Porting `jetkvm` would mean shipping a
JetKVM install layout for a daemon nobody installs on a JetKVM.

### 3.3 `flash-appliance` and `pve-appliance`

`flash-appliance` downloads a signed Gokrazy archive (GAF) of the Tailscale appliance image from
`pkgs.tailscale.com`, verifies it with `clientupdate/distsign`, and writes it to a raw block device —
a destructive whole-disk flash, root-only, with an `mkfs.ext4` for the writable `/perm` partition.
`pve-appliance` builds the same image into a raw disk and drives `qm create` / `qm disk import` /
`qm set` on a Proxmox VE host to create a VM from it. Both are marked `[experimental]` and hidden in
Go's help.

**Out of scope, and not merely unbuilt.** Their payload is Tailscale Inc.'s signed appliance image,
containing Tailscale Inc.'s binaries; there is no such image for this fork, and shipping a command
that flashes *someone else's* product image over a user's disk would be a strange thing for this
daemon to do. They also sit outside what this repo is: a daemon plus a CLI, not an image builder or a
hypervisor front-end. The signature-verified-download machinery has a genuine, in-scope analogue in
this fork's `tnet update`, whose integrity-vs-authenticity limits are already documented.

### 3.4 `systray`

Registered under `configure` on Linux, and previously ruled out of scope in the parity ledger as
`tailscale systray`: it installs and configures a desktop system-tray applet. Same ruling, recorded
here too so that reading the `configure` tree alone gives the complete answer — this repo ships a
daemon and a CLI, not a desktop GUI.

---

## 4. What would reopen any of this

The ruling is about what this fork *ships*, not about difficulty, so it changes when the shipping
does:

- this repo starts publishing a **Synology `.spk`** → `synology` and `synology-cert` become buildable
  (and `configure-host` follows automatically);
- this repo starts publishing an **appliance image** → the appliance pair becomes meaningful, against
  that image and its own signing key;
- this repo grows a **macOS GUI with a system extension** → `sysext` and `mac-vpn` stop being
  refusals and grow real implementations.

Until one of those happens, an absence here is a decision, and a sweep that re-finds it should read
this file rather than file a bead.

---

## 5. Ledger note

`PARITY_GAP_ANALYSIS.md` §4.6 carries the row that filed this question, and §6 is the
intentional-deviation list. Neither is edited here — the next ledger pass should collapse that §4.6
row to a pointer at this document, and add to §6: **the six host-integration `configure` subcommands
are out of scope by decision, and `sysext`/`mac-vpn` are present as Go's own refusals rather than as
implementations.**
