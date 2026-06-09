#!/usr/bin/env bash
#
# install.sh — one-shot installer for the tailscaled-rs daemon (tailnetd) on macOS.
#
# Automates exactly the manual steps documented in ../README.md ("2b. macOS (launchd)"):
# it installs the tailnetd binary, drops the LaunchDaemon plist into
# /Library/LaunchDaemons, creates the root-owned 0700 state directory, pre-creates the
# (non-world-readable) log files, and loads the daemon with launchctl. Re-running it is
# safe: it updates the binary + plist in place and reloads the service cleanly.
#
# WARNING: experimental, unaudited software — not for production. Installing this daemon is
# you opting in, on purpose, to running experimental software (the plist sets the engine's
# TS_RS_EXPERIMENT opt-in for exactly this reason). See ../README.md and ../../SECURITY.md.
#
# Usage:
#   sudo packaging/macos/install.sh [path-to-tailnetd]
#
#   path-to-tailnetd  Optional. Path to the built `tailnetd` binary. If omitted, the script
#                     looks for ./target/release/tailnetd relative to the repository root.

set -euo pipefail

# ---------------------------------------------------------------------------------------------
# Constants — these MUST stay in lockstep with the plist
# (../launchd/cloud.tailscaled-rs.tailnetd.plist) and the README. If you change a path here,
# change it there too.
# ---------------------------------------------------------------------------------------------
readonly LABEL="cloud.tailscaled-rs.tailnetd"
readonly PLIST_NAME="cloud.tailscaled-rs.tailnetd.plist"
readonly PLIST_DEST="/Library/LaunchDaemons/${PLIST_NAME}"
readonly BIN_DIR="/usr/local/bin"
readonly BIN_DEST="${BIN_DIR}/tailnetd"
readonly STATE_DIR="/usr/local/var/tailnetd"
readonly LOG_OUT="/var/log/tailnetd.log"
readonly LOG_ERR="/var/log/tailnetd.err.log"

# Resolve paths RELATIVE TO THIS SCRIPT, never the caller's cwd. The script lives in
# packaging/macos/, so the packaging dir is one level up and the repo root is two levels up.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
PACKAGING_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
readonly PACKAGING_DIR
REPO_ROOT="$(cd "${PACKAGING_DIR}/.." && pwd)"
readonly REPO_ROOT
readonly PLIST_SRC="${PACKAGING_DIR}/launchd/${PLIST_NAME}"

# ---------------------------------------------------------------------------------------------
# 0. Must run as root — launchd system daemons, /Library/LaunchDaemons and /usr/local all
#    require it. Bail early with an actionable message rather than failing halfway through.
# ---------------------------------------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
    echo "error: this installer must run as root." >&2
    echo "       Re-run it with sudo, e.g.:" >&2
    echo "           sudo ${BASH_SOURCE[0]} ${1:-[path-to-tailnetd]}" >&2
    exit 1
fi

# ---------------------------------------------------------------------------------------------
# 1. Locate the tailnetd binary to install.
#    Precedence: explicit first argument > ./target/release/tailnetd under the repo root.
# ---------------------------------------------------------------------------------------------
if [ "$#" -ge 1 ] && [ -n "${1:-}" ]; then
    BIN_SRC="$1"
else
    BIN_SRC="${REPO_ROOT}/target/release/tailnetd"
fi

if [ ! -f "${BIN_SRC}" ]; then
    echo "error: tailnetd binary not found at: ${BIN_SRC}" >&2
    echo "       Build it first from the repo root:" >&2
    echo "           cargo build --release" >&2
    echo "       (add --features tun if you need the kernel TUN data path), then either re-run" >&2
    echo "       this installer or pass the binary path explicitly:" >&2
    echo "           sudo ${BASH_SOURCE[0]} /path/to/tailnetd" >&2
    exit 1
fi

# Verify the plist we are about to install actually ships alongside this script.
if [ ! -f "${PLIST_SRC}" ]; then
    echo "error: launchd plist not found at: ${PLIST_SRC}" >&2
    echo "       Run this script from a checkout of the repository (it resolves the plist" >&2
    echo "       relative to its own location under packaging/macos/)." >&2
    exit 1
fi

echo "tailscaled-rs macOS installer"
echo "  binary source : ${BIN_SRC}"
echo "  plist source  : ${PLIST_SRC}"
echo

# ---------------------------------------------------------------------------------------------
# 2. Install the binary to /usr/local/bin/tailnetd (creating /usr/local/bin if missing).
#    `install -m 0755` is atomic-ish and sets the mode in one shot; re-running overwrites the
#    existing binary in place (idempotent).
# ---------------------------------------------------------------------------------------------
echo "==> Installing binary to ${BIN_DEST} ..."
if [ ! -d "${BIN_DIR}" ]; then
    install -d -m 0755 "${BIN_DIR}"
fi
install -m 0755 "${BIN_SRC}" "${BIN_DEST}"

# ---------------------------------------------------------------------------------------------
# 3. Install the LaunchDaemon plist, then lock it down to the ownership/mode launchd requires
#    for a system daemon (root:wheel, 0644) — exactly as the README documents.
# ---------------------------------------------------------------------------------------------
echo "==> Installing plist to ${PLIST_DEST} ..."
install -m 0644 "${PLIST_SRC}" "${PLIST_DEST}"
chown root:wheel "${PLIST_DEST}"
chmod 0644 "${PLIST_DEST}"

# ---------------------------------------------------------------------------------------------
# 4. Create the state directory up front, root-owned and 0700.
#    The daemon enforces 0700 on it itself, but launchd honours pre-existing permissions, so we
#    create it now: /usr/local is typically owned by the Homebrew user, and this dir holds
#    unencrypted node key material — we do not want it under a non-root parent's default mode.
# ---------------------------------------------------------------------------------------------
echo "==> Creating state directory ${STATE_DIR} (0700 root:wheel) ..."
mkdir -p "${STATE_DIR}"
chown root:wheel "${STATE_DIR}"
chmod 0700 "${STATE_DIR}"

# ---------------------------------------------------------------------------------------------
# 5. Pre-create the log files 0640 root:wheel so they are NOT world-readable.
#    launchd honours pre-existing file permissions; logs can contain node identifiers, so we
#    keep them off other local users' eyes. (Documented as a step in the README.)
# ---------------------------------------------------------------------------------------------
echo "==> Pre-creating log files ${LOG_OUT} and ${LOG_ERR} (0640 root:wheel) ..."
if [ ! -e "${LOG_OUT}" ]; then
    install -m 0640 -o root -g wheel /dev/null "${LOG_OUT}"
fi
if [ ! -e "${LOG_ERR}" ]; then
    install -m 0640 -o root -g wheel /dev/null "${LOG_ERR}"
fi
# Enforce the secure mode/ownership UNCONDITIONALLY, not just on first creation: a log left over
# from a prior run (or created by another tool) with looser perms would otherwise stay
# world/group-readable, and these logs can carry node identifiers. Re-applying is cheap and keeps
# the installer idempotent in the security-relevant sense too.
chown root:wheel "${LOG_OUT}" "${LOG_ERR}"
chmod 0640 "${LOG_OUT}" "${LOG_ERR}"

# ---------------------------------------------------------------------------------------------
# 6. Load (or reload) the daemon.
#    Prefer modern `launchctl bootstrap system`. If the service is already bootstrapped a
#    re-run returns non-zero ("service already loaded" / EALREADY) — that is NOT a failure for
#    an idempotent installer, so on a non-zero bootstrap we boot it out and bootstrap again to
#    pick up the freshly-installed plist, then kickstart it. On very old macOS where the
#    `bootstrap` subcommand is unavailable, fall back to the legacy `launchctl load -w`.
# ---------------------------------------------------------------------------------------------
echo "==> Loading daemon (${LABEL}) ..."
if launchctl bootstrap system "${PLIST_DEST}" 2>/dev/null; then
    echo "    bootstrapped."
elif launchctl print "system/${LABEL}" >/dev/null 2>&1; then
    # Already loaded (this is a re-install): rebootstrap so the new plist takes effect, then
    # restart the service from the freshly-installed binary.
    echo "    already loaded — reloading to pick up the updated plist/binary ..."
    # `bootout` may legitimately fail if the service is mid-teardown / not currently loaded — that
    # is harmless, so it stays tolerant. But the re-`bootstrap` is the load that actually matters,
    # so we must NOT mask its failure and then claim success (that would leave the daemon unloaded
    # while reporting a clean install). If re-bootstrap fails, confirm the service is loaded by
    # another route (`launchctl print`); only then is a kickstart-restart enough. If it is neither
    # bootstrapped nor present, fail loudly so the operator knows the install did not take.
    launchctl bootout "system/${LABEL}" 2>/dev/null || true
    if launchctl bootstrap system "${PLIST_DEST}" 2>/dev/null; then
        launchctl kickstart -k "system/${LABEL}" 2>/dev/null || true
        echo "    reloaded."
    elif launchctl print "system/${LABEL}" >/dev/null 2>&1; then
        # Re-bootstrap was rejected but the service is still loaded (e.g. bootout did not fully
        # settle before bootstrap ran): restart it in place so it picks up the new binary/plist.
        launchctl kickstart -k "system/${LABEL}" 2>/dev/null || true
        echo "    reloaded (restarted existing service)."
    else
        echo "error: failed to reload the daemon — re-bootstrap was rejected and the service is" >&2
        echo "       not loaded. The binary and plist are installed at:" >&2
        echo "           ${BIN_DEST}" >&2
        echo "           ${PLIST_DEST}" >&2
        echo "       Load it manually and inspect the error:" >&2
        echo "           sudo launchctl bootstrap system ${PLIST_DEST}" >&2
        echo "           sudo launchctl print system/${LABEL}" >&2
        exit 1
    fi
else
    # `bootstrap` itself is unsupported on this (older) macOS — use the legacy loader.
    echo "    'launchctl bootstrap' unavailable — falling back to 'launchctl load -w' ..."
    launchctl load -w "${PLIST_DEST}"
    echo "    loaded (legacy)."
fi

# ---------------------------------------------------------------------------------------------
# 7. Success summary.
# ---------------------------------------------------------------------------------------------
cat <<EOF

Done. tailnetd is installed and the launchd daemon has been loaded.

  binary     -> ${BIN_DEST}
  plist      -> ${PLIST_DEST}
  state dir  -> ${STATE_DIR}   (0700 root:wheel — holds node keys + prefs)
  logs       -> ${LOG_OUT}
                ${LOG_ERR}

Check status:
  sudo launchctl print system/${LABEL}
  sudo tnet status                       # if the tnet CLI is installed in ${BIN_DIR}

Follow the logs:
  sudo tail -f ${LOG_OUT} ${LOG_ERR}

Next: join a tailnet (the daemon is running but not yet registered):
  sudo tnet up --authkey-file /path/to/key --hostname my-node
  sudo tnet status
(See ../README.md "3. Join a tailnet" for the safe auth-key flow.)

WARNING: experimental, unaudited software — not for production. Do not rely on it for data
privacy yet. To remove it later, run: sudo ${SCRIPT_DIR}/uninstall.sh
EOF
