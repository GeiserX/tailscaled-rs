#!/usr/bin/env bash
#
# uninstall.sh — remove the tailscaled-rs daemon (tailnetd) launchd service on macOS.
#
# Reverses packaging/macos/install.sh: it boots the LaunchDaemon out, removes the plist from
# /Library/LaunchDaemons, and removes the /usr/local/bin/tailnetd binary. It is idempotent —
# running it when the service is already gone (or was never installed) succeeds without error.
#
# It deliberately DOES NOT delete the state directory (/usr/local/var/tailnetd): that holds the
# node keys + prefs (the node's identity). Removing the service stops the daemon but leaves the
# identity intact, so a later re-install rejoins the same tailnet. To fully forget the node,
# purge the state dir manually (this script prints the exact command).
#
# Usage:
#   sudo packaging/macos/uninstall.sh

set -euo pipefail

# Must stay in lockstep with install.sh / the plist.
readonly LABEL="cloud.tailscaled-rs.tailnetd"
readonly PLIST_NAME="cloud.tailscaled-rs.tailnetd.plist"
readonly PLIST_DEST="/Library/LaunchDaemons/${PLIST_NAME}"
readonly BIN_DEST="/usr/local/bin/tailnetd"
readonly STATE_DIR="/usr/local/var/tailnetd"
readonly LOG_OUT="/var/log/tailnetd.log"
readonly LOG_ERR="/var/log/tailnetd.err.log"

# ---------------------------------------------------------------------------------------------
# 0. Must run as root (touches /Library/LaunchDaemons, the system launchd domain, /usr/local).
# ---------------------------------------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
    echo "error: this uninstaller must run as root." >&2
    echo "       Re-run it with sudo, e.g.:" >&2
    echo "           sudo ${BASH_SOURCE[0]}" >&2
    exit 1
fi

# ---------------------------------------------------------------------------------------------
# 1. Stop + unload the daemon. Tolerate "not loaded": `bootout` returns non-zero if the service
#    is not currently bootstrapped, which is fine for an idempotent uninstall. Prefer the modern
#    `launchctl bootout system <plist>`; if `bootout` is unavailable (older macOS) fall back to
#    the legacy `launchctl unload`.
# ---------------------------------------------------------------------------------------------
echo "==> Unloading daemon (${LABEL}) ..."
if launchctl bootout "system/${LABEL}" 2>/dev/null; then
    echo "    booted out."
elif [ -f "${PLIST_DEST}" ] && launchctl bootout system "${PLIST_DEST}" 2>/dev/null; then
    echo "    booted out (by plist path)."
elif [ -f "${PLIST_DEST}" ] && launchctl unload "${PLIST_DEST}" 2>/dev/null; then
    echo "    unloaded (legacy)."
else
    echo "    not loaded (nothing to unload) — continuing."
fi

# ---------------------------------------------------------------------------------------------
# 2. Remove the plist (idempotent: rm -f does not error if it is already gone).
# ---------------------------------------------------------------------------------------------
echo "==> Removing plist ${PLIST_DEST} ..."
rm -f "${PLIST_DEST}"

# ---------------------------------------------------------------------------------------------
# 3. Remove the binary (idempotent).
# ---------------------------------------------------------------------------------------------
echo "==> Removing binary ${BIN_DEST} ..."
rm -f "${BIN_DEST}"

# ---------------------------------------------------------------------------------------------
# 4. Done. Leave the state directory in place and tell the operator how to purge it.
# ---------------------------------------------------------------------------------------------
cat <<EOF

Done. The tailnetd launchd service has been removed.

  removed : ${PLIST_DEST}
  removed : ${BIN_DEST}

The state directory was left in place (it holds this node's keys + prefs):

  ${STATE_DIR}

A later re-install will reuse it and rejoin the same tailnet. To fully forget this node
(purge its identity), remove it manually:

  sudo tnet down               # log out of the tailnet first (good hygiene)
  sudo rm -rf ${STATE_DIR}

Note: the log files ${LOG_OUT} and ${LOG_ERR} are left
untouched; remove them too if you want a clean slate:

  sudo rm -f ${LOG_OUT} ${LOG_ERR}
EOF
