#!/bin/bash
set -euo pipefail

echo -e "\nmacOS deployment script for Nebula network @@tun_device@@\n"

if [[ "$(id -u)" != "0" ]]; then
    echo "This script must be run as root (use sudo)."
    exit 1
fi

# Paths
NEBULA_BIN_SOURCE=""
NEBULA_BIN_TARGET="/usr/local/bin/nebula"
CONFIG_DIR="/usr/local/etc/nebula/@@tun_device@@"
UPDATE_SCRIPT_DIR="/usr/local/lib/nebula"
UPDATE_SCRIPT_TARGET="${UPDATE_SCRIPT_DIR}/@@tun_device@@-update.sh"
LAUNCH_DAEMONS_DIR="/Library/LaunchDaemons"

echo "* Handling Nebula binary"

if [[ -x "./nebula" ]]; then
    NEBULA_BIN_SOURCE="./nebula"
elif [[ -x "./nebula-darwin" ]]; then
    NEBULA_BIN_SOURCE="./nebula-darwin"
fi

if [[ -z "${NEBULA_BIN_SOURCE}" && -x "${NEBULA_BIN_TARGET}" ]]; then
    NEBULA_BIN_SOURCE="${NEBULA_BIN_TARGET}"
fi

if [[ -n "${NEBULA_BIN_SOURCE}" ]]; then
    install -m 755 "${NEBULA_BIN_SOURCE}" "${NEBULA_BIN_TARGET}"
    echo "Binary installed/updated at ${NEBULA_BIN_TARGET}"
else
    echo "ERROR: Nebula binary not found in package or ${NEBULA_BIN_TARGET}"
    echo "Download from: https://github.com/slackhq/nebula/releases/latest"
    exit 1
fi

echo -e "\n* Stopping and unloading services"
# Always attempt to unload both services before installing files.
launchctl unload "${LAUNCH_DAEMONS_DIR}/nebula_@@tun_device@@.plist" 2>/dev/null || true
launchctl unload "${LAUNCH_DAEMONS_DIR}/nebula_@@tun_device@@-update.plist" 2>/dev/null || true

echo -e "\n* Preparing directories"
mkdir -p "${CONFIG_DIR}" "${UPDATE_SCRIPT_DIR}"

echo -e "\n* Installing configuration and scripts"
cp -f host.* ca.crt config.yaml version node "${CONFIG_DIR}/" 2>/dev/null || {
    echo "ERROR: Required config files missing."
    exit 1
}

if [[ -f "./update.sh" ]]; then
    install -m 740 "./update.sh" "${UPDATE_SCRIPT_TARGET}"
    echo "Update script installed."
fi

echo -e "\n* Configuring launchd services"
# Copy pre-made plist templates from package
if [[ -f "./nebula_@@tun_device@@.plist" ]]; then
    install -m 644 "./nebula_@@tun_device@@.plist" "${LAUNCH_DAEMONS_DIR}/"
    launchctl load -w "${LAUNCH_DAEMONS_DIR}/nebula_@@tun_device@@.plist"
    echo "Main service loaded."
fi

if [[ -f "./nebula_@@tun_device@@-update.plist" ]]; then
    install -m 644 "./nebula_@@tun_device@@-update.plist" "${LAUNCH_DAEMONS_DIR}/"
    launchctl load -w "${LAUNCH_DAEMONS_DIR}/nebula_@@tun_device@@-update.plist"
    echo "Update agent loaded."
fi

echo -e "\nDone."
exit 0