#!/bin/bash
set -euo pipefail

echo -e "\nmacOS removal script for Nebula network @@tun_device@@\n"

if [[ "$(id -u)" != "0" ]]; then
    echo "This script must be run as root (use sudo)."
    exit 1
fi

TUN_DEVICE="@@tun_device@@"
CONFIG_DIR="/usr/local/etc/nebula/${TUN_DEVICE}"
UPDATE_SCRIPT="/usr/local/lib/nebula/${TUN_DEVICE}-update.sh"
LAUNCH_DAEMONS_DIR="/Library/LaunchDaemons"

echo "* Stopping and removing launchd services"
launchctl unload "${LAUNCH_DAEMONS_DIR}/nebula_${TUN_DEVICE}.plist" 2>/dev/null || true
launchctl unload "${LAUNCH_DAEMONS_DIR}/nebula_${TUN_DEVICE}-update.plist" 2>/dev/null || true

rm -f "${LAUNCH_DAEMONS_DIR}/nebula_${TUN_DEVICE}.plist" \
      "${LAUNCH_DAEMONS_DIR}/nebula_${TUN_DEVICE}-update.plist" 2>/dev/null || true

echo "Services unloaded and plist files removed."

echo -e "\n* Removing config and keys from ${CONFIG_DIR}"
if [[ -d "${CONFIG_DIR}" ]]; then
    rm -rf "${CONFIG_DIR}"
    echo "Config directory removed."
fi

echo -e "\n* Removing update script and status"
if [[ -d "/var/run/nebula/${TUN_DEVICE}" ]]; then
    rm -rf "/var/run/nebula/${TUN_DEVICE}"
fi
if [[ -f "${UPDATE_SCRIPT}" ]]; then
    rm -f "${UPDATE_SCRIPT}"
    echo "Update script removed."
fi

echo -e "\n* Optional cleanup:"
echo "  - Remove binary if unused: rm /usr/local/bin/nebula"
echo "  - Check for other configs: ls /usr/local/etc/nebula/"
echo "  - Check launchd plists: ls ${LAUNCH_DAEMONS_DIR}/nebula_*"

echo -e "\nDone."
exit 0