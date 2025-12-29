#!/bin/bash
set -euo pipefail

EXEC_DIR="/usr/lib/nebula/@@tun_device@@"
NEBULA_BINARY="${EXEC_DIR}/nebula"
UPDATE_SCRIPT="${EXEC_DIR}/update.sh"
CONFIG_DIR="/etc/nebula/@@tun_device@@"
CONFIG_FILE="${CONFIG_DIR}/update.conf"
LOCAL_VERSION_FILE="${CONFIG_DIR}/version"
LOCAL_NODE_FILE="${CONFIG_DIR}/node"
BACKUP_DIR="/var/backups/@@tun_device@@"
SERVICE_DIR="/etc/systemd/system"
SERVICE_NAME="nebula_@@tun_device@@"

if [[ ! -f "${CONFIG_FILE}" ]]; then
    echo "ERROR: Configuration file not found: ${CONFIG_FILE}" >&2
    exit 1
fi
source "${CONFIG_FILE}"
if [[ -z "${UPDATE_SERVER:-}" || -z "${AUTH_USER:-}" || -z "${AUTH_PASS:-}" ]]; then
    echo "ERROR: Missing required configuration in ${CONFIG_FILE}" >&2
    exit 1
fi
NTFY_CHANNEL="${NTFY_CHANNEL:-}"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

log_warning() {
    log "WARNING: $*"
}

log_error() {
    log "ERROR: $*"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 2
    fi
}

get_local_version() {
    if [[ -f "${LOCAL_VERSION_FILE}" ]]; then
        cat "${LOCAL_VERSION_FILE}" | tr -d '[:space:]'
    else
        echo "0.0.0"
    fi
}

get_node_name() {
    if [[ -f "${LOCAL_NODE_FILE}" ]]; then
        cat "${LOCAL_NODE_FILE}" | tr -d '[:space:]'
    else
        hostname | cut -d'.' -f1 | tr -d '[:space:]'
    fi
}

get_remote_version() {
    local server="$1"
    local curl_output
    local http_code
    curl_output=$(curl -s -w "%{http_code}" -u "${AUTH_USER}:${AUTH_PASS}" --max-time 10 "${server}/version.txt" 2>/dev/null)
    http_code=${curl_output: -3}
    curl_output=${curl_output%???}
    if [[ "$http_code" != "200" ]]; then
        echo "NO_VERSION_FILE"
        return 0
    fi
    remote_version=$(echo "$curl_output" | tr -d '[:space:]')
    if [[ -z "${remote_version}" ]]; then
        echo "NO_VERSION_FILE"
        return 0
    fi
    echo "${remote_version}"
}

get_nebula_version() {
    if [[ -f "$NEBULA_BINARY" ]]; then
        "$NEBULA_BINARY" --version 2>/dev/null | grep -o "Version: [0-9.]*" | cut -d' ' -f2 || echo "unknown"
    else
        echo "not_found"
    fi
}

download_package() {
    local remote_version="$1"
    local node_name
    local package_name
    local package_url
    node_name=$(get_node_name)
    if [[ -z "${node_name}" ]]; then
        log_error "Cannot determine node name" >&2
        return 1
    fi
    package_name="${node_name}_${remote_version}.zip"
    package_url="${UPDATE_SERVER}/${package_name}"
    TEMP_DIR=$(mktemp -d -t nebula-update-XXXXXX)
    if ! curl -s -u "${AUTH_USER}:${AUTH_PASS}" --connect-timeout 30 -o "${TEMP_DIR}/package.zip" "${package_url}"; then
        log_error "Failed to download package from: ${package_url}" >&2
        rm -rf "${TEMP_DIR}"
        return 1
    fi
    if ! unzip -q -d "${TEMP_DIR}" "${TEMP_DIR}/package.zip"; then
        log_error "Failed to extract package" >&2
        rm -rf "${TEMP_DIR}"
        return 1
    fi
    echo "${TEMP_DIR}"
}

create_backup() {
    rm -rf "${BACKUP_DIR}"
    mkdir -p "${BACKUP_DIR}/config"
    mkdir -p "${BACKUP_DIR}/service"
    mkdir -p "${BACKUP_DIR}/exec"
    for unit in "${SERVICE_NAME}.service" "${SERVICE_NAME}-update.service" "${SERVICE_NAME}-update.timer"; do
        if [[ -f "${SERVICE_DIR}/${unit}" ]]; then
            cp -a "${SERVICE_DIR}/${unit}" "${BACKUP_DIR}/service/" 2>/dev/null || true
        fi
    done
    if [[ -d "${EXEC_DIR}" ]]; then
        cp -a "${EXEC_DIR}"/*.sh "${BACKUP_DIR}/exec/" 2>/dev/null || true
    fi
    if [[ -f "${NEBULA_BINARY}" ]]; then
        cp -a "${NEBULA_BINARY}" "${BACKUP_DIR}/exec/" 2>/dev/null || true
    fi
    if [[ -d "${CONFIG_DIR}" ]]; then
        cp -a "${CONFIG_DIR}/"* "${BACKUP_DIR}/config/" 2>/dev/null || true
    fi
    log "Backup created at: ${BACKUP_DIR}"
}

restore_backup() {
    log "Restoring from backup..."
    if [[ ! -d "${BACKUP_DIR}" ]]; then
        log_error "Backup directory not found: ${BACKUP_DIR}"
        return 1
    fi
    log "Stopping services..."
    systemctl stop "${SERVICE_NAME}.service" 2>/dev/null || true
    systemctl stop "${SERVICE_NAME}-update.timer" 2>/dev/null || true
    if [[ -d "${BACKUP_DIR}/service" ]]; then
        for unit in "${BACKUP_DIR}/service"/*; do
            if [[ -f "$unit" ]]; then
                unit_name=$(basename "$unit")
                cp -a "$unit" "${SERVICE_DIR}"
            fi
        done
        systemctl daemon-reload 2>/dev/null || true
    fi
    if [[ -d "${BACKUP_DIR}/exec" ]]; then
        cp -a "${BACKUP_DIR}/exec"/*.sh "${EXEC_DIR}/" 2>/dev/null || true
        chmod 740 "${EXEC_DIR}"/*.sh 2>/dev/null || true
        chown root:nebula "${EXEC_DIR}"/*.sh 2>/dev/null || true
    fi
    if [[ -f "${BACKUP_DIR}/exec/nebula" ]]; then
        cp -a "${BACKUP_DIR}/exec/nebula" "${NEBULA_BINARY}"
        chown nebula:nebula "${NEBULA_BINARY}" 2>/dev/null || true
        chmod 750 "${NEBULA_BINARY}" 2>/dev/null || true
        setcap cap_net_admin=+pe "${NEBULA_BINARY}" 2>/dev/null || true
    fi
    if [[ -d "${BACKUP_DIR}/config" ]]; then
        rm -rf "${CONFIG_DIR}"
        mkdir -p "${CONFIG_DIR}"
        cp -a "${BACKUP_DIR}/config/"* "${CONFIG_DIR}/" 2>/dev/null || true
        chown -R nebula:nebula "${CONFIG_DIR}" 2>/dev/null || true
    fi
    log "Starting services..."
    systemctl start "${SERVICE_NAME}.service" 2>/dev/null || true
    systemctl start "${SERVICE_NAME}-update.timer" 2>/dev/null || true
    log "Restore completed"
}

apply_update() {
    local temp_dir="$1"
    temp_dir=$(echo "${temp_dir}" | tail -1 | tr -d '[:space:]')
    cd "${temp_dir}" || {
        log_error "Cannot cd to ${temp_dir}"
        return 1
    }
    if [[ ! -f "./deploy.sh" ]]; then
        log_error "deploy.sh not found in ${temp_dir}"
        return 1
    fi
    chmod +x ./deploy.sh
    log "Running deploy.sh..."
    if ! ./deploy.sh; then
        log_error "deploy.sh failed with exit code $?"
        return 1
    fi
    log "Update applied successfully"
}

verify_update() {
    local expected_version="$1"
    local new_local_version
    local remote_version_again
    new_local_version=$(get_local_version)
    log "Local version after update: ${new_local_version}"
    remote_version_again=$(get_remote_version "${UPDATE_SERVER}")
    if [[ "${remote_version_again}" == "NO_VERSION_FILE" ]]; then
        log_error "Could not verify remote version after update"
        return 1
    fi
    if [[ "${new_local_version}" == "${expected_version}" ]] && [[ "${remote_version_again}" == "${expected_version}" ]]; then
        return 0
    else
        log_error "Version verification failed"
        log_error "Expected: ${expected_version}"
        log_error "Local: ${new_local_version}"
        log_error "Remote: ${remote_version_again}"
        return 1
    fi
}

check_service() {
    if systemctl is-active --quiet "${SERVICE_NAME}"; then
        log "Service ${SERVICE_NAME} is running"
        return 0
    else
        log_error "Service ${SERVICE_NAME} is not running"
        systemctl status "${SERVICE_NAME}" --no-pager || true
        return 1
    fi
}

perform_update() {
    local remote_version="$1"
    local local_version
    local temp_dir
    local_version=$(get_local_version)
    log "Downloading update package for version: ${remote_version}"
    temp_dir=$(download_package "${remote_version}")
    if [[ $? -ne 0 ]] || [[ ! -d "${temp_dir}" ]]; then
        log_error "Download failed, no backup needed"
        return 1
    fi
    temp_dir=$(echo "${temp_dir}" | tr -d '[:space:]')
    create_backup
    if ! apply_update "${temp_dir}"; then
        log_error "Update failed, restoring backup..."
        restore_backup
        rm -rf "${temp_dir}"
        return 1
    fi
    if ! verify_update "${remote_version}"; then
        log_error "Verification failed, restoring backup..."
        restore_backup
        rm -rf "${temp_dir}"
        return 1
    fi
    if ! check_service; then
        log_warning "Service check failed, but update applied successfully"
    fi
    rm -rf "${temp_dir}"
    rm -rf "${BACKUP_DIR}"
    log "Update completed successfully to version ${remote_version}"
    return 0
}

report_result() {
    local result_code="$1"
    local old_version="${2:-$(get_local_version)}"
    local current_version="${3:-$(get_local_version)}"
    local result_text=""
    local node_name=$(get_node_name)
    local nebula_version=$(get_nebula_version)
    if [[ "$result_code" -eq 1 ]]; then
        return 0
    fi
    case $result_code in
        0) result_text="updated" ;;
        2) result_text="error" ;;
    esac
    local status_dir="/var/run/nebula/@@tun_device@@"
    mkdir -p "$status_dir"
    cat > "${status_dir}/update-status.json" << EOF
{
"node": "$node_name",
"result": "${result_text}",
"previous": "$old_version",
"current": "$current_version",
"nebula": "$nebula_version",
"timestamp": "$(date -Iseconds)"
}
EOF
    chmod 755 "$status_dir" 2>/dev/null || true
    chmod 644 "${status_dir}/update-status.json" 2>/dev/null || true
    if [[ -n "${NTFY_CHANNEL:-}" ]]; then
        local channel_clean=$(echo "${NTFY_CHANNEL}" | tr -d '[:space:]')
        if [[ -n "$channel_clean" ]]; then
            local ntfy_url="https://ntfy.sh/${channel_clean}"
            case $result_code in
                0) echo "Updated from ${old_version} --> ${current_version}"$'\n'"Nebula version: ${nebula_version}" | \
                    curl -H "Title: ${node_name} @ @@tun_device@@" \
                         -H "Tags:white_check_mark" \
                         -H "Priority:3" \
                         --data-binary @- "${ntfy_url}" >/dev/null 2>&1 ;;
                2) echo "ERROR on update from ${old_version} --> ${current_version}"$'\n'"Nebula version: ${nebula_version}" | \
                    curl -H "Title: ${node_name} @ @@tun_device@@" \
                         -H "Tags:warning" \
                         -H "Priority:4" \
                         --data-binary @- "${ntfy_url}" >/dev/null 2>&1 ;;
            esac
        fi
    fi
}

main() {
    check_root
    local old_version=$(get_local_version)
    local remote_version=$(get_remote_version "${UPDATE_SERVER}")
    case "$remote_version" in
        NO_VERSION_FILE)
            log "No version.txt on server (or empty)"
            exit 1
            ;;
        *)
            if [[ "$old_version" == "$remote_version" ]]; then
                log "No update required (already at ${old_version})"
                exit 1
            else
                log "Starting update from ${old_version} to ${remote_version}..."
                if perform_update "$remote_version"; then
                    log "Update process completed successfully"
                    report_result 0 "$old_version" "$remote_version"
                    exit 0
                else
                    log_error "Update process failed"
                    report_result 2 "$old_version" "$remote_version"
                    exit 2
                fi
            fi
            ;;
    esac
}

main "$@"