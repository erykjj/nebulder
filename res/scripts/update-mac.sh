#!/bin/bash
set -euo pipefail

# Configuration
LOCAL_VERSION_FILE="/usr/local/etc/nebula/@@tun_device@@/version"
LOCAL_NODE_FILE="/usr/local/etc/nebula/@@tun_device@@/node"
BACKUP_DIR="/var/backups/@@tun_device@@"
NEBULA_BINARY="/usr/local/bin/nebula"
NEBULA_CONFIG_DIR="/usr/local/etc/nebula/@@tun_device@@"
SERVICE_NAME="nebula_@@tun_device@@"
UPDATE_SCRIPT="/usr/local/lib/nebula/@@tun_device@@-update.sh"

CONFIG_FILE="/usr/local/etc/nebula/@@tun_device@@/update.conf"
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

log_success() {
    log "SUCCESS: $*"
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

create_backup() {
    rm -rf "${BACKUP_DIR}"
    mkdir -p "${BACKUP_DIR}"
    mkdir -p "${BACKUP_DIR}/Library/LaunchDaemons"

    if [[ -f "/Library/LaunchDaemons/${SERVICE_NAME}.plist" ]]; then
        cp -a "/Library/LaunchDaemons/${SERVICE_NAME}.plist" "${BACKUP_DIR}/Library/LaunchDaemons/" 2>/dev/null || true
    fi
    if [[ -f "/Library/LaunchDaemons/${SERVICE_NAME}-update.plist" ]]; then
        cp -a "/Library/LaunchDaemons/${SERVICE_NAME}-update.plist" "${BACKUP_DIR}/Library/LaunchDaemons/" 2>/dev/null || true
    fi

    if [[ -f "${UPDATE_SCRIPT}" ]]; then
        cp -a "${UPDATE_SCRIPT}" "${BACKUP_DIR}/" 2>/dev/null || true
    fi
    if [[ -f "${NEBULA_BINARY}" ]]; then
        cp -a "${NEBULA_BINARY}" "${BACKUP_DIR}/" 2>/dev/null || true
    fi
    if [[ -d "${NEBULA_CONFIG_DIR}" ]]; then
        cp -a "${NEBULA_CONFIG_DIR}" "${BACKUP_DIR}/config" 2>/dev/null || true
    fi
    log "Backup created at: ${BACKUP_DIR}"
}

restore_backup() {
    log "Restoring from backup..."
    if [[ ! -d "${BACKUP_DIR}" ]]; then
        log_error "Backup directory not found: ${BACKUP_DIR}"
        return 1
    fi
    # Run the deploy.sh script from the backup to restore everything
    if [[ -f "${BACKUP_DIR}/deploy.sh" ]]; then
        if /bin/bash "${BACKUP_DIR}/deploy.sh"; then
            log "Restore completed via backup's deploy.sh"
            return 0
        else
            log_error "Restore script failed"
            return 1
        fi
    else
        log_error "Backup deploy script not found"
        return 1
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
    log "Package downloaded and extracted to: ${TEMP_DIR}" >&2
    echo "${TEMP_DIR}"
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
        log_success "Version verification passed"
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
    log "Checking nebula service status..."
    # Check if service is loaded and likely running
    if launchctl list | grep -q "${SERVICE_NAME}"; then
        log_success "Service ${SERVICE_NAME} is loaded"
        return 0
    else
        log_error "Service ${SERVICE_NAME} is not loaded"
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
    log "Package downloaded to: ${temp_dir}"
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
    log "Cleanup completed"
    log_success "Update completed successfully to version ${remote_version}"
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

trim_log() {
    local log_file="$1"
    local max_size_mb=1
    local max_size_bytes=$((max_size_mb * 1024 * 1024))
    if [[ -f "$log_file" ]] && [[ $(stat -f%z "$log_file" 2>/dev/null || echo 0) -gt $max_size_bytes ]]; then
        tail -c ${max_size_bytes} "$log_file" > "${log_file}.tmp" && mv "${log_file}.tmp" "$log_file"
        log "Trimmed oversized log file: $log_file"
    fi
}

main() {
    trim_log "/usr/local/var/log/nebula_@@tun_device@@.log"
    trim_log "/usr/local/var/log/nebula_@@tun_device@@-update.log"
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
                    log_success "Update process completed successfully"
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