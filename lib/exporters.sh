#!/usr/bin/env bash
# ==============================================================================
# NGINX Monitor Stack - Prometheus Exporters Installer
# ==============================================================================
# Functions to install node_exporter and nginx-prometheus-exporter.
# This file should be sourced by other scripts, not executed directly.
# ==============================================================================

# Ensure required libraries are loaded
if ! declare -f log_info &>/dev/null; then
    echo "Error: common.sh must be sourced before exporters.sh" >&2
    exit 1
fi

# ------------------------------------------------------------------------------
# Version Configuration
# ------------------------------------------------------------------------------

readonly NODE_EXPORTER_VERSION="1.7.0"
readonly NGINX_EXPORTER_VERSION="1.1.0"

# Download base URLs
readonly NODE_EXPORTER_DOWNLOAD_BASE="https://github.com/prometheus/node_exporter/releases/download"
readonly NGINX_EXPORTER_DOWNLOAD_BASE="https://github.com/nginxinc/nginx-prometheus-exporter/releases/download"

# Installation paths
readonly EXPORTERS_INSTALL_DIR="${INSTALL_DIR}/exporters"
readonly NODE_EXPORTER_BINARY="${EXPORTERS_INSTALL_DIR}/node_exporter"
readonly NGINX_EXPORTER_BINARY="${EXPORTERS_INSTALL_DIR}/nginx-prometheus-exporter"

# ==============================================================================
# NODE EXPORTER
# ==============================================================================

# Get download URL for node_exporter
get_node_exporter_download_url() {
    local version="${1:-$NODE_EXPORTER_VERSION}"
    local arch="${ARCH:-amd64}"

    echo "${NODE_EXPORTER_DOWNLOAD_BASE}/v${version}/node_exporter-${version}.linux-${arch}.tar.gz"
}

# Install node_exporter binary
install_node_exporter_binary() {
    log_step "Installing Node Exporter ${NODE_EXPORTER_VERSION}"

    # Check if already installed with same version
    if [[ -f "$NODE_EXPORTER_BINARY" ]]; then
        local installed_version
        installed_version=$("$NODE_EXPORTER_BINARY" --version 2>&1 | head -1 | grep -oP 'version \K[0-9.]+' || echo "unknown")
        if [[ "$installed_version" == "$NODE_EXPORTER_VERSION" ]]; then
            log_info "Node Exporter ${NODE_EXPORTER_VERSION} is already installed"
            return 0
        fi
        log_info "Upgrading Node Exporter from ${installed_version} to ${NODE_EXPORTER_VERSION}"
    fi

    # Create service user
    create_service_user "$EXPORTER_USER" "Prometheus exporters"

    # Create directories
    log_substep "Creating directories"
    secure_directory "$EXPORTERS_INSTALL_DIR" root root 0755

    # Download node_exporter
    local download_url
    download_url=$(get_node_exporter_download_url)
    local checksum
    checksum=$(get_known_checksum "node_exporter" "$NODE_EXPORTER_VERSION" "$ARCH")

    log_substep "Downloading Node Exporter"
    local temp_archive
    temp_archive=$(mktemp)

    if [[ -n "$checksum" ]]; then
        secure_download "$download_url" "$temp_archive" "$checksum"
    else
        log_warn "No known checksum for Node Exporter ${NODE_EXPORTER_VERSION} ${ARCH}"
        secure_download "$download_url" "$temp_archive"
    fi

    # Extract archive
    log_substep "Extracting archive"
    local temp_dir
    temp_dir=$(mktemp -d)

    tar -xzf "$temp_archive" -C "$temp_dir"
    rm -f "$temp_archive"

    # Find extracted directory
    local extracted_dir
    extracted_dir=$(find "$temp_dir" -maxdepth 1 -type d -name "node_exporter-*" | head -1)

    if [[ -z "$extracted_dir" ]]; then
        rm -rf "$temp_dir"
        die "Failed to extract Node Exporter archive"
    fi

    # Install binary
    log_substep "Installing binary"
    install -m 0755 "${extracted_dir}/node_exporter" "$NODE_EXPORTER_BINARY"

    # Cleanup
    rm -rf "$temp_dir"

    # Verify installation
    if ! "$NODE_EXPORTER_BINARY" --version &>/dev/null; then
        die "Node Exporter installation verification failed"
    fi

    log_success "Node Exporter ${NODE_EXPORTER_VERSION} installed successfully"
    audit_log "INSTALL" "node_exporter version=${NODE_EXPORTER_VERSION}"
    save_state "node_exporter" "$NODE_EXPORTER_VERSION"
}

# Create node_exporter systemd service
create_node_exporter_service() {
    log_substep "Creating Node Exporter systemd service"

    local systemd_dir
    systemd_dir=$(get_systemd_dir)
    local service_file="${systemd_dir}/node_exporter.service"

    # Define collectors to enable/disable for security
    # We disable some collectors that might expose sensitive info
    local collectors_disabled=(
        "arp"           # Network ARP table
        "bonding"       # Not commonly needed
        "infiniband"    # Not commonly used
        "ipvs"          # Not commonly used
        "nfs"           # Only if using NFS
        "nfsd"          # Only if using NFS server
        "zfs"           # Only if using ZFS
        "textfile"      # Disabled unless explicitly needed
        "systemd"       # Can expose service details
    )

    local disabled_flags=""
    for collector in "${collectors_disabled[@]}"; do
        disabled_flags+=" --no-collector.${collector}"
    done

    cat > "$service_file" << EOF
[Unit]
Description=Prometheus Node Exporter
Documentation=https://prometheus.io/docs/guides/node-exporter/
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${NODE_EXPORTER_BINARY} \\
    --web.listen-address=127.0.0.1:${NODE_EXPORTER_PORT} \\
    --web.disable-exporter-metrics \\
    --log.level=warn${disabled_flags}

Restart=on-failure
RestartSec=5

# Security hardening (minimal - node_exporter needs broad /proc access)
User=${EXPORTER_USER}
Group=${EXPORTER_USER}
NoNewPrivileges=yes
ProtectHome=yes
PrivateTmp=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

[Install]
WantedBy=multi-user.target
EOF

    chmod 0644 "$service_file"
    systemd_reload

    log_debug "Node Exporter systemd service created"
}

# Start node_exporter service
start_node_exporter() {
    log_substep "Starting Node Exporter service"

    enable_and_start_service "node_exporter"

    if wait_for_port "$NODE_EXPORTER_PORT" 15; then
        log_success "Node Exporter is running on 127.0.0.1:${NODE_EXPORTER_PORT}"
    else
        log_error "Node Exporter failed to start"
        return 1
    fi
}

# Full node_exporter installation
install_node_exporter() {
    install_node_exporter_binary
    create_node_exporter_service
    start_node_exporter
}

# Uninstall node_exporter
uninstall_node_exporter() {
    log_substep "Uninstalling Node Exporter"

    stop_and_disable_service "node_exporter" || true

    local systemd_dir
    systemd_dir=$(get_systemd_dir)
    rm -f "${systemd_dir}/node_exporter.service"
    rm -f "$NODE_EXPORTER_BINARY"

    systemd_reload
    log_success "Node Exporter uninstalled"
    audit_log "UNINSTALL" "node_exporter"
}

# ==============================================================================
# NGINX PROMETHEUS EXPORTER
# ==============================================================================

# Get download URL for nginx-prometheus-exporter
get_nginx_exporter_download_url() {
    local version="${1:-$NGINX_EXPORTER_VERSION}"
    local arch="${ARCH:-amd64}"

    echo "${NGINX_EXPORTER_DOWNLOAD_BASE}/v${version}/nginx-prometheus-exporter_${version}_linux_${arch}.tar.gz"
}

# Install nginx-prometheus-exporter binary
install_nginx_exporter_binary() {
    log_step "Installing NGINX Prometheus Exporter ${NGINX_EXPORTER_VERSION}"

    # Check if NGINX is installed
    if ! $NGINX_INSTALLED; then
        log_warn "NGINX is not installed - skipping NGINX exporter installation"
        return 0
    fi

    # Check if already installed with same version
    if [[ -f "$NGINX_EXPORTER_BINARY" ]]; then
        local installed_version
        installed_version=$("$NGINX_EXPORTER_BINARY" --version 2>&1 | grep -oP '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "unknown")
        if [[ "$installed_version" == "$NGINX_EXPORTER_VERSION" ]]; then
            log_info "NGINX Prometheus Exporter ${NGINX_EXPORTER_VERSION} is already installed"
            return 0
        fi
    fi

    # Create service user (reuse exporter user)
    create_service_user "$EXPORTER_USER" "Prometheus exporters"

    # Create directories
    log_substep "Creating directories"
    secure_directory "$EXPORTERS_INSTALL_DIR" root root 0755

    # Download nginx-prometheus-exporter
    local download_url
    download_url=$(get_nginx_exporter_download_url)
    local checksum
    checksum=$(get_known_checksum "nginx_exporter" "$NGINX_EXPORTER_VERSION" "$ARCH")

    log_substep "Downloading NGINX Prometheus Exporter"
    local temp_archive
    temp_archive=$(mktemp)

    if [[ -n "$checksum" ]]; then
        secure_download "$download_url" "$temp_archive" "$checksum"
    else
        log_warn "No known checksum for NGINX Exporter ${NGINX_EXPORTER_VERSION} ${ARCH}"
        secure_download "$download_url" "$temp_archive"
    fi

    # Extract archive
    log_substep "Extracting archive"
    local temp_dir
    temp_dir=$(mktemp -d)

    tar -xzf "$temp_archive" -C "$temp_dir"
    rm -f "$temp_archive"

    # Install binary (the tarball extracts directly, not into a subdirectory)
    log_substep "Installing binary"
    if [[ -f "${temp_dir}/nginx-prometheus-exporter" ]]; then
        install -m 0755 "${temp_dir}/nginx-prometheus-exporter" "$NGINX_EXPORTER_BINARY"
    else
        # Try to find it
        local found_binary
        found_binary=$(find "$temp_dir" -name "nginx-prometheus-exporter" -type f | head -1)
        if [[ -n "$found_binary" ]]; then
            install -m 0755 "$found_binary" "$NGINX_EXPORTER_BINARY"
        else
            rm -rf "$temp_dir"
            die "Could not find nginx-prometheus-exporter binary in archive"
        fi
    fi

    # Cleanup
    rm -rf "$temp_dir"

    # Verify installation
    if ! "$NGINX_EXPORTER_BINARY" --version &>/dev/null; then
        die "NGINX Prometheus Exporter installation verification failed"
    fi

    log_success "NGINX Prometheus Exporter ${NGINX_EXPORTER_VERSION} installed successfully"
    audit_log "INSTALL" "nginx_exporter version=${NGINX_EXPORTER_VERSION}"
    save_state "nginx_exporter" "$NGINX_EXPORTER_VERSION"
}

# Create nginx-prometheus-exporter systemd service
create_nginx_exporter_service() {
    log_substep "Creating NGINX Prometheus Exporter systemd service"

    # Determine stub_status URL
    local stub_status_url="${NGINX_STUB_STATUS_URL:-http://127.0.0.1:${NGINX_STUB_STATUS_PORT}/nginx_status}"

    local systemd_dir
    systemd_dir=$(get_systemd_dir)
    local service_file="${systemd_dir}/nginx-prometheus-exporter.service"

    cat > "$service_file" << EOF
[Unit]
Description=NGINX Prometheus Exporter
Documentation=https://github.com/nginxinc/nginx-prometheus-exporter
After=network-online.target nginx.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=${NGINX_EXPORTER_BINARY} \\
    --web.listen-address=127.0.0.1:${NGINX_EXPORTER_PORT} \\
    --nginx.scrape-uri=${stub_status_url}

Restart=on-failure
RestartSec=5

# Security hardening
$(get_systemd_hardening_options "$EXPORTER_USER" "/")

[Install]
WantedBy=multi-user.target
EOF

    chmod 0644 "$service_file"
    systemd_reload

    log_debug "NGINX Prometheus Exporter systemd service created"
}

# Start nginx-prometheus-exporter service
start_nginx_exporter() {
    log_substep "Starting NGINX Prometheus Exporter service"

    enable_and_start_service "nginx-prometheus-exporter"

    if wait_for_port "$NGINX_EXPORTER_PORT" 15; then
        log_success "NGINX Prometheus Exporter is running on 127.0.0.1:${NGINX_EXPORTER_PORT}"
    else
        log_error "NGINX Prometheus Exporter failed to start"
        log_warn "This may be because NGINX stub_status is not configured yet"
        return 1
    fi
}

# Full nginx-prometheus-exporter installation
install_nginx_exporter() {
    if ! $NGINX_INSTALLED; then
        log_warn "Skipping NGINX exporter - NGINX not installed"
        return 0
    fi

    install_nginx_exporter_binary
    create_nginx_exporter_service
    # Don't start yet - need stub_status configured first
    log_info "NGINX Prometheus Exporter installed but not started (waiting for stub_status configuration)"
}

# Uninstall nginx-prometheus-exporter
uninstall_nginx_exporter() {
    log_substep "Uninstalling NGINX Prometheus Exporter"

    stop_and_disable_service "nginx-prometheus-exporter" || true

    local systemd_dir
    systemd_dir=$(get_systemd_dir)
    rm -f "${systemd_dir}/nginx-prometheus-exporter.service"
    rm -f "$NGINX_EXPORTER_BINARY"

    systemd_reload
    log_success "NGINX Prometheus Exporter uninstalled"
    audit_log "UNINSTALL" "nginx_exporter"
}

# ==============================================================================
# COMBINED OPERATIONS
# ==============================================================================

# Install all exporters
install_all_exporters() {
    install_node_exporter
    install_nginx_exporter
}

# Uninstall all exporters
uninstall_all_exporters() {
    uninstall_node_exporter
    uninstall_nginx_exporter

    # Remove shared user if no longer needed
    if user_exists "$EXPORTER_USER"; then
        if ! pgrep -u "$EXPORTER_USER" &>/dev/null; then
            userdel "$EXPORTER_USER" 2>/dev/null || true
            log_debug "Removed user: $EXPORTER_USER"
        fi
    fi

    # Remove exporters directory if empty
    if [[ -d "$EXPORTERS_INSTALL_DIR" ]]; then
        rmdir "$EXPORTERS_INSTALL_DIR" 2>/dev/null || true
    fi
}

# Health check for exporters
check_exporters_health() {
    local all_healthy=true

    echo "Exporters Status:"

    # Node exporter
    echo -n "  node_exporter: "
    if systemctl is-active --quiet node_exporter 2>/dev/null; then
        if curl -sf "http://127.0.0.1:${NODE_EXPORTER_PORT}/metrics" &>/dev/null; then
            echo "healthy"
        else
            echo "running but not responding"
            all_healthy=false
        fi
    else
        echo "not running"
        all_healthy=false
    fi

    # NGINX exporter
    echo -n "  nginx_exporter: "
    if systemctl is-active --quiet nginx-prometheus-exporter 2>/dev/null; then
        if curl -sf "http://127.0.0.1:${NGINX_EXPORTER_PORT}/metrics" &>/dev/null; then
            echo "healthy"
        else
            echo "running but not responding"
            all_healthy=false
        fi
    else
        if $NGINX_INSTALLED; then
            echo "not running"
            all_healthy=false
        else
            echo "not installed (NGINX not present)"
        fi
    fi

    $all_healthy
}

# ------------------------------------------------------------------------------
# Self-check
# ------------------------------------------------------------------------------

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "This script should be sourced, not executed directly."
    echo "Usage: source ${BASH_SOURCE[0]}"
    exit 1
fi
