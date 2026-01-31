#!/usr/bin/env bash
# ==============================================================================
# NGINX Monitor Stack - Prometheus Installer
# ==============================================================================
# Functions to download, install, and configure Prometheus securely.
# This file should be sourced by other scripts, not executed directly.
# ==============================================================================

# Ensure required libraries are loaded
if ! declare -f log_info &>/dev/null; then
    echo "Error: common.sh must be sourced before prometheus.sh" >&2
    exit 1
fi

# ------------------------------------------------------------------------------
# Prometheus Configuration
# ------------------------------------------------------------------------------

# Prometheus version to install
readonly PROMETHEUS_VERSION="2.50.1"
readonly PROMETHEUS_DOWNLOAD_BASE="https://github.com/prometheus/prometheus/releases/download"

# Installation paths
readonly PROMETHEUS_INSTALL_DIR="${INSTALL_DIR}/prometheus"
readonly PROMETHEUS_BIN_DIR="${PROMETHEUS_INSTALL_DIR}/bin"
readonly PROMETHEUS_CONFIG_DIR="${CONFIG_DIR}/prometheus"
readonly PROMETHEUS_DATA_DIR="${DATA_DIR}/prometheus"
readonly PROMETHEUS_BINARY="${PROMETHEUS_BIN_DIR}/prometheus"
readonly PROMETHEUS_PROMTOOL="${PROMETHEUS_BIN_DIR}/promtool"
readonly PROMETHEUS_CONFIG="${PROMETHEUS_CONFIG_DIR}/prometheus.yml"

# ------------------------------------------------------------------------------
# Installation Functions
# ------------------------------------------------------------------------------

# Get the download URL for Prometheus
get_prometheus_download_url() {
    local version="${1:-$PROMETHEUS_VERSION}"
    local arch="${ARCH:-amd64}"

    echo "${PROMETHEUS_DOWNLOAD_BASE}/v${version}/prometheus-${version}.linux-${arch}.tar.gz"
}

# Download and install Prometheus binary
install_prometheus_binary() {
    log_step "Installing Prometheus ${PROMETHEUS_VERSION}"

    # Check if already installed with same version
    if [[ -f "$PROMETHEUS_BINARY" ]]; then
        local installed_version
        installed_version=$("$PROMETHEUS_BINARY" --version 2>&1 | head -1 | grep -oP 'prometheus, version \K[0-9.]+' || echo "unknown")
        if [[ "$installed_version" == "$PROMETHEUS_VERSION" ]]; then
            log_info "Prometheus ${PROMETHEUS_VERSION} is already installed"
            return 0
        fi
        log_info "Upgrading Prometheus from ${installed_version} to ${PROMETHEUS_VERSION}"
    fi

    # Create service user
    create_service_user "$PROMETHEUS_USER" "Prometheus monitoring system"

    # Create directories
    log_substep "Creating directories"
    secure_directory "$PROMETHEUS_INSTALL_DIR" root root 0755
    secure_directory "$PROMETHEUS_BIN_DIR" root root 0755
    secure_directory "$PROMETHEUS_CONFIG_DIR" "$PROMETHEUS_USER" "$PROMETHEUS_USER" 0750
    secure_data_directory "$PROMETHEUS_DATA_DIR" "$PROMETHEUS_USER" "$PROMETHEUS_USER"

    # Download Prometheus
    local download_url
    download_url=$(get_prometheus_download_url)
    local checksum
    checksum=$(get_known_checksum "prometheus" "$PROMETHEUS_VERSION" "$ARCH")

    log_substep "Downloading Prometheus"
    local temp_archive
    temp_archive=$(mktemp)

    if [[ -n "$checksum" ]]; then
        secure_download "$download_url" "$temp_archive" "$checksum"
    else
        log_warn "No known checksum for Prometheus ${PROMETHEUS_VERSION} ${ARCH}, downloading without verification"
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
    extracted_dir=$(find "$temp_dir" -maxdepth 1 -type d -name "prometheus-*" | head -1)

    if [[ -z "$extracted_dir" ]]; then
        rm -rf "$temp_dir"
        die "Failed to extract Prometheus archive"
    fi

    # Install binaries
    log_substep "Installing binaries"
    install -m 0755 "${extracted_dir}/prometheus" "$PROMETHEUS_BINARY"
    install -m 0755 "${extracted_dir}/promtool" "$PROMETHEUS_PROMTOOL"

    # Install console templates and libraries (optional but useful)
    if [[ -d "${extracted_dir}/consoles" ]]; then
        cp -r "${extracted_dir}/consoles" "${PROMETHEUS_INSTALL_DIR}/"
        chown -R "$PROMETHEUS_USER:$PROMETHEUS_USER" "${PROMETHEUS_INSTALL_DIR}/consoles"
    fi

    if [[ -d "${extracted_dir}/console_libraries" ]]; then
        cp -r "${extracted_dir}/console_libraries" "${PROMETHEUS_INSTALL_DIR}/"
        chown -R "$PROMETHEUS_USER:$PROMETHEUS_USER" "${PROMETHEUS_INSTALL_DIR}/console_libraries"
    fi

    # Cleanup
    rm -rf "$temp_dir"

    # Verify installation
    if ! "$PROMETHEUS_BINARY" --version &>/dev/null; then
        die "Prometheus installation verification failed"
    fi

    log_success "Prometheus ${PROMETHEUS_VERSION} installed successfully"
    audit_log "INSTALL" "prometheus version=${PROMETHEUS_VERSION}"

    # Save state
    save_state "prometheus" "$PROMETHEUS_VERSION"
}

# Create Prometheus configuration file
create_prometheus_config() {
    log_substep "Creating Prometheus configuration"

    local config_template="${SCRIPT_DIR}/configs/prometheus/prometheus.yml.template"

    # If template exists, use it; otherwise create default
    if [[ -f "$config_template" ]]; then
        # Copy and process template
        cp "$config_template" "$PROMETHEUS_CONFIG"
    else
        # Create default configuration
        cat > "$PROMETHEUS_CONFIG" << 'EOF'
# Prometheus configuration for NGINX Monitor Stack
# Generated automatically - modify with caution

global:
  scrape_interval: 15s
  evaluation_interval: 15s

  # Security: disable remote write receiver
  # external_labels are used when federating or remote writing
  external_labels:
    monitor: 'nginx-monitor-stack'

# Alertmanager configuration (disabled by default)
# alerting:
#   alertmanagers:
#     - static_configs:
#         - targets:
#           - localhost:9093

# Rule files for alerting
rule_files:
  - "/etc/nginx-monitor/prometheus/alert-rules.yml"

# Scrape configurations
scrape_configs:
  # Prometheus itself
  - job_name: 'prometheus'
    static_configs:
      - targets: ['127.0.0.1:9090']
    # Scrape prometheus metrics less frequently
    scrape_interval: 30s

  # Node exporter for system metrics
  - job_name: 'node'
    static_configs:
      - targets: ['127.0.0.1:9100']

  # NGINX exporter for NGINX metrics
  - job_name: 'nginx'
    static_configs:
      - targets: ['127.0.0.1:9113']
EOF
    fi

    # Set secure permissions
    secure_config_file "$PROMETHEUS_CONFIG" "$PROMETHEUS_USER" "$PROMETHEUS_USER"

    # Validate configuration
    if ! "$PROMETHEUS_PROMTOOL" check config "$PROMETHEUS_CONFIG" &>/dev/null; then
        log_error "Prometheus configuration validation failed:"
        "$PROMETHEUS_PROMTOOL" check config "$PROMETHEUS_CONFIG" || true
        die "Invalid Prometheus configuration"
    fi

    log_debug "Prometheus configuration validated successfully"
}

# Create Prometheus alert rules
create_prometheus_alert_rules() {
    log_substep "Creating alert rules"

    local rules_file="${PROMETHEUS_CONFIG_DIR}/alert-rules.yml"
    local rules_template="${SCRIPT_DIR}/configs/prometheus/alert-rules.yml"

    if [[ -f "$rules_template" ]]; then
        cp "$rules_template" "$rules_file"
    else
        # Create default alert rules
        cat > "$rules_file" << 'EOF'
# Prometheus Alert Rules for NGINX Monitor Stack
# These are sensible defaults - customize as needed

groups:
  - name: nginx_alerts
    interval: 30s
    rules:
      # NGINX is down
      - alert: NginxDown
        expr: nginx_up == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "NGINX is down"
          description: "NGINX has been down for more than 1 minute."

      # High error rate (5xx responses)
      - alert: NginxHighErrorRate
        expr: |
          sum(rate(nginx_http_requests_total{status=~"5.."}[5m]))
          / sum(rate(nginx_http_requests_total[5m])) > 0.05
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High NGINX error rate"
          description: "NGINX 5xx error rate is above 5% for the last 5 minutes."

      # Too many connections
      - alert: NginxHighConnections
        expr: nginx_connections_active > 1000
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High number of NGINX connections"
          description: "NGINX has more than 1000 active connections."

  - name: system_alerts
    interval: 30s
    rules:
      # High CPU usage
      - alert: HighCpuUsage
        expr: |
          100 - (avg by(instance) (rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100) > 80
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "High CPU usage"
          description: "CPU usage is above 80% for the last 10 minutes."

      # Low disk space
      - alert: LowDiskSpace
        expr: |
          (node_filesystem_avail_bytes{mountpoint="/"}
          / node_filesystem_size_bytes{mountpoint="/"}) * 100 < 10
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Low disk space"
          description: "Less than 10% disk space remaining on root filesystem."

      # High memory usage
      - alert: HighMemoryUsage
        expr: |
          (1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100 > 90
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "High memory usage"
          description: "Memory usage is above 90% for the last 10 minutes."

      # Node exporter down
      - alert: NodeExporterDown
        expr: up{job="node"} == 0
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "Node exporter is down"
          description: "Node exporter has been unreachable for more than 2 minutes."
EOF
    fi

    secure_config_file "$rules_file" "$PROMETHEUS_USER" "$PROMETHEUS_USER"

    # Validate rules
    if ! "$PROMETHEUS_PROMTOOL" check rules "$rules_file" &>/dev/null; then
        log_warn "Alert rules validation failed - rules may have syntax errors"
    fi
}

# Create Prometheus systemd service
create_prometheus_service() {
    log_substep "Creating systemd service"

    local systemd_dir
    systemd_dir=$(get_systemd_dir)
    local service_file="${systemd_dir}/prometheus.service"

    cat > "$service_file" << EOF
[Unit]
Description=Prometheus Monitoring System
Documentation=https://prometheus.io/docs/
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${PROMETHEUS_BINARY} \\
    --config.file=${PROMETHEUS_CONFIG} \\
    --storage.tsdb.path=${PROMETHEUS_DATA_DIR} \\
    --storage.tsdb.retention.time=15d \\
    --storage.tsdb.retention.size=5GB \\
    --web.listen-address=127.0.0.1:${PROMETHEUS_PORT} \\
    --web.console.templates=${PROMETHEUS_INSTALL_DIR}/consoles \\
    --web.console.libraries=${PROMETHEUS_INSTALL_DIR}/console_libraries \\
    --web.enable-lifecycle \\
    --log.level=info

ExecReload=/bin/kill -HUP \$MAINPID
TimeoutStopSec=30
Restart=on-failure
RestartSec=5

# Security hardening
$(get_systemd_hardening_options "$PROMETHEUS_USER" "$PROMETHEUS_DATA_DIR" "ReadWritePaths=${PROMETHEUS_DATA_DIR}
ReadOnlyPaths=${PROMETHEUS_CONFIG_DIR} ${PROMETHEUS_INSTALL_DIR}")

[Install]
WantedBy=multi-user.target
EOF

    chmod 0644 "$service_file"
    systemd_reload

    log_debug "Prometheus systemd service created"
}

# Start Prometheus service
start_prometheus() {
    log_substep "Starting Prometheus service"

    enable_and_start_service "prometheus"

    # Wait for Prometheus to be ready
    log_debug "Waiting for Prometheus to be ready..."
    if wait_for_port "$PROMETHEUS_PORT" 30; then
        log_success "Prometheus is running on 127.0.0.1:${PROMETHEUS_PORT}"
    else
        log_error "Prometheus failed to start within 30 seconds"
        journalctl -u prometheus --no-pager -n 20 || true
        return 1
    fi
}

# ------------------------------------------------------------------------------
# Main Installation Function
# ------------------------------------------------------------------------------

# Full Prometheus installation
install_prometheus() {
    install_prometheus_binary
    create_prometheus_alert_rules   # Must come before config validation
    create_prometheus_config
    create_prometheus_service
    start_prometheus
}

# ------------------------------------------------------------------------------
# Uninstallation Functions
# ------------------------------------------------------------------------------

# Stop and remove Prometheus
uninstall_prometheus() {
    log_step "Uninstalling Prometheus"

    # Stop service
    stop_and_disable_service "prometheus" || true

    # Remove service file
    local systemd_dir
    systemd_dir=$(get_systemd_dir)
    rm -f "${systemd_dir}/prometheus.service"
    systemd_reload

    # Remove installation directories
    rm -rf "$PROMETHEUS_INSTALL_DIR"
    rm -rf "$PROMETHEUS_CONFIG_DIR"

    # Optionally remove data (ask user or use flag)
    if [[ "${REMOVE_DATA:-false}" == "true" ]]; then
        rm -rf "$PROMETHEUS_DATA_DIR"
        log_debug "Removed Prometheus data directory"
    else
        log_info "Prometheus data preserved at: $PROMETHEUS_DATA_DIR"
    fi

    # Remove user (only if no other processes are using it)
    if user_exists "$PROMETHEUS_USER"; then
        if ! pgrep -u "$PROMETHEUS_USER" &>/dev/null; then
            userdel "$PROMETHEUS_USER" 2>/dev/null || true
            log_debug "Removed user: $PROMETHEUS_USER"
        fi
    fi

    log_success "Prometheus uninstalled"
    audit_log "UNINSTALL" "prometheus"
}

# ------------------------------------------------------------------------------
# Health Check
# ------------------------------------------------------------------------------

# Check if Prometheus is healthy
check_prometheus_health() {
    local url="http://127.0.0.1:${PROMETHEUS_PORT}/-/healthy"

    if curl -sf "$url" &>/dev/null; then
        echo "healthy"
        return 0
    else
        echo "unhealthy"
        return 1
    fi
}

# Get Prometheus status information
get_prometheus_status() {
    echo "Prometheus Status:"
    echo "  Binary:  ${PROMETHEUS_BINARY}"
    echo "  Config:  ${PROMETHEUS_CONFIG}"
    echo "  Data:    ${PROMETHEUS_DATA_DIR}"
    echo "  Port:    ${PROMETHEUS_PORT}"

    if systemctl is-active --quiet prometheus 2>/dev/null; then
        echo "  Service: running"
        echo "  Health:  $(check_prometheus_health)"
    else
        echo "  Service: stopped"
    fi
}

# ------------------------------------------------------------------------------
# Self-check
# ------------------------------------------------------------------------------

# This ensures the file is being sourced, not executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "This script should be sourced, not executed directly."
    echo "Usage: source ${BASH_SOURCE[0]}"
    exit 1
fi
