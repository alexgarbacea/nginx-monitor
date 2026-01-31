#!/usr/bin/env bash
# ==============================================================================
# NGINX Monitor Stack - Grafana Installer
# ==============================================================================
# Functions to install and configure Grafana securely.
# Uses official Grafana repositories for installation.
# This file should be sourced by other scripts, not executed directly.
# ==============================================================================

# Ensure required libraries are loaded
if ! declare -f log_info &>/dev/null; then
    echo "Error: common.sh must be sourced before grafana.sh" >&2
    exit 1
fi

# ------------------------------------------------------------------------------
# Grafana Configuration
# ------------------------------------------------------------------------------

# Installation paths
readonly GRAFANA_CONFIG_DIR="${CONFIG_DIR}/grafana"
readonly GRAFANA_DATA_DIR="${DATA_DIR}/grafana"
readonly GRAFANA_LOG_DIR="${LOG_DIR}/grafana"
readonly GRAFANA_PROVISIONING_DIR="${GRAFANA_CONFIG_DIR}/provisioning"
readonly GRAFANA_DASHBOARDS_DIR="${GRAFANA_CONFIG_DIR}/dashboards"

# Grafana repository configuration
readonly GRAFANA_GPG_KEY_URL="https://apt.grafana.com/gpg.key"
readonly GRAFANA_APT_REPO="https://apt.grafana.com"
readonly GRAFANA_YUM_REPO="https://rpm.grafana.com"

# ------------------------------------------------------------------------------
# Repository Setup
# ------------------------------------------------------------------------------

# Add Grafana repository for Debian-based systems
add_grafana_apt_repo() {
    log_substep "Adding Grafana APT repository"

    # Install required packages
    apt-get update -qq
    apt-get install -y -qq apt-transport-https software-properties-common gnupg2 curl

    # Download and add GPG key securely
    local gpg_key_file="/usr/share/keyrings/grafana.gpg"

    # Download key
    curl -fsSL "$GRAFANA_GPG_KEY_URL" | gpg --dearmor -o "$gpg_key_file"
    chmod 0644 "$gpg_key_file"

    # Add repository
    echo "deb [signed-by=${gpg_key_file}] ${GRAFANA_APT_REPO} stable main" > /etc/apt/sources.list.d/grafana.list
    chmod 0644 /etc/apt/sources.list.d/grafana.list

    # Update package list
    apt-get update -qq

    log_debug "Grafana APT repository added"
}

# Add Grafana repository for RHEL-based systems
add_grafana_yum_repo() {
    log_substep "Adding Grafana YUM/DNF repository"

    cat > /etc/yum.repos.d/grafana.repo << EOF
[grafana]
name=Grafana OSS
baseurl=${GRAFANA_YUM_REPO}
repo_gpgcheck=1
enabled=1
gpgcheck=1
gpgkey=https://rpm.grafana.com/gpg.key
sslverify=1
sslcacert=/etc/pki/tls/certs/ca-bundle.crt
EOF

    chmod 0644 /etc/yum.repos.d/grafana.repo

    # Import GPG key
    rpm --import https://rpm.grafana.com/gpg.key 2>/dev/null || true

    log_debug "Grafana YUM repository added"
}

# Add Grafana repository based on OS
add_grafana_repo() {
    case "$OS_FAMILY" in
        debian)
            add_grafana_apt_repo
            ;;
        rhel)
            add_grafana_yum_repo
            ;;
        *)
            die "Unsupported OS family for Grafana installation: $OS_FAMILY"
            ;;
    esac
}

# ------------------------------------------------------------------------------
# Installation Functions
# ------------------------------------------------------------------------------

# Install Grafana package
install_grafana_package() {
    log_step "Installing Grafana"

    # Check if already installed
    if command_exists grafana-server; then
        local installed_version
        installed_version=$(grafana-server --version 2>&1 | grep -oP 'Version \K[0-9.]+' || echo "unknown")
        log_info "Grafana ${installed_version} is already installed"
        return 0
    fi

    # Remove any dangling symlink from previous installation
    # (prevents dpkg post-install script failure)
    if [[ -L /etc/grafana/grafana.ini ]]; then
        rm -f /etc/grafana/grafana.ini
    fi

    # Add repository
    add_grafana_repo

    # Install Grafana
    log_substep "Installing Grafana package"
    case "$OS_FAMILY" in
        debian)
            apt-get install -y -qq grafana
            ;;
        rhel)
            $PACKAGE_MANAGER install -y -q grafana
            ;;
    esac

    # Verify installation
    if ! command_exists grafana-server; then
        die "Grafana installation failed"
    fi

    local version
    version=$(grafana-server --version 2>&1 | grep -oP 'Version \K[0-9.]+' || echo "unknown")
    log_success "Grafana ${version} installed successfully"
    audit_log "INSTALL" "grafana version=${version}"
    save_state "grafana" "$version"
}

# Create Grafana directories
create_grafana_directories() {
    log_substep "Creating Grafana directories"

    # Main directories
    secure_directory "$GRAFANA_CONFIG_DIR" root "$GRAFANA_USER" 0750
    secure_data_directory "$GRAFANA_DATA_DIR" "$GRAFANA_USER" "$GRAFANA_USER"
    secure_directory "$GRAFANA_LOG_DIR" "$GRAFANA_USER" "$GRAFANA_USER" 0750

    # Provisioning directories
    secure_directory "$GRAFANA_PROVISIONING_DIR" root "$GRAFANA_USER" 0750
    secure_directory "${GRAFANA_PROVISIONING_DIR}/dashboards" root "$GRAFANA_USER" 0750
    secure_directory "${GRAFANA_PROVISIONING_DIR}/datasources" root "$GRAFANA_USER" 0750
    secure_directory "${GRAFANA_PROVISIONING_DIR}/notifiers" root "$GRAFANA_USER" 0750
    secure_directory "${GRAFANA_PROVISIONING_DIR}/alerting" root "$GRAFANA_USER" 0750
    secure_directory "${GRAFANA_PROVISIONING_DIR}/plugins" root "$GRAFANA_USER" 0750

    # Dashboards directory
    secure_directory "$GRAFANA_DASHBOARDS_DIR" root "$GRAFANA_USER" 0750
}

# Generate secure Grafana admin password
generate_grafana_admin_password() {
    local password
    password=$(generate_secure_password 24)

    # Store the password securely
    store_secret "grafana_admin_password" "$password"

    echo "$password"
}

# Configure Grafana
configure_grafana() {
    log_substep "Configuring Grafana"

    # Generate admin password
    local admin_password
    admin_password=$(generate_grafana_admin_password)

    # Backup original config
    backup_file "/etc/grafana/grafana.ini"

    # Create custom configuration
    local config_file="${GRAFANA_CONFIG_DIR}/grafana.ini"

    cat > "$config_file" << EOF
# Grafana Configuration for NGINX Monitor Stack
# Generated automatically - security hardened

[paths]
data = ${GRAFANA_DATA_DIR}
logs = ${GRAFANA_LOG_DIR}
plugins = ${GRAFANA_DATA_DIR}/plugins
provisioning = ${GRAFANA_PROVISIONING_DIR}

[server]
# Bind to localhost only - use reverse proxy for external access
http_addr = 127.0.0.1
http_port = ${GRAFANA_PORT}
protocol = http
domain = localhost
root_url = %(protocol)s://%(domain)s:%(http_port)s/
serve_from_sub_path = false
router_logging = false
enable_gzip = true

[database]
type = sqlite3
path = ${GRAFANA_DATA_DIR}/grafana.db
# Enable WAL mode for better performance and reliability
wal = true

[session]
# Session cookie settings
cookie_name = grafana_session
cookie_secure = false
session_life_time = 86400
cookie_samesite = lax

[security]
# Admin credentials
admin_user = admin
admin_password = ${admin_password}
# Force admin to change password on first login
admin_email = admin@localhost
# Secret key for signing
secret_key = $(generate_secure_token 32)
# Disable gravatar
disable_gravatar = true
# Cookie security
cookie_secure = false
cookie_samesite = lax
strict_transport_security = false
x_content_type_options = true
x_xss_protection = true
content_security_policy = true
# Disable embedding
allow_embedding = false

[users]
# Disable self-service registration
allow_sign_up = false
allow_org_create = false
auto_assign_org = true
auto_assign_org_role = Viewer
default_theme = dark

[auth]
# Disable anonymous access
disable_login_form = false
disable_signout_menu = false
# Login settings
login_cookie_name = grafana_session
login_maximum_inactive_lifetime_duration = 7d
login_maximum_lifetime_duration = 30d
oauth_auto_login = false

[auth.anonymous]
# Disable anonymous access
enabled = false

[auth.basic]
enabled = true

[smtp]
enabled = false

[log]
mode = file
level = info
filters =

[log.file]
log_rotate = true
max_lines = 1000000
max_size_shift = 28
daily_rotate = true
max_days = 7

[analytics]
# Disable analytics and reporting
reporting_enabled = false
check_for_updates = false
check_for_plugin_updates = false
feedback_links_enabled = false

[dashboards]
versions_to_keep = 5
min_refresh_interval = 5s

[unified_alerting]
enabled = true

[plugins]
enable_alpha = false
plugin_admin_enabled = false

[feature_toggles]
enable =
EOF

    secure_config_file "$config_file" root "$GRAFANA_USER"

    # Link to Grafana's expected location
    ln -sf "$config_file" /etc/grafana/grafana.ini 2>/dev/null || true

    log_debug "Grafana configuration created"
}

# Create Prometheus datasource provisioning
create_grafana_datasource() {
    log_substep "Configuring Prometheus datasource"

    local datasource_file="${GRAFANA_PROVISIONING_DIR}/datasources/prometheus.yml"

    cat > "$datasource_file" << EOF
# Prometheus Datasource Configuration
# Auto-provisioned by NGINX Monitor Stack

apiVersion: 1

deleteDatasources:
  - name: Prometheus
    orgId: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://127.0.0.1:${PROMETHEUS_PORT}
    isDefault: true
    editable: false
    jsonData:
      httpMethod: POST
      manageAlerts: true
      prometheusType: Prometheus
      prometheusVersion: "2.50.0"
      timeInterval: "15s"
EOF

    secure_config_file "$datasource_file" root "$GRAFANA_USER"
    log_debug "Prometheus datasource provisioned"
}

# Create dashboard provisioning configuration
create_grafana_dashboard_provisioning() {
    log_substep "Configuring dashboard provisioning"

    local provider_file="${GRAFANA_PROVISIONING_DIR}/dashboards/default.yml"

    cat > "$provider_file" << EOF
# Dashboard Provisioning Configuration
# Auto-provisioned by NGINX Monitor Stack

apiVersion: 1

providers:
  - name: 'NGINX Monitor Stack'
    orgId: 1
    folder: 'NGINX Monitor'
    folderUid: 'nginx-monitor'
    type: file
    disableDeletion: false
    updateIntervalSeconds: 60
    allowUiUpdates: true
    options:
      path: ${GRAFANA_DASHBOARDS_DIR}
      foldersFromFilesStructure: false
EOF

    secure_config_file "$provider_file" root "$GRAFANA_USER"
    log_debug "Dashboard provisioning configured"
}

# Copy dashboards to Grafana
install_grafana_dashboards() {
    log_substep "Installing dashboards"

    local source_dir="${SCRIPT_DIR}/dashboards"

    if [[ -d "$source_dir" ]]; then
        find "$source_dir" -name "*.json" -type f | while read -r dashboard; do
            local filename
            filename=$(basename "$dashboard")
            cp "$dashboard" "${GRAFANA_DASHBOARDS_DIR}/${filename}"
            secure_config_file "${GRAFANA_DASHBOARDS_DIR}/${filename}" root "$GRAFANA_USER"
            log_debug "Installed dashboard: $filename"
        done
    else
        log_warn "Dashboard source directory not found: $source_dir"
    fi
}

# Override Grafana systemd service for additional hardening
create_grafana_service_override() {
    log_substep "Hardening Grafana systemd service"

    local override_dir="/etc/systemd/system/grafana-server.service.d"
    mkdir -p "$override_dir"

    cat > "${override_dir}/security.conf" << EOF
[Service]
# Additional security hardening
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

# Override paths to use our custom directories
Environment="GF_PATHS_CONFIG=${GRAFANA_CONFIG_DIR}/grafana.ini"
Environment="GF_PATHS_DATA=${GRAFANA_DATA_DIR}"
Environment="GF_PATHS_LOGS=${GRAFANA_LOG_DIR}"
Environment="GF_PATHS_PROVISIONING=${GRAFANA_PROVISIONING_DIR}"
EOF

    chmod 0644 "${override_dir}/security.conf"
    systemd_reload

    log_debug "Grafana service hardening applied"
}

# Start Grafana service
start_grafana() {
    log_substep "Starting Grafana service"

    enable_and_start_service "grafana-server"

    if wait_for_port "$GRAFANA_PORT" 30; then
        log_success "Grafana is running on 127.0.0.1:${GRAFANA_PORT}"
    else
        log_error "Grafana failed to start within 30 seconds"
        journalctl -u grafana-server --no-pager -n 20 || true
        return 1
    fi

    # Set admin password using grafana-cli (config file only works on first-ever start)
    local admin_password
    admin_password=$(read_secret "grafana_admin_password")
    if [[ -n "$admin_password" ]]; then
        log_substep "Setting Grafana admin password"
        # Need to specify homepath and config for custom installations
        if grafana-cli --homepath /usr/share/grafana --config "${GRAFANA_CONFIG_DIR}/grafana.ini" admin reset-admin-password "$admin_password" &>/dev/null; then
            log_debug "Admin password set successfully"
        else
            log_warn "Could not set admin password via CLI, using config file default"
        fi
    fi
}

# ------------------------------------------------------------------------------
# Main Installation Function
# ------------------------------------------------------------------------------

# Full Grafana installation
install_grafana() {
    install_grafana_package
    create_grafana_directories
    configure_grafana
    create_grafana_datasource
    create_grafana_dashboard_provisioning
    install_grafana_dashboards
    create_grafana_service_override
    start_grafana

    # Print access information
    local admin_password
    admin_password=$(read_secret "grafana_admin_password")

    echo ""
    echo "=============================================="
    echo "  Grafana Access Information"
    echo "=============================================="
    echo ""
    echo "  URL:      http://127.0.0.1:${GRAFANA_PORT}"
    echo "  Username: admin"
    echo "  Password: ${admin_password}"
    echo ""
    echo "  IMPORTANT: Change the admin password after first login!"
    echo "  The password is stored in: ${CONFIG_DIR}/secrets/grafana_admin_password"
    echo ""
    echo "=============================================="
}

# ------------------------------------------------------------------------------
# Uninstallation Functions
# ------------------------------------------------------------------------------

# Uninstall Grafana
uninstall_grafana() {
    log_step "Uninstalling Grafana"

    # Stop service
    stop_and_disable_service "grafana-server" || true

    # Remove service override
    rm -rf /etc/systemd/system/grafana-server.service.d
    systemd_reload

    # Remove package
    log_substep "Removing Grafana package"
    case "$OS_FAMILY" in
        debian)
            apt-get remove -y -qq grafana || true
            apt-get autoremove -y -qq || true
            rm -f /etc/apt/sources.list.d/grafana.list
            rm -f /usr/share/keyrings/grafana.gpg
            ;;
        rhel)
            $PACKAGE_MANAGER remove -y -q grafana || true
            rm -f /etc/yum.repos.d/grafana.repo
            ;;
    esac

    # Remove configuration
    rm -rf "$GRAFANA_CONFIG_DIR"
    rm -rf "$GRAFANA_LOG_DIR"

    # Optionally remove data
    if [[ "${REMOVE_DATA:-false}" == "true" ]]; then
        rm -rf "$GRAFANA_DATA_DIR"
        log_debug "Removed Grafana data directory"
    else
        log_info "Grafana data preserved at: $GRAFANA_DATA_DIR"
    fi

    # Remove stored secrets
    rm -f "${CONFIG_DIR}/secrets/grafana_admin_password"

    log_success "Grafana uninstalled"
    audit_log "UNINSTALL" "grafana"
}

# ------------------------------------------------------------------------------
# Health Check
# ------------------------------------------------------------------------------

# Check Grafana health
check_grafana_health() {
    local url="http://127.0.0.1:${GRAFANA_PORT}/api/health"

    local response
    response=$(curl -sf "$url" 2>/dev/null || echo "{}")

    if echo "$response" | grep -q '"database": "ok"'; then
        echo "healthy"
        return 0
    else
        echo "unhealthy"
        return 1
    fi
}

# Get Grafana status
get_grafana_status() {
    echo "Grafana Status:"
    echo "  Config: ${GRAFANA_CONFIG_DIR}/grafana.ini"
    echo "  Data:   ${GRAFANA_DATA_DIR}"
    echo "  Port:   ${GRAFANA_PORT}"

    if systemctl is-active --quiet grafana-server 2>/dev/null; then
        echo "  Service: running"
        echo "  Health:  $(check_grafana_health)"
    else
        echo "  Service: stopped"
    fi
}

# ------------------------------------------------------------------------------
# Self-check
# ------------------------------------------------------------------------------

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "This script should be sourced, not executed directly."
    echo "Usage: source ${BASH_SOURCE[0]}"
    exit 1
fi
