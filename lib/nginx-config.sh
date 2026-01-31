#!/usr/bin/env bash
# ==============================================================================
# NGINX Monitor Stack - NGINX Configuration
# ==============================================================================
# Functions to configure NGINX stub_status for metrics collection.
# This file should be sourced by other scripts, not executed directly.
# ==============================================================================

# Ensure required libraries are loaded
if ! declare -f log_info &>/dev/null; then
    echo "Error: common.sh must be sourced before nginx-config.sh" >&2
    exit 1
fi

# ------------------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------------------

readonly NGINX_MONITOR_CONFIG_NAME="nginx-monitor-status.conf"
readonly STUB_STATUS_LOCATION="/nginx_status"

# ------------------------------------------------------------------------------
# NGINX Configuration Functions
# ------------------------------------------------------------------------------

# Get the NGINX configuration include directory
get_nginx_include_dir() {
    local include_dirs=(
        "${NGINX_CONF_DIR}/conf.d"
        "${NGINX_CONF_DIR}/sites-enabled"
        "/etc/nginx/conf.d"
        "/etc/nginx/sites-enabled"
    )

    for dir in "${include_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            echo "$dir"
            return 0
        fi
    done

    # Create conf.d if it doesn't exist
    if [[ -n "$NGINX_CONF_DIR" ]]; then
        mkdir -p "${NGINX_CONF_DIR}/conf.d"
        echo "${NGINX_CONF_DIR}/conf.d"
        return 0
    fi

    die "Could not find or create NGINX include directory"
}

# Check if stub_status is already configured
is_stub_status_configured() {
    if [[ -z "$NGINX_CONF_DIR" ]]; then
        return 1
    fi

    # Search for stub_status in all config files
    if grep -r "stub_status" "$NGINX_CONF_DIR" --include="*.conf" &>/dev/null; then
        return 0
    fi

    return 1
}

# Validate NGINX configuration
validate_nginx_config() {
    log_debug "Validating NGINX configuration"

    if "$NGINX_BINARY" -t &>/dev/null; then
        return 0
    else
        log_error "NGINX configuration validation failed:"
        "$NGINX_BINARY" -t 2>&1 || true
        return 1
    fi
}

# Create stub_status configuration
create_stub_status_config() {
    log_step "Configuring NGINX stub_status"

    if ! $NGINX_INSTALLED; then
        log_warn "NGINX is not installed - skipping stub_status configuration"
        return 0
    fi

    # Check if already configured
    if is_stub_status_configured; then
        log_info "NGINX stub_status is already configured"

        # Check if our config file exists
        local include_dir
        include_dir=$(get_nginx_include_dir)
        if [[ -f "${include_dir}/${NGINX_MONITOR_CONFIG_NAME}" ]]; then
            log_debug "Using existing nginx-monitor configuration"
        else
            log_warn "stub_status configured elsewhere - not modifying"
        fi

        # Test if it's accessible
        local test_url="http://127.0.0.1:${NGINX_STUB_STATUS_PORT}${STUB_STATUS_LOCATION}"
        if test_stub_status "$test_url"; then
            NGINX_STUB_STATUS_URL="$test_url"
            log_success "stub_status is accessible at: $NGINX_STUB_STATUS_URL"
        else
            log_warn "stub_status may not be accessible - verify configuration"
        fi

        return 0
    fi

    log_substep "Creating stub_status server block"

    local include_dir
    include_dir=$(get_nginx_include_dir)
    local config_file="${include_dir}/${NGINX_MONITOR_CONFIG_NAME}"

    # Create the configuration
    cat > "$config_file" << EOF
# NGINX Monitor Stack - Status Configuration
# This file is managed by nginx-monitor - modifications may be overwritten
#
# SECURITY: This server block is bound to localhost only.
# Metrics are NOT accessible from external networks.

server {
    # Listen on localhost only - not accessible externally
    listen 127.0.0.1:${NGINX_STUB_STATUS_PORT};

    # Explicitly disable IPv6 for this block (localhost only)
    # listen [::1]:${NGINX_STUB_STATUS_PORT};

    server_name localhost 127.0.0.1;

    # Disable access logging for status endpoint to reduce noise
    access_log off;

    # NGINX stub_status endpoint
    location ${STUB_STATUS_LOCATION} {
        stub_status on;

        # Only allow localhost access
        allow 127.0.0.1;
        deny all;
    }

    # Health check endpoint
    location /health {
        return 200 'OK';
        add_header Content-Type text/plain;

        allow 127.0.0.1;
        deny all;
    }

    # Deny all other locations
    location / {
        deny all;
        return 403;
    }
}
EOF

    secure_config_file "$config_file" root root

    log_debug "stub_status configuration created: $config_file"

    # Validate the configuration
    if ! validate_nginx_config; then
        log_error "NGINX configuration validation failed after adding stub_status"
        log_substep "Removing invalid configuration"
        rm -f "$config_file"
        die "Failed to configure NGINX stub_status"
    fi

    # Check if NGINX include is present in main config
    ensure_nginx_includes

    # Reload NGINX to apply changes
    reload_nginx

    # Update the stub status URL
    NGINX_STUB_STATUS_URL="http://127.0.0.1:${NGINX_STUB_STATUS_PORT}${STUB_STATUS_LOCATION}"

    # Verify it's working
    sleep 1
    if test_stub_status "$NGINX_STUB_STATUS_URL"; then
        log_success "stub_status configured successfully: $NGINX_STUB_STATUS_URL"
    else
        log_warn "stub_status configured but not yet accessible"
        log_warn "You may need to reload NGINX manually: nginx -s reload"
    fi

    audit_log "CONFIGURE" "nginx stub_status port=${NGINX_STUB_STATUS_PORT}"
    save_state "nginx_stub_status" "${NGINX_STUB_STATUS_PORT}"
}

# Ensure NGINX main config includes conf.d
ensure_nginx_includes() {
    if [[ -z "$NGINX_CONF_FILE" ]]; then
        return 0
    fi

    local include_dir
    include_dir=$(get_nginx_include_dir)
    local include_pattern="${include_dir}/*.conf"

    # Check if include already exists
    if grep -q "include.*${include_dir}" "$NGINX_CONF_FILE" 2>/dev/null; then
        log_debug "NGINX include directive already present"
        return 0
    fi

    # Check if generic conf.d include exists
    if grep -q "include.*/conf\.d/\*\.conf" "$NGINX_CONF_FILE" 2>/dev/null; then
        log_debug "NGINX conf.d include already present"
        return 0
    fi

    log_warn "NGINX configuration may not include ${include_dir}"
    log_warn "You may need to add: include ${include_pattern}; to your nginx.conf"
}

# Reload NGINX
reload_nginx() {
    log_substep "Reloading NGINX"

    if systemctl is-active --quiet nginx 2>/dev/null; then
        systemctl reload nginx
    elif [[ -f "$NGINX_PID_FILE" ]]; then
        "$NGINX_BINARY" -s reload
    else
        log_warn "Could not reload NGINX - service may not be running"
        return 1
    fi

    log_debug "NGINX reloaded"
}

# Test NGINX configuration and restart if needed
test_and_restart_nginx() {
    if ! validate_nginx_config; then
        return 1
    fi

    if systemctl is-active --quiet nginx 2>/dev/null; then
        systemctl restart nginx
    else
        "$NGINX_BINARY" -s stop 2>/dev/null || true
        "$NGINX_BINARY"
    fi
}

# ------------------------------------------------------------------------------
# NGINX Metrics Collection Helper
# ------------------------------------------------------------------------------

# Parse stub_status output
parse_stub_status() {
    local url="${1:-$NGINX_STUB_STATUS_URL}"

    if [[ -z "$url" ]]; then
        die "stub_status URL not configured"
    fi

    local response
    response=$(curl -sf "$url" 2>/dev/null)

    if [[ -z "$response" ]]; then
        return 1
    fi

    # Parse the response
    # Format:
    # Active connections: 1
    # server accepts handled requests
    #  16 16 16
    # Reading: 0 Writing: 1 Waiting: 0

    local active accepts handled requests reading writing waiting

    active=$(echo "$response" | grep "Active connections:" | awk '{print $3}')
    reading=$(echo "$response" | grep "Reading:" | awk '{print $2}')
    writing=$(echo "$response" | grep "Writing:" | awk '{print $4}')
    waiting=$(echo "$response" | grep "Waiting:" | awk '{print $6}')

    local accepts_line
    accepts_line=$(echo "$response" | grep -A1 "server accepts" | tail -1)
    accepts=$(echo "$accepts_line" | awk '{print $1}')
    handled=$(echo "$accepts_line" | awk '{print $2}')
    requests=$(echo "$accepts_line" | awk '{print $3}')

    cat << EOF
{
  "active_connections": ${active:-0},
  "accepts": ${accepts:-0},
  "handled": ${handled:-0},
  "requests": ${requests:-0},
  "reading": ${reading:-0},
  "writing": ${writing:-0},
  "waiting": ${waiting:-0}
}
EOF
}

# Get NGINX status summary
get_nginx_status() {
    echo "NGINX Status:"
    echo "  Binary:    ${NGINX_BINARY:-not found}"
    echo "  Version:   ${NGINX_VERSION:-unknown}"
    echo "  Config:    ${NGINX_CONF_FILE:-not found}"
    echo "  Logs:      ${NGINX_LOG_DIR:-not found}"

    if systemctl is-active --quiet nginx 2>/dev/null; then
        echo "  Service:   running"
    else
        echo "  Service:   stopped"
    fi

    if [[ -n "$NGINX_STUB_STATUS_URL" ]]; then
        echo "  Stub URL:  ${NGINX_STUB_STATUS_URL}"
        if test_stub_status "$NGINX_STUB_STATUS_URL"; then
            echo "  Stub Status: accessible"
            echo ""
            echo "Current Metrics:"
            parse_stub_status "$NGINX_STUB_STATUS_URL" 2>/dev/null || echo "  (unable to parse)"
        else
            echo "  Stub Status: not accessible"
        fi
    else
        echo "  Stub URL:  not configured"
    fi
}

# ------------------------------------------------------------------------------
# Removal Functions
# ------------------------------------------------------------------------------

# Remove stub_status configuration
remove_stub_status_config() {
    log_step "Removing NGINX stub_status configuration"

    if ! $NGINX_INSTALLED; then
        return 0
    fi

    local include_dir
    include_dir=$(get_nginx_include_dir)
    local config_file="${include_dir}/${NGINX_MONITOR_CONFIG_NAME}"

    if [[ -f "$config_file" ]]; then
        # Backup before removing
        backup_file "$config_file"
        rm -f "$config_file"
        log_debug "Removed: $config_file"

        # Validate and reload
        if validate_nginx_config; then
            reload_nginx
            log_success "NGINX stub_status configuration removed"
        else
            log_error "NGINX configuration invalid after removal"
            log_warn "Manual intervention may be required"
        fi
    else
        log_debug "No stub_status configuration to remove"
    fi

    audit_log "REMOVE" "nginx stub_status"
}

# ------------------------------------------------------------------------------
# Configuration Installation (for templates)
# ------------------------------------------------------------------------------

# Install NGINX configuration snippet
install_nginx_config_snippet() {
    local source_file="$1"
    local dest_name="${2:-$(basename "$source_file")}"

    if ! $NGINX_INSTALLED; then
        log_warn "NGINX not installed - skipping config snippet installation"
        return 0
    fi

    local include_dir
    include_dir=$(get_nginx_include_dir)
    local dest_file="${include_dir}/${dest_name}"

    # Backup if exists
    backup_file "$dest_file"

    # Copy and secure
    cp "$source_file" "$dest_file"
    secure_config_file "$dest_file" root root

    # Validate
    if ! validate_nginx_config; then
        log_error "NGINX configuration invalid after installing: $dest_name"
        rm -f "$dest_file"
        return 1
    fi

    log_debug "Installed NGINX config snippet: $dest_name"
}

# ------------------------------------------------------------------------------
# Self-check
# ------------------------------------------------------------------------------

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "This script should be sourced, not executed directly."
    echo "Usage: source ${BASH_SOURCE[0]}"
    exit 1
fi
