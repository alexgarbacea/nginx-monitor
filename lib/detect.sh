#!/usr/bin/env bash
# ==============================================================================
# NGINX Monitor Stack - Detection Utilities
# ==============================================================================
# Functions to detect OS, NGINX installation, and system configuration.
# This file should be sourced by other scripts, not executed directly.
# ==============================================================================

# Ensure common.sh is loaded
if ! declare -f log_info &>/dev/null; then
    echo "Error: common.sh must be sourced before detect.sh" >&2
    exit 1
fi

# ------------------------------------------------------------------------------
# OS Detection
# ------------------------------------------------------------------------------

# Detected OS information (populated by detect_os)
declare -g OS_ID=""
declare -g OS_VERSION_ID=""
declare -g OS_PRETTY_NAME=""
declare -g OS_FAMILY=""      # debian, rhel, or unknown
declare -g ARCH=""           # x86_64, aarch64, etc.
declare -g PACKAGE_MANAGER="" # apt, yum, or dnf

# Detect the operating system
detect_os() {
    log_substep "Detecting operating system"

    # Get architecture
    ARCH=$(uname -m)
    log_debug "Architecture: $ARCH"

    # Check for supported architecture
    case "$ARCH" in
        x86_64|amd64)
            ARCH="amd64"
            ;;
        aarch64|arm64)
            ARCH="arm64"
            ;;
        *)
            die "Unsupported architecture: $ARCH. Only x86_64 and arm64 are supported."
            ;;
    esac

    # Try to read /etc/os-release (standard on modern Linux)
    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        source /etc/os-release

        OS_ID="${ID:-unknown}"
        OS_VERSION_ID="${VERSION_ID:-unknown}"
        OS_PRETTY_NAME="${PRETTY_NAME:-$OS_ID $OS_VERSION_ID}"
    else
        die "Cannot detect OS: /etc/os-release not found. This installer requires a modern Linux distribution."
    fi

    # Determine OS family and package manager
    case "$OS_ID" in
        ubuntu|debian|linuxmint|pop)
            OS_FAMILY="debian"
            PACKAGE_MANAGER="apt"
            ;;
        centos|rhel|rocky|almalinux|fedora|ol)
            OS_FAMILY="rhel"
            if command_exists dnf; then
                PACKAGE_MANAGER="dnf"
            else
                PACKAGE_MANAGER="yum"
            fi
            ;;
        amzn)
            OS_FAMILY="rhel"
            if [[ "$OS_VERSION_ID" == "2" ]]; then
                PACKAGE_MANAGER="yum"
            else
                PACKAGE_MANAGER="dnf"
            fi
            ;;
        *)
            die "Unsupported OS: $OS_ID. Supported: Ubuntu, Debian, CentOS, RHEL, Rocky, AlmaLinux, Amazon Linux."
            ;;
    esac

    log_debug "OS: $OS_ID $OS_VERSION_ID ($OS_FAMILY family)"
    log_debug "Package manager: $PACKAGE_MANAGER"

    # Verify minimum version requirements
    verify_os_version
}

# Verify minimum OS version requirements
verify_os_version() {
    local min_version

    case "$OS_ID" in
        ubuntu)
            min_version="20.04"
            ;;
        debian)
            min_version="11"
            ;;
        centos|rhel|rocky|almalinux|ol)
            min_version="8"
            ;;
        fedora)
            min_version="35"
            ;;
        amzn)
            min_version="2"
            ;;
        *)
            # Unknown OS, skip version check
            return 0
            ;;
    esac

    # Compare versions (simple numeric comparison)
    local current_major
    local min_major
    current_major=$(echo "$OS_VERSION_ID" | cut -d. -f1)
    min_major=$(echo "$min_version" | cut -d. -f1)

    if [[ "$current_major" -lt "$min_major" ]]; then
        die "$OS_PRETTY_NAME is not supported. Minimum version: $OS_ID $min_version"
    fi

    log_debug "OS version check passed: $OS_VERSION_ID >= $min_version"
}

# Get the correct systemd directory
get_systemd_dir() {
    if [[ -d /etc/systemd/system ]]; then
        echo "/etc/systemd/system"
    elif [[ -d /lib/systemd/system ]]; then
        echo "/lib/systemd/system"
    else
        die "Cannot find systemd directory"
    fi
}

# ------------------------------------------------------------------------------
# NGINX Detection
# ------------------------------------------------------------------------------

# Detected NGINX information (populated by detect_nginx)
declare -g NGINX_INSTALLED=false
declare -g NGINX_BINARY=""
declare -g NGINX_VERSION=""
declare -g NGINX_CONF_DIR=""
declare -g NGINX_CONF_FILE=""
declare -g NGINX_LOG_DIR=""
declare -g NGINX_PID_FILE=""
declare -g NGINX_STUB_STATUS_URL=""
declare -g NGINX_IS_PLUS=false

# Detect NGINX installation
detect_nginx() {
    log_substep "Detecting NGINX installation"

    # Find NGINX binary
    if command_exists nginx; then
        NGINX_BINARY=$(command -v nginx)
        NGINX_INSTALLED=true
    elif [[ -x /usr/sbin/nginx ]]; then
        NGINX_BINARY="/usr/sbin/nginx"
        NGINX_INSTALLED=true
    elif [[ -x /usr/local/nginx/sbin/nginx ]]; then
        NGINX_BINARY="/usr/local/nginx/sbin/nginx"
        NGINX_INSTALLED=true
    else
        log_warn "NGINX not found. Some features will be unavailable."
        NGINX_INSTALLED=false
        return 0
    fi

    log_debug "NGINX binary: $NGINX_BINARY"

    # Get NGINX version
    NGINX_VERSION=$("$NGINX_BINARY" -v 2>&1 | sed 's/nginx version: nginx\///')
    log_debug "NGINX version: $NGINX_VERSION"

    # Check if NGINX Plus
    if echo "$NGINX_VERSION" | grep -qi "plus"; then
        NGINX_IS_PLUS=true
        log_debug "NGINX Plus detected"
    fi

    # Find configuration directory
    detect_nginx_config

    # Find log directory
    detect_nginx_logs

    # Check for existing stub_status
    detect_nginx_stub_status
}

# Detect NGINX configuration paths
detect_nginx_config() {
    # Try common config locations
    local config_locations=(
        "/etc/nginx"
        "/usr/local/nginx/conf"
        "/usr/local/etc/nginx"
    )

    for conf_dir in "${config_locations[@]}"; do
        if [[ -f "${conf_dir}/nginx.conf" ]]; then
            NGINX_CONF_DIR="$conf_dir"
            NGINX_CONF_FILE="${conf_dir}/nginx.conf"
            log_debug "NGINX config: $NGINX_CONF_FILE"
            break
        fi
    done

    if [[ -z "$NGINX_CONF_FILE" ]]; then
        # Try to get from nginx -t output
        local nginx_test_output
        nginx_test_output=$("$NGINX_BINARY" -t 2>&1 || true)
        local detected_conf
        detected_conf=$(echo "$nginx_test_output" | grep -oP 'configuration file \K[^ ]+' | head -1)

        if [[ -n "$detected_conf" && -f "$detected_conf" ]]; then
            NGINX_CONF_FILE="$detected_conf"
            NGINX_CONF_DIR=$(dirname "$NGINX_CONF_FILE")
            log_debug "NGINX config (from -t): $NGINX_CONF_FILE"
        else
            log_warn "Could not detect NGINX configuration location"
        fi
    fi

    # Get PID file location from config
    if [[ -n "$NGINX_CONF_FILE" ]]; then
        NGINX_PID_FILE=$(grep -oP '^\s*pid\s+\K[^;]+' "$NGINX_CONF_FILE" 2>/dev/null | tr -d ' ' || echo "/run/nginx.pid")
    else
        NGINX_PID_FILE="/run/nginx.pid"
    fi
    log_debug "NGINX PID file: $NGINX_PID_FILE"
}

# Detect NGINX log directory
detect_nginx_logs() {
    local log_locations=(
        "/var/log/nginx"
        "/usr/local/nginx/logs"
        "/var/log"
    )

    for log_dir in "${log_locations[@]}"; do
        if [[ -d "$log_dir" ]] && [[ -f "${log_dir}/access.log" || -f "${log_dir}/nginx/access.log" ]]; then
            NGINX_LOG_DIR="$log_dir"
            log_debug "NGINX log dir: $NGINX_LOG_DIR"
            break
        fi
    done

    if [[ -z "$NGINX_LOG_DIR" ]]; then
        NGINX_LOG_DIR="/var/log/nginx"
        log_debug "Using default log dir: $NGINX_LOG_DIR"
    fi
}

# Detect existing stub_status configuration
detect_nginx_stub_status() {
    if [[ -z "$NGINX_CONF_DIR" ]]; then
        return 0
    fi

    # Search for stub_status in all config files
    local stub_status_found=false
    local stub_location=""

    # Search main config and includes
    while IFS= read -r -d '' config_file; do
        if grep -q "stub_status" "$config_file" 2>/dev/null; then
            stub_status_found=true
            # Try to extract the location
            stub_location=$(grep -B5 "stub_status" "$config_file" | grep -oP 'location\s+\K[^ {]+' | tail -1 || true)
            log_debug "Found stub_status in: $config_file (location: ${stub_location:-unknown})"
            break
        fi
    done < <(find "$NGINX_CONF_DIR" -name "*.conf" -type f -print0 2>/dev/null)

    if $stub_status_found; then
        # Try to determine the URL
        # This is a best-effort detection; might not be accurate for complex configs
        if [[ -n "$stub_location" ]]; then
            NGINX_STUB_STATUS_URL="http://127.0.0.1${stub_location}"
            log_debug "Detected stub_status URL: $NGINX_STUB_STATUS_URL"
        fi
    else
        log_debug "No existing stub_status configuration found"
    fi
}

# Test if stub_status endpoint is accessible
test_stub_status() {
    local url="${1:-$NGINX_STUB_STATUS_URL}"

    if [[ -z "$url" ]]; then
        return 1
    fi

    local response
    response=$(curl -s --connect-timeout 5 "$url" 2>/dev/null || true)

    if echo "$response" | grep -q "Active connections:"; then
        log_debug "stub_status endpoint is accessible: $url"
        return 0
    else
        log_debug "stub_status endpoint not accessible: $url"
        return 1
    fi
}

# ------------------------------------------------------------------------------
# Existing Installation Detection
# ------------------------------------------------------------------------------

# Check for existing monitoring installations
detect_existing_installations() {
    log_substep "Checking for existing installations"

    local found_existing=false

    # Check for Prometheus
    if command_exists prometheus || systemctl is-active --quiet prometheus 2>/dev/null; then
        log_warn "Existing Prometheus installation detected"
        found_existing=true
    fi

    # Check for Grafana
    if command_exists grafana-server || systemctl is-active --quiet grafana-server 2>/dev/null; then
        log_warn "Existing Grafana installation detected"
        found_existing=true
    fi

    # Check for node_exporter
    if command_exists node_exporter || systemctl is-active --quiet node_exporter 2>/dev/null; then
        log_warn "Existing node_exporter installation detected"
        found_existing=true
    fi

    # Check for nginx-prometheus-exporter
    if command_exists nginx-prometheus-exporter || systemctl is-active --quiet nginx-prometheus-exporter 2>/dev/null; then
        log_warn "Existing nginx-prometheus-exporter installation detected"
        found_existing=true
    fi

    # Check our own state file
    if [[ -f "$STATE_FILE" ]]; then
        log_warn "Previous nginx-monitor installation detected"
        found_existing=true
    fi

    if $found_existing; then
        return 0
    else
        log_debug "No existing installations detected"
        return 1
    fi
}

# ------------------------------------------------------------------------------
# System Resource Detection
# ------------------------------------------------------------------------------

# Get system memory in MB
get_system_memory_mb() {
    local mem_kb
    mem_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    echo $((mem_kb / 1024))
}

# Get number of CPU cores
get_cpu_cores() {
    nproc
}

# Get available disk space in GB for a path
get_disk_space_gb() {
    local path="${1:-/}"
    df -BG "$path" | tail -1 | awk '{print $4}' | tr -d 'G'
}

# Check minimum system requirements
check_system_requirements() {
    log_substep "Checking system requirements"

    local mem_mb
    mem_mb=$(get_system_memory_mb)
    local min_mem_mb=512

    if [[ $mem_mb -lt $min_mem_mb ]]; then
        die "Insufficient memory: ${mem_mb}MB available, ${min_mem_mb}MB required"
    fi
    log_debug "Memory check passed: ${mem_mb}MB"

    local disk_gb
    disk_gb=$(get_disk_space_gb "/")
    local min_disk_gb=2

    if [[ $disk_gb -lt $min_disk_gb ]]; then
        die "Insufficient disk space: ${disk_gb}GB available, ${min_disk_gb}GB required"
    fi
    log_debug "Disk check passed: ${disk_gb}GB"

    # Check if systemd is available
    if ! command_exists systemctl; then
        die "systemd is required but not found"
    fi
    log_debug "systemd check passed"
}

# ------------------------------------------------------------------------------
# Network Detection
# ------------------------------------------------------------------------------

# Get the primary network interface
get_primary_interface() {
    ip route | grep default | awk '{print $5}' | head -1
}

# Get the primary IP address
get_primary_ip() {
    local interface
    interface=$(get_primary_interface)

    if [[ -n "$interface" ]]; then
        ip addr show "$interface" | grep -oP 'inet \K[\d.]+' | head -1
    else
        hostname -I | awk '{print $1}'
    fi
}

# Check if a firewall is active
detect_firewall() {
    if command_exists ufw && ufw status 2>/dev/null | grep -q "Status: active"; then
        echo "ufw"
    elif command_exists firewall-cmd && firewall-cmd --state 2>/dev/null | grep -q "running"; then
        echo "firewalld"
    elif command_exists iptables && iptables -L -n 2>/dev/null | grep -qv "^Chain .* (policy ACCEPT)"; then
        echo "iptables"
    else
        echo "none"
    fi
}

# ------------------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------------------

# Print detection summary
print_detection_summary() {
    echo ""
    echo "=========================================="
    echo "  System Detection Summary"
    echo "=========================================="
    echo ""
    echo "Operating System:"
    echo "  Name:     $OS_PRETTY_NAME"
    echo "  Family:   $OS_FAMILY"
    echo "  Arch:     $ARCH"
    echo "  Package:  $PACKAGE_MANAGER"
    echo ""
    echo "NGINX:"
    if $NGINX_INSTALLED; then
        echo "  Status:   Installed"
        echo "  Version:  $NGINX_VERSION"
        echo "  Config:   ${NGINX_CONF_FILE:-not detected}"
        echo "  Logs:     ${NGINX_LOG_DIR:-not detected}"
        if [[ -n "$NGINX_STUB_STATUS_URL" ]]; then
            echo "  Stub URL: $NGINX_STUB_STATUS_URL"
        fi
    else
        echo "  Status:   Not installed"
    fi
    echo ""
    echo "System Resources:"
    echo "  Memory:   $(get_system_memory_mb) MB"
    echo "  CPU:      $(get_cpu_cores) cores"
    echo "  Disk:     $(get_disk_space_gb /) GB free"
    echo ""
    echo "Network:"
    echo "  IP:       $(get_primary_ip)"
    echo "  Firewall: $(detect_firewall)"
    echo ""
    echo "=========================================="
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
