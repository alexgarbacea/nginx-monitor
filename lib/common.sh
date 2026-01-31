#!/usr/bin/env bash
# ==============================================================================
# NGINX Monitor Stack - Common Utilities
# ==============================================================================
# Shared functions for logging, error handling, and privilege management.
# This file should be sourced by other scripts, not executed directly.
# ==============================================================================

set -euo pipefail

# ------------------------------------------------------------------------------
# Constants
# ------------------------------------------------------------------------------

readonly NGINX_MONITOR_VERSION="1.0.0"
readonly NGINX_MONITOR_NAME="nginx-monitor-stack"
readonly INSTALL_DIR="/opt/nginx-monitor"
readonly CONFIG_DIR="/etc/nginx-monitor"
readonly LOG_DIR="/var/log/nginx-monitor"
readonly DATA_DIR="/var/lib/nginx-monitor"
readonly STATE_FILE="${CONFIG_DIR}/.install-state"

# Service users (non-root)
readonly PROMETHEUS_USER="prometheus"
readonly GRAFANA_USER="grafana"
readonly EXPORTER_USER="nginx-exporter"

# Default ports (all bind to localhost)
readonly PROMETHEUS_PORT=9090
readonly GRAFANA_PORT=3000
readonly NODE_EXPORTER_PORT=9100
readonly NGINX_EXPORTER_PORT=9113
readonly NGINX_STUB_STATUS_PORT=8080

# ------------------------------------------------------------------------------
# Color Output (disabled if not a terminal)
# ------------------------------------------------------------------------------

if [[ -t 1 ]]; then
    readonly RED='\033[0;31m'
    readonly GREEN='\033[0;32m'
    readonly YELLOW='\033[0;33m'
    readonly BLUE='\033[0;34m'
    readonly MAGENTA='\033[0;35m'
    readonly CYAN='\033[0;36m'
    readonly WHITE='\033[0;37m'
    readonly BOLD='\033[1m'
    readonly RESET='\033[0m'
else
    readonly RED=''
    readonly GREEN=''
    readonly YELLOW=''
    readonly BLUE=''
    readonly MAGENTA=''
    readonly CYAN=''
    readonly WHITE=''
    readonly BOLD=''
    readonly RESET=''
fi

# ------------------------------------------------------------------------------
# Logging Functions
# ------------------------------------------------------------------------------

# Get timestamp for logs
_timestamp() {
    date '+%Y-%m-%d %H:%M:%S'
}

# Log info message
log_info() {
    echo -e "${BLUE}[INFO]${RESET} $(_timestamp) $*"
}

# Log success message
log_success() {
    echo -e "${GREEN}[OK]${RESET}   $(_timestamp) $*"
}

# Log warning message
log_warn() {
    echo -e "${YELLOW}[WARN]${RESET} $(_timestamp) $*" >&2
}

# Log error message
log_error() {
    echo -e "${RED}[ERROR]${RESET} $(_timestamp) $*" >&2
}

# Log debug message (only if DEBUG is set)
log_debug() {
    if [[ "${DEBUG:-0}" == "1" ]]; then
        echo -e "${MAGENTA}[DEBUG]${RESET} $(_timestamp) $*"
    fi
}

# Log step in installation process
log_step() {
    echo -e "\n${BOLD}${CYAN}==>${RESET} ${BOLD}$*${RESET}"
}

# Log sub-step
log_substep() {
    echo -e "  ${CYAN}->${RESET} $*"
}

# ------------------------------------------------------------------------------
# Error Handling
# ------------------------------------------------------------------------------

# Exit with error message
die() {
    log_error "$*"
    exit 1
}

# Exit with error if previous command failed
die_on_error() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        die "$* (exit code: $exit_code)"
    fi
}

# Trap handler for unexpected errors
trap_error() {
    local line_no=$1
    local error_code=$2
    log_error "Script failed at line ${line_no} with exit code ${error_code}"
    log_error "Run with DEBUG=1 for more information"
    exit "$error_code"
}

# Set up error trap
setup_error_trap() {
    trap 'trap_error ${LINENO} $?' ERR
}

# ------------------------------------------------------------------------------
# Privilege Management
# ------------------------------------------------------------------------------

# Check if running as root
is_root() {
    [[ "$(id -u)" -eq 0 ]]
}

# Require root privileges
require_root() {
    if ! is_root; then
        die "This script must be run as root. Use: sudo $0"
    fi
}

# Check if a user exists
user_exists() {
    local username="$1"
    id "$username" &>/dev/null
}

# Create a system user for a service
create_service_user() {
    local username="$1"
    local description="${2:-Service user}"
    local home_dir="${3:-/nonexistent}"

    if user_exists "$username"; then
        log_debug "User '$username' already exists"
        return 0
    fi

    log_substep "Creating service user: $username"

    # Create system user with no login shell and no home directory
    useradd \
        --system \
        --no-create-home \
        --home-dir "$home_dir" \
        --shell /usr/sbin/nologin \
        --comment "$description" \
        "$username"

    log_debug "Created user '$username'"
}

# ------------------------------------------------------------------------------
# Directory Management
# ------------------------------------------------------------------------------

# Create directory with proper ownership and permissions
create_secure_dir() {
    local dir="$1"
    local owner="${2:-root}"
    local group="${3:-root}"
    local mode="${4:-0755}"

    if [[ ! -d "$dir" ]]; then
        mkdir -p "$dir"
        log_debug "Created directory: $dir"
    fi

    chown "$owner:$group" "$dir"
    chmod "$mode" "$dir"
}

# Create required directories for installation
create_install_dirs() {
    log_substep "Creating installation directories"

    create_secure_dir "$INSTALL_DIR" root root 0755
    create_secure_dir "$CONFIG_DIR" root root 0755
    create_secure_dir "$LOG_DIR" root root 0755
    create_secure_dir "$DATA_DIR" root root 0755
}

# ------------------------------------------------------------------------------
# File Operations
# ------------------------------------------------------------------------------

# Backup a file before modifying
backup_file() {
    local file="$1"
    local backup_dir="${CONFIG_DIR}/backups"

    if [[ -f "$file" ]]; then
        create_secure_dir "$backup_dir" root root 0700
        local timestamp
        timestamp=$(date '+%Y%m%d_%H%M%S')
        local backup_name
        backup_name=$(basename "$file")
        cp -p "$file" "${backup_dir}/${backup_name}.${timestamp}.bak"
        log_debug "Backed up $file to ${backup_dir}/${backup_name}.${timestamp}.bak"
    fi
}

# Write content to file with secure permissions
write_secure_file() {
    local file="$1"
    local content="$2"
    local owner="${3:-root}"
    local group="${4:-root}"
    local mode="${5:-0644}"

    # Create parent directory if needed
    local parent_dir
    parent_dir=$(dirname "$file")
    [[ -d "$parent_dir" ]] || mkdir -p "$parent_dir"

    # Write content
    echo "$content" > "$file"

    # Set ownership and permissions
    chown "$owner:$group" "$file"
    chmod "$mode" "$file"

    log_debug "Wrote secure file: $file (owner=$owner, mode=$mode)"
}

# ------------------------------------------------------------------------------
# State Management
# ------------------------------------------------------------------------------

# Save installation state
save_state() {
    local component="$1"
    local version="${2:-unknown}"

    create_secure_dir "$(dirname "$STATE_FILE")" root root 0755

    # Append to state file
    echo "${component}=${version}:$(date -Iseconds)" >> "$STATE_FILE"
    chmod 0600 "$STATE_FILE"
}

# Check if component is installed
is_component_installed() {
    local component="$1"

    [[ -f "$STATE_FILE" ]] && grep -q "^${component}=" "$STATE_FILE"
}

# Get installed version of component
get_component_version() {
    local component="$1"

    if [[ -f "$STATE_FILE" ]]; then
        grep "^${component}=" "$STATE_FILE" | tail -1 | cut -d'=' -f2 | cut -d':' -f1
    fi
}

# ------------------------------------------------------------------------------
# Dependency Checks
# ------------------------------------------------------------------------------

# Check if a command exists
command_exists() {
    command -v "$1" &>/dev/null
}

# Require a command to be available
require_command() {
    local cmd="$1"
    local package="${2:-$1}"

    if ! command_exists "$cmd"; then
        die "Required command '$cmd' not found. Please install '$package' first."
    fi
}

# Check required dependencies
check_dependencies() {
    log_substep "Checking dependencies"

    local missing=()

    # Required commands
    local required_cmds=(curl wget tar gzip systemctl)

    for cmd in "${required_cmds[@]}"; do
        if ! command_exists "$cmd"; then
            missing+=("$cmd")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        die "Missing required commands: ${missing[*]}"
    fi

    log_debug "All dependencies satisfied"
}

# ------------------------------------------------------------------------------
# Network Utilities
# ------------------------------------------------------------------------------

# Check if a port is in use
is_port_in_use() {
    local port="$1"

    if command_exists ss; then
        ss -tuln | grep -q ":${port} "
    elif command_exists netstat; then
        netstat -tuln | grep -q ":${port} "
    else
        # Fallback: try to connect
        (echo >/dev/tcp/127.0.0.1/"$port") &>/dev/null
    fi
}

# Wait for a service to be available on a port
wait_for_port() {
    local port="$1"
    local timeout="${2:-30}"
    local elapsed=0

    while ! is_port_in_use "$port"; do
        if [[ $elapsed -ge $timeout ]]; then
            return 1
        fi
        sleep 1
        ((elapsed++))
    done

    return 0
}

# ------------------------------------------------------------------------------
# Service Management
# ------------------------------------------------------------------------------

# Reload systemd daemon
systemd_reload() {
    systemctl daemon-reload
}

# Enable and start a service
enable_and_start_service() {
    local service="$1"

    systemd_reload
    systemctl enable "$service"
    systemctl start "$service"

    # Verify it started
    if ! systemctl is-active --quiet "$service"; then
        log_error "Failed to start $service"
        systemctl status "$service" --no-pager || true
        return 1
    fi

    log_success "Service $service is running"
}

# Stop and disable a service
stop_and_disable_service() {
    local service="$1"

    if systemctl is-active --quiet "$service" 2>/dev/null; then
        systemctl stop "$service"
    fi

    if systemctl is-enabled --quiet "$service" 2>/dev/null; then
        systemctl disable "$service"
    fi
}

# ------------------------------------------------------------------------------
# User Interaction
# ------------------------------------------------------------------------------

# Ask for confirmation
confirm() {
    local prompt="${1:-Continue?}"
    local default="${2:-n}"

    local yn_prompt
    if [[ "$default" == "y" ]]; then
        yn_prompt="[Y/n]"
    else
        yn_prompt="[y/N]"
    fi

    while true; do
        read -rp "${prompt} ${yn_prompt} " response
        response="${response:-$default}"

        case "${response,,}" in
            y|yes) return 0 ;;
            n|no) return 1 ;;
            *) echo "Please answer yes or no." ;;
        esac
    done
}

# Generate a random password
generate_password() {
    local length="${1:-32}"

    # Use /dev/urandom for cryptographically secure random data
    # Filter to alphanumeric characters for compatibility
    tr -dc 'A-Za-z0-9' < /dev/urandom | head -c "$length"
}

# ------------------------------------------------------------------------------
# Cleanup Handler
# ------------------------------------------------------------------------------

# List of cleanup functions to run on exit
declare -a CLEANUP_FUNCTIONS=()

# Register a cleanup function
register_cleanup() {
    CLEANUP_FUNCTIONS+=("$1")
}

# Run all cleanup functions
run_cleanup() {
    local exit_code=$?

    for func in "${CLEANUP_FUNCTIONS[@]}"; do
        if declare -f "$func" &>/dev/null; then
            "$func" || true
        fi
    done

    exit $exit_code
}

# Set up cleanup trap
setup_cleanup_trap() {
    trap run_cleanup EXIT
}

# ------------------------------------------------------------------------------
# Validation
# ------------------------------------------------------------------------------

# Validate that variable is set and not empty
require_var() {
    local var_name="$1"
    local var_value="${!var_name:-}"

    if [[ -z "$var_value" ]]; then
        die "Required variable '$var_name' is not set"
    fi
}

# Validate that a file exists
require_file() {
    local file="$1"

    if [[ ! -f "$file" ]]; then
        die "Required file not found: $file"
    fi
}

# Validate that a directory exists
require_dir() {
    local dir="$1"

    if [[ ! -d "$dir" ]]; then
        die "Required directory not found: $dir"
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
