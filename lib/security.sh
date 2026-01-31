#!/usr/bin/env bash
# ==============================================================================
# NGINX Monitor Stack - Security Utilities
# ==============================================================================
# Functions for secure downloads, checksum verification, and hardening.
# This file should be sourced by other scripts, not executed directly.
# ==============================================================================

# Ensure common.sh is loaded
if ! declare -f log_info &>/dev/null; then
    echo "Error: common.sh must be sourced before security.sh" >&2
    exit 1
fi

# ------------------------------------------------------------------------------
# Download Security
# ------------------------------------------------------------------------------

# Secure download with retry and timeout
# Usage: secure_download <url> <output_file> [expected_sha256]
secure_download() {
    local url="$1"
    local output="$2"
    local expected_sha256="${3:-}"
    local max_retries=3
    local retry_delay=5
    local timeout=300

    log_debug "Downloading: $url"

    # Validate URL format (basic check)
    if [[ ! "$url" =~ ^https:// ]]; then
        die "Security error: Only HTTPS URLs are allowed. Got: $url"
    fi

    # Create temp file for download
    local temp_file
    temp_file=$(mktemp)

    # Ensure temp file is cleaned up
    trap "rm -f '$temp_file'" RETURN

    local attempt=1
    local success=false

    while [[ $attempt -le $max_retries ]]; do
        log_debug "Download attempt $attempt of $max_retries"

        if curl \
            --silent \
            --show-error \
            --location \
            --fail \
            --max-time "$timeout" \
            --retry 0 \
            --proto '=https' \
            --tlsv1.2 \
            --output "$temp_file" \
            "$url"; then
            success=true
            break
        fi

        log_warn "Download attempt $attempt failed, retrying in ${retry_delay}s..."
        sleep "$retry_delay"
        ((attempt++))
    done

    if ! $success; then
        die "Failed to download $url after $max_retries attempts"
    fi

    # Verify checksum if provided
    if [[ -n "$expected_sha256" ]]; then
        verify_sha256 "$temp_file" "$expected_sha256"
    fi

    # Move to final location
    mv "$temp_file" "$output"
    trap - RETURN  # Clear the trap since we moved the file

    log_debug "Download complete: $output"
}

# Verify SHA256 checksum of a file
verify_sha256() {
    local file="$1"
    local expected="$2"

    log_debug "Verifying SHA256 checksum..."

    local actual
    if command_exists sha256sum; then
        actual=$(sha256sum "$file" | awk '{print $1}')
    elif command_exists shasum; then
        actual=$(shasum -a 256 "$file" | awk '{print $1}')
    else
        die "No SHA256 utility found (sha256sum or shasum required)"
    fi

    # Case-insensitive comparison
    if [[ "${actual,,}" != "${expected,,}" ]]; then
        die "Checksum verification failed!
  Expected: $expected
  Actual:   $actual
  File:     $file

This could indicate a corrupted download or a security issue.
Please verify the download source and try again."
    fi

    log_debug "Checksum verified: $actual"
}

# Verify GPG signature of a file
verify_gpg_signature() {
    local file="$1"
    local sig_file="$2"
    local key_url="${3:-}"
    local key_id="${4:-}"

    if ! command_exists gpg; then
        log_warn "GPG not installed, skipping signature verification"
        return 0
    fi

    # Import key if URL provided
    if [[ -n "$key_url" ]]; then
        log_debug "Importing GPG key from: $key_url"
        local key_file
        key_file=$(mktemp)
        secure_download "$key_url" "$key_file"
        gpg --import "$key_file" 2>/dev/null || true
        rm -f "$key_file"
    fi

    # Verify signature
    log_debug "Verifying GPG signature..."
    if gpg --verify "$sig_file" "$file" 2>/dev/null; then
        log_debug "GPG signature verified"
    else
        die "GPG signature verification failed for: $file"
    fi
}

# ------------------------------------------------------------------------------
# Checksum Fetching and Verification
# ------------------------------------------------------------------------------

# Cache directory for downloaded checksums
CHECKSUM_CACHE_DIR="/tmp/nginx-monitor-checksums"

# Fetch checksum from official GitHub release
# Downloads the sha256sums.txt file and extracts the relevant checksum
fetch_checksum_from_release() {
    local component="$1"
    local version="$2"
    local filename="$3"

    local checksums_url=""
    local cache_file="${CHECKSUM_CACHE_DIR}/${component}-${version}-checksums.txt"

    # Determine the checksums URL based on component
    case "$component" in
        prometheus)
            checksums_url="https://github.com/prometheus/prometheus/releases/download/v${version}/sha256sums.txt"
            ;;
        node_exporter)
            checksums_url="https://github.com/prometheus/node_exporter/releases/download/v${version}/sha256sums.txt"
            ;;
        nginx_exporter)
            checksums_url="https://github.com/nginxinc/nginx-prometheus-exporter/releases/download/v${version}/sha256sums.txt"
            ;;
        *)
            log_debug "Unknown component for checksum fetch: $component"
            echo ""
            return 0
            ;;
    esac

    # Create cache directory
    mkdir -p "$CHECKSUM_CACHE_DIR" 2>/dev/null || true

    # Check if we have a cached version
    if [[ -f "$cache_file" ]]; then
        log_debug "Using cached checksums for ${component} ${version}"
    else
        # Download checksums file
        log_debug "Fetching checksums from: $checksums_url"

        if ! curl \
            --silent \
            --show-error \
            --location \
            --fail \
            --max-time 30 \
            --proto '=https' \
            --tlsv1.2 \
            --output "$cache_file" \
            "$checksums_url" 2>/dev/null; then
            log_debug "Failed to fetch checksums from $checksums_url"
            rm -f "$cache_file" 2>/dev/null || true
            echo ""
            return 0
        fi
    fi

    # Parse the checksums file to find our filename
    # Format is: <checksum>  <filename> (two spaces between)
    local checksum=""
    checksum=$(grep -E "^[a-f0-9]{64}[[:space:]]+${filename}$" "$cache_file" 2>/dev/null | awk '{print $1}' | head -1)

    if [[ -z "$checksum" ]]; then
        # Try alternative format (some releases use single space or different naming)
        checksum=$(grep "${filename}" "$cache_file" 2>/dev/null | grep -oE "^[a-f0-9]{64}" | head -1)
    fi

    if [[ -n "$checksum" ]]; then
        log_debug "Found checksum for ${filename}: ${checksum}"
        echo "$checksum"
    else
        log_debug "Checksum not found for ${filename} in checksums file"
        echo ""
    fi
}

# Get the SHA256 checksum for a component
# First tries to fetch from official release, falls back to hardcoded if available
get_known_checksum() {
    local component="$1"
    local version="$2"
    local arch="$3"

    local filename=""

    # Determine the expected filename based on component
    case "$component" in
        prometheus)
            filename="prometheus-${version}.linux-${arch}.tar.gz"
            ;;
        node_exporter)
            filename="node_exporter-${version}.linux-${arch}.tar.gz"
            ;;
        nginx_exporter)
            filename="nginx-prometheus-exporter_${version}_linux_${arch}.tar.gz"
            ;;
        *)
            echo ""
            return 0
            ;;
    esac

    # Try to fetch checksum from official release
    local checksum=""
    checksum=$(fetch_checksum_from_release "$component" "$version" "$filename")

    if [[ -n "$checksum" ]]; then
        echo "$checksum"
        return 0
    fi

    # Fallback: return empty - dynamic fetch is the primary method
    # If GitHub is unreachable, installation proceeds with a warning
    echo ""
}

# Clean up checksum cache
cleanup_checksum_cache() {
    if [[ -d "$CHECKSUM_CACHE_DIR" ]]; then
        rm -rf "$CHECKSUM_CACHE_DIR"
        log_debug "Cleaned up checksum cache"
    fi
}

# ------------------------------------------------------------------------------
# File Permission Hardening
# ------------------------------------------------------------------------------

# Set secure permissions on a configuration file
secure_config_file() {
    local file="$1"
    local owner="${2:-root}"
    local group="${3:-root}"

    if [[ ! -f "$file" ]]; then
        log_warn "Cannot secure non-existent file: $file"
        return 1
    fi

    chown "$owner:$group" "$file"
    chmod 0640 "$file"
    log_debug "Secured config file: $file (owner=$owner:$group, mode=0640)"
}

# Set secure permissions on an executable
secure_executable() {
    local file="$1"
    local owner="${2:-root}"
    local group="${3:-root}"

    if [[ ! -f "$file" ]]; then
        log_warn "Cannot secure non-existent file: $file"
        return 1
    fi

    chown "$owner:$group" "$file"
    chmod 0755 "$file"
    log_debug "Secured executable: $file (owner=$owner:$group, mode=0755)"
}

# Set secure permissions on a directory
secure_directory() {
    local dir="$1"
    local owner="${2:-root}"
    local group="${3:-root}"
    local mode="${4:-0750}"

    if [[ ! -d "$dir" ]]; then
        mkdir -p "$dir"
    fi

    chown "$owner:$group" "$dir"
    chmod "$mode" "$dir"
    log_debug "Secured directory: $dir (owner=$owner:$group, mode=$mode)"
}

# Set secure permissions on data directory (more restrictive)
secure_data_directory() {
    local dir="$1"
    local owner="${2:-root}"
    local group="${3:-root}"

    secure_directory "$dir" "$owner" "$group" "0700"
}

# ------------------------------------------------------------------------------
# Systemd Hardening
# ------------------------------------------------------------------------------

# Generate hardened systemd service options
# Returns a string of systemd security options
get_systemd_hardening_options() {
    local user="$1"
    local working_dir="${2:-/}"
    local additional_options="${3:-}"

    cat << EOF
# Security hardening
User=${user}
Group=${user}
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
LockPersonality=yes
# Note: MemoryDenyWriteExecute breaks Go applications (Prometheus, exporters)
RestrictRealtime=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged
CapabilityBoundingSet=
AmbientCapabilities=
${additional_options}
EOF
}

# ------------------------------------------------------------------------------
# Secret Generation
# ------------------------------------------------------------------------------

# Generate a cryptographically secure random string
generate_secure_token() {
    local length="${1:-32}"
    local charset="${2:-A-Za-z0-9}"

    # Use /dev/urandom for cryptographically secure random data
    tr -dc "$charset" < /dev/urandom | head -c "$length"
}

# Generate a secure password with mixed characters
generate_secure_password() {
    local length="${1:-24}"

    # Ensure at least one of each character type
    local upper lower digit special
    upper=$(tr -dc 'A-Z' < /dev/urandom | head -c 1)
    lower=$(tr -dc 'a-z' < /dev/urandom | head -c 1)
    digit=$(tr -dc '0-9' < /dev/urandom | head -c 1)
    special=$(tr -dc '!@#$%^&*' < /dev/urandom | head -c 1)

    # Generate remaining characters
    local remaining=$((length - 4))
    local rest
    rest=$(tr -dc 'A-Za-z0-9!@#$%^&*' < /dev/urandom | head -c "$remaining")

    # Combine and shuffle
    echo "${upper}${lower}${digit}${special}${rest}" | fold -w1 | shuf | tr -d '\n'
}

# Store a secret securely
store_secret() {
    local name="$1"
    local value="$2"
    local secrets_dir="${CONFIG_DIR}/secrets"

    secure_directory "$secrets_dir" root root 0700

    local secret_file="${secrets_dir}/${name}"
    echo "$value" > "$secret_file"
    chmod 0600 "$secret_file"
    chown root:root "$secret_file"

    log_debug "Stored secret: $name"
}

# Read a stored secret
read_secret() {
    local name="$1"
    local secrets_dir="${CONFIG_DIR}/secrets"
    local secret_file="${secrets_dir}/${name}"

    if [[ -f "$secret_file" ]]; then
        cat "$secret_file"
    else
        echo ""
    fi
}

# ------------------------------------------------------------------------------
# Input Validation
# ------------------------------------------------------------------------------

# Validate that a string contains only safe characters
validate_safe_string() {
    local value="$1"
    local name="${2:-value}"
    local pattern="${3:-^[a-zA-Z0-9_-]+$}"

    if [[ ! "$value" =~ $pattern ]]; then
        die "Invalid $name: contains unsafe characters"
    fi
}

# Validate an IP address
validate_ip_address() {
    local ip="$1"

    if [[ ! "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        die "Invalid IP address: $ip"
    fi

    # Validate each octet
    IFS='.' read -ra octets <<< "$ip"
    for octet in "${octets[@]}"; do
        if [[ "$octet" -lt 0 || "$octet" -gt 255 ]]; then
            die "Invalid IP address: $ip (octet $octet out of range)"
        fi
    done
}

# Validate a port number
validate_port() {
    local port="$1"
    local name="${2:-port}"

    if [[ ! "$port" =~ ^[0-9]+$ ]]; then
        die "Invalid $name: must be a number"
    fi

    if [[ "$port" -lt 1 || "$port" -gt 65535 ]]; then
        die "Invalid $name: must be between 1 and 65535"
    fi
}

# ------------------------------------------------------------------------------
# Audit Logging
# ------------------------------------------------------------------------------

# Initialize audit log
init_audit_log() {
    local audit_log="${LOG_DIR}/audit.log"
    local audit_dir
    audit_dir=$(dirname "$audit_log")

    secure_directory "$audit_dir" root root 0750
    touch "$audit_log"
    chmod 0640 "$audit_log"

    echo "# NGINX Monitor Stack Audit Log" >> "$audit_log"
    echo "# Initialized: $(date -Iseconds)" >> "$audit_log"
}

# Write to audit log
audit_log() {
    local action="$1"
    local details="${2:-}"
    local audit_log="${LOG_DIR}/audit.log"

    local timestamp
    timestamp=$(date -Iseconds)
    local user
    user=$(whoami)

    echo "${timestamp} | ${user} | ${action} | ${details}" >> "$audit_log"
}

# ------------------------------------------------------------------------------
# Security Checks
# ------------------------------------------------------------------------------

# Check for common security issues
security_audit() {
    log_step "Running security audit"

    local issues=()

    # Check if running as root (for context)
    if is_root; then
        log_debug "Running as root - will drop privileges for services"
    fi

    # Check world-writable directories in PATH
    IFS=':' read -ra path_dirs <<< "$PATH"
    for dir in "${path_dirs[@]}"; do
        if [[ -d "$dir" ]] && [[ -w "$dir" ]] && [[ ! -O "$dir" ]]; then
            issues+=("World-writable directory in PATH: $dir")
        fi
    done

    # Check if SELinux/AppArmor is enabled
    if command_exists getenforce; then
        local selinux_status
        selinux_status=$(getenforce 2>/dev/null || echo "unknown")
        if [[ "$selinux_status" == "Enforcing" ]]; then
            log_debug "SELinux is enforcing - may need policy adjustments"
        fi
    fi

    if command_exists aa-status; then
        if aa-status --enabled 2>/dev/null; then
            log_debug "AppArmor is enabled - may need profile adjustments"
        fi
    fi

    # Report issues
    if [[ ${#issues[@]} -gt 0 ]]; then
        log_warn "Security issues detected:"
        for issue in "${issues[@]}"; do
            log_warn "  - $issue"
        done
    else
        log_success "No security issues detected"
    fi
}

# Verify that we're not running in an obviously compromised environment
sanity_check() {
    log_debug "Running environment sanity check"

    # Check for suspicious environment variables
    local suspicious_vars=("LD_PRELOAD" "LD_LIBRARY_PATH" "DYLD_INSERT_LIBRARIES")
    for var in "${suspicious_vars[@]}"; do
        if [[ -n "${!var:-}" ]]; then
            log_warn "Suspicious environment variable set: $var"
        fi
    done

    # Verify critical binaries haven't been tampered with (basic check)
    local critical_binaries=("/bin/bash" "/usr/bin/curl" "/usr/bin/systemctl")
    for binary in "${critical_binaries[@]}"; do
        if [[ -f "$binary" ]]; then
            # Check if executable and not world-writable
            if [[ ! -x "$binary" ]]; then
                die "Critical binary not executable: $binary"
            fi
            local perms
            perms=$(stat -c '%a' "$binary" 2>/dev/null || stat -f '%Lp' "$binary" 2>/dev/null)
            if [[ "${perms: -1}" =~ [2367] ]]; then
                log_warn "Critical binary is world-writable: $binary"
            fi
        fi
    done

    log_debug "Sanity check passed"
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
