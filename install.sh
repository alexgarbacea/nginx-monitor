#!/usr/bin/env bash
# ==============================================================================
# NGINX Monitor Stack - Main Installer
# ==============================================================================
#
# One-command installer for a complete NGINX monitoring stack.
# Installs and configures:
#   - Prometheus (metrics collection)
#   - Node Exporter (system metrics)
#   - NGINX Prometheus Exporter (NGINX metrics)
#   - Grafana (visualization)
#
# Usage:
#   sudo ./install.sh [options]
#
# Options:
#   --skip-nginx      Skip NGINX exporter installation
#   --skip-grafana    Skip Grafana installation
#   --uninstall       Remove all components
#   --status          Show status of all components
#   --help            Show this help message
#
# Security:
#   - All services bind to localhost only
#   - Grafana protected with generated password
#   - No external network exposure by default
#
# ==============================================================================

set -euo pipefail

# ------------------------------------------------------------------------------
# Script Location
# ------------------------------------------------------------------------------

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR

# ------------------------------------------------------------------------------
# Load Libraries
# ------------------------------------------------------------------------------

source "${SCRIPT_DIR}/lib/common.sh"
source "${SCRIPT_DIR}/lib/security.sh"
source "${SCRIPT_DIR}/lib/detect.sh"
source "${SCRIPT_DIR}/lib/prometheus.sh"
source "${SCRIPT_DIR}/lib/exporters.sh"
source "${SCRIPT_DIR}/lib/grafana.sh"
source "${SCRIPT_DIR}/lib/nginx-config.sh"

# ------------------------------------------------------------------------------
# Command Line Options
# ------------------------------------------------------------------------------

SKIP_NGINX=false
SKIP_GRAFANA=false
DO_UNINSTALL=false
DO_STATUS=false
REMOVE_DATA=false
PURGE=false
QUIET=false

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --skip-nginx)
                SKIP_NGINX=true
                shift
                ;;
            --skip-grafana)
                SKIP_GRAFANA=true
                shift
                ;;
            --uninstall)
                DO_UNINSTALL=true
                shift
                ;;
            --remove-data)
                REMOVE_DATA=true
                shift
                ;;
            --purge)
                PURGE=true
                REMOVE_DATA=true
                shift
                ;;
            --status)
                DO_STATUS=true
                shift
                ;;
            --quiet|-q)
                QUIET=true
                shift
                ;;
            --debug)
                DEBUG=1
                shift
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                die "Unknown option: $1. Use --help for usage information."
                ;;
        esac
    done
}

show_help() {
    cat << 'EOF'
NGINX Monitor Stack Installer

Usage:
  sudo ./install.sh [options]

Options:
  --skip-nginx      Skip NGINX exporter (useful if NGINX not installed)
  --skip-grafana    Skip Grafana installation (Prometheus only)
  --uninstall       Remove all installed components
  --remove-data     Also remove data directories during uninstall
  --status          Show status of all components
  --quiet, -q       Minimal output
  --debug           Enable debug logging
  --help, -h        Show this help message

Examples:
  # Full installation
  sudo ./install.sh

  # Install without Grafana
  sudo ./install.sh --skip-grafana

  # Check status
  sudo ./install.sh --status

  # Complete removal
  sudo ./install.sh --uninstall --remove-data

Security Notes:
  - All services bind to 127.0.0.1 (localhost only)
  - Grafana admin password is randomly generated
  - NGINX stub_status is accessible only from localhost
  - No ports are exposed to external networks by default

For more information, see README.md
EOF
}

# ------------------------------------------------------------------------------
# Banner
# ------------------------------------------------------------------------------

print_banner() {
    if $QUIET; then
        return
    fi

    cat << 'EOF'

  _   _  ____ ___ _   ___  __  __  __             _ _
 | \ | |/ ___|_ _| \ | \ \/ / |  \/  | ___  _ __ (_) |_ ___  _ __
 |  \| | |  _ | ||  \| |\  /  | |\/| |/ _ \| '_ \| | __/ _ \| '__|
 | |\  | |_| || || |\  |/  \  | |  | | (_) | | | | | || (_) | |
 |_| \_|\____|___|_| \_/_/\_\ |_|  |_|\___/|_| |_|_|\__\___/|_|

  NGINX Monitoring Stack Installer
  Version: 1.0.0

EOF
}

# ------------------------------------------------------------------------------
# Pre-flight Checks
# ------------------------------------------------------------------------------

preflight_checks() {
    log_step "Running pre-flight checks"

    # Must be root
    require_root

    # Check dependencies
    check_dependencies

    # Detect OS
    detect_os

    # Check system requirements
    check_system_requirements

    # Detect NGINX
    detect_nginx

    # Security sanity check
    sanity_check

    # Check for existing installations
    if detect_existing_installations; then
        log_warn "Existing installations detected"
        if ! $QUIET; then
            if ! confirm "Continue anyway?"; then
                die "Installation cancelled"
            fi
        fi
    fi

    log_success "Pre-flight checks passed"
}

# ------------------------------------------------------------------------------
# Installation
# ------------------------------------------------------------------------------

run_installation() {
    print_banner

    log_step "Starting NGINX Monitor Stack installation"
    log_info "OS: $OS_PRETTY_NAME ($ARCH)"

    # Pre-flight checks
    preflight_checks

    # Print detection summary
    if ! $QUIET; then
        print_detection_summary
        echo ""
        if ! confirm "Proceed with installation?"; then
            die "Installation cancelled"
        fi
    fi

    # Create base directories
    log_step "Creating installation directories"
    create_install_dirs

    # Initialize audit log
    init_audit_log
    audit_log "START" "nginx-monitor installation"

    # Install Prometheus
    install_prometheus

    # Install Node Exporter
    install_node_exporter

    # Configure NGINX and install NGINX exporter
    if ! $SKIP_NGINX && $NGINX_INSTALLED; then
        create_stub_status_config
        install_nginx_exporter

        # Now start the NGINX exporter (after stub_status is configured)
        start_nginx_exporter
    elif $SKIP_NGINX; then
        log_info "Skipping NGINX exporter installation (--skip-nginx)"
    else
        log_info "Skipping NGINX exporter installation (NGINX not found)"
    fi

    # Install Grafana
    if ! $SKIP_GRAFANA; then
        install_grafana
    else
        log_info "Skipping Grafana installation (--skip-grafana)"
    fi

    # Cleanup temporary files
    cleanup_checksum_cache

    # Final status
    audit_log "COMPLETE" "nginx-monitor installation"
    print_installation_summary
}

# ------------------------------------------------------------------------------
# Uninstallation
# ------------------------------------------------------------------------------

run_uninstallation() {
    log_step "Starting NGINX Monitor Stack uninstallation"

    require_root

    if ! $QUIET; then
        echo ""
        log_warn "This will remove the following components:"
        echo "  - Prometheus"
        echo "  - Node Exporter"
        echo "  - NGINX Prometheus Exporter"
        echo "  - Grafana"
        echo "  - NGINX stub_status configuration"
        echo ""

        if $REMOVE_DATA; then
            log_warn "Data directories will also be removed!"
        else
            echo "Data directories will be preserved."
        fi

        echo ""
        if ! confirm "Continue with uninstallation?"; then
            die "Uninstallation cancelled"
        fi
    fi

    # Source detection for nginx paths
    detect_os 2>/dev/null || true
    detect_nginx 2>/dev/null || true

    # Uninstall in reverse order
    uninstall_grafana 2>/dev/null || true
    uninstall_all_exporters 2>/dev/null || true
    remove_stub_status_config 2>/dev/null || true
    uninstall_prometheus 2>/dev/null || true

    # Remove base directories if empty
    rmdir "$INSTALL_DIR" 2>/dev/null || true
    rmdir "$CONFIG_DIR" 2>/dev/null || true
    rmdir "$LOG_DIR" 2>/dev/null || true

    if $REMOVE_DATA; then
        rm -rf "$DATA_DIR"
    fi

    log_success "NGINX Monitor Stack uninstalled successfully"
}

# ------------------------------------------------------------------------------
# Status Check
# ------------------------------------------------------------------------------

run_status() {
    echo ""
    echo "=========================================="
    echo "  NGINX Monitor Stack Status"
    echo "=========================================="
    echo ""

    # Detect environment
    detect_os 2>/dev/null || true
    detect_nginx 2>/dev/null || true

    # Prometheus status
    get_prometheus_status
    echo ""

    # Exporter status
    check_exporters_health
    echo ""

    # Grafana status
    get_grafana_status
    echo ""

    # NGINX status
    if $NGINX_INSTALLED; then
        get_nginx_status
        echo ""
    fi

    echo "=========================================="
}

# ------------------------------------------------------------------------------
# Installation Summary
# ------------------------------------------------------------------------------

print_installation_summary() {
    local grafana_password
    grafana_password=$(read_secret "grafana_admin_password" 2>/dev/null || echo "N/A")

    cat << EOF

================================================================================
  NGINX Monitor Stack - Installation Complete!
================================================================================

  All services are running and bound to localhost (127.0.0.1).

  PROMETHEUS
    URL:     http://127.0.0.1:${PROMETHEUS_PORT}
    Config:  ${PROMETHEUS_CONFIG}

  NODE EXPORTER
    URL:     http://127.0.0.1:${NODE_EXPORTER_PORT}/metrics

EOF

    if ! $SKIP_NGINX && $NGINX_INSTALLED; then
        cat << EOF
  NGINX EXPORTER
    URL:     http://127.0.0.1:${NGINX_EXPORTER_PORT}/metrics

EOF
    fi

    if ! $SKIP_GRAFANA; then
        cat << EOF
  GRAFANA
    URL:      http://127.0.0.1:${GRAFANA_PORT}
    Username: admin
    Password: ${grafana_password}

    IMPORTANT: Change the admin password after first login!

EOF
    fi

    cat << EOF
  COMMANDS
    Check status:  sudo ${SCRIPT_DIR}/install.sh --status
    Uninstall:     sudo ${SCRIPT_DIR}/install.sh --uninstall

  ACCESSING REMOTELY
    By default, all services are bound to localhost only.
    To access from another machine, set up SSH port forwarding:

    ssh -L 3000:127.0.0.1:3000 -L 9090:127.0.0.1:9090 user@your-server

    Then access http://localhost:3000 in your browser.

  DOCUMENTATION
    README:    ${SCRIPT_DIR}/README.md
    Security:  ${SCRIPT_DIR}/SECURITY.md

================================================================================
EOF
}

# ------------------------------------------------------------------------------
# Main Entry Point
# ------------------------------------------------------------------------------

main() {
    # Parse command line arguments
    parse_args "$@"

    # Set up error handling
    setup_error_trap
    setup_cleanup_trap

    # Route to appropriate action
    if $DO_STATUS; then
        run_status
    elif $DO_UNINSTALL; then
        run_uninstallation
    else
        run_installation
    fi
}

# Run main function with all arguments
main "$@"
