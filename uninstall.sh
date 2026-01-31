#!/usr/bin/env bash
# ==============================================================================
# NGINX Monitor Stack - Uninstaller
# ==============================================================================
# Cleanly removes all NGINX Monitor Stack components.
#
# Usage:
#   sudo ./uninstall.sh [--remove-data]
#
# Options:
#   --remove-data    Also remove data directories (Prometheus data, etc.)
#   --force          Skip confirmation prompts
#   --help           Show this help message
#
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR

# Execute the main installer with uninstall flag
exec "${SCRIPT_DIR}/install.sh" --uninstall "$@"
