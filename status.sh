#!/usr/bin/env bash
# ==============================================================================
# NGINX Monitor Stack - Status Checker
# ==============================================================================
# Shows the status of all NGINX Monitor Stack components.
#
# Usage:
#   ./status.sh
#
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR

# Execute the main installer with status flag
exec "${SCRIPT_DIR}/install.sh" --status "$@"
