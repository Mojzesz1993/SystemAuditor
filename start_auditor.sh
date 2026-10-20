#!/usr/bin/env bash
# ==============================================================================
# SystemAuditor Enterprise — Skrypt Uruchomieniowy Bash (Linux Debian/Ubuntu/RHEL)
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PYTHON_BIN="${PYTHON_BIN:-python3}"

echo "[*] Uruchamianie SystemAuditor Enterprise..."
exec "$PYTHON_BIN" run_system.py "$@"
