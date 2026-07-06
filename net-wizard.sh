#!/usr/bin/env bash
# ============================================================
#   W1CK3D_NET_WIZARD -- launcher (Linux / macOS)
#   Runs the GUI, preferring the local ./.venv if the installer
#   created one, else the system python3.
# ============================================================
set -euo pipefail
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$APP_DIR"

if [ -x "$APP_DIR/.venv/bin/python" ]; then
    PY="$APP_DIR/.venv/bin/python"
else
    PY="$(command -v python3 || command -v python || true)"
fi

if [ -z "${PY:-}" ]; then
    echo "python3 not found. Run ./install.sh (Linux) or install.command (macOS) first." >&2
    exit 1
fi

exec "$PY" app.py "$@"
