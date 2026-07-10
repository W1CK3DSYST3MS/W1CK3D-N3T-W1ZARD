#!/usr/bin/env bash
# ============================================================
#   W1CK3D_NET_WIZARD -- macOS installer
#   Double-click in Finder to run. Sets up Python deps, checks
#   optional tools, and drops a launcher on your Desktop.
# ============================================================
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$APP_DIR"

say()  { printf '\033[38;5;135m%s\033[0m\n' "$*"; }
ok()   { printf '\033[38;5;42m[OK]\033[0m %s\n' "$*"; }
note() { printf '\033[38;5;208m[NOTE]\033[0m %s\n' "$*"; }
fail() { printf '\033[38;5;196m[FAIL]\033[0m %s\n' "$*"; }

say "============================================================"
say "  W1CK3D_NET_WIZARD -- macOS installer"
say "============================================================"

# ── Python 3 ────────────────────────────────────────────────
if ! command -v python3 >/dev/null 2>&1; then
    fail "python3 not found."
    echo "     Install from https://www.python.org/downloads/  (recommended:"
    echo "     the python.org build ships a working Tk), or:  brew install python-tk"
    read -r -p "Press Return to close…" _; exit 1
fi
ok "Found $(python3 --version)"

# ── tkinter ─────────────────────────────────────────────────
if ! python3 -c 'import tkinter' >/dev/null 2>&1; then
    fail "tkinter is missing from this Python."
    echo "     Easiest fix: install Python from https://www.python.org/downloads/"
    echo "     (its Tk is bundled).  Homebrew users:  brew install python-tk"
    read -r -p "Press Return to close…" _; exit 1
fi
ok "tkinter present"

# ── Python dependencies ─────────────────────────────────────
say "Installing Python dependencies (pyshark, manuf)…"
if python3 -m pip install --user --quiet --upgrade pyshark manuf 2>/dev/null; then
    ok "Dependencies installed (--user)."
else
    note "pip --user failed. Creating a local venv…"
    python3 -m venv "$APP_DIR/.venv"
    "$APP_DIR/.venv/bin/pip" install --quiet --upgrade pyshark manuf
    ok "Dependencies installed into ./.venv"
fi

# ── Optional external tools ─────────────────────────────────
if command -v tshark >/dev/null 2>&1; then
    ok "tshark found (live capture + analysis enabled)."
else
    note "tshark not found — needed for capture analysis."
    echo "     Install Wireshark from https://www.wireshark.org/ or:  brew install wireshark"
fi
if command -v nmap >/dev/null 2>&1; then
    ok "nmap found (guided scans enabled)."
else
    note "nmap not found — needed for guided scans.  brew install nmap"
fi

# ── Desktop launcher (.command) ─────────────────────────────
say "Creating Desktop launcher…"
LAUNCHER="$APP_DIR/net-wizard.sh"
chmod +x "$LAUNCHER" 2>/dev/null || true
DESK="$HOME/Desktop/W1CK3D NET WIZARD.command"
cat > "$DESK" <<EOF
#!/usr/bin/env bash
exec "$LAUNCHER"
EOF
chmod +x "$DESK"
ok "Launcher on your Desktop: 'W1CK3D NET WIZARD.command'"
note "First launch: right-click it → Open (to clear Gatekeeper's unsigned warning)."

say "============================================================"
say "  Done!"
echo "  TO LAUNCH:  double-click 'W1CK3D NET WIZARD.command' on your Desktop"
echo "  DIAGNOSE:   python3 diagnose.pyw"
say "============================================================"
read -r -p "Press Return to close…" _
