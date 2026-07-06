#!/usr/bin/env bash
# ============================================================
#   W1CK3D_NET_WIZARD -- Linux installer
#   Sets up Python deps, checks optional tools, installs a
#   desktop launcher. Does NOT require root (except the optional
#   dumpcap capability step, which will prompt for sudo).
# ============================================================
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$APP_DIR"

say()  { printf '\033[38;5;135m%s\033[0m\n' "$*"; }   # purple
ok()   { printf '\033[38;5;42m[OK]\033[0m %s\n' "$*"; }
note() { printf '\033[38;5;208m[NOTE]\033[0m %s\n' "$*"; }
fail() { printf '\033[38;5;196m[FAIL]\033[0m %s\n' "$*"; }

say "============================================================"
say "  W1CK3D_NET_WIZARD -- Linux installer"
say "============================================================"

# ── Python 3 ────────────────────────────────────────────────
if ! command -v python3 >/dev/null 2>&1; then
    fail "python3 not found. Install it with your package manager, e.g.:"
    echo "     Debian/Ubuntu/Kali:  sudo apt install python3 python3-pip python3-tk"
    echo "     Fedora:              sudo dnf install python3 python3-pip python3-tkinter"
    echo "     Arch:                sudo pacman -S python python-pip tk"
    exit 1
fi
ok "Found $(python3 --version)"

# ── tkinter ─────────────────────────────────────────────────
if ! python3 -c 'import tkinter' >/dev/null 2>&1; then
    fail "python3-tk (tkinter) is missing — the GUI needs it."
    echo "     Debian/Ubuntu/Kali:  sudo apt install python3-tk"
    echo "     Fedora:              sudo dnf install python3-tkinter"
    echo "     Arch:                sudo pacman -S tk"
    exit 1
fi
ok "tkinter present"

# ── Python dependencies ─────────────────────────────────────
say "Installing Python dependencies (pyshark, manuf)…"
if python3 -m pip install --user --quiet --upgrade pyshark manuf 2>/dev/null; then
    ok "Dependencies installed (--user)."
else
    note "pip --user failed (PEP 668 / externally-managed env). Trying a venv…"
    python3 -m venv "$APP_DIR/.venv"
    # shellcheck disable=SC1091
    "$APP_DIR/.venv/bin/pip" install --quiet --upgrade pyshark manuf
    ok "Dependencies installed into ./.venv"
fi

# ── Optional external tools ─────────────────────────────────
if command -v tshark >/dev/null 2>&1; then
    ok "Wireshark/tshark found (live capture + analysis enabled)."
else
    note "tshark not found — needed for capture analysis."
    echo "     Debian/Ubuntu/Kali:  sudo apt install tshark"
fi
if command -v nmap >/dev/null 2>&1; then
    ok "nmap found (guided scans enabled)."
else
    note "nmap not found — needed for guided scans.  sudo apt install nmap"
fi

# ── Non-root capture capability (optional) ──────────────────
if command -v dumpcap >/dev/null 2>&1 && ! groups | grep -qw wireshark; then
    note "To capture without root, allow your user to use dumpcap:"
    echo "     sudo dpkg-reconfigure wireshark-common   # choose 'Yes'"
    echo "     sudo usermod -aG wireshark \"\$USER\"       # then log out/in"
fi

# ── Desktop launcher ────────────────────────────────────────
say "Installing desktop launcher…"
LAUNCHER="$APP_DIR/net-wizard.sh"
chmod +x "$LAUNCHER" 2>/dev/null || true
DESKTOP_DIR="$HOME/.local/share/applications"
mkdir -p "$DESKTOP_DIR"
cat > "$DESKTOP_DIR/w1ck3d-net-wizard.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=W1CK3D NET WIZARD
Comment=Offline network capture analyzer
Exec="$LAUNCHER"
Icon=$APP_DIR/assets/icon_256.png
Terminal=false
Categories=Network;Security;Utility;
EOF
chmod +x "$DESKTOP_DIR/w1ck3d-net-wizard.desktop" 2>/dev/null || true
update-desktop-database "$DESKTOP_DIR" >/dev/null 2>&1 || true
ok "Launcher installed (find 'W1CK3D NET WIZARD' in your app menu)."

say "============================================================"
say "  Done!"
echo "  TO LAUNCH:  ./net-wizard.sh   (or use your app menu)"
echo "  DIAGNOSE:   python3 diagnose.pyw"
say "============================================================"
