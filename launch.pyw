"""
launch.pyw  -  W1CK3D_NET_WIZARD  -  Windows launcher
Double-click this file to start the app.

.pyw files run with pythonw.exe — no console window, no PowerShell,
no execution policy issues. Works as long as Python 3.10+ is installed.
If Python is not installed, Windows will prompt you to find an app to open it.
"""
import sys
import os
import subprocess
import ctypes
from pathlib import Path
from datetime import datetime

APP_DIR  = Path(__file__).parent.resolve()
APP_PY   = APP_DIR / 'app.py'
LOG_FILE = APP_DIR / 'launch.log'

def _log(msg):
    try:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"{datetime.now():%Y-%m-%d %H:%M:%S}  {msg}\n")
    except Exception:
        pass

def _alert(title, msg, icon=0x10):
    """Show a Windows MessageBox. Works before tkinter exists."""
    ctypes.windll.user32.MessageBoxW(0, msg, title, icon)

_log("=" * 50)
_log("launch.pyw started")
_log(f"Python: {sys.version}")
_log(f"Executable: {sys.executable}")
_log(f"App dir: {APP_DIR}")

# ── 1. Verify app.py exists ────────────────────────────────────────────────────
if not APP_PY.exists():
    msg = (f"app.py was not found in:\n{APP_DIR}\n\n"
           f"Make sure launch.pyw is inside the W1CK3D_NET_WIZARD folder "
           f"alongside app.py.")
    _log(f"FAIL: app.py not found")
    _alert("W1CK3D_NET_WIZARD — File Missing", msg)
    sys.exit(1)

# ── 2. Check tkinter ───────────────────────────────────────────────────────────
try:
    import tkinter
    _log(f"tkinter OK (Tk {tkinter.TkVersion})")
except ImportError as e:
    msg = (f"tkinter (the GUI framework) is not available in this Python.\n\n"
           f"Error: {e}\n\n"
           f"Fix:\n"
           f"1. Open  Start → Add or Remove Programs\n"
           f"2. Find Python, click Modify\n"
           f"3. Make sure  'tcl/tk and IDLE'  is ticked\n"
           f"4. Click Modify to repair, then double-click launch.pyw again.\n\n"
           f"Or reinstall Python from  https://www.python.org/downloads/\n"
           f"(the standard python.org installer includes tkinter by default)")
    _log(f"FAIL: tkinter - {e}")
    _alert("W1CK3D_NET_WIZARD — tkinter Missing", msg)
    sys.exit(1)

# ── 3. Install/verify pip dependencies ────────────────────────────────────────
_log("Running pip install pyshark manuf ...")
try:
    r = subprocess.run(
        [sys.executable, '-m', 'pip', 'install',
         '--quiet', '--disable-pip-version-check', 'pyshark', 'manuf'],
        capture_output=True, text=True, timeout=120,
        cwd=str(APP_DIR)
    )
    _log(f"pip stdout: {r.stdout.strip()}")
    if r.returncode != 0:
        _log(f"pip stderr: {r.stderr.strip()}")
except Exception as e:
    _log(f"pip warning (non-fatal): {e}")

# ── 4. Launch app.py in the same Python, same directory ───────────────────────
# We use sys.executable (pythonw.exe) so no console window appears.
# stderr goes to launch.log so any crash is captured.
_log("Launching app.py ...")
try:
    with open(LOG_FILE, 'ab') as log_handle:
        proc = subprocess.Popen(
            [sys.executable, str(APP_PY)],
            cwd=str(APP_DIR),
            stderr=log_handle,
            stdout=subprocess.DEVNULL,
        )
    _log(f"Process started PID {proc.pid}")

    # Wait up to 8 seconds. If the app exits within that window it crashed.
    try:
        proc.wait(timeout=8)
        code = proc.returncode
        if code != 0:
            _log(f"CRASH: exit code {code}")
            # Read the last 30 lines of the log for context
            try:
                lines = LOG_FILE.read_text(encoding='utf-8', errors='replace').splitlines()
                excerpt = '\n'.join(lines[-30:])
            except Exception:
                excerpt = '(could not read log)'
            msg = (f"W1CK3D_NET_WIZARD crashed on startup (exit code {code}).\n\n"
                   f"Last log entries:\n"
                   f"{'─' * 40}\n"
                   f"{excerpt}\n"
                   f"{'─' * 40}\n\n"
                   f"Full log saved to:\n{LOG_FILE}\n\n"
                   f"Run diagnose.pyw for a detailed diagnostic report.")
            _alert("W1CK3D_NET_WIZARD — Crash", msg)
            sys.exit(code)
        else:
            _log("App exited cleanly within timeout (normal for very fast exit)")
    except subprocess.TimeoutExpired:
        _log("App running normally (still alive after 8s)")

except Exception as e:
    _log(f"EXCEPTION launching app: {e}")
    _alert("W1CK3D_NET_WIZARD — Launch Error",
           f"Could not start the app:\n\n{e}\n\nLog: {LOG_FILE}")
    sys.exit(1)
