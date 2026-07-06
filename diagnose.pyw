"""
diagnose.pyw  -  W1CK3D_NET_WIZARD  -  Diagnostic tool
Double-click this file to run a full system check.

Results are shown in a popup window AND saved to diagnose_results.txt
in this folder. Send that file if you need support.
"""
import sys
import os
import subprocess
import ctypes
import importlib
from pathlib import Path
from datetime import datetime

APP_DIR     = Path(__file__).parent.resolve()
RESULT_FILE = APP_DIR / 'diagnose_results.txt'

lines = []

def p(msg=''):
    lines.append(msg)

def check(label, ok, detail=''):
    status = 'PASS' if ok else 'FAIL'
    line = f"  [{status}] {label}"
    if detail:
        line += f"\n         {detail}"
    lines.append(line)
    return ok

def section(title):
    lines.append('')
    lines.append('─' * 50)
    lines.append(f'  {title}')
    lines.append('─' * 50)

def _alert(title, msg):
    ctypes.windll.user32.MessageBoxW(0, msg, title, 0x40)  # MB_ICONINFORMATION

p(f"W1CK3D_NET_WIZARD — Diagnostic Report")
p(f"Generated: {datetime.now():%Y-%m-%d %H:%M:%S}")
p(f"App dir:   {APP_DIR}")

# ── Python ─────────────────────────────────────────────────────────────────────
section("Python")
p(f"  Executable : {sys.executable}")
p(f"  Version    : {sys.version}")
vi = sys.version_info
check("Python 3.10+", vi >= (3, 10),
      f"Found {vi.major}.{vi.minor} — need 3.10 or newer from https://www.python.org/")

# ── tkinter ────────────────────────────────────────────────────────────────────
section("tkinter (GUI framework)")
try:
    import tkinter as tk
    check("tkinter installed", True, f"Tk version {tk.TkVersion}")
except ImportError as e:
    check("tkinter installed", False,
          f"{e}\n"
          f"         Fix: Start → Add/Remove Programs → Python → Modify\n"
          f"         Make sure 'tcl/tk and IDLE' is ticked → Modify")

# ── Required files ─────────────────────────────────────────────────────────────
section("Required Files")
os.chdir(APP_DIR)
for fname in ['app.py', 'analyze.py', 'cli.py', 'scheduler.py',
              'live_capture.py', 'admin_panel.py',
              'analyzer/__init__.py', 'tools/__init__.py',
              'assets/icon.ico', 'assets/icon_tk.png']:
    exists = (APP_DIR / fname).exists()
    check(fname, exists, '' if exists else f"MISSING from {APP_DIR}")

# ── Python imports ─────────────────────────────────────────────────────────────
section("Python Module Imports")
sys.path.insert(0, str(APP_DIR))

import_tests = [
    ('analyzer.storage',      'ReportStore'),
    ('analyze',               'run_analysis'),
    ('tools.ip_investigate',  'lookup_ip'),
    ('tools.protocol_library','load_library'),
    ('tools.scan_profiles',   'SCAN_PROFILES'),
    ('tools.wireless_analyzer','analyze_80211_pcap'),
    ('admin_panel',           'AdminSettingsPanel'),
    ('cli',                   'analyze_file'),
    ('scheduler',             'effective_config'),
    ('live_capture',          'CaptureSession'),
]

for mod_name, attr in import_tests:
    try:
        mod = importlib.import_module(mod_name)
        getattr(mod, attr)
        check(mod_name, True)
    except Exception as e:
        check(mod_name, False, str(e)[:120])

# ── pip packages ───────────────────────────────────────────────────────────────
section("pip Packages")
for pkg in ['pyshark', 'manuf']:
    try:
        importlib.import_module(pkg)
        check(pkg, True)
    except ImportError:
        check(pkg, False,
              f"Run:  python -m pip install {pkg}")

# ── External tools ─────────────────────────────────────────────────────────────
section("External Tools")
import shutil

tshark = (shutil.which('tshark') or
          (r'C:\Program Files\Wireshark\tshark.exe'
           if Path(r'C:\Program Files\Wireshark\tshark.exe').exists() else None))
check("tshark (Wireshark)",
      bool(tshark),
      tshark or "Install from https://www.wireshark.org/  (tick Npcap)")

nmap = (shutil.which('nmap') or
        (r'C:\Program Files\Nmap\nmap.exe'
         if Path(r'C:\Program Files\Nmap\nmap.exe').exists() else None))
check("nmap",
      bool(nmap),
      nmap or "Install from https://nmap.org/download.html")

# ── Summary ────────────────────────────────────────────────────────────────────
p('')
p('=' * 50)
fails = sum(1 for l in lines if '[FAIL]' in l)
passes = sum(1 for l in lines if '[PASS]' in l)
p(f"  Results:  {passes} passed   {fails} failed")
p('=' * 50)
if fails == 0:
    p("  All checks passed. If the app still won't open,")
    p("  check launch.log in this folder for the crash details.")
else:
    p("  Fix the FAIL items above and try launching again.")
p('')

# Write file
report = '\n'.join(lines)
RESULT_FILE.write_text(report, encoding='utf-8')

# Show popup summary
popup = report if len(report) < 2000 else (
    '\n'.join(l for l in lines if 'FAIL' in l or '=' in l or '─' in l)
    + f"\n\nFull report saved to:\n{RESULT_FILE}"
)

title = "W1CK3D_NET_WIZARD — Diagnostics"
if fails == 0:
    _alert(title + " (All Passed)", popup)
else:
    ctypes.windll.user32.MessageBoxW(0, popup, title, 0x10)  # MB_ICONERROR

# Also try to open the result file in Notepad
try:
    subprocess.Popen(['notepad.exe', str(RESULT_FILE)])
except Exception:
    pass
