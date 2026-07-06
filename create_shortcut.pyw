import sys, os, ctypes, subprocess, tempfile
from pathlib import Path

APP_DIR  = Path(__file__).parent.resolve()
LAUNCH   = APP_DIR / 'launch.pyw'
ICON     = APP_DIR / 'assets' / 'icon.ico'
DESKTOP  = Path.home() / 'Desktop'
SHORTCUT = DESKTOP / 'W1CK3D_NET_WIZARD.lnk'

def alert(title, msg, error=False):
    icon = 0x10 if error else 0x40
    ctypes.windll.user32.MessageBoxW(0, msg, title, icon)

if not LAUNCH.exists():
    alert('Missing File',
          'launch.pyw not found in:\n' + str(APP_DIR) +
          '\n\nMake sure all files are in the same folder.', error=True)
    sys.exit(1)

pythonw = Path(sys.executable)
if pythonw.name.lower() == 'python.exe':
    pw = pythonw.parent / 'pythonw.exe'
    if pw.exists():
        pythonw = pw

ps = (
    '$ws = New-Object -COM WScript.Shell; '
    '$s = $ws.CreateShortcut(' + repr(str(SHORTCUT)) + '); '
    '$s.TargetPath = ' + repr(str(pythonw)) + '; '
    '$s.Arguments = ' + repr('"' + str(LAUNCH) + '"') + '; '
    '$s.WorkingDirectory = ' + repr(str(APP_DIR)) + '; '
    '$s.IconLocation = ' + repr(str(ICON)) + '; '
    '$s.Description = "W1CK3D_NET_WIZARD"; '
    '$s.Save()'
)

r = subprocess.run(
    ['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', ps],
    capture_output=True, text=True
)

if SHORTCUT.exists():
    alert('W1CK3D_NET_WIZARD',
          'Desktop shortcut created!\n\n'
          '"W1CK3D_NET_WIZARD" is now on your desktop.')
else:
    alert('Shortcut Failed',
          'Could not create the shortcut automatically.\n\n'
          'Error: ' + (r.stderr.strip() or r.stdout.strip() or 'unknown') + '\n\n'
          'Manual fix:\n'
          '1. Right-click launch.pyw\n'
          '2. Send to > Desktop (create shortcut)\n'
          '3. Right-click the new shortcut > Properties > Change Icon\n'
          '   Point to: ' + str(ICON), error=True)
