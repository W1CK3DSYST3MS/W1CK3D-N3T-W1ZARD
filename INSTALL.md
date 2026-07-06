# Install guide — W1CK3D NET WIZARD

Requires Python 3.8+ with tkinter (developed/tested on Python 3.12).

---

## Windows

1. Download and extract the Windows release package.
2. Double-click `install.bat`.
   - It locates your Python install, installs `pyshark` and `manuf` via pip, unblocks the downloaded scripts, and creates a desktop shortcut.
3. Launch the app from the desktop shortcut, or run `launch.pyw` directly.

**Troubleshooting**
- **SmartScreen warning ("Windows protected your PC")** — this appears because the app isn't code-signed, not because it's flagged as malicious. Click **More info → Run anyway**.
- **"Python not found"** — install Python 3.8+ from [python.org](https://www.python.org/downloads/) and check **"Add python.exe to PATH"** during setup, then re-run `install.bat`.
- **tkinter missing** — the official python.org installer includes tkinter by default; if you installed Python via the Microsoft Store, reinstall using the python.org installer instead.

## Linux

1. Download and extract the Linux release package.
2. Run:
   ```
   ./install.sh
   ```
   This installs dependencies (either system-wide or into a local venv, depending on your distro's pip policy), checks for tkinter/tshark/nmap, and adds an app-menu launcher.
3. Launch via `./net-wizard.sh` or the app-menu entry.

**Troubleshooting**
- **tkinter missing** — install your distro's package, e.g. `sudo apt install python3-tk` (Debian/Ubuntu), `sudo dnf install python3-tkinter` (Fedora), `sudo pacman -S tk` (Arch).
- **tshark permission denied / "no permission to capture"** — tshark needs raw-socket access. Add your user to the `wireshark` group and re-log in:
  ```
  sudo usermod -aG wireshark $USER
  ```
  Then log out and back in (group membership doesn't apply to your current session).
- **nmap not found** — install via your package manager, e.g. `sudo apt install nmap`.
- **externally-managed-environment pip error** — the installer falls back to a local venv automatically; if running manually, create one yourself: `python3 -m venv .venv && source .venv/bin/activate && pip install pyshark manuf`.

## macOS (untested)

There's no packaged macOS release yet — the maintainer hasn't been able to test on macOS. It's expected to work by running from source (below), since it only relies on Python's standard Tkinter GUI plus `pyshark`/`manuf`, but it hasn't been verified. Likely rough edges if you try it:

- **Gatekeeper** may block unsigned scripts the first time — right-click (Control-click) and choose **Open** to bypass, then confirm in the dialog.
- **tkinter missing** — the python.org installer for macOS includes tkinter; Homebrew's `python3` may not, in which case run `brew install python-tk`.
- **tshark permission prompt** — macOS will ask for permission to capture network traffic the first time; approve it in System Settings → Privacy & Security if it doesn't prompt automatically.

If you try it on macOS, reports of what works or breaks are welcome via an issue.

## Any OS, from source

```
pip install pyshark manuf
python app.py
```

For headless / scripted use, see `cli.py`.

Optional external tools, install separately if you want the features that use them:
- [Wireshark/tshark](https://www.wireshark.org/) — required for capture analysis.
- [nmap](https://nmap.org/) — required for guided scans.

The app detects when these are missing and points you to the relevant installer.

---

## Where your data lives

Everything the app creates — reports, captures, config, and the device registry — is stored under `~/W1CK3DWizard/` in your home directory. Nothing is written to the install folder, and uninstalling the app does not touch this folder or your saved reports.
