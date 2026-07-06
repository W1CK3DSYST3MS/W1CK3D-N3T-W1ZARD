#!/usr/bin/env python3
"""
app.py  -  Native desktop GUI for the pcap analyzer.

Run:
    python app.py

Uses only Python's standard library (tkinter) for the UI, so there are no
extra GUI dependencies. The analyzer itself still needs pyshark + manuf
(and tshark on PATH).

The app is fully offline:
  - Analysis runs locally, no network calls.
  - Reports are saved to ~/W1CK3DWizard/Reports/ as self-contained folders
    (HTML + JSON + metadata), so they remain readable forever even if this
    app is uninstalled — you can just open the HTML file directly.

Layout:
  +--------------------------------------------------------------+
  |  [Analyze capture...] [Open reports folder]     (toolbar)    |
  +--------------------------------------------------------------+
  |   Past reports      |           Report detail                |
  |   (list)            |   [Summary | Devices | Findings]       |
  |                     |                                        |
  +--------------------------------------------------------------+
  |  Status bar                                                  |
  +--------------------------------------------------------------+
"""

import csv
import json
import os
import platform
import queue
import re
import shutil
import struct
import subprocess
import sys
import threading
import tkinter as tk
import webbrowser
from datetime import datetime
from pathlib import Path
from tkinter import ttk, filedialog, messagebox

# Make the analyzer package importable when running this file directly
sys.path.insert(0, str(Path(__file__).parent))

import theme                                  # noqa: E402  W1CK3D SYST3MS theme
from theme import C                            # noqa: E402  semantic colour palette
from analyzer.storage import ReportStore      # noqa: E402
from analyzer.base import SEVERITY_COLORS      # noqa: E402  canonical severity ramp
from analyze import run_analysis              # noqa: E402
from tools.ip_investigate import lookup_ip, format_investigation, extract_ips  # noqa: E402
from tools.protocol_library import (          # noqa: E402
    load_library, save_user_entry, delete_user_entry,
    lookup_port, lookup_layer, ALL_CATEGORIES,
    RISK_NONE, RISK_LOW, RISK_MEDIUM, RISK_HIGH,

    lookup_layer_hint, lookup_port_iana,
)
from tools.scan_profiles import (             # noqa: E402
    SCAN_PROFILES, get_profiles_by_category,
    build_step_args, parse_nmap_output,
)
from tools.wireless_analyzer import analyze_80211_pcap  # noqa: E402
from admin_panel import AdminSettingsPanel               # noqa: E402


APP_NAME = 'W1CK3D_NET_WIZARD'
DEFAULT_REPORTS_DIR = Path.home() / 'W1CK3DWizard' / 'Reports'
CONFIG_PATH = Path.home() / 'W1CK3DWizard' / 'config.json'


def _load_config() -> dict:
    try:
        return json.loads(CONFIG_PATH.read_text(encoding='utf-8'))
    except Exception:
        return {}


def _save_config(cfg: dict):
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2), encoding='utf-8')

def _pcap_link_type(path: str) -> int:
    """
    Read the link-layer type from a pcap or pcapng file header.
    Returns the link type integer, or -1 on failure / unrecognised format.

    Relevant types:
        1   = Ethernet (managed-mode WiFi looks like this)
        105 = IEEE 802.11  (raw, no radiotap)
        127 = IEEE 802.11 + Radiotap  (typical Wireshark monitor-mode output)
    """
    _80211_LINK_TYPES = {105, 127}  # exposed so callers can compare
    try:
        with open(path, 'rb') as f:
            magic = f.read(4)
            if len(magic) < 4:
                return -1

            # ── Legacy PCAP (24-byte global header) ──
            # LE microsec: d4 c3 b2 a1 | BE microsec: a1 b2 c3 d4
            # LE nanosec:  4d 3c 2b 1a | BE nanosec:  1a 2b 3c 4d
            if magic[0] in (0xd4, 0x4d, 0xa1, 0x1a):
                le  = magic[0] in (0xd4, 0x4d)
                f.seek(20)
                raw = f.read(4)
                if len(raw) < 4:
                    return -1
                return struct.unpack('<I' if le else '>I', raw)[0]

            # ── PCAPNG (Section Header Block type = 0x0A0D0D0A) ──
            if magic == b'\x0a\x0d\x0d\x0a':
                shb_len_raw = f.read(4)           # block total length
                bom         = f.read(4)            # byte-order magic
                le  = (bom == b'\x4d\x3c\x2b\x1a')
                fmt = '<' if le else '>'
                shb_len = struct.unpack(fmt + 'I', shb_len_raw)[0]
                f.seek(shb_len)                    # skip past SHB
                idb_type_raw = f.read(4)
                if len(idb_type_raw) < 4:
                    return -1
                if struct.unpack(fmt + 'I', idb_type_raw)[0] != 1:
                    return -1                       # expected Interface Description Block
                f.seek(shb_len + 8)                # skip IDB block-type + block-length
                lt_raw = f.read(2)
                if len(lt_raw) < 2:
                    return -1
                return struct.unpack(fmt + 'H', lt_raw)[0]

    except Exception:
        pass
    return -1


# Link types that carry raw 802.11 frames (with or without radiotap header)
_80211_LINK_TYPES = {105, 127}


def _find_nmap() -> 'str | None':
    """Locate the nmap executable, checking common Windows install paths as fallback."""
    found = shutil.which('nmap')
    if found:
        return found
    candidates = [
        r'C:\Program Files (x86)\Nmap\nmap.exe',
        r'C:\Program Files\Nmap\nmap.exe',
        '/usr/local/bin/nmap',
        '/usr/bin/nmap',
    ]
    for exe in candidates:
        if os.path.exists(exe):
            os.environ['PATH'] = os.path.dirname(exe) + os.pathsep + os.environ.get('PATH', '')
            return exe
    return None

NMAP_EXE = _find_nmap()


# SEVERITY_COLORS is imported from analyzer.base (the canonical W1CK3D SYST3MS
# ramp) so the GUI treeview tags and the HTML report never drift apart.
SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info']


# --------------------------------------------------------------------- helpers
def open_in_file_manager(path: Path):
    """Open a folder in the system file manager."""
    path = str(path)
    system = platform.system()
    try:
        if system == 'Windows':
            os.startfile(path)
        elif system == 'Darwin':
            subprocess.run(['open', path], check=False)
        else:
            subprocess.run(['xdg-open', path], check=False)
    except Exception as e:
        messagebox.showerror('Could not open folder', str(e))


def fmt_bytes(n):
    n = float(n or 0)
    for unit in ('B', 'KB', 'MB', 'GB'):
        if n < 1024:
            return f'{n:.1f} {unit}'
        n /= 1024
    return f'{n:.1f} TB'


def fmt_timestamp(iso):
    if not iso:
        return ''
    # "2026-04-20T21:30:45" -> "2026-04-20 21:30"
    return iso.replace('T', ' ')[:16]


# =========================================================== progress dialog
class ProgressDialog(tk.Toplevel):
    """Modal window shown during background analysis."""

    def __init__(self, parent, filename):
        super().__init__(parent)
        self.title('Analyzing capture')
        self.geometry('440x140')
        self.transient(parent)
        self.resizable(False, False)
        self.grab_set()
        # Disable the close button — user must wait for analysis to finish
        self.protocol('WM_DELETE_WINDOW', lambda: None)

        frame = ttk.Frame(self, padding=20)
        frame.pack(fill='both', expand=True)

        ttk.Label(frame,
                  text=f'Analyzing {filename}',
                  font=('TkDefaultFont', 11, 'bold')).pack(anchor='w')

        self.message_var = tk.StringVar(value='Starting…')
        ttk.Label(frame, textvariable=self.message_var,
                  foreground=C['muted']).pack(anchor='w', pady=(8, 12))

        self.progress = ttk.Progressbar(frame, mode='indeterminate', length=400)
        self.progress.pack()
        self.progress.start(12)

        # Center over parent
        self.update_idletasks()
        px = parent.winfo_rootx() + parent.winfo_width() // 2 - self.winfo_width() // 2
        py = parent.winfo_rooty() + parent.winfo_height() // 2 - self.winfo_height() // 2
        self.geometry(f'+{px}+{py}')

    def set_message(self, msg):
        self.message_var.set(msg)


# ======================================================= live capture dialog
class LiveCaptureDialog(tk.Toplevel):
    """
    Live capture dialog with focused scan modes, extended durations, and BLE support.
    Runs tshark with a mode-appropriate BPF capture filter and shows a live size counter.
    """

    _DURATIONS = [
        ('30 seconds',    30),
        ('1 minute',      60),
        ('2 minutes',    120),
        ('5 minutes',    300),
        ('10 minutes',   600),
        ('15 minutes',   900),
        ('30 minutes',  1800),
        ('1 hour',      3600),
    ]

    _SCAN_MODES = [
        {
            'id': 'full',
            'label': 'Full Capture — All Traffic',
            'desc': ('Captures everything on the selected interface with no filter. '
                     'Best starting point for general network analysis.'),
            'filter': None,
            'warn': None,
        },
        {
            'id': 'remote_access',
            'label': 'Remote Access Threats',
            'desc': ('Monitors SSH (22), RDP (3389), VNC (5900-5903), Telnet (23), and common '
                     'backdoor ports. Detects brute-force attempts and unusual remote control activity.'),
            'filter': ('tcp port 22 or tcp port 23 or tcp port 3389 or '
                       'tcp port 5900 or tcp port 5901 or tcp port 5902 or '
                       'tcp port 5903 or tcp port 4444 or tcp port 6667'),
            'warn': None,
        },
        {
            'id': 'wireless_threats',
            'label': 'Wireless Threats — Deauth / Probe Flood',
            'desc': ('Captures raw 802.11 management frames. Detects deauthentication attacks '
                     '(used to disconnect devices), disassociation floods, and probe request '
                     'sweeps used by wireless scanners.'),
            'filter': None,
            'warn': ('Requires a WiFi adapter in monitor mode.\n'
                     'Linux (Kali/Parrot): run  sudo airmon-ng start wlan0  then select '
                     'the wlan0mon interface from the list above. '
                     'Or:  sudo iw dev wlan0 set type monitor && sudo ip link set wlan0 up\n'
                     'Windows: install Npcap with "Support raw 802.11 traffic" enabled, '
                     'then select the monitor-mode interface from the list.'),
        },
        {
            'id': 'video',
            'label': 'Video Transmissions',
            'desc': ('Targets IP camera streams (RTSP port 554/8554), live streaming (RTMP port 1935), '
                     'RTP/RTCP media sessions, and IP multicast IPTV. '
                     'Reveals who is streaming video and where the feed is going.'),
            'filter': ('port 554 or port 8554 or port 1935 or '
                       'udp port 5004 or udp port 5005 or '
                       '(udp and ip[16] >= 224)'),
            'warn': None,
        },
        {
            'id': 'dns_broadcast',
            'label': 'DNS & Broadcast Traffic',
            'desc': ('DNS queries (what every device is looking up), ARP (who is on the network), '
                     'mDNS/Bonjour, UPnP/SSDP, and NBNS. '
                     'Reveals device enumeration, unusual outbound lookups, and rogue DHCP.'),
            'filter': ('port 53 or arp or udp port 5353 or '
                       'udp port 1900 or udp port 137 or udp port 138 or '
                       'udp port 67 or udp port 68'),
            'warn': None,
        },
        {
            'id': 'ble',
            'label': 'Bluetooth Low Energy (BLE)',
            'desc': ('Captures BLE advertising packets, connections, and device enumeration. '
                     'Select a Bluetooth LE interface from the list. '
                     'Useful for IoT device discovery and BLE security analysis.'),
            'filter': None,
            'warn': ('Select a Bluetooth or BLE interface from the interface list above. '
                     'Requires a Bluetooth adapter and Wireshark/Npcap with Bluetooth support installed.'),
        },
        {
            'id': 'custom',
            'label': 'Custom BPF Filter',
            'desc': ('Write your own Berkeley Packet Filter expression. '
                     'Examples:  "port 80"    "host 192.168.1.1 and tcp"    "icmp"    "not port 443"'),
            'filter': '__custom__',
            'warn': None,
        },
    ]

    def __init__(self, parent, on_complete_cb):
        super().__init__(parent)
        self.title('Live Capture')
        self.geometry('640x560')
        self.minsize(560, 480)
        self.transient(parent)
        self.resizable(True, False)
        self.grab_set()
        self.protocol('WM_DELETE_WINDOW', self._cancel)

        self._on_complete = on_complete_cb
        self._proc        = None
        self._timer_id    = None
        self._interfaces  = []
        self._output_file = None
        self._total_secs  = 300
        self._remaining   = 0

        self._build_ui()
        threading.Thread(target=self._load_interfaces, daemon=True).start()

    # ─────────────────────────────────────── UI construction
    def _build_ui(self):
        outer = ttk.Frame(self, padding=16)
        outer.pack(fill='both', expand=True)
        outer.columnconfigure(1, weight=1)
        r = 0

        # Interface
        ttk.Label(outer, text='Interface:',
                  font=('TkDefaultFont', 10, 'bold')).grid(
                      row=r, column=0, sticky='w', pady=(0, 4))
        self._iface_var = tk.StringVar()
        self._iface_cb  = ttk.Combobox(outer, textvariable=self._iface_var,
                                        state='readonly', width=52)
        self._iface_cb.grid(row=r, column=1, sticky='ew', padx=(8, 0), pady=(0, 4))
        r += 1

        # Duration
        ttk.Label(outer, text='Duration:',
                  font=('TkDefaultFont', 10, 'bold')).grid(
                      row=r, column=0, sticky='w', pady=(0, 8))
        self._dur_var = tk.StringVar(value='5 minutes')
        ttk.Combobox(outer, textvariable=self._dur_var, state='readonly',
                     values=[d[0] for d in self._DURATIONS],
                     width=20).grid(row=r, column=1, sticky='w', padx=(8, 0), pady=(0, 8))
        r += 1

        # Scan Mode LabelFrame
        mode_lf = ttk.LabelFrame(outer, text='Scan Mode', padding=(8, 6))
        mode_lf.grid(row=r, column=0, columnspan=2, sticky='ew', pady=(0, 6))
        r += 1

        self._mode_var = tk.StringVar(value='full')
        for mode in self._SCAN_MODES:
            ttk.Radiobutton(mode_lf, text=mode['label'],
                            variable=self._mode_var, value=mode['id'],
                            command=self._on_mode_change).pack(anchor='w', pady=1)

        # Mode description
        self._mode_desc_var = tk.StringVar()
        ttk.Label(outer, textvariable=self._mode_desc_var,
                  foreground=C['muted'], font=('TkDefaultFont', 8),
                  wraplength=570, justify='left').grid(
                      row=r, column=0, columnspan=2, sticky='w', padx=2, pady=(0, 4))
        r += 1

        # Custom BPF filter entry (hidden unless Custom mode selected)
        self._custom_frame = ttk.Frame(outer)
        self._custom_frame.grid(row=r, column=0, columnspan=2, sticky='ew', pady=(0, 4))
        ttk.Label(self._custom_frame, text='BPF filter:',
                  font=('TkDefaultFont', 9)).pack(side='left')
        self._custom_filter_var = tk.StringVar()
        ttk.Entry(self._custom_frame, textvariable=self._custom_filter_var,
                  width=55).pack(side='left', padx=(6, 0), fill='x', expand=True)
        self._custom_frame.grid_remove()
        r += 1

        # Warning label (hidden unless mode needs special setup)
        self._warn_var = tk.StringVar()
        self._warn_lbl = ttk.Label(outer, textvariable=self._warn_var,
                                   foreground=C['warning'],
                                   background=C['raised'],
                                   font=('TkDefaultFont', 8),
                                   wraplength=570, justify='left', padding=(6, 3))
        self._warn_lbl.grid(row=r, column=0, columnspan=2, sticky='ew', pady=(0, 6))
        self._warn_lbl.grid_remove()
        r += 1

        # Status + progress
        self._status_var = tk.StringVar(value='Loading interfaces…')
        ttk.Label(outer, textvariable=self._status_var,
                  foreground=C['body']).grid(
                      row=r, column=0, columnspan=2, sticky='w', pady=(4, 2))
        r += 1

        self._progress = ttk.Progressbar(outer, mode='determinate')
        self._progress.grid(row=r, column=0, columnspan=2, sticky='ew', pady=(0, 6))
        r += 1

        # Admin note (platform-specific)
        if platform.system() == 'Windows':
            _cap_note = ('Note: on Windows, tshark may need to run as Administrator '
                         'to capture on physical interfaces.')
        else:
            _cap_note = ('Note: tshark requires the "wireshark" group or root to capture. '
                         'Run the installer (install.sh) once to configure this, '
                         'or launch the app with:  sudo ./run.sh')
        ttk.Label(outer, text=_cap_note,
                  foreground=C['faint'], font=('TkDefaultFont', 8),
                  wraplength=570).grid(row=r, column=0, columnspan=2,
                                       sticky='w', pady=(0, 10))
        r += 1

        # Buttons
        btn_row = ttk.Frame(outer)
        btn_row.grid(row=r, column=0, columnspan=2, sticky='e')
        ttk.Button(btn_row, text='Cancel',
                   command=self._cancel).pack(side='left', padx=(0, 8))
        self._start_btn = ttk.Button(btn_row, text='  ▶  Start Capture  ',
                                     command=self._start, state='disabled')
        self._start_btn.pack(side='left')

        # Init description text
        self._on_mode_change()

        # Center over parent
        self.update_idletasks()
        p = self.master
        px = p.winfo_rootx() + p.winfo_width()  // 2 - self.winfo_width()  // 2
        py = p.winfo_rooty() + p.winfo_height() // 2 - self.winfo_height() // 2
        self.geometry(f'+{px}+{py}')

    def _on_mode_change(self):
        mode_id = self._mode_var.get()
        mode    = next((m for m in self._SCAN_MODES if m['id'] == mode_id), None)
        if not mode:
            return
        self._mode_desc_var.set(mode['desc'])
        if mode['filter'] == '__custom__':
            self._custom_frame.grid()
        else:
            self._custom_frame.grid_remove()
        if mode.get('warn'):
            self._warn_var.set(f'⚠  {mode["warn"]}')
            self._warn_lbl.grid()
        else:
            self._warn_lbl.grid_remove()

    def _get_capture_filter(self) -> 'str | None':
        mode_id = self._mode_var.get()
        mode    = next((m for m in self._SCAN_MODES if m['id'] == mode_id), None)
        if not mode:
            return None
        f = mode.get('filter')
        if f == '__custom__':
            return self._custom_filter_var.get().strip() or None
        return f

    # ─────────────────────────────────────── interface discovery
    def _load_interfaces(self):
        try:
            result = subprocess.run(
                ['tshark', '-D'],
                capture_output=True, text=True, timeout=10,
            )
            interfaces = []
            for line in result.stdout.strip().splitlines():
                m = re.match(r'^(\d+)\.\s+(.+)$', line.strip())
                if not m:
                    continue
                num  = m.group(1)
                rest = m.group(2)
                friendly = re.search(r'\((.+)\)$', rest)
                name = friendly.group(1) if friendly else rest
                interfaces.append((num, name))
            self.after(0, lambda: self._set_interfaces(interfaces))
        except Exception as e:
            self.after(0, lambda msg=str(e):
                       self._status_var.set(f'Could not list interfaces: {msg}'))

    def _set_interfaces(self, interfaces):
        if not interfaces:
            self._status_var.set(
                'No interfaces found. Make sure tshark/Wireshark is installed and on PATH.')
            return
        self._interfaces = interfaces

        def _tag(name: str) -> str:
            n = name.lower()
            if any(x in n for x in ('bluetooth', 'ble', 'bt', 'bthle')):
                return '[BLE] '
            if any(x in n for x in ('wi-fi', 'wifi', 'wireless', 'wlan', '802.11', 'airport')):
                return '[WiFi] '
            if any(x in n for x in ('ethernet', 'eth', 'local area', 'realtek', 'intel(r) ethernet')):
                return '[ETH] '
            return ''

        display = [f'{num}. {_tag(name)}{name}' for num, name in interfaces]
        self._iface_cb['values'] = display
        self._iface_cb.current(0)
        self._status_var.set('Ready — select an interface, mode, and duration.')
        self._start_btn.config(state='normal')

    # ─────────────────────────────────────── capture control
    def _start(self):
        sel = self._iface_cb.current()
        if sel < 0 or sel >= len(self._interfaces):
            return
        iface_num = self._interfaces[sel][0]

        dur_label = self._dur_var.get()
        secs = next((d[1] for d in self._DURATIONS if d[0] == dur_label), 300)
        self._total_secs = secs
        self._remaining  = secs

        captures_dir = Path.home() / 'W1CK3DWizard' / 'captures'
        captures_dir.mkdir(parents=True, exist_ok=True)
        ts      = datetime.now().strftime('%Y%m%d_%H%M%S')
        mode_id = self._mode_var.get()
        self._output_file = str(captures_dir / f'live_{mode_id}_{ts}.pcap')

        self._start_btn.config(state='disabled')
        self._iface_cb.config(state='disabled')
        self._progress.config(maximum=secs, value=0)
        self._tick()

        cmd = ['tshark', '-i', iface_num,
               '-a', f'duration:{secs}',
               '-w', self._output_file]

        cap_filter = self._get_capture_filter()
        if cap_filter:
            cmd += ['-f', cap_filter]

        def worker():
            try:
                self._proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                self._proc.wait()
                self.after(0, self._capture_done)
            except Exception as e:
                self.after(0, lambda msg=str(e): self._capture_error(msg))

        threading.Thread(target=worker, daemon=True).start()

    def _tick(self):
        if self._remaining <= 0:
            return
        elapsed = self._total_secs - self._remaining
        self._progress['value'] = elapsed
        m, s = divmod(self._remaining, 60)

        # Live file-size indicator so the user knows data is being captured
        size_str = ''
        if self._output_file:
            try:
                sz = os.path.getsize(self._output_file)
                if sz >= 1_048_576:
                    size_str = f'  •  {sz / 1_048_576:.1f} MB captured'
                elif sz >= 1024:
                    size_str = f'  •  {sz // 1024} KB captured'
                elif sz > 0:
                    size_str = f'  •  {sz} B captured'
            except OSError:
                pass

        self._status_var.set(f'Capturing…  {m:02d}:{s:02d} remaining{size_str}')
        self._remaining -= 1
        self._timer_id = self.after(1000, self._tick)

    def _capture_done(self):
        if self._timer_id:
            self.after_cancel(self._timer_id)
        self._status_var.set('Capture complete — starting analysis…')
        self.after(300, self._finish)

    def _finish(self):
        path = self._output_file
        self.destroy()
        if path:
            self._on_complete(path)

    def _capture_error(self, msg):
        if self._timer_id:
            self.after_cancel(self._timer_id)
        self._status_var.set(f'Error: {msg}')
        self._start_btn.config(state='normal')
        self._iface_cb.config(state='readonly')

    def _cancel(self):
        if self._proc and self._proc.poll() is None:
            try:
                self._proc.terminate()
            except Exception:
                pass
        if self._timer_id:
            self.after_cancel(self._timer_id)
        self.destroy()


# ========================================================= compare dialog
def _ext_pct(net: dict) -> int:
    total = net.get('internal_packets', 0) + net.get('external_packets', 0)
    return round(100 * net.get('external_packets', 0) / total) if total else 0


class CompareDialog(tk.Toplevel):
    """
    Diff two saved reports: new/resolved findings, new/removed devices, traffic delta.
    Can be opened from the File menu or by right-clicking a report.
    """

    def __init__(self, parent, store, preselect_id=None):
        super().__init__(parent)
        self.title('Compare Reports')
        self.geometry('820x660')
        self.transient(parent)
        self.minsize(640, 480)
        self._store = store

        reports = store.list_all()
        self._report_ids = [r['id'] for r in reports]

        def _lbl(r):
            ts  = fmt_timestamp(r.get('timestamp', ''))
            fn  = r.get('original_filename', r['id'])
            nd  = r.get('device_count', 0)
            nf  = r.get('total_findings', 0)
            return f'{fn}   {ts}   {nd} dev · {nf} findings'

        labels = [_lbl(r) for r in reports]

        # ---- controls ----
        ctrl = ttk.Frame(self, padding=(16, 12, 16, 4))
        ctrl.pack(fill='x')
        ctrl.columnconfigure(1, weight=1)

        ttk.Label(ctrl, text='Before (baseline):',
                  font=('TkDefaultFont', 10, 'bold')).grid(
                      row=0, column=0, sticky='w', padx=(0, 10))
        self._before_var = tk.StringVar()
        self._before_cb  = ttk.Combobox(ctrl, textvariable=self._before_var,
                                         values=labels, state='readonly', width=72)
        self._before_cb.grid(row=0, column=1, sticky='ew')

        ttk.Label(ctrl, text='After (compare to):',
                  font=('TkDefaultFont', 10, 'bold')).grid(
                      row=1, column=0, sticky='w', padx=(0, 10), pady=(6, 0))
        self._after_var = tk.StringVar()
        self._after_cb  = ttk.Combobox(ctrl, textvariable=self._after_var,
                                        values=labels, state='readonly', width=72)
        self._after_cb.grid(row=1, column=1, sticky='ew', pady=(6, 0))

        ttk.Button(ctrl, text='  Compare  ',
                   command=self._run).grid(row=2, column=1, sticky='e', pady=(10, 4))

        # ---- results text ----
        res_frame = ttk.Frame(self)
        res_frame.pack(fill='both', expand=True, padx=16, pady=(0, 12))

        self._t = tk.Text(res_frame, wrap='word', font=('TkDefaultFont', 10),
                          relief='flat', padx=10, pady=10,
                          background=self.cget('bg'))
        vsb = ttk.Scrollbar(res_frame, orient='vertical', command=self._t.yview)
        self._t.configure(yscrollcommand=vsb.set)
        self._t.pack(side='left', fill='both', expand=True)
        vsb.pack(side='right', fill='y')
        self._t.config(state='disabled')

        self._t.tag_configure('h1',      font=('TkDefaultFont', 13, 'bold'), spacing3=6)
        self._t.tag_configure('h2',      font=('TkDefaultFont', 11, 'bold'),
                                          spacing1=14, spacing3=4)
        self._t.tag_configure('label',   foreground=C['muted'],
                                          font=('TkDefaultFont', 9, 'bold'))
        self._t.tag_configure('body',    spacing3=3)
        self._t.tag_configure('divider', foreground=C['line'])
        self._t.tag_configure('tip',     foreground=C['faint'],
                                          font=('TkDefaultFont', 9),
                                          lmargin1=6, lmargin2=6)
        self._t.tag_configure('resolved',   foreground=C['secure'],
                                             font=('TkDefaultFont', 9, 'bold'))
        self._t.tag_configure('new_bad',    foreground=C['critical'],
                                             font=('TkDefaultFont', 9, 'bold'))
        self._t.tag_configure('new_device', foreground=C['secure'],
                                             font=('TkDefaultFont', 9))
        self._t.tag_configure('removed',    foreground=C['faint'],
                                             font=('TkDefaultFont', 9))
        self._t.tag_configure('persists',   foreground=C['muted'],
                                             font=('TkDefaultFont', 9))
        self._t.tag_configure('improved',   foreground=C['secure'],
                                             font=('TkDefaultFont', 12, 'bold'))
        self._t.tag_configure('worse',      foreground=C['critical'],
                                             font=('TkDefaultFont', 12, 'bold'))
        self._t.tag_configure('neutral',    foreground=C['muted'],
                                             font=('TkDefaultFont', 12, 'bold'))
        for sev, color in SEVERITY_COLORS.items():
            self._t.tag_configure(f'sev_{sev}', foreground=color,
                                   font=('TkDefaultFont', 9, 'bold'))

        # ---- pre-select sensible defaults ----
        if len(reports) >= 2:
            if preselect_id and preselect_id in self._report_ids:
                ai = self._report_ids.index(preselect_id)
                bi = ai + 1 if ai + 1 < len(reports) else 0
            else:
                bi, ai = 1, 0   # second-newest = before, newest = after
            self._before_cb.current(bi)
            self._after_cb.current(ai)

        # ---- center ----
        self.update_idletasks()
        px = parent.winfo_rootx() + parent.winfo_width()  // 2 - self.winfo_width()  // 2
        py = parent.winfo_rooty() + parent.winfo_height() // 2 - self.winfo_height() // 2
        self.geometry(f'+{px}+{py}')

        if len(reports) >= 2:
            self.after(120, self._run)

    # ---------------------------------------------------------------- compare
    def _run(self):
        bi = self._before_cb.current()
        ai = self._after_cb.current()
        if bi < 0 or ai < 0:
            return
        if bi == ai:
            messagebox.showinfo('Same report',
                                'Please choose two different reports to compare.',
                                parent=self)
            return
        try:
            base_r = json.loads(self._store.json_path(self._report_ids[bi]).read_text())
            new_r  = json.loads(self._store.json_path(self._report_ids[ai]).read_text())
            base_m = self._store.get(self._report_ids[bi]) or {}
            new_m  = self._store.get(self._report_ids[ai])  or {}
        except Exception as e:
            messagebox.showerror('Load error', str(e), parent=self)
            return
        self._render(base_r, new_r, base_m, new_m)

    def _render(self, base_r, new_r, base_m, new_m):
        DIV = '━' * 56

        # ── Device diff ───────────────────────────────────────────────────
        base_devs = {d['mac']: d for d in base_r['devices']['devices'] if d.get('mac')}
        new_devs  = {d['mac']: d for d in new_r['devices']['devices']  if d.get('mac')}

        added_macs   = sorted(set(new_devs) - set(base_devs))
        removed_macs = sorted(set(base_devs) - set(new_devs))
        n_unchanged  = len(set(base_devs) & set(new_devs))

        # ── Finding diff ──────────────────────────────────────────────────
        def fkey(f):
            return (f['title'].strip(), f['category'].strip())

        base_finds = {fkey(f): f for f in base_r['threats'].get('findings', [])}
        new_finds  = {fkey(f): f for f in new_r['threats'].get('findings',  [])}

        new_keys      = sorted(set(new_finds) - set(base_finds))
        resolved_keys = sorted(set(base_finds) - set(new_finds))
        persists_n    = len(set(base_finds) & set(new_finds))

        # ── Overall verdict ───────────────────────────────────────────────
        new_crit_high = [k for k in new_keys
                         if new_finds[k]['severity'] in ('critical', 'high')]
        net_delta = len(new_keys) - len(resolved_keys)

        if new_crit_high:
            verdict, verdict_text = 'worse', (
                f'WORSE — {len(new_crit_high)} new critical/high '
                f'finding{"s" if len(new_crit_high) != 1 else ""} appeared')
        elif net_delta < 0:
            n = len(resolved_keys)
            verdict, verdict_text = 'improved', (
                f'IMPROVED — {n} finding{"s" if n != 1 else ""} resolved')
        elif net_delta > 0:
            n = len(new_keys)
            verdict, verdict_text = 'worse', (
                f'WORSE — {n} new finding{"s" if n != 1 else ""} appeared')
        elif added_macs:
            verdict, verdict_text = 'neutral', (
                f'MINOR CHANGES — {len(added_macs)} new device'
                f'{"s" if len(added_macs) != 1 else ""}, no new findings')
        elif removed_macs:
            verdict, verdict_text = 'neutral', 'MINOR CHANGES — devices left the network'
        else:
            verdict, verdict_text = 'neutral', 'UNCHANGED — no significant differences'

        # ── Build output ──────────────────────────────────────────────────
        t = self._t
        t.config(state='normal')
        t.delete('1.0', 'end')

        t.insert('end', 'Report Comparison\n', 'h1')
        t.insert('end', DIV + '\n', 'divider')
        t.insert('end', '  Before:  ', 'label')
        t.insert('end',
                 f'{base_m.get("original_filename","?")}   '
                 f'{fmt_timestamp(base_m.get("timestamp",""))}   '
                 f'{base_m.get("device_count",0)} devices · '
                 f'{base_m.get("total_findings",0)} findings\n', 'body')
        t.insert('end', '  After:   ', 'label')
        t.insert('end',
                 f'{new_m.get("original_filename","?")}   '
                 f'{fmt_timestamp(new_m.get("timestamp",""))}   '
                 f'{new_m.get("device_count",0)} devices · '
                 f'{new_m.get("total_findings",0)} findings\n', 'body')
        t.insert('end', '\n  Overall: ', 'label')
        t.insert('end', verdict_text + '\n', verdict)

        # ── Findings section ──────────────────────────────────────────────
        t.insert('end', '\n' + DIV + '\n', 'divider')
        t.insert('end', '  Findings\n', 'h2')
        t.insert('end', DIV + '\n', 'divider')

        parts = []
        if new_keys:      parts.append(f'+{len(new_keys)} new')
        if resolved_keys: parts.append(f'−{len(resolved_keys)} resolved')
        parts.append(f'{persists_n} unchanged')
        t.insert('end', '\n  ' + '  ·  '.join(parts) + '\n', 'label')

        if resolved_keys:
            t.insert('end', '\n  Resolved  (fixed between captures)\n', 'label')
            for k in resolved_keys:
                f = base_finds[k]
                t.insert('end', '  ✓  ', 'resolved')
                t.insert('end', f'{f["title"]}  ', 'resolved')
                t.insert('end', f'was {f["severity"].upper()}\n',
                         f'sev_{f["severity"]}')

        if new_keys:
            t.insert('end', '\n  New  (appeared in After)\n', 'label')
            for k in new_keys:
                f = new_finds[k]
                t.insert('end', '  ✗  ', 'new_bad')
                t.insert('end', f'{f["title"]}  ', 'new_bad')
                t.insert('end', f'{f["severity"].upper()}\n',
                         f'sev_{f["severity"]}')

        if persists_n:
            t.insert('end',
                     f'\n  {persists_n} finding{"s" if persists_n != 1 else ""} '
                     f'present in both captures.\n', 'persists')

        if not new_keys and not resolved_keys and not persists_n:
            t.insert('end', '\n  Both captures are finding-free.\n', 'resolved')

        # ── Devices section ───────────────────────────────────────────────
        t.insert('end', '\n' + DIV + '\n', 'divider')
        t.insert('end', '  Devices\n', 'h2')
        t.insert('end', DIV + '\n', 'divider')

        dev_parts = []
        if added_macs:   dev_parts.append(f'+{len(added_macs)} new')
        if removed_macs: dev_parts.append(f'−{len(removed_macs)} removed')
        dev_parts.append(f'{n_unchanged} unchanged')
        t.insert('end', '\n  ' + '  ·  '.join(dev_parts) + '\n', 'label')

        if added_macs:
            t.insert('end', '\n  New devices  (appeared in After)\n', 'label')
            for mac in added_macs:
                d    = new_devs[mac]
                ips  = ', '.join(d.get('ip_addresses', []))
                host = ', '.join(d.get('hostnames', []))
                line = f'  +  {d.get("likely_type","Unknown")}   MAC {mac}'
                if ips:  line += f'   IP {ips}'
                if host: line += f'   ({host})'
                t.insert('end', line + '\n', 'new_device')

        if removed_macs:
            t.insert('end', '\n  Removed devices  (only in Before)\n', 'label')
            for mac in removed_macs:
                d   = base_devs[mac]
                ips = ', '.join(d.get('ip_addresses', []))
                line = f'  −  {d.get("likely_type","Unknown")}   MAC {mac}'
                if ips: line += f'   IP {ips}'
                t.insert('end', line + '\n', 'removed')

        if not added_macs and not removed_macs:
            t.insert('end', '\n  Device list is identical between the two captures.\n',
                     'persists')

        # ── Traffic section ───────────────────────────────────────────────
        t.insert('end', '\n' + DIV + '\n', 'divider')
        t.insert('end', '  Traffic\n', 'h2')
        t.insert('end', DIV + '\n', 'divider')

        base_net = base_r.get('network', {})
        new_net  = new_r.get('network', {})
        bep      = _ext_pct(base_net)
        nep      = _ext_pct(new_net)

        t.insert('end', '\n  External traffic:  ', 'label')
        pct_line = f'{bep}% → {nep}%'
        if nep > bep:
            t.insert('end', pct_line + '  (increased)\n', 'new_bad')
        elif nep < bep:
            t.insert('end', pct_line + '  (decreased)\n', 'resolved')
        else:
            t.insert('end', pct_line + '\n', 'body')

        t.insert('end', '  Outbound data:    ', 'label')
        t.insert('end',
                 f'{fmt_bytes(base_net.get("bytes_external", 0))} → '
                 f'{fmt_bytes(new_net.get("bytes_external", 0))}\n', 'body')

        base_ext = {ip for ip, _ in (base_net.get('top_external_ips') or [])}
        new_ext  = {ip for ip, _ in (new_net.get('top_external_ips')  or [])}
        new_dest = sorted(new_ext - base_ext)
        gone_dest = sorted(base_ext - new_ext)

        if new_dest:
            t.insert('end',
                     f'\n  New external destinations (+{len(new_dest)}):\n',
                     'label')
            for ip in new_dest[:10]:
                t.insert('end', f'    •  {ip}\n', 'new_bad')
            if len(new_dest) > 10:
                t.insert('end', f'    … and {len(new_dest)-10} more\n', 'tip')

        if gone_dest:
            t.insert('end',
                     f'\n  Destinations no longer seen (−{len(gone_dest)}):\n',
                     'label')
            for ip in gone_dest[:8]:
                t.insert('end', f'    •  {ip}\n', 'removed')

        t.insert('end',
                 '\n  Tip: load either report individually for full details '
                 'and per-finding recommendations.\n', 'tip')

        t.config(state='disabled')
        t.see('1.0')


# ================================================================= scan wizard

class ScanTaskWizard(tk.Toplevel):
    """
    Multi-step nmap scan wizard with plain-English result interpretation.

    Left panel:  numbered step list with live status icons.
    Right panel: step description, command preview, raw output log,
                 rich findings panel (device ID, port explanations,
                 topology, issues + fixes), and a pre-built recommended
                 next-scan command ready to run.
    """

    _ICON  = {'pending': '○', 'running': '▶', 'done': '✓', 'error': '✗'}
    _ICLR  = {'pending': C['faint'], 'running': C['info'],
               'done': C['secure'],   'error':   C['critical']}

    def __init__(self, parent, profile: dict, target: str):
        super().__init__(parent)
        self.title(f'Scan Task — {profile["label"]}')
        self.geometry('1080x720')
        self.minsize(800, 560)
        self.resizable(True, True)
        self.transient(parent)

        self._app              = parent
        self._profile          = profile
        self._target           = target
        self._steps            = profile['steps']
        self._context          = {'open_ports': '', 'hosts': []}
        self._status           = ['pending'] * len(self._steps)
        self._cur              = 0
        self._cancelled        = False
        self._left_panel       = None   # set in _build_ui
        self._next_steps_shown = False  # guard so panel is only built once
        self._ns_container    = None   # container frame rebuilt by _refresh_next_steps
        self._completed_recs  = []     # ordered list of finished next-step rec dicts
        self._done_rec_labels = set()  # labels of all completed next-step scans

        self._build_ui()
        self._select_step(0)

    # ── UI construction ───────────────────────────────────────────────────────

    def _build_ui(self):
        main = ttk.PanedWindow(self, orient='horizontal')
        main.pack(fill='both', expand=True, padx=8, pady=(8, 0))

        # ── Left: step list
        left = ttk.Frame(main, width=240)
        left.pack_propagate(False)
        main.add(left, weight=0)
        self._left_panel = left

        ttk.Label(left, text='Steps',
                  font=('TkDefaultFont', 10, 'bold')).pack(anchor='w', padx=8, pady=(4, 8))

        self._icon_lbls = []
        self._step_lbls = []
        for i, step in enumerate(self._steps):
            row = ttk.Frame(left)
            row.pack(fill='x', padx=6, pady=2)
            icon = ttk.Label(row, text=self._ICON['pending'], width=2,
                             foreground=self._ICLR['pending'])
            icon.pack(side='left')
            lbl = ttk.Label(row, text=step['label'], wraplength=180,
                            justify='left', foreground=C['body'])
            lbl.pack(side='left', padx=(2, 0))
            self._icon_lbls.append(icon)
            self._step_lbls.append(lbl)
            for w in (row, lbl):
                w.bind('<Button-1>', lambda e, idx=i: self._select_step(idx))

        ttk.Separator(left, orient='horizontal').pack(fill='x', pady=8)
        ttk.Label(left, text='Target', foreground=C['muted'],
                  font=('TkDefaultFont', 8, 'bold')).pack(anchor='w', padx=8)
        ttk.Label(left, text=self._target, font=('Courier', 9),
                  foreground=C['accent_glow'], wraplength=210).pack(anchor='w', padx=8)

        ttk.Separator(left, orient='horizontal').pack(fill='x', pady=8)
        for state, icon in self._ICON.items():
            lr = ttk.Frame(left)
            lr.pack(anchor='w', padx=8, pady=1)
            ttk.Label(lr, text=icon, foreground=self._ICLR[state], width=3).pack(side='left')
            ttk.Label(lr, text=state.capitalize(), foreground=C['muted'],
                      font=('TkDefaultFont', 8)).pack(side='left')

        # ── Right: vertical split — top log / bottom analysis
        right = ttk.Frame(main)
        main.add(right, weight=1)

        # Fixed header section
        hdr = ttk.Frame(right)
        hdr.pack(fill='x')

        self._header_var = tk.StringVar()
        ttk.Label(hdr, textvariable=self._header_var,
                  font=('TkDefaultFont', 12, 'bold')).pack(anchor='w', pady=(4, 2))

        self._desc_var = tk.StringVar()
        ttk.Label(hdr, textvariable=self._desc_var, foreground=C['muted'],
                  wraplength=780, justify='left').pack(anchor='w', pady=(0, 4))

        cmd_row = ttk.Frame(hdr)
        cmd_row.pack(fill='x', pady=(0, 4))
        ttk.Label(cmd_row, text='Running: ', foreground=C['muted'],
                  font=('TkDefaultFont', 9)).pack(side='left')
        self._cmd_var = tk.StringVar()
        ttk.Label(cmd_row, textvariable=self._cmd_var, font=('Courier', 9),
                  foreground=C['body']).pack(side='left')

        ttk.Separator(right, orient='horizontal').pack(fill='x', pady=(0, 4))

        # ── Fixed footer — must be packed BEFORE the expanding vpane so it is
        #    always visible.  Contains the recommendation bar (hidden until a
        #    step finishes) and the persistent action buttons.
        footer = ttk.Frame(right)
        footer.pack(fill='x', side='bottom', pady=(4, 0))

        # Action button row
        self._btn_row = ttk.Frame(footer)
        btn_row = self._btn_row
        btn_row.pack(fill='x', pady=(4, 6))

        self._run_btn = ttk.Button(btn_row, text='  Run this step  ',
                                   command=self._run_current_step)
        self._run_btn.pack(side='left')

        self._next_btn = ttk.Button(btn_row, text='  Next step  ',
                                    command=self._advance_step, state='disabled')
        self._next_btn.pack(side='left', padx=(8, 0))

        self._status_lbl = ttk.Label(btn_row, text='Ready.',
                                     foreground=C['muted'])
        self._status_lbl.pack(side='left', padx=(12, 0))

        ttk.Button(btn_row, text='Close', command=self._close).pack(side='right')

        # ── Vertical PanedWindow: raw log (top) + analysis (bottom)
        # Packed AFTER footer so it fills only the remaining space.
        vpane = ttk.PanedWindow(right, orient='vertical')
        vpane.pack(fill='both', expand=True)

        # Raw output log
        log_frame = ttk.LabelFrame(vpane, text='Raw nmap Output', padding=4)
        vpane.add(log_frame, weight=1)

        self._log = tk.Text(log_frame, wrap='word', font=('Courier', 9),
                            relief='flat', padx=4, pady=4,
                            background=C['inset'], foreground=C['strong'],
                            state='disabled')
        log_vsb = ttk.Scrollbar(log_frame, orient='vertical', command=self._log.yview)
        self._log.configure(yscrollcommand=log_vsb.set)
        self._log.pack(side='left', fill='both', expand=True)
        log_vsb.pack(side='right', fill='y')

        self._log.tag_configure('info', foreground=C['info'], font=('Courier', 9, 'bold'))
        self._log.tag_configure('grey', foreground=C['faint'], font=('Courier', 9))
        self._log.tag_configure('ok',   foreground=C['secure'], font=('TkDefaultFont', 9, 'bold'))
        self._log.tag_configure('raw',  font=('Courier', 9), foreground=C['body'],
                                lmargin1=4, lmargin2=4)

        # Plain-English analysis panel
        analysis_frame = ttk.LabelFrame(vpane, text='Plain-English Analysis', padding=4)
        vpane.add(analysis_frame, weight=2)

        self._analysis = tk.Text(analysis_frame, wrap='word', font=('TkDefaultFont', 9),
                                 relief='flat', padx=6, pady=6,
                                 background=C['inset'], state='disabled')
        av = ttk.Scrollbar(analysis_frame, orient='vertical', command=self._analysis.yview)
        self._analysis.configure(yscrollcommand=av.set)
        self._analysis.pack(side='left', fill='both', expand=True)
        av.pack(side='right', fill='y')

        # Text tags for analysis panel
        self._analysis.tag_configure('section',  font=('TkDefaultFont', 10, 'bold'),
                                     foreground=C['strong'], spacing1=12, spacing3=4)
        self._analysis.tag_configure('subsec',   font=('TkDefaultFont', 9, 'bold'),
                                     foreground=C['body'], spacing1=6, spacing3=2)
        self._analysis.tag_configure('body',     font=('TkDefaultFont', 9), spacing3=2)
        self._analysis.tag_configure('indent',   font=('TkDefaultFont', 9),
                                     lmargin1=20, lmargin2=20, spacing3=2)
        self._analysis.tag_configure('cmd',      font=('Courier', 9), foreground=C['accent_glow'],
                                     lmargin1=20, lmargin2=20, background=C['inset'], spacing3=4)
        self._analysis.tag_configure('HIGH',     foreground=C['critical'],
                                     font=('TkDefaultFont', 9, 'bold'))
        self._analysis.tag_configure('MEDIUM',   foreground=C['warning'],
                                     font=('TkDefaultFont', 9, 'bold'))
        self._analysis.tag_configure('LOW',      foreground=C['info'],
                                     font=('TkDefaultFont', 9, 'bold'))
        self._analysis.tag_configure('NONE',     foreground=C['secure'],
                                     font=('TkDefaultFont', 9))
        self._analysis.tag_configure('UNKNOWN',  foreground=C['accent_glow'],
                                     font=('TkDefaultFont', 9, 'bold'))
        self._analysis.tag_configure('ok',       foreground=C['secure'],
                                     font=('TkDefaultFont', 9))
        self._analysis.tag_configure('warn',     foreground=C['critical'],
                                     font=('TkDefaultFont', 9))
        self._analysis.tag_configure('issue_hdr', foreground=C['warning'],
                                     font=('TkDefaultFont', 9, 'bold'), spacing1=6)
        self._analysis.tag_configure('rec_hdr',  foreground=C['accent_glow'],
                                     font=('TkDefaultFont', 9, 'bold'), spacing1=8)

    # ── Step selection ────────────────────────────────────────────────────────

    def _select_step(self, idx: int):
        if idx >= len(self._steps):
            return
        self._cur = idx
        step = self._steps[idx]

        for i, lbl in enumerate(self._step_lbls):
            bold = i == idx
            lbl.configure(
                font=('TkDefaultFont', 9, 'bold') if bold else ('TkDefaultFont', 9),
                foreground=C['strong'] if bold else C['body'],
            )

        self._header_var.set(step['label'])
        self._desc_var.set(step.get('description', ''))

        args   = build_step_args(step, self._context)
        target = self._get_target(step)
        self._cmd_var.set('nmap ' + ' '.join(args) + ' ' + target)

        st = self._status[idx]
        if st == 'done':
            self._run_btn.config(text=f'  Re-run Step {idx + 1}  ', state='normal')
        elif st == 'running':
            self._run_btn.config(text='  Running…  ', state='disabled')
        else:
            # Pending — write a "ready" briefing into the analysis panel
            self._run_btn.config(
                text=f'  ▶  Run Step {idx + 1}: {step["label"]}  ', state='normal')
            self._status_lbl.config(
                text=f'Step {idx + 1} ready — click the Run button to start the scan.')
            self._show_step_ready(idx, step, args, target)

        has_next   = idx < len(self._steps) - 1
        next_ready = self._status[idx] == 'done' and has_next
        if next_ready:
            next_label = self._steps[idx + 1]['label']
            self._next_btn.config(
                state='normal',
                text=f'  ▶  Run Step {idx + 2}: {next_label}  ')
        else:
            self._next_btn.config(
                state='disabled',
                text='  Scan complete  ' if not has_next else '  (complete this step first)  ')

    def _get_target(self, step: dict) -> str:
        if step.get('target_from_hosts') and self._context.get('hosts'):
            return ' '.join(self._context['hosts'])
        return self._target

    def _show_step_ready(self, idx: int, step: dict, args: list, target: str):
        """Write a ready-to-run briefing into the analysis panel for a pending step."""
        t = self._analysis
        t.config(state='normal')
        t.delete('1.0', 'end')

        total = len(self._steps)
        t.insert('end', f'STEP {idx + 1} OF {total} — READY TO SCAN\n', 'section')
        t.insert('end', f'  {step["label"]}\n\n', 'subsec')

        desc = step.get('description', '')
        if desc:
            t.insert('end', f'  {desc}\n\n', 'body')

        t.insert('end', 'COMMAND THAT WILL RUN\n', 'section')
        t.insert('end', f'  nmap {" ".join(args)} {target}\n\n', 'cmd')

        # Explain what this step is looking for
        parse_mode = step.get('parse', 'ports')
        mode_desc = {
            'hosts':    'This scan looks for live hosts on the network — who is online.',
            'ports':    'This scan checks which network ports are open on the target.',
            'services': 'This scan identifies the exact software and version running on each port.',
            'os':       'This scan attempts to identify the operating system of the target.',
            'vulns':    'This scan checks for known security vulnerabilities on the target.',
        }.get(parse_mode, 'This step gathers information about the target.')
        t.insert('end', 'WHAT THIS STEP DOES\n', 'section')
        t.insert('end', f'  {mode_desc}\n\n', 'body')

        if idx == 0:
            t.insert('end', 'HOW TO START\n', 'section')
            t.insert('end',
                     f'  Click  ▶ Run Step 1: {step["label"]}  below to begin.\n'
                     f'  Results and plain-English analysis will appear here when the scan finishes.\n',
                     'indent')
        else:
            t.insert('end', 'CONTEXT FROM PREVIOUS STEPS\n', 'section')
            if self._context.get('open_ports'):
                t.insert('end',
                         f'  Ports carried forward: {self._context["open_ports"]}\n', 'body')
            if self._context.get('hosts'):
                t.insert('end',
                         f'  Hosts carried forward: {", ".join(self._context["hosts"])}\n',
                         'body')
            t.insert('end',
                     f'\n  Click  ▶ Run Step {idx + 1}: {step["label"]}  below to begin.\n',
                     'indent')

        t.config(state='disabled')

    # ── Step execution ────────────────────────────────────────────────────────

    def _run_current_step(self):
        if not NMAP_EXE:
            messagebox.showerror('nmap not found',
                                 'nmap is not installed or not on your PATH.\n'
                                 'Download from nmap.org and ensure it is on PATH.',
                                 parent=self)
            return

        idx  = self._cur
        step = self._steps[idx]
        self._cancelled = False
        self._status[idx] = 'running'
        self._set_icon(idx, 'running')
        self._run_btn.config(text='  Running…  ', state='disabled')
        self._next_btn.config(state='disabled')
        self._status_lbl.config(text='Scan running — please wait…')

        # Clear analysis for this step
        self._analysis.config(state='normal')
        self._analysis.delete('1.0', 'end')
        self._analysis.insert('end', 'Analysis will appear here when the scan completes.\n', 'body')
        self._analysis.config(state='disabled')

        args       = build_step_args(step, self._context)
        target     = self._get_target(step)
        cmd        = [NMAP_EXE] + args + [target]
        cmd_str    = 'nmap ' + ' '.join(args) + ' ' + target
        parse_mode = step.get('parse', 'ports')

        self._log_write(f'\n$ {cmd_str}\n', 'info')
        self._log_write('Running scan — please wait…\n', 'grey')

        def worker():
            try:
                result = subprocess.run(cmd, capture_output=True, text=True,
                                        encoding='utf-8', errors='replace', timeout=600)
                out = result.stdout or result.stderr or '(no output)'
            except subprocess.TimeoutExpired:
                out = 'ERROR: Scan timed out after 10 minutes.'
            except Exception as exc:
                out = f'ERROR: {exc}'
            if not self._cancelled:
                self.after(0, lambda o=out, a=args, p=parse_mode:
                           self._step_done(idx, o, a, p))

        threading.Thread(target=worker, daemon=True).start()

    def _step_done(self, idx: int, output: str, step_args: list, parse_mode: str):
        from tools.nmap_explainer import explain_results

        self._status[idx] = 'done'
        self._set_icon(idx, 'done')
        self._status_lbl.config(text='Step complete.')
        self._log_write('\n' + output + '\n', 'raw')

        has_next = idx < len(self._steps) - 1
        explain  = {}

        try:
            parsed = parse_nmap_output(output, parse_mode)

            if parsed['open_ports']:
                self._context['open_ports'] = ','.join(
                    str(p) for p in sorted(set(parsed['open_ports'])))
            if parsed['hosts']:
                self._context['hosts'] = parsed['hosts']

            target  = self._get_target(self._steps[idx])
            explain = explain_results(parsed, output, step_args, target, parse_mode)
            self._render_analysis(parsed, explain)

            if has_next:
                self._append_transition_summary(idx, parsed)

        except Exception as exc:
            import traceback
            err_text = traceback.format_exc()
            self._log_write(f'\n[Analysis error: {exc}]\n', 'info')
            t = self._analysis
            t.config(state='normal')
            t.delete('1.0', 'end')
            t.insert('end', 'Analysis Error\n', 'section')
            t.insert('end',
                     'The scan completed but the analysis engine hit an error.\n'
                     'The raw output above is still valid.\n\n', 'body')
            t.insert('end', err_text, 'cmd')
            t.config(state='disabled')

        finally:
            # Always restore the UI so the wizard is never permanently stuck.
            if has_next:
                next_label = self._steps[idx + 1]['label']
                self._run_btn.config(text=f'  Re-run Step {idx + 1}  ', state='normal')
                self._next_btn.config(
                    text=f'  ▶  Run Step {idx + 2}: {next_label}  ', state='normal')
                self._status_lbl.config(
                    text=f'Step {idx + 1} complete — review the summary above, '
                         f'then click the button to start Step {idx + 2}.')
            else:
                self._run_btn.config(text=f'  Re-run Step {idx + 1}  ', state='normal')
                self._next_btn.config(text='  All steps done  ', state='disabled')
                self._status_lbl.config(text='All steps complete — see recommended next steps on the left.')
                self._log_write('\n✓  All scan steps complete.\n', 'ok')
                self._build_next_steps_panel(explain.get('recommendations', []))

            # Refresh command preview for next step
            self._select_step(idx)

    # ── Transition summary (appended to analysis after each step) ────────────

    def _append_transition_summary(self, cur_idx: int, parsed: dict):
        """Append a plain-English step-complete briefing to the analysis panel."""
        t = self._analysis
        t.config(state='normal')

        def w(text, tag='body'):
            t.insert('end', text, tag)

        w('\n─────────────────────────────────────────\n', 'indent')
        w('STEP COMPLETE — WHAT WAS FOUND\n', 'section')

        hosts = parsed.get('hosts', [])
        ports = parsed.get('open_ports', [])
        svcs  = parsed.get('services', {})

        # Findings summary
        if hosts:
            noun = 'host' if len(hosts) == 1 else 'hosts'
            shown = ', '.join(hosts[:6])
            suffix = f'  (and {len(hosts) - 6} more)' if len(hosts) > 6 else ''
            w(f'  • {len(hosts)} live {noun} discovered: {shown}{suffix}\n', 'body')

        if ports:
            port_str = ', '.join(str(p) for p in sorted(ports)[:12])
            suffix   = f'  (and {len(ports) - 12} more)' if len(ports) > 12 else ''
            w(f'  • {len(ports)} open port{"s" if len(ports) != 1 else ""}: '
              f'{port_str}{suffix}\n', 'body')

        if svcs:
            svc_names = [f'{port}/{svc}' for port, _proto, svc, _ver in svcs[:6]]
            w(f'  • Services identified: {", ".join(svc_names)}\n', 'body')

        if not hosts and not ports and not svcs:
            summary = parsed.get('summary', [])
            msg = summary[0] if summary else 'No specific hosts or ports were recorded.'
            w(f'  • {msg}\n', 'body')

        # What was adjusted for the next step
        next_step = self._steps[cur_idx + 1]
        step_args = next_step.get('args', [])
        adjustments = []

        if any('{open_ports}' in str(a) for a in step_args) and self._context.get('open_ports'):
            adjustments.append(
                f'Port list locked to ports found above: {self._context["open_ports"]}')

        if next_step.get('target_from_hosts') and self._context.get('hosts'):
            shown = ', '.join(self._context['hosts'][:6])
            adjustments.append(
                f'Target updated to the {len(self._context["hosts"])} '
                f'discovered host{"s" if len(self._context["hosts"]) != 1 else ""}: {shown}')

        w('\n', 'body')
        if adjustments:
            w('ADJUSTMENTS MADE TO NEXT STEP\n', 'section')
            for adj in adjustments:
                w(f'  • {adj}\n', 'body')
        else:
            w('NEXT STEP\n', 'section')
            w(f'  No changes were needed — Step {cur_idx + 2} will use the same '
              f'target and settings.\n', 'body')

        next_args = build_step_args(next_step, self._context)
        next_tgt  = self._get_target(next_step)
        w(f'\n  Command ready:  nmap {" ".join(next_args)} {next_tgt}\n', 'cmd')
        w('\n  Click the button below to run this step when you are ready.\n', 'indent')

        t.config(state='disabled')
        t.see('end')

    # ── Analysis renderer ─────────────────────────────────────────────────────

    def _render_analysis(self, parsed: dict, explain: dict):
        """Write rich plain-English analysis into the analysis Text widget."""
        t = self._analysis
        t.config(state='normal')
        t.delete('1.0', 'end')

        def w(text, tag='body'):
            t.insert('end', text, tag)

        any_content = False

        # ── Topology / network map
        topo = explain.get('topology', '')
        if topo:
            w('NETWORK MAP\n', 'section')
            w(topo + '\n', 'indent')
            any_content = True

        # ── Device identification
        devs = explain.get('device_ids', [])
        if devs:
            w('DEVICE IDENTIFICATION\n', 'section')
            for d in devs:
                conf_label = {'high': '(confirmed)', 'medium': '(likely)', 'low': '(possible)'}
                cl = conf_label.get(d['confidence'], '')
                w(f'  {d["ip"]}  →  {d["type"]}  {cl}\n', 'subsec')
                if d.get('os'):
                    w(f'    OS: {d["os"]}\n', 'indent')
                if d.get('vendor'):
                    w(f'    Hardware: {d["vendor"]}\n', 'indent')
                w(f'    {d["why"]}\n', 'indent')
            any_content = True

        # ── ACTION PLAN — synthesised from port findings, shown prominently
        port_details = explain.get('port_details', [])
        if port_details:
            high   = [p for p in port_details if p.get('concern') == 'HIGH']
            medium = [p for p in port_details if p.get('concern') == 'MEDIUM']
            safe   = [p for p in port_details if p.get('concern') in ('LOW', 'NONE')]

            w('ACTION PLAN\n', 'section')
            if not high and not medium:
                w('  ✓  No critical or high-risk issues found on the scanned ports.\n'
                  '     Use the Next Steps panel on the left to continue scanning\n'
                  '     for a more complete picture.\n\n', 'ok')
            else:
                num = 0
                if high:
                    w('  FIX IMMEDIATELY\n', 'HIGH')
                    for p in high:
                        num += 1
                        w(f'  {num}. Port {p["port"]} — {p.get("name", p["service"])}\n', 'HIGH')
                        if p.get('action'):
                            w(f'     → {p["action"]}\n', 'indent')
                        w('\n')
                if medium:
                    w('  ADDRESS WHEN POSSIBLE\n', 'MEDIUM')
                    for p in medium:
                        num += 1
                        w(f'  {num}. Port {p["port"]} — {p.get("name", p["service"])}\n', 'MEDIUM')
                        if p.get('action'):
                            w(f'     → {p["action"]}\n', 'indent')
                        w('\n')
            if safe:
                w('  THESE PORTS ARE FINE — NO ACTION NEEDED\n', 'NONE')
                for p in safe:
                    w(f'     • Port {p["port"]} ({p.get("name", p["service"])})'
                      f' — {p.get("plain", "")}\n', 'indent')
                w('\n')
            any_content = True

        # ── Port-by-port explanations (detail reference, below the action plan)
        if port_details:
            w('PORT DETAILS\n', 'section')
            for p in port_details:
                concern = p.get('concern', 'UNKNOWN')
                badge   = {'HIGH': '⚠ HIGH RISK', 'MEDIUM': '⚠ MEDIUM',
                           'LOW': 'ℹ LOW', 'NONE': '✓ NORMAL',
                           'UNKNOWN': '? UNKNOWN'}.get(concern, concern)
                w(f'  Port {p["port"]}/{p["proto"]}  —  {p.get("name", p["service"])}\n',
                  'subsec')
                w(f'    {p.get("plain", "")}\n', 'indent')
                w(f'    Risk: {badge}\n', concern)
                if p.get('reason'):
                    w(f'    Why: {p["reason"]}\n', 'indent')
                w('\n')

        # ── Basic summary (host-discovery scans with no port detail)
        if not port_details and parsed.get('summary'):
            w('SUMMARY\n', 'section')
            for s in parsed['summary']:
                w(f'  {s}\n', 'body')
            any_content = True

        # ── Security flags
        if parsed.get('warnings'):
            w('SECURITY FLAGS\n', 'section')
            for sev, msg in parsed['warnings']:
                tag = sev if sev in ('HIGH', 'MEDIUM', 'LOW') else 'body'
                w(f'  [{sev}]  {msg}\n', tag)
            any_content = True

        # ── Scan-quality issues (why a scan may have missed things)
        issues = explain.get('issues', [])
        if issues:
            w('SCAN ISSUES & HOW TO FIX THEM\n', 'section')
            for iss in issues:
                w(f'  ⚠  {iss["issue"]}\n', 'issue_hdr')
                w(f'     Why this happened: {iss["why"]}\n', 'indent')
                w(f'     What to do: {iss["fix"]}\n', 'indent')
                w(f'     Command to try:\n', 'indent')
                w(f'     {iss["command"]}\n', 'cmd')
            any_content = True

        if not any_content:
            w('Scan completed. No additional analysis available for this step.\n', 'ok')

        t.config(state='disabled')
        t.see('1.0')

    # ── Navigation ────────────────────────────────────────────────────────────

    def _advance_step(self):
        """Advance to the next step and immediately start running it."""
        nxt = self._cur + 1
        if nxt < len(self._steps):
            self._select_step(nxt)
            self._run_current_step()

    # ── Recommended next-step panel ──────────────────────────────────────────

    def _build_next_steps_panel(self, recs: list):
        """Create the NEXT STEPS section in the left panel. Called once after all wizard steps complete."""
        if self._next_steps_shown:
            return
        self._next_steps_shown = True
        self._completed_recs  = []
        self._done_rec_labels = set()
        self._ns_icon_lbls    = []

        left = self._left_panel
        ttk.Separator(left, orient='horizontal').pack(fill='x', pady=(10, 4))
        ttk.Label(left, text='NEXT STEPS',
                  font=('TkDefaultFont', 9, 'bold'),
                  foreground=C['accent_glow']).pack(anchor='w', padx=8, pady=(0, 4))

        self._ns_container = ttk.Frame(left)
        self._ns_container.pack(fill='x')
        self._refresh_next_steps(recs)

    def _refresh_next_steps(self, new_recs: list):
        """
        Rebuild the next-steps list from scratch.
        Completed scans shown greyed at top; pending (not yet done) shown as clickable below.
        Only recs whose label isn't in _done_rec_labels are shown as pending.
        """
        if self._ns_container is None:
            return

        for child in self._ns_container.winfo_children():
            child.destroy()
        self._ns_icon_lbls = []

        # Completed items (greyed, non-clickable)
        for done_rec in self._completed_recs:
            row = ttk.Frame(self._ns_container)
            row.pack(fill='x', padx=6, pady=1)
            ttk.Label(row, text='✓', width=2,
                      foreground=C['secure']).pack(side='left')
            ttk.Label(row, text=done_rec['label'], wraplength=190,
                      justify='left', foreground=C['faint'],
                      font=('TkDefaultFont', 9)).pack(side='left', padx=(2, 0))

        # Pending items — deduplicated: skip anything already done
        pending = [r for r in new_recs if r['label'] not in self._done_rec_labels]

        if self._completed_recs and pending:
            ttk.Separator(self._ns_container,
                          orient='horizontal').pack(fill='x', pady=4, padx=4)

        if not pending:
            msg = ('All recommended scans complete.\n'
                   'Review the Action Plan in the analysis panel.'
                   if self._completed_recs else
                   'No further scans recommended.\n'
                   'Review the Action Plan in the analysis panel.')
            ttk.Label(self._ns_container, text=msg,
                      foreground=C['secure'], font=('TkDefaultFont', 8, 'bold'),
                      justify='left', wraplength=210).pack(anchor='w', padx=6, pady=4)
            return

        for rec in pending:
            row = ttk.Frame(self._ns_container)
            row.pack(fill='x', padx=6, pady=2)

            icon_lbl = ttk.Label(row, text='▶', width=2, foreground=C['info'])
            icon_lbl.pack(side='left')

            name_lbl = ttk.Label(row, text=rec['label'], wraplength=190,
                                 justify='left', foreground=C['accent_glow'],
                                 cursor='hand2')
            name_lbl.pack(side='left', padx=(2, 0))

            self._ns_icon_lbls.append(icon_lbl)
            for widget in (row, icon_lbl, name_lbl):
                widget.bind('<Button-1>',
                            lambda e, r=rec, il=icon_lbl: self._select_next_step(r, il))

    def _select_next_step(self, rec: dict, icon_lbl):
        """Show briefing for a recommended next step and wait for user to click Run."""
        # Update header area
        self._header_var.set(rec['label'])
        self._desc_var.set(rec.get('reason', ''))
        cmd_list = rec.get('command_list', [])
        display_cmd = 'nmap ' + ' '.join(cmd_list[1:]) if cmd_list else rec.get('command', '')
        self._cmd_var.set(display_cmd)

        # Highlight selected rec icon
        for il in getattr(self, '_ns_icon_lbls', []):
            il.configure(text='▶', foreground=C['info'])
        icon_lbl.configure(text='▷', foreground=C['accent_glow'])

        # Configure run button to launch this next step
        self._run_btn.config(
            text=f'  ▶  Run: {rec["label"]}  ',
            state='normal',
            command=lambda r=rec, il=icon_lbl: self._run_next_step(r, il))
        self._next_btn.config(state='disabled', text='')
        self._status_lbl.config(text='Review the briefing below, then click Run to start.')

        # Write briefing into analysis panel
        t = self._analysis
        t.config(state='normal')
        t.delete('1.0', 'end')
        t.insert('end', 'RECOMMENDED NEXT STEP\n', 'section')
        t.insert('end', f'  {rec["label"]}\n\n', 'subsec')
        reason = rec.get('reason', '')
        if reason:
            t.insert('end', 'WHY THIS STEP\n', 'section')
            t.insert('end', f'  {reason}\n\n', 'body')
        if cmd_list:
            t.insert('end', 'COMMAND THAT WILL RUN\n', 'section')
            t.insert('end', f'  {display_cmd}\n\n', 'cmd')
        if self._context.get('open_ports'):
            t.insert('end', 'CONTEXT CARRIED FORWARD\n', 'section')
            t.insert('end', f'  Ports: {self._context["open_ports"]}\n', 'body')
        if self._context.get('hosts'):
            shown = ', '.join(self._context['hosts'][:6])
            t.insert('end', f'  Hosts: {shown}\n', 'body')
        t.insert('end', '\n  Click the Run button below to start this scan.\n', 'indent')
        t.config(state='disabled')

    def _run_next_step(self, rec: dict, icon_lbl):
        """Run a recommended next step inside the wizard window."""
        if not NMAP_EXE:
            messagebox.showerror('nmap not found',
                                 'nmap is not installed or not on your PATH.', parent=self)
            return

        cmd_list = list(rec.get('command_list', []))
        if not cmd_list:
            messagebox.showerror('No command', 'This recommendation has no command to run.',
                                 parent=self)
            return

        if cmd_list[0] == 'nmap':
            cmd_list[0] = NMAP_EXE

        display_cmd = 'nmap ' + ' '.join(cmd_list[1:])
        parse_mode  = 'services'

        # UI: show running state
        icon_lbl.configure(text='▶', foreground=C['warning'])
        self._run_btn.config(text='  Running…  ', state='disabled')
        self._next_btn.config(state='disabled')
        self._status_lbl.config(text='Scan running — please wait…')

        self._analysis.config(state='normal')
        self._analysis.delete('1.0', 'end')
        self._analysis.insert('end', 'Analysis will appear here when the scan finishes.\n', 'body')
        self._analysis.config(state='disabled')

        self._log_write(f'\n{"─" * 50}\n', 'grey')
        self._log_write(f'NEXT STEP — {rec["label"]}\n', 'info')
        self._log_write(f'$ {display_cmd}\n', 'info')
        self._log_write('Running — please wait…\n', 'grey')

        def worker():
            try:
                result = subprocess.run(cmd_list, capture_output=True, text=True,
                                        encoding='utf-8', errors='replace', timeout=600)
                out = result.stdout or result.stderr or '(no output)'
            except subprocess.TimeoutExpired:
                out = 'ERROR: Scan timed out after 10 minutes.'
            except Exception as exc:
                out = f'ERROR: {exc}'
            if not self._cancelled:
                self.after(0, lambda o=out: self._next_step_done(o, rec, icon_lbl, cmd_list, parse_mode))

        threading.Thread(target=worker, daemon=True).start()

    def _next_step_done(self, output: str, rec: dict, icon_lbl,
                        cmd_list: list, parse_mode: str):
        """Handle completion of a recommended next-step scan."""
        from tools.nmap_explainer import explain_results

        # Mark done before any UI work so _refresh_next_steps sees it
        if rec not in self._completed_recs:
            self._completed_recs.append(rec)
        self._done_rec_labels.add(rec['label'])

        self._log_write('\n' + output + '\n', 'raw')
        self._log_write('\n✓  Scan complete.\n', 'ok')

        # Reset run/next buttons to neutral — user picks next action from left panel
        self._run_btn.config(text='  Select a step from the left panel  ',
                             state='disabled', command=lambda: None)
        self._next_btn.config(state='disabled', text='')
        self._status_lbl.config(
            text=f'{rec["label"]} complete — review the Action Plan or select another step.')

        args     = cmd_list[1:-1]
        target   = cmd_list[-1] if cmd_list else self._target
        new_recs = []

        try:
            parsed = parse_nmap_output(output, parse_mode)
            if parsed['open_ports']:
                self._context['open_ports'] = ','.join(
                    str(p) for p in sorted(set(parsed['open_ports'])))
            if parsed['hosts']:
                self._context['hosts'] = parsed['hosts']

            explain  = explain_results(parsed, output, args, target, parse_mode)
            self._render_analysis(parsed, explain)
            new_recs = explain.get('recommendations', [])

        except Exception:
            import traceback
            err_text = traceback.format_exc()
            t = self._analysis
            t.config(state='normal')
            t.delete('1.0', 'end')
            t.insert('end', 'Analysis Error\n', 'section')
            t.insert('end',
                     'The scan completed but the analysis engine hit an error.\n'
                     'The raw output above is still valid.\n\n', 'body')
            t.insert('end', err_text, 'cmd')
            t.config(state='disabled')

        finally:
            self._refresh_next_steps(new_recs)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _set_icon(self, idx: int, state: str):
        self._icon_lbls[idx].configure(text=self._ICON[state],
                                       foreground=self._ICLR[state])

    def _log_write(self, text: str, tag: str = ''):
        self._log.config(state='normal')
        self._log.insert('end', text, tag)
        self._log.see('end')
        self._log.config(state='disabled')

    def _close(self):
        self._cancelled = True
        self.destroy()


# ========================================================================= app
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        self.geometry('1200x720')
        self.minsize(960, 560)

        # ── App icon ──────────────────────────────────────────────────────────
        _icon_dir = Path(__file__).parent / 'assets'
        try:
            if platform.system() == 'Windows':
                # iconbitmap gives a native title-bar and taskbar icon on Windows
                _ico = str(_icon_dir / 'icon.ico')
                if Path(_ico).exists():
                    self.iconbitmap(_ico)
            else:
                # iconphoto works on Linux and macOS
                _png = _icon_dir / 'icon_tk.png'
                if _png.exists():
                    _img = tk.PhotoImage(file=str(_png))
                    self.iconphoto(True, _img)
                    self._icon_img = _img   # keep reference — GC would blank it
        except Exception:
            pass   # icon is cosmetic; never crash the app over it

        # Apply the W1CK3D SYST3MS dark theme (tokens live in theme.py).
        self.palette = theme.apply_theme(self)

        self.store  = ReportStore(DEFAULT_REPORTS_DIR)
        self.cfg = _load_config()
        self.msg_queue = queue.Queue()

        # Currently-loaded report state
        self.current_report_id = None
        self.current_results   = None
        self._new_macs         = set()    # MACs first-seen in the currently loaded report
        self._device_registry  = {}       # full registry dict, loaded on report open

        self._build_menu()
        self._build_ui()
        # _refresh_reports() populates the selector and auto-loads the first report
        self._refresh_reports()

    # --------------------------------------------------------------- menu bar
    def _build_menu(self):
        # A themed POPUP menu (not a native menubar). Native Windows menubars
        # can't be dark-themed; a tk_popup menu honours our SYST3MS palette.
        menubar = self.app_menu = tk.Menu(self, tearoff=False)

        file_menu = tk.Menu(menubar, tearoff=False)
        file_menu.add_command(label='Analyze capture…',
                              accelerator='Ctrl+O',
                              command=self.on_analyze)
        file_menu.add_command(label='Live capture…',
                              accelerator='Ctrl+L',
                              command=self.on_live_capture)
        file_menu.add_separator()
        file_menu.add_command(label='Open reports folder',
                              command=self.on_open_reports_folder)
        file_menu.add_separator()
        file_menu.add_command(label='Compare reports…',
                              command=self.on_compare_reports)
        file_menu.add_separator()
        file_menu.add_command(label='Export findings as CSV…',
                              command=self.on_export_csv)
        file_menu.add_separator()
        file_menu.add_command(label='Protocol Library…',
                              command=self._show_protocol_library)
        file_menu.add_separator()
        file_menu.add_command(label='Settings…', command=self._show_settings)
        file_menu.add_separator()
        file_menu.add_command(label='Quit', accelerator='Ctrl+Q',
                              command=self.destroy)
        menubar.add_cascade(label='File', menu=file_menu)

        tools_menu = tk.Menu(menubar, tearoff=False)
        tools_menu.add_command(label='IT Admin Settings…',
                               command=self._show_admin_settings)
        menubar.add_cascade(label='Tools', menu=tools_menu)

        help_menu = tk.Menu(menubar, tearoff=False)
        help_menu.add_command(label='About', command=self._show_about)
        menubar.add_cascade(label='Help', menu=help_menu)

        # Popped from the ☰ button in the command bar (see _build_command_bar);
        # NOT attached via self.config(menu=…) so no native white menubar.
        self.bind_all('<Control-o>', lambda e: self.on_analyze())
        self.bind_all('<Control-l>', lambda e: self.on_live_capture())
        self.bind_all('<Control-q>', lambda e: self.destroy())

    def _popup_app_menu(self):
        b = self._menu_btn
        try:
            self.app_menu.tk_popup(b.winfo_rootx(),
                                   b.winfo_rooty() + b.winfo_height())
        finally:
            self.app_menu.grab_release()

    # ------------------------------------------------------------------ UI
    # View metadata: key, sidebar name, description, tone, glyph, eyebrow, heading
    _VIEWS = [
        ('summary',     'Overview',    'Network recon',     'purple', '◎',
         '// OVERVIEW',     'Network Reconnaissance'),
        ('devices',     'Devices',     'Hosts discovered',  'blue',   '▤',
         '// DEVICES',      'Device Inventory'),
        ('protocols',   'Protocols',   'Ports & services',  'green',  '⇄',
         '// PROTOCOLS',    'Protocol Library'),
        ('findings',    'Findings',    'Security signals',  'red',    '⚠',
         '// FINDINGS',     'Security Findings'),
        ('investigate', 'Investigate', 'IP intel lookup',   'orange', '⌖',
         '// INVESTIGATE',  'IP Investigation'),
        ('architect',   'Architect',   'Network review',    'blue',   '⛨',
         '// ARCHITECT',    'Architect Review'),
    ]

    def _build_ui(self):
        self.configure(bg=C['base'])
        self._view_meta   = {v[0]: v for v in self._VIEWS}
        self._nav_items   = {}
        self.views        = {}
        self._report_order = []
        self._active_view = None

        self._build_command_bar()
        self._build_report_menu()

        body = ttk.Frame(self, style='Main.TFrame')
        body.pack(fill='both', expand=True)
        self._build_sidebar(body)
        self._build_main(body)

        # ---- Status bar ----
        self.status_var = tk.StringVar(value='Ready')
        status = ttk.Label(self, textvariable=self.status_var, anchor='w',
                           padding=(12, 3), background=C['surface'],
                           foreground=C['muted'], font=(theme.FONTS['mono'], 8))
        status.pack(fill='x', side='bottom')

        # Build the six analysis views into the view stack
        self._build_summary_tab()
        self._build_devices_tab()
        self._build_protocols_tab()
        self._build_findings_tab()
        self._build_investigate_tab()
        self._build_architect_tab()

        self.view_stack.rowconfigure(0, weight=1)
        self.view_stack.columnconfigure(0, weight=1)
        self._select_view('summary')

    # ---------------------------------------------------- shell: command bar
    def _build_command_bar(self):
        bar = ttk.Frame(self, style='CommandBar.TFrame')
        bar.pack(fill='x', side='top')
        tk.Frame(bar, bg=C['line'], height=1).pack(fill='x', side='bottom')
        inner = ttk.Frame(bar, style='CommandBar.TFrame')
        inner.pack(fill='x', padx=12, pady=6)

        # traffic lights
        tl = tk.Canvas(inner, width=52, height=16, bg=C['base'],
                       highlightthickness=0, bd=0)
        for i, col in enumerate((C['critical'], C['warning'], C['secure'])):
            x = 8 + i * 17
            tl.create_oval(x - 5, 3, x + 5, 13, fill=col, outline='')
        tl.pack(side='left')

        ttk.Label(inner, text='w1ck3d://wizard/', style='Url.TLabel').pack(side='left', padx=(12, 0))
        ttk.Label(inner, text='net-wizard', style='UrlAccent.TLabel').pack(side='left')

        # right cluster: menu + report selector + actions + open html
        self._menu_btn = ttk.Button(inner, text='☰', width=3,
                                     command=self._popup_app_menu)
        self._menu_btn.pack(side='right', padx=(8, 0))
        self.open_html_btn = ttk.Button(inner, text='Open HTML ↗',
                                        command=self.on_open_html, state='disabled')
        self.open_html_btn.pack(side='right', padx=(8, 0))
        self._report_actions_btn = ttk.Button(inner, text='⋯', width=3,
                                               command=self._popup_report_menu)
        self._report_actions_btn.pack(side='right', padx=(0, 8))
        self.report_var = tk.StringVar()
        self.report_cb = ttk.Combobox(inner, textvariable=self.report_var,
                                      state='readonly', width=34, values=[])
        self.report_cb.pack(side='right', padx=(0, 8))
        self.report_cb.bind('<<ComboboxSelected>>', lambda e: self._load_selected_report())
        self.report_cb.bind('<Delete>', lambda e: self.on_delete_report())
        ttk.Label(inner, text='REPORT', style='MeterLabel.TLabel').pack(side='right', padx=(0, 8))

    def _build_report_menu(self):
        self.report_menu = tk.Menu(self, tearoff=False)
        self.report_menu.add_command(label='Open full HTML report in browser',
                                     command=self.on_open_html)
        self.report_menu.add_command(label='Open report folder',
                                     command=self.on_open_report_folder)
        self.report_menu.add_separator()
        self.report_menu.add_command(label='Compare with another report…',
                                     command=self._compare_selected_report)
        self.report_menu.add_separator()
        self.report_menu.add_command(label='Delete report',
                                     command=self.on_delete_report)

    def _popup_report_menu(self):
        b = self._report_actions_btn
        try:
            self.report_menu.tk_popup(b.winfo_rootx(),
                                      b.winfo_rooty() + b.winfo_height())
        finally:
            self.report_menu.grab_release()

    # ---------------------------------------------------- shell: sidebar
    def _load_logo_image(self):
        for name in ('icon_32.png', 'icon_48.png', 'icon_tk.png', 'icon.png'):
            p = Path(__file__).parent / 'assets' / name
            if p.exists():
                try:
                    img = tk.PhotoImage(file=str(p))
                    if img.width() > 56:
                        f = max(1, round(img.width() / 40))
                        img = img.subsample(f, f)
                    return img
                except Exception:
                    continue
        return None

    def _build_sidebar(self, parent):
        sb = ttk.Frame(parent, style='Sidebar.TFrame', width=236)
        sb.pack(side='left', fill='y')
        sb.pack_propagate(False)

        head = ttk.Frame(sb, style='SidebarHead.TFrame')
        head.pack(fill='x', padx=14, pady=(14, 12))
        logo = self._load_logo_image()
        if logo is not None:
            l = ttk.Label(head, image=logo, style='Logo.TLabel')
            l.image = logo
            l.pack(side='left')
        txt = ttk.Frame(head, style='SidebarHead.TFrame')
        txt.pack(side='left', padx=(10, 0))
        ttk.Label(txt, text='W1CK3D', style='Logo.TLabel').pack(anchor='w')
        ttk.Label(txt, text='NET WIZARD', style='LogoSub.TLabel').pack(anchor='w')

        tk.Frame(sb, bg=C['line'], height=1).pack(fill='x')

        ttk.Label(sb, text='ARSENAL', style='Arsenal.TLabel').pack(anchor='w', padx=16, pady=(12, 6))
        nav = ttk.Frame(sb, style='Sidebar.TFrame')
        nav.pack(fill='x', padx=8)
        for key, name, desc, tone_name, glyph, *_ in self._VIEWS:
            self._make_nav_item(nav, key, name, desc, tone_name, glyph)

        # footer: global actions + status
        footer = ttk.Frame(sb, style='Sidebar.TFrame')
        footer.pack(side='bottom', fill='x', padx=12, pady=12)
        tk.Frame(footer, bg=C['line'], height=1).pack(fill='x', pady=(0, 10))
        for text, cmd in (('  ⌕  Analyze capture', self.on_analyze),
                          ('  ▶  Live capture', self.on_live_capture),
                          ('  ⇌  Compare reports', self._compare_selected_report),
                          ('  ⟳  Refresh', self._refresh_reports),
                          ('  ⌂  Reports folder', self.on_open_reports_folder)):
            ttk.Button(footer, text=text, command=cmd).pack(fill='x', pady=2)
        row = ttk.Frame(footer, style='Sidebar.TFrame')
        row.pack(fill='x', pady=(10, 0))
        self._build_secure_badge(row).pack(side='left')
        ttk.Label(row, text='v3.1.3', style='SidebarBadge.TLabel').pack(side='right')

    def _build_secure_badge(self, parent):
        chip = tk.Frame(parent, bg=C['surface'])
        dot = tk.Canvas(chip, width=10, height=10, bg=C['surface'],
                        highlightthickness=0, bd=0)
        dot.create_oval(2, 2, 8, 8, fill=C['secure_glow'], outline='')
        dot.pack(side='left', padx=(0, 5))
        tk.Label(chip, text='SECURE · OFFLINE', bg=C['surface'], fg=C['secure'],
                 font=(theme.FONTS['heading'], 8, 'bold')).pack(side='left')
        return chip

    def _make_nav_item(self, parent, key, name, desc, tone_name, glyph):
        fr = tk.Frame(parent, bg=C['surface'], cursor='hand2')
        fr.pack(fill='x', pady=2)
        rail = tk.Frame(fr, bg=C['surface'], width=3)
        rail.pack(side='left', fill='y')
        icon = tk.Label(fr, text=glyph, bg=C['surface'], fg=C['muted'],
                        font=(theme.FONTS['heading'], 14), width=2)
        icon.pack(side='left', padx=(8, 4), pady=8)
        txt = tk.Frame(fr, bg=C['surface'])
        txt.pack(side='left', fill='x', expand=True, pady=6)
        name_lbl = tk.Label(txt, text=name, bg=C['surface'], fg=C['body'],
                            font=(theme.FONTS['heading'], 11, 'bold'), anchor='w')
        name_lbl.pack(fill='x')
        desc_lbl = tk.Label(txt, text=desc, bg=C['surface'], fg=C['faint'],
                            font=(theme.FONTS['body'], 9), anchor='w')
        desc_lbl.pack(fill='x')
        self._nav_items[key] = {'frame': fr, 'rail': rail, 'icon': icon,
                                'name': name_lbl, 'desc': desc_lbl, 'txt': txt,
                                'tone': tone_name}
        for w in (fr, rail, icon, txt, name_lbl, desc_lbl):
            w.bind('<Button-1>', lambda e, k=key: self._select_view(k))
            w.bind('<Enter>', lambda e, k=key: self._nav_hover(k, True))
            w.bind('<Leave>', lambda e, k=key: self._nav_hover(k, False))

    def _nav_hover(self, key, entering):
        if key == self._active_view:
            return
        item = self._nav_items[key]
        bg = C['hover'] if entering else C['surface']
        for part in ('frame', 'icon', 'txt', 'name', 'desc'):
            try:
                item[part].configure(bg=bg)
            except tk.TclError:
                pass
        item['rail'].configure(bg=C['line_strong'] if entering else C['surface'])

    def _select_view(self, key):
        self._active_view = key
        for k, item in self._nav_items.items():
            active = (k == key)
            glow = theme.tone_glow(item['tone'])
            bg = C['hover'] if active else C['surface']
            for part in ('frame', 'icon', 'txt', 'name', 'desc'):
                item[part].configure(bg=bg)
            item['rail'].configure(bg=glow if active else C['surface'])
            item['icon'].configure(fg=glow if active else C['muted'])
            item['name'].configure(fg=C['strong'] if active else C['body'])
        if key in self.views:
            self.views[key].tkraise()
        meta = self._view_meta.get(key)
        if meta:
            self.eyebrow_var.set(meta[5])
            self.h1_var.set(meta[6])

    # ---------------------------------------------------- shell: main area
    def _build_main(self, parent):
        main = ttk.Frame(parent, style='Main.TFrame')
        main.pack(side='left', fill='both', expand=True)

        header = ttk.Frame(main, style='Main.TFrame')
        header.pack(fill='x', padx=24, pady=(16, 4))

        left = ttk.Frame(header, style='Main.TFrame')
        left.pack(side='left', fill='x', expand=True)
        self.eyebrow_var = tk.StringVar(value='// OVERVIEW')
        ttk.Label(left, textvariable=self.eyebrow_var, style='Eyebrow.TLabel').pack(anchor='w')
        self.h1_var = tk.StringVar(value='Network Reconnaissance')
        ttk.Label(left, textvariable=self.h1_var, style='H1.TLabel').pack(anchor='w', pady=(3, 0))
        self.detail_title = ttk.Label(left, text='No report selected', style='Sub.TLabel')
        self.detail_title.pack(anchor='w', pady=(3, 0))

        # threat meter (right)
        mwrap = ttk.Frame(header, style='Main.TFrame')
        mwrap.pack(side='right', anchor='ne')
        ttk.Label(mwrap, text='THREAT', style='MeterLabel.TLabel').pack(anchor='e')
        self._meter_canvas = tk.Canvas(mwrap, width=136, height=16, bg=C['base'],
                                       highlightthickness=0, bd=0)
        self._meter_canvas.pack(anchor='e', pady=(4, 2))
        self._meter_value_lbl = ttk.Label(mwrap, text='—', style='Sub.TLabel')
        self._meter_value_lbl.pack(anchor='e')
        self._render_threat_meter(0, 'green', '—')

        tk.Frame(main, bg=C['line'], height=1).pack(fill='x', padx=24, pady=(8, 0))

        self.view_stack = ttk.Frame(main, style='Main.TFrame')
        self.view_stack.pack(fill='both', expand=True, padx=12, pady=8)

    def _register_view(self, key, frame):
        frame.grid(row=0, column=0, sticky='nsew')
        self.views[key] = frame

    def _render_threat_meter(self, level, tone_name, label):
        cv = self._meter_canvas
        cv.delete('all')
        segs, gap, w, h = 5, 4, 136, 12
        seg_w = (w - gap * (segs - 1)) / segs
        color = theme.tone(tone_name)
        for i in range(segs):
            x0 = i * (seg_w + gap)
            filled = i < level
            cv.create_rectangle(x0, 2, x0 + seg_w, 2 + h,
                                fill=color if filled else C['raised'],
                                outline=C['line'])
        self._meter_value_lbl.configure(text=label)

    def _threat_level(self, results):
        counts = (results.get('threats', {}) or {}).get('counts_by_severity', {}) or {}
        if counts.get('critical'): return 5, 'red',    'CRITICAL'
        if counts.get('high'):     return 4, 'red',    'HIGH'
        if counts.get('medium'):   return 3, 'orange', 'MEDIUM'
        if counts.get('low'):      return 2, 'blue',   'LOW'
        if counts.get('info'):     return 1, 'blue',   'INFO'
        return 0, 'green', 'CLEAR'

    # ------------------------------------------------------- summary tab
    def _build_summary_tab(self):
        frame = ttk.Frame(self.view_stack, style='Main.TFrame', padding=(16, 8))
        self._register_view('summary', frame)

        self.summary_text = tk.Text(frame, wrap='word', height=1,
                                    font=('TkDefaultFont', 10),
                                    relief='flat', padx=4, pady=4,
                                    background=self.cget('bg'))
        self.summary_text.pack(fill='both', expand=True)
        self.summary_text.config(state='disabled')

        # Text tags for formatting
        self.summary_text.tag_configure('h1',
                                         font=('TkDefaultFont', 14, 'bold'),
                                         spacing3=8)
        self.summary_text.tag_configure('h2',
                                         font=('TkDefaultFont', 11, 'bold'),
                                         spacing1=12, spacing3=4)
        self.summary_text.tag_configure('label', foreground=C['muted'])
        self.summary_text.tag_configure('value', font=('TkDefaultFont', 10, 'bold'))
        for sev, color in SEVERITY_COLORS.items():
            self.summary_text.tag_configure(f'sev_{sev}', foreground=color,
                                             font=('TkDefaultFont', 10, 'bold'))
        self.summary_text.tag_configure('new_device', foreground=C['secure'],
                                         font=('TkDefaultFont', 10, 'bold'))

    # ------------------------------------------------------- devices tab
    def _build_devices_tab(self):
        frame = ttk.Frame(self.view_stack, style='Main.TFrame', padding=(16, 8))
        self._register_view('devices', frame)

        cols = ('type', 'hostname', 'ip', 'mac', 'vendor', 'packets', 'bytes')
        self.devices_tv = ttk.Treeview(frame, columns=cols, show='headings')
        self.devices_tv.heading('type', text='Device type')
        self.devices_tv.heading('hostname', text='Hostname')
        self.devices_tv.heading('ip', text='IP')
        self.devices_tv.heading('mac', text='MAC')
        self.devices_tv.heading('vendor', text='Vendor')
        self.devices_tv.heading('packets', text='Packets')
        self.devices_tv.heading('bytes', text='Data')

        self.devices_tv.column('type', width=200, anchor='w')
        self.devices_tv.column('hostname', width=160, anchor='w')
        self.devices_tv.column('ip', width=130, anchor='w')
        self.devices_tv.column('mac', width=150, anchor='w')
        self.devices_tv.column('vendor', width=140, anchor='w')
        self.devices_tv.column('packets', width=80, anchor='e')
        self.devices_tv.column('bytes', width=80, anchor='e')

        vsb = ttk.Scrollbar(frame, orient='vertical',
                            command=self.devices_tv.yview)
        self.devices_tv.configure(yscrollcommand=vsb.set)
        self.devices_tv.pack(side='left', fill='both', expand=True)
        vsb.pack(side='right', fill='y')

        self.devices_tv.tag_configure('gateway', font=('TkDefaultFont', 9, 'bold'),
                                       foreground=C['accent_glow'])
        self.devices_tv.tag_configure('new_device', foreground=C['secure'],
                                       font=('TkDefaultFont', 9, 'bold'))
        self.devices_tv.tag_configure('gateway_new', font=('TkDefaultFont', 9, 'bold'),
                                       foreground=C['secure'])

        # Right-click context menu
        self.device_menu = tk.Menu(self, tearoff=False)
        self.device_menu.add_command(label='Label this device…',
                                     command=self._label_selected_device)
        self.device_menu.add_command(label='Investigate IP(s)…',
                                     command=self._investigate_device_ip)
        self.devices_tv.bind('<Button-3>', self._show_device_context)
        self.devices_tv.bind('<Button-2>', self._show_device_context)

    # ------------------------------------------------------- protocols tab
    def _build_protocols_tab(self):
        frame = ttk.Frame(self.view_stack, style='Main.TFrame', padding=(16, 8))
        self._register_view('protocols', frame)

        # ---- toolbar ----
        toolbar = ttk.Frame(frame)
        toolbar.pack(fill='x', pady=(2, 4))

        ttk.Label(toolbar, text='Search:',
                  font=('TkDefaultFont', 9, 'bold')).pack(side='left')
        self._proto_search_var = tk.StringVar()
        self._proto_search_var.trace_add('write', lambda *_: self._apply_proto_filter())
        ttk.Entry(toolbar, textvariable=self._proto_search_var,
                  width=20).pack(side='left', padx=(4, 12))

        ttk.Button(toolbar, text='  Manage Protocol Library…  ',
                   command=self._show_protocol_library).pack(side='left')

        self._proto_unknown_only = tk.BooleanVar(value=False)
        ttk.Checkbutton(toolbar, text='Show unknown only',
                        variable=self._proto_unknown_only,
                        command=self._apply_proto_filter).pack(side='left', padx=(12, 0))

        # ---- split pane: list top, description bottom ----
        paned = ttk.PanedWindow(frame, orient='vertical')
        paned.pack(fill='both', expand=True)

        list_frame = ttk.Frame(paned)
        paned.add(list_frame, weight=2)

        cols = ('name', 'category', 'packets', 'risk', 'status')
        self.protocols_tv = ttk.Treeview(list_frame, columns=cols, show='headings',
                                         selectmode='browse')
        self.protocols_tv.heading('name',     text='Protocol')
        self.protocols_tv.heading('category', text='Category')
        self.protocols_tv.heading('packets',  text='Packets')
        self.protocols_tv.heading('risk',     text='Risk')
        self.protocols_tv.heading('status',   text='What it is')

        self.protocols_tv.column('name',     width=160, anchor='w')
        self.protocols_tv.column('category', width=110, anchor='w')
        self.protocols_tv.column('packets',  width=80,  anchor='e')
        self.protocols_tv.column('risk',     width=80,  anchor='w')
        self.protocols_tv.column('status',   width=380, anchor='w')

        pvsb = ttk.Scrollbar(list_frame, orient='vertical',
                             command=self.protocols_tv.yview)
        self.protocols_tv.configure(yscrollcommand=pvsb.set)
        self.protocols_tv.pack(side='left', fill='both', expand=True)
        pvsb.pack(side='right', fill='y')

        # row tags: colour-code by risk/known status
        self.protocols_tv.tag_configure('risk_none',    foreground=C['body'])
        self.protocols_tv.tag_configure('risk_low',     foreground=C['info'])
        self.protocols_tv.tag_configure('risk_medium',  foreground=C['warning'])
        self.protocols_tv.tag_configure('risk_high',    foreground=C['critical'],
                                         font=('TkDefaultFont', 9, 'bold'))
        self.protocols_tv.tag_configure('hint',        foreground=C['accent'],
                                         font=('TkDefaultFont', 9))
        self.protocols_tv.tag_configure('unknown',      foreground=C['accent_glow'],
                                         font=('TkDefaultFont', 9, 'bold'))

        self.protocols_tv.bind('<<TreeviewSelect>>', lambda e: self._show_proto_detail())

        # ---- description panel ----
        desc_frame = ttk.Frame(paned)
        paned.add(desc_frame, weight=1)

        self.proto_text = tk.Text(desc_frame, wrap='word',
                                  font=('TkDefaultFont', 10),
                                  relief='flat', padx=10, pady=8,
                                  background=self.cget('bg'))
        pdvsb = ttk.Scrollbar(desc_frame, orient='vertical',
                               command=self.proto_text.yview)
        self.proto_text.configure(yscrollcommand=pdvsb.set)
        self.proto_text.pack(side='left', fill='both', expand=True)
        pdvsb.pack(side='right', fill='y')
        self.proto_text.config(state='disabled')

        self.proto_text.tag_configure('name',    font=('TkDefaultFont', 13, 'bold'), spacing3=4)
        self.proto_text.tag_configure('full',    foreground=C['muted'],
                                      font=('TkDefaultFont', 10), spacing3=8)
        self.proto_text.tag_configure('label',   font=('TkDefaultFont', 9, 'bold'),
                                      foreground=C['body'], spacing1=8)
        self.proto_text.tag_configure('body',    spacing3=3)
        self.proto_text.tag_configure('tip',     foreground=C['faint'],
                                      font=('TkDefaultFont', 9),
                                      lmargin1=6, lmargin2=6, spacing3=4)
        self.proto_text.tag_configure('warn',    foreground=C['critical'],
                                      font=('TkDefaultFont', 10, 'bold'))
        self.proto_text.tag_configure('risk_high',   foreground=C['critical'],
                                      font=('TkDefaultFont', 9, 'bold'))
        self.proto_text.tag_configure('risk_medium', foreground=C['warning'],
                                      font=('TkDefaultFont', 9, 'bold'))
        self.proto_text.tag_configure('risk_low',    foreground=C['info'],
                                      font=('TkDefaultFont', 9, 'bold'))
        self.proto_text.tag_configure('risk_none',   foreground=C['secure'],
                                      font=('TkDefaultFont', 9, 'bold'))
        self.proto_text.tag_configure('hint',     foreground=C['accent'],
                                      font=('TkDefaultFont', 9, 'bold'))
        self.proto_text.tag_configure('unknown',     foreground=C['accent_glow'],
                                      font=('TkDefaultFont', 9, 'bold'))

        # Right-click menu
        self.proto_menu = tk.Menu(self, tearoff=False)
        self.proto_menu.add_command(label='Add to Protocol Library…',
                                    command=self._proto_add_to_library)
        self.proto_menu.add_command(label='Edit library entry…',
                                    command=self._proto_edit_entry)
        self.protocols_tv.bind('<Button-3>', self._show_proto_context)
        self.protocols_tv.bind('<Button-2>', self._show_proto_context)

        # Store rendered rows for filtering
        self._proto_rows_all = []   # list of (iid, values, tags, entry_or_None)

    # ------------------------------------------------------- findings tab
    def _build_findings_tab(self):
        frame = ttk.Frame(self.view_stack, style='Main.TFrame', padding=(16, 8))
        self._register_view('findings', frame)

        # Split: top = list, bottom = detail pane
        paned = ttk.PanedWindow(frame, orient='vertical')
        paned.pack(fill='both', expand=True)

        # Findings list
        list_frame = ttk.Frame(paned)
        paned.add(list_frame, weight=1)

        # Severity filter bar
        filter_bar = ttk.Frame(list_frame)
        filter_bar.pack(fill='x', pady=(2, 4))
        ttk.Label(filter_bar, text='Show:',
                  font=('TkDefaultFont', 9, 'bold')).pack(side='left', padx=(2, 6))
        self._sev_filter_vars = {}
        for sev in SEVERITY_ORDER:
            var = tk.BooleanVar(value=True)
            self._sev_filter_vars[sev] = var
            cb = tk.Checkbutton(
                filter_bar, text=sev.capitalize(), variable=var,
                fg=SEVERITY_COLORS[sev], activeforeground=SEVERITY_COLORS[sev],
                font=('TkDefaultFont', 9, 'bold'), bd=0, relief='flat',
                command=self._apply_findings_filter,
            )
            cb.pack(side='left', padx=2)
        ttk.Button(filter_bar, text='Export CSV…',
                   command=self.on_export_csv).pack(side='right', padx=4)

        # Treeview in its own sub-frame so filter_bar sits above it
        tv_frame = ttk.Frame(list_frame)
        tv_frame.pack(fill='both', expand=True)

        cols = ('severity', 'title', 'category', 'device')
        self.findings_tv = ttk.Treeview(tv_frame, columns=cols, show='headings')
        self.findings_tv.heading('severity', text='Severity')
        self.findings_tv.heading('title', text='Finding')
        self.findings_tv.heading('category', text='Category')
        self.findings_tv.heading('device', text='Affected device')
        self.findings_tv.column('severity', width=90, anchor='w')
        self.findings_tv.column('title', width=380, anchor='w')
        self.findings_tv.column('category', width=110, anchor='w')
        self.findings_tv.column('device', width=200, anchor='w')

        fvsb = ttk.Scrollbar(tv_frame, orient='vertical',
                             command=self.findings_tv.yview)
        self.findings_tv.configure(yscrollcommand=fvsb.set)
        self.findings_tv.pack(side='left', fill='both', expand=True)
        fvsb.pack(side='right', fill='y')

        for sev, color in SEVERITY_COLORS.items():
            self.findings_tv.tag_configure(sev, foreground=color)

        self.findings_tv.bind('<<TreeviewSelect>>',
                              lambda e: self._show_finding_detail())

        # Finding detail
        detail_frame = ttk.Frame(paned)
        paned.add(detail_frame, weight=1)

        self.finding_text = tk.Text(detail_frame, wrap='word', height=8,
                                    font=('TkDefaultFont', 10),
                                    relief='flat', padx=10, pady=10,
                                    background=self.cget('bg'))
        fd_vsb = ttk.Scrollbar(detail_frame, orient='vertical',
                                command=self.finding_text.yview)
        self.finding_text.configure(yscrollcommand=fd_vsb.set)
        self.finding_text.pack(side='left', fill='both', expand=True)
        fd_vsb.pack(side='right', fill='y')
        self.finding_text.config(state='disabled')

        # Tags for the detail pane
        self.finding_text.tag_configure('title',
                                         font=('TkDefaultFont', 12, 'bold'),
                                         spacing3=6)
        self.finding_text.tag_configure('label',
                                         font=('TkDefaultFont', 9, 'bold'),
                                         foreground=C['body'], spacing1=8)
        self.finding_text.tag_configure('body', spacing3=4)
        self.finding_text.tag_configure('tech', font=('Courier', 9),
                                         foreground=C['muted'], lmargin1=12,
                                         lmargin2=12)
        self.finding_text.tag_configure('rec', background=C['inset'],
                                         foreground=C['info'],
                                         lmargin1=8, lmargin2=8,
                                         spacing1=4, spacing3=4)
        for sev, color in SEVERITY_COLORS.items():
            self.finding_text.tag_configure(f'sev_{sev}', foreground=color,
                                             font=('TkDefaultFont', 10, 'bold'))

        # Right-click menu on findings → investigate
        self.finding_menu = tk.Menu(self, tearoff=False)
        self.finding_menu.add_command(label='Investigate IP(s) from this finding',
                                      command=self._investigate_selected_finding)
        self.findings_tv.bind('<Button-3>', self._show_finding_context)
        self.findings_tv.bind('<Button-2>', self._show_finding_context)

    # --------------------------------------------------- investigate tab
    def _build_investigate_tab(self):
        frame = ttk.Frame(self.view_stack, style='Main.TFrame', padding=(16, 8))
        self._register_view('investigate', frame)

        # Row 1: IP lookup + batch button
        input_row = ttk.Frame(frame)
        input_row.pack(fill='x', pady=(0, 4))

        ttk.Label(input_row, text='IP address:',
                  font=('TkDefaultFont', 10, 'bold')).pack(side='left')
        self._investigate_ip_var = tk.StringVar()
        ip_entry = ttk.Entry(input_row, textvariable=self._investigate_ip_var,
                             width=22, font=('Courier', 11))
        ip_entry.pack(side='left', padx=(8, 8))
        ip_entry.bind('<Return>', lambda e: self._run_investigate())

        self._investigate_btn = ttk.Button(input_row, text='  Look up  ',
                                           command=self._run_investigate)
        self._investigate_btn.pack(side='left')

        self._batch_btn = ttk.Button(input_row, text='  Batch: all report IPs  ',
                                     command=self._run_batch_investigate)
        self._batch_btn.pack(side='left', padx=(8, 0))

        self._investigate_status = ttk.Label(input_row, text='',
                                             foreground=C['muted'])
        self._investigate_status.pack(side='left', padx=(12, 0))

        # Row 2: scan profiles button
        nmap_row = ttk.Frame(frame)
        nmap_row.pack(fill='x', pady=(0, 6))

        ttk.Label(nmap_row, text='nmap scans:',
                  font=('TkDefaultFont', 10, 'bold')).pack(side='left')
        self._nmap_btn = ttk.Button(nmap_row, text='  Scan Profiles…  ',
                                    command=self._show_scan_profiles)
        self._nmap_btn.pack(side='left', padx=(8, 8))
        if NMAP_EXE is None:
            self._nmap_btn.config(state='disabled')
            ttk.Label(nmap_row, text='nmap not found — install from nmap.org',
                      foreground=C['critical'],
                      font=('TkDefaultFont', 8)).pack(side='left')
        else:
            ttk.Label(nmap_row, text='(nmap detected)',
                      foreground=C['secure'],
                      font=('TkDefaultFont', 8)).pack(side='left')

        ttk.Label(frame,
                  text='Look up any IP for geolocation, WHOIS, open ports, and CVEs. '
                       'Run nmap scans or batch-investigate all external IPs from the loaded report.',
                  foreground=C['muted']).pack(anchor='w', pady=(0, 8))

        # Results text area
        result_frame = ttk.Frame(frame)
        result_frame.pack(fill='both', expand=True)

        self.investigate_text = tk.Text(result_frame, wrap='word',
                                        font=('TkDefaultFont', 10),
                                        relief='flat', padx=8, pady=8,
                                        background=self.cget('bg'))
        iv_vsb = ttk.Scrollbar(result_frame, orient='vertical',
                                command=self.investigate_text.yview)
        self.investigate_text.configure(yscrollcommand=iv_vsb.set)
        self.investigate_text.pack(side='left', fill='both', expand=True)
        iv_vsb.pack(side='right', fill='y')
        self.investigate_text.config(state='disabled')

        self.investigate_text.tag_configure('h1',
                                             font=('TkDefaultFont', 13, 'bold'),
                                             spacing3=4)
        self.investigate_text.tag_configure('h2',
                                             font=('TkDefaultFont', 10, 'bold'),
                                             foreground=C['body'],
                                             spacing1=10, spacing3=2)
        self.investigate_text.tag_configure('label',
                                             font=('TkDefaultFont', 9, 'bold'),
                                             foreground=C['muted'])
        self.investigate_text.tag_configure('body', spacing3=2)
        self.investigate_text.tag_configure('tip',
                                             foreground=C['muted'],
                                             font=('TkDefaultFont', 9),
                                             lmargin1=4, lmargin2=4,
                                             spacing3=4)
        self.investigate_text.tag_configure('warn',
                                             foreground=C['critical'],
                                             font=('TkDefaultFont', 10, 'bold'))
        self.investigate_text.tag_configure('vuln',
                                             foreground=C['critical'],
                                             font=('Courier', 9))
        self.investigate_text.tag_configure('risky',
                                             foreground=C['warning'],
                                             font=('TkDefaultFont', 10, 'bold'))
        self.investigate_text.tag_configure('tech',
                                             font=('Courier', 9),
                                             foreground=C['body'],
                                             lmargin1=4, lmargin2=4,
                                             spacing3=2)

    # ========================================================= data loading
    def _selected_report_id(self):
        """Return the report id currently chosen in the selector, or None."""
        if not hasattr(self, 'report_cb'):
            return None
        idx = self.report_cb.current()
        if 0 <= idx < len(self._report_order):
            return self._report_order[idx]
        return None

    def _refresh_reports(self, select_id=None):
        """Reload the report selector from disk (auto-loads a report)."""
        prev = self._selected_report_id()

        reports = self.store.list_all()
        self._report_order = []
        values = []
        for r in reports:
            rid = r['id']
            self._report_order.append(rid)
            findings = r.get('finding_counts', {}) or {}
            parts = [f"{findings[s]} {s}" for s in SEVERITY_ORDER if findings.get(s)]
            tag = ('  ·  ' + ', '.join(parts)) if parts else '  ·  clean'
            name = r.get('original_filename', rid)
            values.append(f"{name}  ·  {fmt_timestamp(r.get('timestamp', ''))}{tag}")
        self.report_cb.configure(values=values)

        self.status_var.set(f'{len(reports)} report(s) · stored in {self.store.root}')

        target = select_id or prev
        if target and target in self._report_order:
            self.report_cb.current(self._report_order.index(target))
            self._load_selected_report()
        elif reports:
            self.report_cb.current(0)
            self._load_selected_report()
        else:
            self.report_cb.set('')
            self._clear_detail_view()

    def _load_selected_report(self):
        report_id = self._selected_report_id()
        if not report_id:
            return
        try:
            results = json.loads(self.store.json_path(report_id).read_text())
        except Exception as e:
            messagebox.showerror('Could not load report', str(e))
            return

        self.current_report_id = report_id
        self.current_results = results
        meta = self.store.get(report_id) or {}
        self.detail_title.config(text=meta.get('original_filename', report_id))
        self.open_html_btn.config(state='normal')
        # Threat meter reflects the loaded report's worst finding severity
        level, tone_name, label = self._threat_level(results)
        self._render_threat_meter(level, tone_name, label)

        # Update device registry and capture which MACs are brand new
        from tools.device_registry import update_from_report, load_registry
        self._new_macs        = set(update_from_report(results))
        self._device_registry = load_registry()

        self._render_summary(results, meta)
        self._render_devices(results)
        self._render_protocols(results)
        self._render_findings(results)
        self._arch_btn.config(state='normal')
        self._arch_status_var.set('Ready — click Run Network Review')

    def _clear_detail_view(self):
        self.current_report_id = None
        self.current_results   = None
        self._all_findings_raw = None
        self._new_macs         = set()
        self._device_registry  = {}
        self.detail_title.config(text='No report selected')
        self.open_html_btn.config(state='disabled')
        self._render_threat_meter(0, 'green', '—')
        self._arch_btn.config(state='disabled')
        self._arch_status_var.set('Load a report to enable.')
        for text_widget in (self.summary_text, self.finding_text):
            text_widget.config(state='normal')
            text_widget.delete('1.0', 'end')
            text_widget.config(state='disabled')
        self.devices_tv.delete(*self.devices_tv.get_children())
        self.protocols_tv.delete(*self.protocols_tv.get_children())
        self.findings_tv.delete(*self.findings_tv.get_children())
        self._proto_rows_all = []
        self.proto_text.config(state='normal')
        self.proto_text.delete('1.0', 'end')
        self.proto_text.config(state='disabled')

    # =============================================================== rendering
    def _render_summary(self, results, meta):
        devices = results['devices']
        net = results['network']
        threats = results['threats']

        total = net.get('internal_packets', 0) + net.get('external_packets', 0)
        internal_pct = (100 * net['internal_packets'] // total) if total else 0
        external_pct = 100 - internal_pct if total else 0

        t = self.summary_text
        t.config(state='normal')
        t.delete('1.0', 'end')

        t.insert('end', meta.get('original_filename', ''), 'h1')
        t.insert('end', '\n')
        t.insert('end', f'Analyzed {fmt_timestamp(meta.get("timestamp",""))}  ·  '
                         f'{meta.get("total_packets", 0):,} packets\n')

        t.insert('end', '\nAt a glance\n', 'h2')
        t.insert('end', 'Devices found: ', 'label')
        t.insert('end', f'{devices.get("count", 0)}\n', 'value')

        if self._new_macs:
            n = len(self._new_macs)
            t.insert('end', 'New devices: ', 'label')
            t.insert('end',
                     f'{n} device{"s" if n != 1 else ""} not seen in any previous report  '
                     f'(right-click in Devices tab to label them)\n',
                     'new_device')

        counts = threats.get('counts_by_severity', {}) or {}
        total_findings = threats.get('total', 0)
        t.insert('end', 'Findings: ', 'label')
        if total_findings == 0:
            t.insert('end', 'none — nothing obvious stood out\n', 'value')
        else:
            parts = []
            for sev in SEVERITY_ORDER:
                if counts.get(sev):
                    parts.append((f'{counts[sev]} {sev}', f'sev_{sev}'))
            for i, (txt, tag) in enumerate(parts):
                if i > 0:
                    t.insert('end', ' · ')
                t.insert('end', txt, tag)
            t.insert('end', '\n')

        t.insert('end', '\nNetwork\n', 'h2')
        gw = net.get('gateway_ip') or 'not identified'
        gw_mac = net.get('gateway_mac') or '?'
        t.insert('end', 'Gateway: ', 'label')
        t.insert('end', f'{gw}  (MAC {gw_mac})\n', 'value')

        dns = ', '.join(net.get('dns_servers', []) or []) or 'not identified'
        t.insert('end', 'DNS server(s): ', 'label')
        t.insert('end', f'{dns}\n', 'value')

        subnets = ', '.join(net.get('subnets', []) or []) or 'not identified'
        t.insert('end', 'Subnets: ', 'label')
        t.insert('end', f'{subnets}\n', 'value')

        t.insert('end', 'Traffic split: ', 'label')
        t.insert('end', f'{internal_pct}% internal · {external_pct}% external '
                         f'({fmt_bytes(net.get("bytes_external", 0))} outbound)\n',
                         'value')

        top_ext = net.get('top_external_ips', [])[:5]
        if top_ext:
            t.insert('end', '\nTop external destinations\n', 'h2')
            for ip, count in top_ext:
                t.insert('end', f'  • {ip}  ', 'label')
                t.insert('end', f'({count:,} packets)\n')

        t.insert('end', '\nTip:', 'label')
        t.insert('end', ' open the full HTML report for the color-coded '
                         'version with recommendations for each finding.\n')
        t.config(state='disabled')

    def _render_devices(self, results):
        self.devices_tv.delete(*self.devices_tv.get_children())
        devices = sorted(
            results['devices']['devices'],
            key=lambda d: (not d.get('is_gateway'), -d.get('packet_count', 0)),
        )
        for d in devices:
            mac        = d.get('mac', '')
            is_gateway = d.get('is_gateway', False)
            is_new     = mac in self._new_macs

            # Prefer user label; fall back to auto-detected type
            reg_entry  = self._device_registry.get(mac, {})
            user_label = reg_entry.get('label', '').strip()
            label      = f'★ {user_label}' if user_label else d['likely_type']
            if is_gateway:
                label = '[GATEWAY] ' + label

            if is_new and is_gateway:
                tags = ('gateway_new',)
            elif is_gateway:
                tags = ('gateway',)
            elif is_new:
                tags = ('new_device',)
            else:
                tags = ()

            self.devices_tv.insert(
                '', 'end',
                values=(label,
                        ', '.join(d.get('hostnames', [])) or '—',
                        ', '.join(d.get('ip_addresses', [])) or '—',
                        mac,
                        d.get('vendor') or '—',
                        f'{d.get("packet_count", 0):,}',
                        fmt_bytes(d.get('bytes_total', 0))),
                tags=tags,
            )

    def _render_findings(self, results):
        findings = results['threats'].get('findings', [])
        device_lookup = {d['mac']: d
                         for d in results['devices']['devices']}

        # Store raw data so the severity filter can re-render without re-loading
        self._all_findings_raw = (findings, device_lookup)
        self._apply_findings_filter()

        # Clear detail pane
        self.finding_text.config(state='normal')
        self.finding_text.delete('1.0', 'end')
        if findings:
            self.finding_text.insert('end',
                'Select a finding above to see the full explanation and '
                'what to do about it.', 'body')
        else:
            self.finding_text.insert('end',
                'No security issues detected in this capture. This does '
                'not guarantee the network is clean — encrypted traffic '
                'can hide a lot — but nothing obvious stood out.', 'body')
        self.finding_text.config(state='disabled')

    def _show_finding_detail(self):
        sel = self.findings_tv.selection()
        if not sel:
            return
        payload = self._findings_by_iid.get(sel[0])
        if not payload:
            return
        finding, device_lookup = payload

        t = self.finding_text
        t.config(state='normal')
        t.delete('1.0', 'end')

        # Severity + title
        t.insert('end', finding['severity'].upper() + '  ',
                 f'sev_{finding["severity"]}')
        t.insert('end', finding['title'] + '\n', 'title')

        # Description
        t.insert('end', finding.get('description', ''), 'body')
        t.insert('end', '\n')

        # Affected device
        mac = finding.get('device_mac')
        if mac and mac in device_lookup:
            d = device_lookup[mac]
            ips = ', '.join(d.get('ip_addresses', []))
            hosts = ', '.join(d.get('hostnames', []))
            parts = [d.get('likely_type', 'Unknown device')]
            if hosts:
                parts.append(f'hostname {hosts}')
            if ips:
                parts.append(f'IP {ips}')
            parts.append(f'MAC {mac}')
            t.insert('end', '\nAffected device: ', 'label')
            t.insert('end', '  ·  '.join(parts) + '\n', 'body')

        # Recommendation
        if finding.get('recommendation'):
            t.insert('end', '\nWhat to do\n', 'label')
            t.insert('end', finding['recommendation'] + '\n', 'rec')

        # Technical details
        if finding.get('technical'):
            t.insert('end', '\nTechnical detail\n', 'label')
            t.insert('end', finding['technical'] + '\n', 'tech')

        # Evidence (as JSON)
        if finding.get('evidence'):
            t.insert('end', '\nEvidence\n', 'label')
            t.insert('end', json.dumps(finding['evidence'], indent=2) + '\n', 'tech')

        t.config(state='disabled')

    # =============================================================== actions
    def on_analyze(self):
        path = filedialog.askopenfilename(
            title='Choose a Wireshark capture file',
            filetypes=[('Capture files', '*.pcap *.pcapng *.cap'),
                       ('All files', '*.*')],
        )
        if not path:
            return
        self._analyze_file(path)
        if _pcap_link_type(path) in _80211_LINK_TYPES:
            # 802.11 capture — also open the wireless threat analysis window.
            # Short delay so the regular analysis progress dialog appears first.
            self.after(600, lambda: self._analyze_wireless_pcap(path))

    def _post(self, kind, payload):
        self.msg_queue.put((kind, payload))

    def _poll_analysis(self, dialog):
        try:
            while True:
                kind, payload = self.msg_queue.get_nowait()
                if kind == 'msg':
                    dialog.set_message(payload)
                elif kind == 'done':
                    dialog.destroy()
                    self.status_var.set(f'Analysis complete: {payload}')
                    self._refresh_reports(select_id=payload)
                    return
                elif kind == 'error':
                    dialog.destroy()
                    messagebox.showerror(
                        'Analysis failed',
                        'Something went wrong while analyzing the capture.\n\n'
                        f'{payload}\n\n'
                        'If this is about tshark not being found, make sure '
                        'Wireshark is installed and tshark is on your PATH.')
                    return
        except queue.Empty:
            pass
        self.after(150, lambda: self._poll_analysis(dialog))

    def on_open_html(self):
        if not self.current_report_id:
            return
        html = self.store.html_path(self.current_report_id)
        if html.exists():
            webbrowser.open(html.resolve().as_uri())
        else:
            messagebox.showerror('Report missing',
                                 'HTML report file could not be found.')

    def on_open_reports_folder(self):
        open_in_file_manager(self.store.root)

    def on_open_report_folder(self):
        if not self.current_report_id:
            return
        open_in_file_manager(self.store.root / self.current_report_id)

    def on_delete_report(self):
        report_id = self._selected_report_id()
        if not report_id:
            return
        meta = self.store.get(report_id) or {}
        name = meta.get('original_filename', report_id)
        if not messagebox.askyesno(
            'Delete report?',
            f'Permanently delete the report for "{name}"?\n\n'
            'The saved files will be removed from disk.'):
            return
        self.store.delete(report_id)
        self.status_var.set(f'Deleted: {report_id}')
        self._refresh_reports()

    def _show_finding_context(self, event):
        row = self.findings_tv.identify_row(event.y)
        if row:
            self.findings_tv.selection_set(row)
            self._show_finding_detail()
            self.finding_menu.tk_popup(event.x_root, event.y_root)

    def _investigate_selected_finding(self):
        sel = self.findings_tv.selection()
        if not sel:
            return
        payload = self._findings_by_iid.get(sel[0])
        if not payload:
            return
        finding, _ = payload
        ips = extract_ips(finding)
        if not ips:
            messagebox.showinfo('No IPs found',
                                'No IP addresses were found in this finding.')
            return
        if len(ips) == 1:
            self._open_investigate(ips[0])
        else:
            # Multiple IPs — ask which one
            win = tk.Toplevel(self)
            win.title('Choose IP to investigate')
            win.geometry('300x200')
            win.transient(self)
            win.grab_set()
            ttk.Label(win, text='Select an IP address:',
                      font=('TkDefaultFont', 10, 'bold')).pack(pady=(12, 4))
            lb = tk.Listbox(win, selectmode='browse')
            lb.pack(fill='both', expand=True, padx=12)
            for ip in ips:
                lb.insert('end', ip)
            lb.selection_set(0)
            def _pick():
                idx = lb.curselection()
                if idx:
                    win.destroy()
                    self._open_investigate(ips[idx[0]])
            ttk.Button(win, text='Investigate', command=_pick).pack(pady=8)

    def _select_investigate_tab(self):
        """Switch to the Investigate view in the arsenal."""
        self._select_view('investigate')

    def _open_investigate(self, ip: str):
        self._investigate_ip_var.set(ip)
        self._select_investigate_tab()
        self._run_investigate()

    def _run_investigate(self):
        ip = self._investigate_ip_var.get().strip()
        if not ip:
            return
        self._investigate_btn.config(state='disabled')
        self._investigate_status.config(text='Looking up…')

        t = self.investigate_text
        t.config(state='normal')
        t.delete('1.0', 'end')
        t.insert('end', f'Fetching information for {ip}…\n', 'body')
        t.config(state='disabled')

        api_keys = {
            'shodan':     self.cfg.get('shodan_api_key')    or '',
            'whois_is':   self.cfg.get('whois_is_api_key')  or '',
            'abuseipdb':  self.cfg.get('abuseipdb_api_key') or '',
        }

        def worker():
            try:
                data = lookup_ip(ip, api_keys=api_keys)
                self.after(0, lambda: self._show_investigate_results(data))
            except Exception as e:
                self.after(0, lambda: self._show_investigate_error(str(e)))

        threading.Thread(target=worker, daemon=True).start()

    def _show_investigate_results(self, data):
        self._investigate_btn.config(state='normal')
        self._investigate_status.config(text='Done')
        t = self.investigate_text
        t.config(state='normal')
        t.delete('1.0', 'end')
        for text, tag in format_investigation(data):
            t.insert('end', text, tag)
        t.config(state='disabled')

    def _show_investigate_error(self, msg):
        self._investigate_btn.config(state='normal')
        self._investigate_status.config(text='Error')
        t = self.investigate_text
        t.config(state='normal')
        t.delete('1.0', 'end')
        t.insert('end', f'Lookup failed:\n{msg}\n', 'warn')
        t.config(state='disabled')

    # ----------------------------------------- architect tab build
    def _build_architect_tab(self):
        frame = ttk.Frame(self.view_stack, style='Main.TFrame', padding=(16, 8))
        self._register_view('architect', frame)

        ctrl = ttk.Frame(frame)
        ctrl.pack(fill='x', pady=(0, 6))

        self._arch_btn = ttk.Button(ctrl, text='  Run Network Review  ',
                                    command=self._run_architect_review,
                                    state='disabled')
        self._arch_btn.pack(side='left')

        self._arch_status_var = tk.StringVar(value='Load a report to enable.')
        ttk.Label(ctrl, textvariable=self._arch_status_var,
                  foreground=C['muted']).pack(side='left', padx=(12, 0))

        ttk.Label(frame,
                  text='Analyses the loaded report and gives plain-English recommendations '
                       'on how to improve your network architecture and security posture.',
                  foreground=C['muted']).pack(anchor='w', pady=(0, 8))

        result_frame = ttk.Frame(frame)
        result_frame.pack(fill='both', expand=True)

        self.architect_text = tk.Text(result_frame, wrap='word',
                                      font=('TkDefaultFont', 10),
                                      relief='flat', padx=8, pady=8,
                                      background=self.cget('bg'))
        arch_vsb = ttk.Scrollbar(result_frame, orient='vertical',
                                  command=self.architect_text.yview)
        self.architect_text.configure(yscrollcommand=arch_vsb.set)
        self.architect_text.pack(side='left', fill='both', expand=True)
        arch_vsb.pack(side='right', fill='y')
        self.architect_text.config(state='disabled')

        self.architect_text.tag_configure('h1',
            font=('TkDefaultFont', 14, 'bold'), spacing3=6)
        self.architect_text.tag_configure('h2',
            font=('TkDefaultFont', 11, 'bold'), spacing1=16, spacing3=4)
        self.architect_text.tag_configure('status_action',
            foreground=C['critical'], font=('TkDefaultFont', 10, 'bold'))
        self.architect_text.tag_configure('status_attention',
            foreground=C['warning'], font=('TkDefaultFont', 10, 'bold'))
        self.architect_text.tag_configure('status_good',
            foreground=C['secure'], font=('TkDefaultFont', 10, 'bold'))
        self.architect_text.tag_configure('body',
            spacing3=4, lmargin1=6, lmargin2=6)
        self.architect_text.tag_configure('step',
            lmargin1=14, lmargin2=26, spacing3=4,
            font=('TkDefaultFont', 9))
        self.architect_text.tag_configure('tip',
            foreground=C['muted'], font=('TkDefaultFont', 9),
            lmargin1=8, lmargin2=8, spacing1=2, spacing3=10)
        self.architect_text.tag_configure('label',
            foreground=C['muted'], font=('TkDefaultFont', 9))
        self.architect_text.tag_configure('divider',
            foreground=C['line'])

    # ----------------------------------------- architect run + render
    def _run_architect_review(self):
        if not self.current_results:
            return
        self._arch_btn.config(state='disabled')
        self._arch_status_var.set('Analysing…')
        results = self.current_results

        def worker():
            from analyzer.architect import evaluate
            overall, sections = evaluate(results)
            self.after(0, lambda: self._render_architect_results(overall, sections))

        threading.Thread(target=worker, daemon=True).start()

    def _render_architect_results(self, overall: str, sections: list):
        from analyzer.architect import ACTION, ATTENTION, GOOD

        self._arch_btn.config(state='normal')
        self._arch_status_var.set('Review complete')

        meta       = self.store.get(self.current_report_id) or {}
        n_dev      = self.current_results['devices'].get('count', 0)
        n_findings = self.current_results['threats'].get('total', 0)

        STATUS_TAG   = {ACTION: 'status_action',
                        ATTENTION: 'status_attention',
                        GOOD: 'status_good'}
        STATUS_LABEL = {ACTION: 'ACTION REQUIRED',
                        ATTENTION: 'NEEDS ATTENTION',
                        GOOD: 'GOOD'}

        t = self.architect_text
        t.config(state='normal')
        t.delete('1.0', 'end')

        # Header
        t.insert('end', 'Network Architecture Review\n', 'h1')
        t.insert('end', '━' * 54 + '\n', 'divider')
        t.insert('end',
                 f'  {meta.get("original_filename", "")}  ·  '
                 f'{n_dev} devices  ·  '
                 f'{n_findings} finding{"s" if n_findings != 1 else ""}\n',
                 'label')
        t.insert('end', '\n  Overall assessment:  ', 'label')
        t.insert('end', STATUS_LABEL[overall] + '\n\n', STATUS_TAG[overall])

        # Sections
        for sec in sections:
            tag   = STATUS_TAG[sec.status]
            label = STATUS_LABEL[sec.status]

            t.insert('end', '━' * 54 + '\n', 'divider')
            t.insert('end', f'  {sec.title}    ', 'h2')
            t.insert('end', label + '\n', tag)
            t.insert('end', '━' * 54 + '\n', 'divider')

            t.insert('end', '\n  ' + sec.summary + '\n\n', 'body')

            for para in sec.body:
                t.insert('end', '  ' + para + '\n\n', 'body')

            if sec.steps:
                t.insert('end', '  What to do:\n', 'label')
                for i, step in enumerate(sec.steps, 1):
                    t.insert('end', f'  {i}. {step}\n\n', 'step')

            if sec.tip:
                t.insert('end', f'  Tip: {sec.tip}\n', 'tip')

            t.insert('end', '\n')

        t.config(state='disabled')
        t.see('1.0')

    # ----------------------------------------- severity filter
    def _apply_findings_filter(self):
        if not getattr(self, '_all_findings_raw', None):
            return
        findings, device_lookup = self._all_findings_raw
        active = {s for s, v in self._sev_filter_vars.items() if v.get()}

        self.findings_tv.delete(*self.findings_tv.get_children())
        self._findings_by_iid = {}

        for i, f in enumerate(findings):
            if f['severity'] not in active:
                continue
            dev = ''
            if f.get('device_mac') and f['device_mac'] in device_lookup:
                d = device_lookup[f['device_mac']]
                dev = d.get('likely_type', '')
                if d.get('hostnames'):
                    dev += f' ({", ".join(d["hostnames"][:1])})'
            iid = f'finding_{i}'
            self.findings_tv.insert(
                '', 'end', iid=iid,
                values=(f['severity'].upper(), f['title'], f['category'], dev),
                tags=(f['severity'],),
            )
            self._findings_by_iid[iid] = (f, device_lookup)

    # ----------------------------------------- CSV export
    def on_export_csv(self):
        if not self.current_results:
            messagebox.showinfo('No report', 'Open a report first.')
            return
        findings = self.current_results['threats'].get('findings', [])
        if not findings:
            messagebox.showinfo('No findings', 'This report has no findings to export.')
            return
        device_lookup = {d['mac']: d
                         for d in self.current_results['devices']['devices']}
        path = filedialog.asksaveasfilename(
            title='Export findings as CSV',
            defaultextension='.csv',
            filetypes=[('CSV files', '*.csv'), ('All files', '*.*')],
            initialfile=f'{self.current_report_id}_findings.csv',
        )
        if not path:
            return
        with open(path, 'w', newline='', encoding='utf-8') as fh:
            writer = csv.writer(fh)
            writer.writerow(['Severity', 'Title', 'Category', 'Description',
                             'Affected Device', 'IP Addresses', 'Recommendation'])
            for f in findings:
                dev_name = dev_ips = ''
                mac = f.get('device_mac')
                if mac and mac in device_lookup:
                    d = device_lookup[mac]
                    dev_name = d.get('likely_type', '')
                    dev_ips = ', '.join(d.get('ip_addresses', []))
                writer.writerow([
                    f['severity'], f['title'], f['category'],
                    f.get('description', ''), dev_name, dev_ips,
                    f.get('recommendation', ''),
                ])
        self.status_var.set(f'Exported {len(findings)} findings → {Path(path).name}')
        if messagebox.askyesno('Export complete',
                               f'{len(findings)} findings saved.\nOpen the file?'):
            try:
                if platform.system() == 'Windows':
                    os.startfile(path)
                elif platform.system() == 'Darwin':
                    subprocess.run(['open', path], check=False)
                else:
                    subprocess.run(['xdg-open', path], check=False)
            except Exception:
                pass

    # ----------------------------------------- scan profiles
    def _show_scan_profiles(self):
        """Open the scan profile picker dialog."""
        dlg = tk.Toplevel(self)
        dlg.title('Scan Profiles')
        dlg.geometry('840x580')
        dlg.resizable(True, True)
        dlg.transient(self)
        dlg.grab_set()

        pane = ttk.PanedWindow(dlg, orient='horizontal')
        pane.pack(fill='both', expand=True, padx=8, pady=8)

        # ── Left: profile treeview
        left = ttk.Frame(pane, width=310)
        left.pack_propagate(False)
        pane.add(left, weight=0)

        ttk.Label(left, text='Select a scan profile:',
                  font=('TkDefaultFont', 10, 'bold')).pack(anchor='w', pady=(0, 4))

        tv = ttk.Treeview(left, show='tree', selectmode='browse')
        tv_vsb = ttk.Scrollbar(left, orient='vertical', command=tv.yview)
        tv.configure(yscrollcommand=tv_vsb.set)
        tv.pack(side='left', fill='both', expand=True)
        tv_vsb.pack(side='right', fill='y')

        iid_to_profile: dict = {}
        for cat, profiles in get_profiles_by_category().items():
            cat_iid = tv.insert('', 'end', text=f'  {cat}',
                                open=True, tags=('category',))
            for p in profiles:
                p_iid = tv.insert(cat_iid, 'end',
                                   text=f'    {p["label"]}', tags=('profile',))
                iid_to_profile[p_iid] = p

        tv.tag_configure('category', font=('TkDefaultFont', 10, 'bold'),
                         foreground=C['body'])
        tv.tag_configure('profile', font=('TkDefaultFont', 9),
                         foreground=C['accent_glow'])

        # ── Right: description pane
        right = ttk.Frame(pane)
        pane.add(right, weight=1)

        ttk.Label(right, text='Profile Details',
                  font=('TkDefaultFont', 10, 'bold')).pack(anchor='w', pady=(0, 4))

        desc = tk.Text(right, wrap='word', font=('TkDefaultFont', 10),
                       relief='flat', padx=8, pady=8,
                       background=dlg.cget('bg'), state='disabled')
        desc.pack(fill='both', expand=True)
        desc.tag_configure('h1',   font=('TkDefaultFont', 12, 'bold'), spacing3=4)
        desc.tag_configure('h2',   font=('TkDefaultFont', 10, 'bold'), spacing1=8, spacing3=2)
        desc.tag_configure('body', spacing3=2)
        desc.tag_configure('step', foreground=C['body'],
                           lmargin1=12, lmargin2=12, spacing3=1)
        desc.tag_configure('tip',  foreground=C['muted'], font=('TkDefaultFont', 9),
                           lmargin1=20, lmargin2=20, spacing3=3)

        # ── Target row
        tgt_row = ttk.Frame(dlg)
        tgt_row.pack(fill='x', padx=8, pady=(0, 4))
        ttk.Label(tgt_row, text='Target (IP or range):',
                  font=('TkDefaultFont', 10, 'bold')).pack(side='left')
        tgt_var  = tk.StringVar(value=self._investigate_ip_var.get().strip())
        hint_var = tk.StringVar()
        ttk.Entry(tgt_row, textvariable=tgt_var,
                  width=26, font=('Courier', 10)).pack(side='left', padx=(8, 8))
        ttk.Label(tgt_row, textvariable=hint_var, foreground=C['faint'],
                  font=('TkDefaultFont', 8)).pack(side='left')

        # ── Bottom buttons
        btn_row = ttk.Frame(dlg)
        btn_row.pack(fill='x', padx=8, pady=(0, 8))

        selected = [None]

        def run_scan():
            p = selected[0]
            if not p:
                messagebox.showinfo('No selection', 'Select a scan profile first.',
                                    parent=dlg)
                return
            target = tgt_var.get().strip()
            if not target:
                messagebox.showinfo('No target',
                                    'Enter a target IP address or network range.',
                                    parent=dlg)
                return
            if not NMAP_EXE:
                messagebox.showerror(
                    'nmap not found',
                    'nmap is not installed or not on your PATH.\n'
                    'Download from nmap.org and add it to PATH.',
                    parent=dlg)
                return
            self._investigate_ip_var.set(target)
            dlg.destroy()
            if len(p['steps']) == 1:
                self._run_profile_single(p, target)
            else:
                ScanTaskWizard(self, p, target)

        ttk.Button(btn_row, text='  Run Selected Scan  ',
                   command=run_scan).pack(side='left')
        ttk.Button(btn_row, text='Cancel',
                   command=dlg.destroy).pack(side='left', padx=(8, 0))

        def on_select(event):
            sel = tv.selection()
            if not sel:
                return
            p = iid_to_profile.get(sel[0])
            if not p:
                return
            selected[0] = p
            hint = p.get('target_hint', '')
            hint_var.set(f'e.g. {hint}' if hint else '')
            if hint and not tgt_var.get():
                tgt_var.set(hint)

            desc.config(state='normal')
            desc.delete('1.0', 'end')
            desc.insert('end', p['label'] + '\n', 'h1')
            desc.insert('end', p['description'] + '\n', 'body')
            if len(p['steps']) > 1:
                desc.insert('end', f'\nThis is a {len(p["steps"])}-step scan:\n', 'h2')
                for i, s in enumerate(p['steps'], 1):
                    desc.insert('end', f'  {i}. {s["label"]}\n', 'step')
                    desc.insert('end', f'     {s.get("description", "")}\n', 'tip')
            desc.config(state='disabled')

        tv.bind('<<TreeviewSelect>>', on_select)

    def _run_profile_single(self, profile: dict, target: str):
        """Run a single-step scan profile inline in the investigate_text panel."""
        step       = profile['steps'][0]
        args       = build_step_args(step, {})
        cmd        = [NMAP_EXE] + args + [target]
        cmd_str    = 'nmap ' + ' '.join(args) + ' ' + target
        parse_mode = step.get('parse', 'ports')

        self._select_investigate_tab()
        t = self.investigate_text
        t.config(state='normal')
        t.insert('end', f'\n\n{profile["label"]}\n', 'h2')
        if step.get('description'):
            t.insert('end', f'  {step["description"]}\n', 'tip')
        t.insert('end', f'  $ {cmd_str}\n\n', 'tip')
        t.config(state='disabled')
        self._nmap_btn.config(state='disabled')

        def worker():
            try:
                result = subprocess.run(cmd, capture_output=True, text=True,
                                        encoding='utf-8', errors='replace', timeout=300)
                out = result.stdout or result.stderr or '(no output)'
            except subprocess.TimeoutExpired:
                out = 'Scan timed out after 5 minutes.'
            except Exception as exc:
                out = f'Error: {exc}'
            parsed = parse_nmap_output(out, parse_mode)
            self.after(0, lambda: self._finish_profile_single(out, parsed, args, target, parse_mode))

        threading.Thread(target=worker, daemon=True).start()

    def _finish_profile_single(self, raw: str, parsed: dict,
                                step_args: list, target: str, parse_mode: str):
        from tools.nmap_explainer import explain_results
        self._nmap_btn.config(state='normal')
        t = self.investigate_text
        t.config(state='normal')
        t.insert('end', raw + '\n', 'tech')

        explain = explain_results(parsed, raw, step_args, target, parse_mode)
        self._write_inline_analysis(t, parsed, explain)

        t.config(state='disabled')
        t.see('end')

    def _write_inline_analysis(self, t: tk.Text, parsed: dict, explain: dict):
        """Write rich analysis into an existing investigate_text widget."""
        any_content = False

        # Topology
        topo = explain.get('topology', '')
        if topo:
            t.insert('end', '\nNetwork Map\n', 'h2')
            t.insert('end', topo + '\n', 'tip')
            any_content = True

        # Device IDs
        devs = explain.get('device_ids', [])
        if devs:
            t.insert('end', '\nDevice Identification\n', 'h2')
            for d in devs:
                conf = {'high': '(confirmed)', 'medium': '(likely)',
                        'low': '(possible)'}.get(d['confidence'], '')
                t.insert('end', f'  {d["ip"]}  →  {d["type"]}  {conf}\n', 'body')
                if d.get('os'):
                    t.insert('end', f'    OS: {d["os"]}\n', 'tip')
                if d.get('vendor'):
                    t.insert('end', f'    Hardware: {d["vendor"]}\n', 'tip')
            any_content = True

        # Port explanations
        ports = explain.get('port_details', [])
        if ports:
            t.insert('end', '\nOpen Ports — Plain English\n', 'h2')
            for p in ports:
                concern = p.get('concern', 'UNKNOWN')
                tag = ('warn'   if concern == 'HIGH'
                       else 'risky' if concern == 'MEDIUM'
                       else 'tip')
                t.insert('end',
                         f'  Port {p["port"]}/{p["proto"]}  —  '
                         f'{p.get("name", p["service"])}\n', 'body')
                t.insert('end', f'    {p.get("plain", "")}\n', 'tip')
                if p.get('action'):
                    t.insert('end', f'    Action: {p["action"]}\n', tag)
            any_content = True

        # Security flags
        if parsed.get('warnings'):
            t.insert('end', '\nSecurity Flags\n', 'h2')
            for sev, msg in parsed['warnings']:
                tag = ('warn' if sev == 'HIGH' else 'risky' if sev == 'MEDIUM' else 'tip')
                t.insert('end', f'  [{sev}]  {msg}\n', tag)
            any_content = True

        # Issues + fixes
        issues = explain.get('issues', [])
        if issues:
            t.insert('end', '\nScan Issues & Suggested Fixes\n', 'h2')
            for iss in issues:
                t.insert('end', f'  ⚠  {iss["issue"]}\n', 'risky')
                t.insert('end', f'     {iss["why"]}\n', 'tip')
                t.insert('end', f'     Fix: {iss["fix"]}\n', 'tip')
                t.insert('end', f'     Try: {iss["command"]}\n', 'tip')
            any_content = True

        # Recommendations
        recs = explain.get('recommendations', [])
        if recs:
            t.insert('end', '\nRecommended Next Steps\n', 'h2')
            for i, rec in enumerate(recs, 1):
                t.insert('end', f'  {i}. {rec["label"]}\n', 'body')
                t.insert('end', f'     {rec["reason"]}\n', 'tip')
                t.insert('end', f'     Command: {rec["command"]}\n', 'tip')
            any_content = True

        if not any_content and not parsed.get('summary'):
            t.insert('end', '  Scan completed — no notable findings.\n', 'tip')

    def _run_ad_hoc_nmap(self, cmd_list: list, label: str = ''):
        """Run an arbitrary nmap command list in the Investigate tab."""
        if not NMAP_EXE:
            messagebox.showinfo('nmap not found',
                                'nmap is not installed or not on your PATH.')
            return

        # Ensure the executable path is resolved (recommendations use the string 'nmap')
        if cmd_list and cmd_list[0] == 'nmap':
            cmd_list = [NMAP_EXE] + cmd_list[1:]

        self._select_investigate_tab()
        cmd_str    = 'nmap ' + ' '.join(cmd_list[1:])  # always display as 'nmap ...'
        parse_mode = 'services'  # default for ad-hoc scans
        target     = cmd_list[-1] if cmd_list else ''

        t = self.investigate_text
        t.config(state='normal')
        t.insert('end', f'\n\n{label or "Recommended Scan"}\n', 'h2')
        t.insert('end', f'  $ {cmd_str}\n\n', 'tip')
        t.config(state='disabled')
        self._nmap_btn.config(state='disabled')

        def worker():
            try:
                result = subprocess.run(cmd_list, capture_output=True, text=True,
                                        encoding='utf-8', errors='replace', timeout=300)
                out = result.stdout or result.stderr or '(no output)'
            except subprocess.TimeoutExpired:
                out = 'Scan timed out after 5 minutes.'
            except Exception as exc:
                out = f'Error: {exc}'
            args   = cmd_list[1:-1]  # everything between exe and target
            parsed = parse_nmap_output(out, parse_mode)
            self.after(0, lambda: self._finish_profile_single(
                out, parsed, args, target, parse_mode))

        threading.Thread(target=worker, daemon=True).start()

    # ----------------------------------------- batch IP investigation
    def _run_batch_investigate(self):
        if not self.current_results:
            messagebox.showinfo('No report', 'Load a report first.')
            return
        net = self.current_results.get('network', {})
        findings = self.current_results.get('threats', {}).get('findings', [])

        ips = set()
        for ip, _ in net.get('top_external_ips', []) or []:
            ips.add(ip)
        for f in findings:
            ips.update(extract_ips(f))
        ips = sorted(ips)

        if not ips:
            messagebox.showinfo('No IPs', 'No external IPs found in the current report.')
            return

        self._select_investigate_tab()
        api_keys = {
            'shodan':     self.cfg.get('shodan_api_key')    or '',
            'whois_is':   self.cfg.get('whois_is_api_key')  or '',
            'abuseipdb':  self.cfg.get('abuseipdb_api_key') or '',
        }
        t = self.investigate_text
        t.config(state='normal')
        t.delete('1.0', 'end')
        t.insert('end', f'Batch Investigation  ({len(ips)} IPs from current report)\n', 'h1')
        t.insert('end', '  Lookups running — this may take a minute…\n', 'tip')
        t.config(state='disabled')

        self._investigate_btn.config(state='disabled')
        self._batch_btn.config(state='disabled')
        self._nmap_btn.config(state='disabled')

        def worker():
            rows = []
            for idx, ip in enumerate(ips):
                self.after(0, lambda i=idx, a=ip: self._batch_tick(i + 1, len(ips), a))
                rows.append((ip, lookup_ip(ip, api_keys=api_keys)))
            self.after(0, lambda: self._show_batch_results(rows))

        threading.Thread(target=worker, daemon=True).start()

    def _batch_tick(self, current: int, total: int, ip: str):
        self._investigate_status.config(text=f'{current}/{total}  {ip}')

    def _show_batch_results(self, rows: list):
        self._investigate_btn.config(state='normal')
        self._batch_btn.config(state='normal')
        self._nmap_btn.config(state='normal')
        self._investigate_status.config(text='Done')

        # Determine if any row has valid AbuseIPDB data
        has_abuse = any(
            r[1].get('abuseipdb') and not r[1]['abuseipdb'].get('error')
            for r in rows
        )

        t = self.investigate_text
        t.config(state='normal')
        t.delete('1.0', 'end')
        t.insert('end', f'Batch Investigation  ({len(rows)} IPs)\n', 'h1')
        t.insert('end', '\n')

        if has_abuse:
            hdr = f'{"IP":<18}  {"Country":<12}  {"Org / ISP":<28}  {"Open Ports":<20}  {"CVEs":<8}  Abuse\n'
            sep = f'{"─"*18}  {"─"*12}  {"─"*28}  {"─"*20}  {"─"*8}  {"─"*5}\n'
        else:
            hdr = f'{"IP":<18}  {"Country":<14}  {"Org / ISP":<30}  {"Open Ports":<24}  CVEs\n'
            sep = f'{"─"*18}  {"─"*14}  {"─"*30}  {"─"*24}  {"─"*8}\n'
        t.insert('end', hdr, 'label')
        t.insert('end', sep, 'label')

        for ip, data in rows:
            if data.get('private'):
                t.insert('end', f'{ip:<18}  ', 'tech')
                t.insert('end', 'local / private address\n', 'tip')
                continue
            geo     = data.get('geo') or {}
            idb     = data.get('internetdb') or {}
            sh      = data.get('shodan') or {}
            abuse   = data.get('abuseipdb') or {}

            if has_abuse:
                country   = (geo.get('country') or '?')[:12]
                org       = (geo.get('org') or geo.get('isp') or '?')[:28]
                ports     = sorted(set((idb.get('ports') or []) + (sh.get('ports') or [])))
                ports_str = ','.join(str(p) for p in ports[:5]) if ports else '-'
                if len(ports) > 5:
                    ports_str += f' +{len(ports)-5}'
                vulns     = list(idb.get('vulns') or []) + list(sh.get('vulns') or [])
                cve_str   = f'{len(vulns)} CVEs' if vulns else '-'
                score     = abuse.get('score')
                abuse_str = f'{score}%' if score is not None else '-'
                row_str = f'{ip:<18}  {country:<12}  {org:<28}  {ports_str:<20}  '
                t.insert('end', row_str, 'tech')
                t.insert('end', f'{cve_str:<8}  ', 'vuln' if vulns else 'tech')
                abuse_tag = ('warn'  if (score or 0) >= 75
                             else 'risky' if (score or 0) >= 25
                             else 'tech')
                t.insert('end', abuse_str + '\n', abuse_tag)
            else:
                country   = (geo.get('country') or '?')[:14]
                org       = (geo.get('org') or geo.get('isp') or '?')[:30]
                ports     = sorted(set((idb.get('ports') or []) + (sh.get('ports') or [])))
                ports_str = ','.join(str(p) for p in ports[:7]) if ports else '-'
                if len(ports) > 7:
                    ports_str += f' +{len(ports)-7}'
                vulns   = list(idb.get('vulns') or []) + list(sh.get('vulns') or [])
                cve_str = f'{len(vulns)} CVEs' if vulns else '-'
                row_str = f'{ip:<18}  {country:<14}  {org:<30}  {ports_str:<24}  '
                t.insert('end', row_str, 'tech')
                t.insert('end', cve_str + '\n', 'vuln' if vulns else 'tech')

        t.insert('end', '\n  Tip: paste any IP into the field above and click Look up for full details.\n',
                 'tip')
        t.config(state='disabled')

    # ----------------------------------------- compare reports
    def on_compare_reports(self):
        reports = self.store.list_all()
        if len(reports) < 2:
            messagebox.showinfo(
                'Not enough reports',
                'You need at least two saved reports to compare.\n\n'
                'Analyse a couple of captures first, then come back.',
            )
            return
        CompareDialog(self, self.store)

    def _compare_selected_report(self):
        preselect = self._selected_report_id()
        reports   = self.store.list_all()
        if len(reports) < 2:
            messagebox.showinfo(
                'Not enough reports',
                'You need at least two saved reports to compare.',
            )
            return
        CompareDialog(self, self.store, preselect_id=preselect)

    # ----------------------------------------- live capture
    def on_live_capture(self):
        if not shutil.which('tshark'):
            messagebox.showinfo(
                'tshark not found',
                (
                    'tshark must be installed and on your PATH.\n\n'
                    'Linux (Kali / Parrot):\n'
                    '  sudo apt install tshark\n\n'
                    'Windows:\n'
                    '  Install Wireshark from wireshark.org\n'
                    '  Tick "Add tshark to PATH" during setup,\n'
                    '  then restart this application.'
                ),
            )
            return

        def _on_done(path):
            if _pcap_link_type(path) in _80211_LINK_TYPES:
                self._analyze_wireless_pcap(path)
            else:
                self._analyze_file(path)

        LiveCaptureDialog(self, on_complete_cb=_on_done)

    def _analyze_wireless_pcap(self, path: str):
        """Open the 802.11 findings window and run the wireless analyzer in a thread."""
        dlg = tk.Toplevel(self)
        dlg.title(f'802.11 Analysis — {Path(path).name}')
        dlg.geometry('780x600')
        dlg.minsize(600, 400)

        # ── header
        hdr = ttk.Frame(dlg, padding=(12, 10, 12, 4))
        hdr.pack(fill='x')
        ttk.Label(hdr, text='802.11 Wireless Threat Analysis',
                  font=('TkDefaultFont', 12, 'bold')).pack(side='left')
        ttk.Label(hdr, text=Path(path).name,
                  foreground=C['muted']).pack(side='left', padx=(10, 0))

        # ── scrollable text body
        body = ttk.Frame(dlg, padding=(12, 0, 12, 12))
        body.pack(fill='both', expand=True)

        txt = tk.Text(body, wrap='word', state='disabled', relief='flat',
                      font=('TkDefaultFont', 10), padx=8, pady=8,
                      background=C['inset'], foreground=C['strong'])
        sb  = ttk.Scrollbar(body, orient='vertical', command=txt.yview)
        txt.configure(yscrollcommand=sb.set)
        sb.pack(side='right', fill='y')
        txt.pack(fill='both', expand=True)

        # text tags
        txt.tag_configure('h1',     font=('TkDefaultFont', 11, 'bold'))
        txt.tag_configure('h2',     font=('TkDefaultFont', 10, 'bold'), spacing1=8)
        txt.tag_configure('high',   foreground=C['critical'], font=('TkDefaultFont', 10, 'bold'))
        txt.tag_configure('medium', foreground=C['warning'], font=('TkDefaultFont', 10, 'bold'))
        txt.tag_configure('low',    foreground=C['accent_glow'], font=('TkDefaultFont', 10, 'bold'))
        txt.tag_configure('ok',     foreground=C['secure'], font=('TkDefaultFont', 10, 'bold'))
        txt.tag_configure('body',   foreground=C['body'])
        txt.tag_configure('indent', foreground=C['muted'], lmargin1=20, lmargin2=20)
        txt.tag_configure('sep',    foreground=C['line'])
        txt.tag_configure('dim',    foreground=C['faint'], font=('TkDefaultFont', 9))

        def w(text, tag='body'):
            txt.config(state='normal')
            txt.insert('end', text, tag)
            txt.config(state='disabled')

        w('Analyzing management frames…\n', 'dim')
        txt.update_idletasks()

        def worker():
            result = analyze_80211_pcap(path)
            dlg.after(0, lambda: _render(result))

        def _render(result):
            txt.config(state='normal')
            txt.delete('1.0', 'end')
            txt.config(state='disabled')

            err = result.get('error')
            if err:
                w(f'Error during analysis:\n{err}\n\n', 'high')
                w('Make sure pyshark is installed:  pip install pyshark\n', 'body')
                return

            frame_total = result.get('frame_total', 0)
            raw         = result.get('raw_counts', {})
            ssids       = result.get('ssids_seen', [])
            findings    = result.get('findings', [])

            w('CAPTURE SUMMARY\n', 'h1')
            if frame_total == 0:
                w(
                    '  No 802.11 management frames found.\n\n'
                    '  This usually means the capture was taken on an interface that was\n'
                    '  not in monitor mode, so only normal IP traffic was recorded.\n\n'
                    + (
                        '  To capture raw 802.11 frames on Linux (Kali / Parrot):\n'
                        '    1. sudo airmon-ng start wlan0\n'
                        '       (creates wlan0mon — select that interface in Live Capture)\n'
                        '    2. Or: sudo iw dev wlan0 set type monitor\n'
                        '           sudo ip link set wlan0 up\n'
                        '    3. Not all adapters support monitor mode — Alfa AWUS036ACH\n'
                        '       and Alfa AWUS036NHA are widely supported.\n'
                        if platform.system() != 'Windows' else
                        '  To capture raw 802.11 frames on Windows:\n'
                        '    1. Install Npcap with "Support raw 802.11 traffic" enabled.\n'
                        '    2. Put your adapter into monitor mode before capturing.\n'
                        '    3. Most built-in Intel/Realtek adapters do not support\n'
                        '       monitor mode on Windows — a dedicated USB adapter is needed.\n'
                    ),
                    'body',
                )
                return

            w(f'  Management frames analysed: {frame_total}\n', 'body')
            if ssids:
                w(f'  Networks seen ({len(ssids)}): ', 'body')
                w(', '.join(ssids[:8]))
                if len(ssids) > 8:
                    w(f' … and {len(ssids) - 8} more')
                w('\n')
            if raw:
                w('  Frame breakdown:\n', 'body')
                for name, count in sorted(raw.items(), key=lambda x: -x[1]):
                    w(f'    {name:<28} {count}\n', 'dim')
            w('\n')

            _sev_tag = {'high': 'high', 'medium': 'medium', 'low': 'low'}

            if not findings:
                w('FINDINGS\n', 'h1')
                w('  ✓  No threats detected in this capture.\n', 'ok')
                w('\n')
                w(
                    '  Note: detection requires a monitor-mode capture containing '
                    '802.11 management frames. If you expected to see deauth frames or '
                    'probe sweeps and none appeared, check that your adapter was in '
                    'monitor mode during the capture.\n',
                    'dim',
                )
                return

            # Sort: high first
            _order = {'high': 0, 'medium': 1, 'low': 2}
            findings.sort(key=lambda f: _order.get(f['severity'], 9))

            w(f'FINDINGS  ({len(findings)} issue{"s" if len(findings) != 1 else ""})\n', 'h1')
            for i, f in enumerate(findings, 1):
                sev = f['severity']
                badge = {'high': '⚠ HIGH', 'medium': '⚠ MEDIUM', 'low': 'ℹ LOW'}.get(sev, sev.upper())
                w(f'  {i}. [{badge}]  ', _sev_tag.get(sev, 'body'))
                w(f'{f["title"]}\n', 'h2')
                w(f'  {f["description"]}\n\n', 'body')

                ev = f.get('evidence', {})
                if ev:
                    w('  Evidence:\n', 'h2')
                    for k, v in ev.items():
                        label = k.replace('_', ' ').title()
                        if isinstance(v, list):
                            v = ', '.join(str(x) for x in v)
                        w(f'    {label}: {v}\n', 'indent')
                    w('\n')

                rem = f.get('remediation', '')
                if rem:
                    w('  What to do:\n', 'h2')
                    for line in rem.splitlines():
                        w(f'  {line}\n', 'indent')
                    w('\n')

                if i < len(findings):
                    w('  ' + '─' * 60 + '\n', 'sep')

        threading.Thread(target=worker, daemon=True).start()

    def _analyze_file(self, path: str):
        """Run analysis on *path* (extracted so live capture can reuse it)."""
        filename = Path(path).name
        dialog   = ProgressDialog(self, filename)

        def worker():
            try:
                self._post('msg', 'Reading packets…')
                results, total = run_analysis(path)
                self._post('msg', 'Saving report…')
                report_id = self.store.save(
                    path, results, total, original_filename=filename,
                )
                self._post('done', report_id)
            except Exception as e:
                import traceback
                traceback.print_exc()
                self._post('error', str(e))

        threading.Thread(target=worker, daemon=True).start()
        self.after(150, lambda: self._poll_analysis(dialog))

    # ----------------------------------------- device registry helpers
    def _show_device_context(self, event):
        row = self.devices_tv.identify_row(event.y)
        if row:
            self.devices_tv.selection_set(row)
            self.device_menu.tk_popup(event.x_root, event.y_root)

    def _label_selected_device(self):
        sel = self.devices_tv.selection()
        if not sel:
            return
        mac = str(self.devices_tv.item(sel[0])['values'][3])
        if not mac:
            return
        self._label_device_dialog(mac)

    def _investigate_device_ip(self):
        sel = self.devices_tv.selection()
        if not sel:
            return
        ip_str = str(self.devices_tv.item(sel[0])['values'][2])
        if not ip_str or ip_str == '—':
            messagebox.showinfo('No IP', 'No IP address found for this device.')
            return
        ips = [ip.strip() for ip in ip_str.split(',') if ip.strip()]
        self._open_investigate(ips[0])

    def _label_device_dialog(self, mac: str):
        from tools.device_registry import set_label, load_registry
        reg           = load_registry()
        current_label = reg.get(mac, {}).get('label', '')
        device_type   = reg.get(mac, {}).get('device_type', '')

        win = tk.Toplevel(self)
        win.title('Label device')
        win.geometry('380x180')
        win.transient(self)
        win.grab_set()
        win.resizable(False, False)

        frame = ttk.Frame(win, padding=20)
        frame.pack(fill='both', expand=True)

        ttk.Label(frame, text=f'MAC:  {mac}',
                  foreground=C['muted']).pack(anchor='w')
        if device_type:
            ttk.Label(frame, text=f'Type: {device_type}',
                      foreground=C['muted']).pack(anchor='w')

        ttk.Label(frame, text='Your label for this device:',
                  font=('TkDefaultFont', 10, 'bold')).pack(anchor='w', pady=(10, 4))

        label_var = tk.StringVar(value=current_label)
        entry_w   = ttk.Entry(frame, textvariable=label_var,
                               font=('TkDefaultFont', 10), width=36)
        entry_w.pack(fill='x')
        entry_w.focus_set()
        entry_w.select_range(0, 'end')

        def _save():
            set_label(mac, label_var.get())
            self._device_registry = load_registry()
            if self.current_results:
                self._render_devices(self.current_results)
            win.destroy()

        entry_w.bind('<Return>', lambda e: _save())

        btn_row = ttk.Frame(frame)
        btn_row.pack(fill='x', pady=(14, 0))
        ttk.Button(btn_row, text='Cancel', command=win.destroy).pack(side='right', padx=(6, 0))
        ttk.Button(btn_row, text='Save', command=_save).pack(side='right')

        win.update_idletasks()
        px = self.winfo_rootx() + self.winfo_width()  // 2 - win.winfo_width()  // 2
        py = self.winfo_rooty() + self.winfo_height() // 2 - win.winfo_height() // 2
        win.geometry(f'+{px}+{py}')

    # ======================================================= protocol tab render

    def _render_protocols(self, results):
        """Build the Protocols tab from analysis results and the protocol library."""
        self.protocols_tv.delete(*self.protocols_tv.get_children())
        self._proto_rows_all = []
        self.proto_text.config(state='normal')
        self.proto_text.delete('1.0', 'end')
        self.proto_text.config(state='disabled')

        proto_data = results.get('protocols') or {}
        if not proto_data:
            return

        library = load_library()

        # ── build a deduplicated list of observed protocols ───────────────────
        seen_names = set()
        rows = []  # (display_name, category, count, risk, status_text, entry_or_None, source_key)

        _RISK_LABEL = {
            RISK_NONE: '–',
            RISK_LOW: 'Low',
            RISK_MEDIUM: 'Medium',
            RISK_HIGH: 'High',
        }

        # Pass 1: named layers (most specific — pyshark identified the protocol)
        layers = proto_data.get('layers') or {}
        for layer_name, count in sorted(layers.items(), key=lambda x: -x[1]):
            entry = lookup_layer(layer_name, library)
            if entry:
                if entry['name'] in seen_names:
                    continue
                seen_names.add(entry['name'])
                rows.append((
                    entry['name'],
                    entry.get('category', ''),
                    count,
                    entry.get('risk', RISK_NONE),
                    entry.get('plain_english', '')[:80],
                    entry,
                    f'layer:{layer_name}',
                ))
            else:
                hint = lookup_layer_hint(layer_name)
                display = hint['name'] if hint else layer_name.upper()
                if display in seen_names:
                    continue
                seen_names.add(display)
                cat    = hint.get('category', 'Unknown') if hint else 'Unknown'
                risk   = hint.get('risk')                if hint else None
                status = (hint['plain_english'][:80]     if hint
                          else 'Not in protocol library — right-click to add it')
                rows.append((display, cat, count, risk, status, hint, f'layer:{layer_name}'))

        # Pass 2: TCP ports (fill in for protocols with no named layer)
        tcp_ports = proto_data.get('tcp_ports') or {}
        for port_str, count in sorted(tcp_ports.items(), key=lambda x: -x[1]):
            try:
                port = int(port_str)
            except ValueError:
                continue
            entry = lookup_port(port, 'tcp', library)
            if entry:
                if entry['name'] in seen_names:
                    continue
                seen_names.add(entry['name'])
                rows.append((
                    entry['name'],
                    entry.get('category', ''),
                    count,
                    entry.get('risk', RISK_NONE),
                    entry.get('plain_english', '')[:80],
                    entry,
                    f'tcp:{port}',
                ))
            else:
                hint = lookup_port_iana(port, 'tcp')
                key  = hint['name'] if hint else f'TCP/{port}'
                if key in seen_names:
                    continue
                seen_names.add(key)
                status = hint['plain_english'][:80] if hint else 'Not in protocol library — right-click to add it'
                rows.append((key, hint.get('category', 'Unknown') if hint else 'Unknown',
                             count, None, status, hint, f'tcp:{port}'))

        # Pass 3: UDP ports
        udp_ports = proto_data.get('udp_ports') or {}
        for port_str, count in sorted(udp_ports.items(), key=lambda x: -x[1]):
            try:
                port = int(port_str)
            except ValueError:
                continue
            entry = lookup_port(port, 'udp', library)
            if entry:
                if entry['name'] in seen_names:
                    continue
                seen_names.add(entry['name'])
                rows.append((
                    entry['name'],
                    entry.get('category', ''),
                    count,
                    entry.get('risk', RISK_NONE),
                    entry.get('plain_english', '')[:80],
                    entry,
                    f'udp:{port}',
                ))
            else:
                hint = lookup_port_iana(port, 'udp')
                key  = hint['name'] if hint else f'UDP/{port}'
                if key in seen_names:
                    continue
                seen_names.add(key)
                status = hint['plain_english'][:80] if hint else 'Not in protocol library — right-click to add it'
                rows.append((key, hint.get('category', 'Unknown') if hint else 'Unknown',
                             count, None, status, hint, f'udp:{port}'))

        # Sort: unknown first, then by risk (worst first), then by count
        _risk_rank = {RISK_HIGH: 0, RISK_MEDIUM: 1, RISK_LOW: 2, RISK_NONE: 3, None: 99}
        def _sort_key(r):
            name, cat, count, risk, status, entry, src = r
            is_hint    = isinstance(entry, dict) and entry.get('_hint')
            is_unknown = entry is None
            tier = 2 if is_unknown else (1 if is_hint else 0)
            return (tier, _risk_rank.get(risk, 99), -count)
        rows.sort(key=_sort_key)

        # Populate treeview
        for i, (name, cat, count, risk, status, entry, src) in enumerate(rows):
            iid = str(i)
            risk_label = _RISK_LABEL.get(risk, '?') if risk else '?'
            is_hint = isinstance(entry, dict) and entry.get('_hint')
            if risk:
                tag = f'risk_{risk}'
            elif is_hint:
                tag = 'hint'
            else:
                tag = 'unknown'
            self.protocols_tv.insert('', 'end', iid=iid,
                                     values=(name, cat, f'{count:,}', risk_label, status),
                                     tags=(tag,))
            self._proto_rows_all.append((iid, (name, cat, count, risk_label, status), tag, entry, src))

        # Auto-select first row
        children = self.protocols_tv.get_children()
        if children:
            self.protocols_tv.selection_set(children[0])
            self.protocols_tv.focus(children[0])
            self._show_proto_detail()

    def _apply_proto_filter(self):
        """Re-filter the protocols treeview based on search text and unknown-only toggle."""
        search = self._proto_search_var.get().lower()
        unknown_only = self._proto_unknown_only.get()

        self.protocols_tv.delete(*self.protocols_tv.get_children())
        for iid, vals, tag, entry, src in self._proto_rows_all:
            name, cat, count, risk_label, status = vals
            is_unknown = (entry is None)
            if unknown_only and not is_unknown:
                continue
            if search and search not in name.lower() and search not in cat.lower() and search not in status.lower():
                continue
            self.protocols_tv.insert('', 'end', iid=iid,
                                     values=(name, cat, count, risk_label, status),
                                     tags=(tag,))

    def _show_proto_detail(self):
        """Populate the description panel for the selected protocol row."""
        sel = self.protocols_tv.selection()
        if not sel:
            return
        iid = sel[0]
        row = next((r for r in self._proto_rows_all if r[0] == iid), None)
        if not row:
            return
        _, vals, _, entry, src = row
        name = vals[0]

        t = self.proto_text
        t.config(state='normal')
        t.delete('1.0', 'end')

        if entry is None:
            # Truly unknown — no library entry and no hint
            t.insert('end', f'{name}\n', 'name')
            t.insert('end', 'Not identified\n', 'unknown')
            t.insert('end', '\nWhat this means\n', 'label')
            t.insert('end',
                     'This port or protocol was not matched to any entry in the library '
                     'or the IANA service registry. That does not automatically mean it '
                     'is dangerous — niche or proprietary protocols are often legitimate.\n', 'body')
            t.insert('end', '\nWhat to do\n', 'label')
            if src.startswith('tcp:') or src.startswith('udp:'):
                transport, port = src.split(':')
                t.insert('end',
                         f'1. Search online for "port {port} {transport.upper()} protocol" '
                         f'to identify what service uses it.\n', 'body')
            else:
                t.insert('end',
                         f'1. Search online for "{name} protocol" to learn what it is.\n', 'body')
            t.insert('end',
                     '2. Right-click this row and choose "Add to Protocol Library…" '
                     'to add your own description.\n', 'body')
            t.insert('end',
                     '3. Use the Investigate tab to look up the IP addresses '
                     'communicating on this port.\n', 'body')
            t.insert('end', f'\nSource: {src}\n', 'tip')

        elif isinstance(entry, dict) and entry.get('_hint'):
            # Tier 2 / Tier 3 hint — partial information available
            t.insert('end', f'{entry["name"]}\n', 'name')
            t.insert('end', 'Identified (partial data)\n', 'hint')
            if entry.get('plain_english'):
                t.insert('end', '\nWhat it is\n', 'label')
                t.insert('end', entry['plain_english'] + '\n', 'body')
            risk = entry.get('risk', RISK_NONE)
            if risk and risk != RISK_NONE:
                risk_labels = {
                    RISK_LOW:    'Low risk — worth knowing about',
                    RISK_MEDIUM: 'Medium risk — investigate if unexpected',
                    RISK_HIGH:   'High risk — take action',
                }
                t.insert('end', '\nRisk: ', 'label')
                t.insert('end', risk_labels.get(risk, risk) + '\n', f'risk_{risk}')
            iana = entry.get('_iana_name')
            if iana:
                t.insert('end', '\nIANA service name:  ', 'label')
                t.insert('end', iana + '\n', 'body')
            t.insert('end', '\nTo add full detail\n', 'label')
            t.insert('end',
                     'Right-click this row and choose "Add to Protocol Library…" '
                     'to add plain-English descriptions, risk rating, and action steps '
                     'that will appear in every future report.\n', 'body')
            t.insert('end', f'\nSource: {src}\n', 'tip')
        else:
            risk = entry.get('risk', RISK_NONE)
            risk_tag = f'risk_{risk}'
            risk_labels = {
                RISK_NONE: 'No specific risk',
                RISK_LOW: 'Low risk — worth knowing about',
                RISK_MEDIUM: 'Medium risk — investigate if unexpected',
                RISK_HIGH: 'High risk — take action',
            }

            t.insert('end', f'{entry["name"]}\n', 'name')
            if entry.get('full_name') and entry['full_name'] != entry['name']:
                t.insert('end', f'{entry["full_name"]}\n', 'full')

            t.insert('end', 'Risk:  ', 'label')
            t.insert('end', risk_labels.get(risk, risk) + '\n', risk_tag)

            if entry.get('plain_english'):
                t.insert('end', '\nWhat it is\n', 'label')
                t.insert('end', entry['plain_english'] + '\n', 'body')

            if entry.get('expected_when'):
                t.insert('end', '\nWhen to expect it\n', 'label')
                t.insert('end', entry['expected_when'] + '\n', 'body')

            if entry.get('unexpected_when'):
                t.insert('end', '\nWhen to investigate\n', 'label')
                t.insert('end', entry['unexpected_when'] + '\n',
                         'warn' if risk in (RISK_HIGH, RISK_MEDIUM) else 'body')

            if entry.get('action'):
                t.insert('end', '\nWhat to do\n', 'label')
                t.insert('end', entry['action'] + '\n', 'body')

            ports = entry.get('ports') or []
            transport = entry.get('transport') or []
            if ports:
                t.insert('end', '\nPorts:  ', 'label')
                t.insert('end', ', '.join(str(p) for p in ports[:12]) + '\n', 'body')
            if transport:
                t.insert('end', 'Transport:  ', 'label')
                t.insert('end', ', '.join(t_val.upper() for t_val in transport) + '\n', 'body')

            if entry.get('user_added'):
                t.insert('end', '\n(User-defined entry — right-click to edit)\n', 'tip')

        t.config(state='disabled')

    def _show_proto_context(self, event):
        sel = self.protocols_tv.identify_row(event.y)
        if sel:
            self.protocols_tv.selection_set(sel)
            self._show_proto_detail()
        try:
            self.proto_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.proto_menu.grab_release()

    def _proto_add_to_library(self):
        """Open the add/edit dialog pre-filled from the selected unknown row."""
        sel = self.protocols_tv.selection()
        if not sel:
            return
        row = next((r for r in self._proto_rows_all if r[0] == sel[0]), None)
        if not row:
            return
        _, vals, _, entry, src = row
        prefill = {}
        if entry:
            prefill = dict(entry)
        else:
            name = vals[0]
            prefill['name'] = name if not name.startswith(('TCP/', 'UDP/')) else ''
            if src.startswith('tcp:'):
                prefill['ports'] = [int(src.split(':')[1])]
                prefill['transport'] = ['tcp']
            elif src.startswith('udp:'):
                prefill['ports'] = [int(src.split(':')[1])]
                prefill['transport'] = ['udp']
        self._open_proto_edit_dialog(prefill, on_save=lambda: self._render_protocols(self.current_results))

    def _proto_edit_entry(self):
        """Open the edit dialog for the selected protocol (user-added entries only)."""
        sel = self.protocols_tv.selection()
        if not sel:
            return
        row = next((r for r in self._proto_rows_all if r[0] == sel[0]), None)
        if not row:
            return
        _, vals, _, entry, _ = row
        if not entry:
            self._proto_add_to_library()
            return
        self._open_proto_edit_dialog(dict(entry),
                                     on_save=lambda: self._render_protocols(self.current_results))

    # ================================================== protocol library manager

    def _show_protocol_library(self):
        """Open the full protocol library manager window."""
        win = tk.Toplevel(self)
        win.title('Protocol Library')
        win.geometry('900x620')
        win.transient(self)
        win.minsize(700, 480)

        # ---- left: list ----
        main = ttk.Frame(win, padding=8)
        main.pack(fill='both', expand=True)
        main.columnconfigure(0, weight=1)
        main.columnconfigure(1, weight=0)
        main.rowconfigure(1, weight=1)

        ttk.Label(main, text='Protocol Library',
                  font=('TkDefaultFont', 12, 'bold')).grid(
                      row=0, column=0, columnspan=2, sticky='w', pady=(0, 6))

        list_frame = ttk.Frame(main)
        list_frame.grid(row=1, column=0, sticky='nsew', padx=(0, 6))
        list_frame.rowconfigure(0, weight=1)
        list_frame.columnconfigure(0, weight=1)

        cols = ('name', 'category', 'risk', 'source')
        lib_tv = ttk.Treeview(list_frame, columns=cols, show='headings',
                               selectmode='browse')
        lib_tv.heading('name',     text='Protocol')
        lib_tv.heading('category', text='Category')
        lib_tv.heading('risk',     text='Risk')
        lib_tv.heading('source',   text='Source')
        lib_tv.column('name',     width=180, anchor='w')
        lib_tv.column('category', width=120, anchor='w')
        lib_tv.column('risk',     width=80,  anchor='w')
        lib_tv.column('source',   width=90,  anchor='w')
        lib_tv_vsb = ttk.Scrollbar(list_frame, orient='vertical', command=lib_tv.yview)
        lib_tv.configure(yscrollcommand=lib_tv_vsb.set)
        lib_tv.grid(row=0, column=0, sticky='nsew')
        lib_tv_vsb.grid(row=0, column=1, sticky='ns')

        lib_tv.tag_configure('builtin',  foreground=C['muted'])
        lib_tv.tag_configure('user',     foreground=C['info'],
                              font=('TkDefaultFont', 9, 'bold'))

        # ---- right: buttons ----
        btn_col = ttk.Frame(main)
        btn_col.grid(row=1, column=1, sticky='n', pady=(0, 0))

        def _populate():
            lib_tv.delete(*lib_tv.get_children())
            library = load_library()
            for e in sorted(library, key=lambda x: x['name'].lower()):
                tag = 'user' if e.get('user_added') else 'builtin'
                source = 'User-added' if e.get('user_added') else 'Built-in'
                lib_tv.insert('', 'end', iid=e['name'],
                              values=(e['name'], e.get('category', ''),
                                      e.get('risk', ''), source),
                              tags=(tag,))

        def _add():
            self._open_proto_edit_dialog({}, on_save=_populate)

        def _edit():
            sel = lib_tv.selection()
            if not sel:
                return
            iid = sel[0]
            library = {e['name']: e for e in load_library()}
            entry = library.get(iid)
            if entry:
                self._open_proto_edit_dialog(dict(entry), on_save=_populate)

        def _delete():
            sel = lib_tv.selection()
            if not sel:
                return
            iid = sel[0]
            library = {e['name']: e for e in load_library()}
            entry = library.get(iid)
            if not entry:
                return
            if not entry.get('user_added'):
                messagebox.showinfo(
                    'Built-in entry',
                    'Built-in protocol entries cannot be deleted. '
                    'You can add a user entry with the same name to override it.',
                    parent=win)
                return
            if messagebox.askyesno('Delete entry',
                                   f'Delete "{iid}" from the library?',
                                   parent=win):
                delete_user_entry(iid)
                _populate()
                if self.current_results:
                    self._render_protocols(self.current_results)

        ttk.Button(btn_col, text='Add…',    command=_add).pack(fill='x', pady=(0, 4))
        ttk.Button(btn_col, text='Edit…',   command=_edit).pack(fill='x', pady=(0, 4))
        ttk.Button(btn_col, text='Delete',  command=_delete).pack(fill='x', pady=(0, 4))
        ttk.Separator(btn_col, orient='horizontal').pack(fill='x', pady=8)
        ttk.Button(btn_col, text='Close',
                   command=win.destroy).pack(fill='x')

        _populate()

        self.update_idletasks()
        px = self.winfo_rootx() + self.winfo_width() // 2 - win.winfo_width() // 2
        py = self.winfo_rooty() + self.winfo_height() // 2 - win.winfo_height() // 2
        win.geometry(f'+{px}+{py}')

    def _open_proto_edit_dialog(self, prefill: dict, on_save=None):
        """Dialog to add or edit a protocol library entry."""
        win = tk.Toplevel(self)
        is_edit = bool(prefill.get('name'))
        win.title('Edit Protocol Entry' if is_edit else 'Add Protocol to Library')
        win.geometry('640x640')
        win.transient(self)
        win.resizable(True, True)
        win.grab_set()

        outer = ttk.Frame(win, padding=16)
        outer.pack(fill='both', expand=True)
        outer.columnconfigure(1, weight=1)

        def _row(label, row, widget_factory):
            ttk.Label(outer, text=label,
                      font=('TkDefaultFont', 9, 'bold')).grid(
                          row=row, column=0, sticky='nw', padx=(0, 10), pady=4)
            w = widget_factory(outer)
            w.grid(row=row, column=1, sticky='ew', pady=4)
            return w

        # Name
        name_var = tk.StringVar(value=prefill.get('name', ''))
        _row('Protocol Name:', 0, lambda p: ttk.Entry(p, textvariable=name_var, width=30))

        # Full name
        full_var = tk.StringVar(value=prefill.get('full_name', ''))
        _row('Full Name:', 1, lambda p: ttk.Entry(p, textvariable=full_var, width=40))

        # Ports
        ports_val = ', '.join(str(p) for p in (prefill.get('ports') or []))
        ports_var = tk.StringVar(value=ports_val)
        _row('Ports\n(comma-separated):', 2,
             lambda p: ttk.Entry(p, textvariable=ports_var, width=30))

        # Transport
        tcp_var = tk.BooleanVar(value='tcp' in (prefill.get('transport') or []))
        udp_var = tk.BooleanVar(value='udp' in (prefill.get('transport') or []))
        def _transport(parent):
            f = ttk.Frame(parent)
            ttk.Checkbutton(f, text='TCP', variable=tcp_var).pack(side='left')
            ttk.Checkbutton(f, text='UDP', variable=udp_var).pack(side='left', padx=(12, 0))
            return f
        _row('Transport:', 3, _transport)

        # Category
        cat_var = tk.StringVar(value=prefill.get('category', ALL_CATEGORIES[0]))
        _row('Category:', 4,
             lambda p: ttk.Combobox(p, textvariable=cat_var,
                                    values=ALL_CATEGORIES, state='readonly', width=20))

        # Risk
        risk_var = tk.StringVar(value=prefill.get('risk', RISK_LOW))
        _row('Risk:', 5,
             lambda p: ttk.Combobox(p, textvariable=risk_var,
                                    values=[RISK_NONE, RISK_LOW, RISK_MEDIUM, RISK_HIGH],
                                    state='readonly', width=12))

        def _textarea(label, row, init_text):
            ttk.Label(outer, text=label,
                      font=('TkDefaultFont', 9, 'bold')).grid(
                          row=row, column=0, sticky='nw', padx=(0, 10), pady=4)
            frame = ttk.Frame(outer)
            frame.grid(row=row, column=1, sticky='ew', pady=4)
            frame.columnconfigure(0, weight=1)
            t = tk.Text(frame, height=3, wrap='word',
                        font=('TkDefaultFont', 10), relief='solid', bd=1)
            t.insert('1.0', init_text or '')
            t.pack(fill='both', expand=True)
            return t

        plain_t  = _textarea('What it is:',         6,  prefill.get('plain_english', ''))
        expect_t = _textarea('When to expect it:',  7,  prefill.get('expected_when', ''))
        unexpect_t = _textarea('When to investigate:', 8, prefill.get('unexpected_when', ''))
        action_t = _textarea('What to do:',         9,  prefill.get('action', ''))

        # Buttons
        btn_row = ttk.Frame(outer)
        btn_row.grid(row=10, column=0, columnspan=2, sticky='e', pady=(12, 0))

        def _save():
            name = name_var.get().strip()
            if not name:
                messagebox.showerror('Required', 'Protocol Name is required.', parent=win)
                return
            transport = []
            if tcp_var.get(): transport.append('tcp')
            if udp_var.get(): transport.append('udp')
            try:
                ports = [int(p.strip()) for p in ports_var.get().split(',') if p.strip()]
            except ValueError:
                messagebox.showerror('Invalid', 'Ports must be comma-separated numbers.', parent=win)
                return
            entry = {
                'name':            name,
                'full_name':       full_var.get().strip(),
                'ports':           ports,
                'transport':       transport,
                'layer_names':     prefill.get('layer_names', []),
                'category':        cat_var.get(),
                'risk':            risk_var.get(),
                'plain_english':   plain_t.get('1.0', 'end').strip(),
                'expected_when':   expect_t.get('1.0', 'end').strip(),
                'unexpected_when': unexpect_t.get('1.0', 'end').strip(),
                'action':          action_t.get('1.0', 'end').strip(),
                'user_added':      True,
            }
            save_user_entry(entry)
            win.destroy()
            if on_save:
                on_save()
            if self.current_results:
                self._render_protocols(self.current_results)

        ttk.Button(btn_row, text='Cancel', command=win.destroy).pack(side='left', padx=(0, 8))
        ttk.Button(btn_row, text='  Save to Library  ', command=_save).pack(side='left')

        self.update_idletasks()
        px = self.winfo_rootx() + self.winfo_width() // 2 - win.winfo_width() // 2
        py = self.winfo_rooty() + self.winfo_height() // 2 - win.winfo_height() // 2
        win.geometry(f'+{px}+{py}')

    def _show_admin_settings(self):
        AdminSettingsPanel(self)

    def _show_settings(self):
        win = tk.Toplevel(self)
        win.title('Settings')
        win.geometry('540x370')
        win.resizable(False, False)
        win.transient(self)
        win.grab_set()

        frame = ttk.Frame(win, padding=20)
        frame.pack(fill='both', expand=True)

        ttk.Label(frame, text='API Keys',
                  font=('TkDefaultFont', 11, 'bold')).grid(
                      row=0, column=0, columnspan=3, sticky='w', pady=(0, 12))

        # Shodan
        ttk.Label(frame, text='Shodan:').grid(
            row=1, column=0, sticky='w', padx=(0, 12))
        shodan_var = tk.StringVar(value=self.cfg.get('shodan_api_key', ''))
        shodan_entry = ttk.Entry(frame, textvariable=shodan_var, width=34,
                                 font=('Courier', 10), show='*')
        shodan_entry.grid(row=1, column=1, sticky='ew')
        show_shodan = tk.BooleanVar(value=False)
        def _toggle_shodan():
            shodan_entry.config(show='' if show_shodan.get() else '*')
        ttk.Checkbutton(frame, text='Show', variable=show_shodan,
                        command=_toggle_shodan).grid(row=1, column=2, padx=(6, 0))
        ttk.Label(frame, text='shodan.io  — ports, services, CVEs',
                  foreground=C['muted']).grid(
                      row=2, column=1, columnspan=2, sticky='w', pady=(2, 10))

        # whois.is
        ttk.Label(frame, text='whois.is:').grid(
            row=3, column=0, sticky='w', padx=(0, 12))
        whoisIs_var = tk.StringVar(value=self.cfg.get('whois_is_api_key', ''))
        whoisIs_entry = ttk.Entry(frame, textvariable=whoisIs_var, width=34,
                                  font=('Courier', 10), show='*')
        whoisIs_entry.grid(row=3, column=1, sticky='ew')
        show_whoisIs = tk.BooleanVar(value=False)
        def _toggle_whoisIs():
            whoisIs_entry.config(show='' if show_whoisIs.get() else '*')
        ttk.Checkbutton(frame, text='Show', variable=show_whoisIs,
                        command=_toggle_whoisIs).grid(row=3, column=2, padx=(6, 0))
        ttk.Label(frame,
                  text='whois.is  — domain registration data  (optional, free tier works without key)',
                  foreground=C['muted']).grid(
                      row=4, column=1, columnspan=2, sticky='w', pady=(2, 10))

        # AbuseIPDB
        ttk.Label(frame, text='AbuseIPDB:').grid(
            row=5, column=0, sticky='w', padx=(0, 12))
        abuse_var = tk.StringVar(value=self.cfg.get('abuseipdb_api_key', ''))
        abuse_entry = ttk.Entry(frame, textvariable=abuse_var, width=34,
                                font=('Courier', 10), show='*')
        abuse_entry.grid(row=5, column=1, sticky='ew')
        show_abuse = tk.BooleanVar(value=False)
        def _toggle_abuse():
            abuse_entry.config(show='' if show_abuse.get() else '*')
        ttk.Checkbutton(frame, text='Show', variable=show_abuse,
                        command=_toggle_abuse).grid(row=5, column=2, padx=(6, 0))
        ttk.Label(frame,
                  text='abuseipdb.com  — abuse confidence score, free tier: 1,000 checks/day',
                  foreground=C['muted']).grid(
                      row=6, column=1, columnspan=2, sticky='w', pady=(2, 16))

        def _save():
            self.cfg['shodan_api_key']    = shodan_var.get().strip()
            self.cfg['whois_is_api_key']  = whoisIs_var.get().strip()
            self.cfg['abuseipdb_api_key'] = abuse_var.get().strip()
            _save_config(self.cfg)
            win.destroy()
            self.status_var.set('Settings saved.')

        btn_row = ttk.Frame(frame)
        btn_row.grid(row=7, column=0, columnspan=3, sticky='e')
        ttk.Button(btn_row, text='Cancel', command=win.destroy).pack(side='left', padx=(0, 8))
        ttk.Button(btn_row, text='Save', command=_save).pack(side='left')

        frame.columnconfigure(1, weight=1)
        win.update_idletasks()
        px = self.winfo_rootx() + self.winfo_width()  // 2 - win.winfo_width()  // 2
        py = self.winfo_rooty() + self.winfo_height() // 2 - win.winfo_height() // 2
        win.geometry(f'+{px}+{py}')

    def _show_about(self):
        messagebox.showinfo(
            'About ' + APP_NAME,
            f'{APP_NAME}\n\n'
            'A plain-English security report for Wireshark captures.\n\n'
            'Analyses run locally and reports are stored offline at:\n'
            f'{self.store.root}\n\n'
            'Each report is a self-contained folder (HTML + JSON) — '
            'the HTML file alone can be opened in any browser, forever, '
            'even without this app installed.'
        )


# =================================================================== entry
def main():
    app = App()
    try:
        app.mainloop()
    except KeyboardInterrupt:
        app.destroy()


if __name__ == '__main__':
    main()
