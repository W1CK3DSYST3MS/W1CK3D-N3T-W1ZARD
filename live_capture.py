#!/usr/bin/env python3
"""
live_capture.py — Live network capture using tshark directly.

Captures traffic from a live network interface without requiring a
pre-existing pcap file.  The capture is written to a pcap which the
existing analysis pipeline then consumes.

This module has no tkinter dependency and is safe to import from the
GUI, the CLI, and the scheduler alike.

Public API
----------
  list_interfaces()          → list[Interface]
  CaptureSession             — subprocess wrapper with progress callbacks
  capture_to_file(...)       → Path          (blocking)
  capture_and_analyze(...)   → dict          (blocking, returns cli.analyze_file() output)

Exceptions
----------
  CaptureError               — base class for all capture failures
  CapturePermissionError     — tshark lacks privileges on the interface

CLI usage
---------
  python live_capture.py --list-interfaces
  python live_capture.py -i eth0 -d 60
  python live_capture.py -i eth0 -d 60 --analyze
  python live_capture.py -i eth0 -d 60 --analyze --fail-on high --format json
  python live_capture.py -i 2 -c 5000 --out /tmp/my.pcap
  python live_capture.py -i wlan0 -d 120 --filter "tcp port 443"

Exit codes (when --analyze is used)
-------------------------------------
  0  Success; no findings at or above --fail-on threshold.
  1  Findings at or above --fail-on threshold.
  2  Fatal error (tshark not found, permission denied, empty capture, etc.).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable

# ---------------------------------------------------------------------------
# Make the project importable when running this file directly
# ---------------------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).parent))

from analyze import TSHARK_PATH  # also applies the Windows CREATE_NO_WINDOW patch

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

CAPTURES_DIR = Path.home() / 'W1CK3DWizard' / 'Captures'


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class CaptureError(RuntimeError):
    """Base exception for all live-capture failures."""


class CapturePermissionError(CaptureError):
    """
    tshark lacks the privileges needed to capture on the requested interface.

    Linux fix  : sudo setcap cap_net_raw,cap_net_admin=eip $(which tshark)
                 or run install.sh which does this automatically.
    macOS fix  : run tshark with sudo, or add your user to the 'access_bpf' group.
    Windows fix: ensure Npcap is installed (https://npcap.com/) and that the
                 'WinPcap API-compatible mode' option was selected during install.
    """


# ---------------------------------------------------------------------------
# Interface discovery
# ---------------------------------------------------------------------------

@dataclass
class Interface:
    index:       int
    name:        str
    description: str

    def __str__(self) -> str:
        desc = f'  ({self.description})' if self.description else ''
        return f'{self.index:>3}.  {self.name:<30}{desc}'


def list_interfaces() -> list[Interface]:
    """
    Return all capture interfaces reported by ``tshark -D``.

    Raises CaptureError if tshark is not found or returns a non-zero exit code.
    """
    if not TSHARK_PATH:
        raise CaptureError(
            'tshark is not installed or not on PATH. '
            'Install Wireshark (https://www.wireshark.org/download.html).'
        )

    result = subprocess.run(
        [TSHARK_PATH, '-D'],
        capture_output=True,
        text=True,
        encoding='utf-8',
        errors='replace',
    )

    if result.returncode != 0:
        raise CaptureError(
            f'tshark -D failed (exit {result.returncode}):\n'
            f'{result.stderr.strip() or result.stdout.strip()}'
        )

    interfaces: list[Interface] = []
    # tshark -D output: "N. name (description)" or "N. name"
    pattern = re.compile(r'^(\d+)\.\s+(\S+)(?:\s+\((.+)\))?', re.MULTILINE)
    for m in pattern.finditer(result.stdout):
        interfaces.append(Interface(
            index=int(m.group(1)),
            name=m.group(2),
            description=(m.group(3) or '').strip(),
        ))

    return interfaces


def _resolve_interface(iface: str | int) -> str:
    """
    Return the interface name to pass to tshark -i.

    Accepts either:
      - An integer index  (1, 2, 3 …) — looked up via tshark -D.
      - A string name     ('eth0', 'wlan0', or a Windows device path)
    """
    try:
        idx = int(iface)
    except (TypeError, ValueError):
        return str(iface)   # already a name

    for ifc in list_interfaces():
        if ifc.index == idx:
            return ifc.name

    raise CaptureError(f'No interface with index {idx}. Run --list-interfaces to see options.')


# ---------------------------------------------------------------------------
# CaptureSession
# ---------------------------------------------------------------------------

# Patterns matched against tshark stderr to extract the live packet count.
_COUNT_PATTERNS = [
    re.compile(r'(\d+)\s+packets?\s+captured', re.IGNORECASE),   # final summary
    re.compile(r'^\s*(\d+)\s*$'),                                 # plain count update
]

# Keywords in stderr that indicate a permission / privilege failure.
_PERMISSION_KEYWORDS = (
    "permission", "not permitted", "access denied",
    "couldn't run", "operation not permitted",
)


class CaptureSession:
    """
    Manages a single live capture subprocess.

    Typical usage (blocking)::

        session = CaptureSession('eth0', '/tmp/out.pcap', duration=60)
        session.start()
        session.wait()
        print(session.packets_captured)

    Non-blocking (e.g. GUI)::

        def update_label(n):
            label.config(text=f'{n:,} packets')

        session = CaptureSession('eth0', '/tmp/out.pcap', duration=60,
                                 on_progress=update_label)
        session.start()
        # … do other work, call session.stop() on Cancel button …
        session.wait()
    """

    def __init__(
        self,
        interface:      str | int,
        output_path:    str | Path,
        duration:       int | None  = None,
        packet_count:   int | None  = None,
        capture_filter: str | None  = None,
        on_progress:    Callable[[int], None] | None = None,
    ):
        if not TSHARK_PATH:
            raise CaptureError(
                'tshark is not installed. '
                'Install Wireshark (https://www.wireshark.org/download.html).'
            )
        if duration is None and packet_count is None:
            raise ValueError('Specify at least one of: duration (seconds) or packet_count.')

        self._interface      = interface
        self._output_path    = Path(output_path)
        self._duration       = duration
        self._packet_count   = packet_count
        self._filter         = capture_filter
        self._on_progress    = on_progress

        self._proc:           subprocess.Popen | None = None
        self._stderr_thread:  threading.Thread | None = None
        self._lock            = threading.Lock()
        self._pkts            = 0          # live packet count
        self._permission_err: str | None   = None
        self._stderr_lines:   list[str]    = []

    # ── lifecycle ─────────────────────────────────────────────────────────────

    def start(self) -> 'CaptureSession':
        """Launch tshark and begin capturing. Returns self for chaining."""
        iface_name = _resolve_interface(self._interface)
        self._output_path.parent.mkdir(parents=True, exist_ok=True)

        cmd = [TSHARK_PATH, '-i', iface_name, '-w', str(self._output_path), '-q']
        if self._duration is not None:
            cmd += ['-a', f'duration:{self._duration}']
        if self._packet_count is not None:
            cmd += ['-c', str(self._packet_count)]
        if self._filter:
            cmd += ['-f', self._filter]

        self._proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        self._stderr_thread = threading.Thread(
            target=self._read_stderr, daemon=True, name='tshark-stderr'
        )
        self._stderr_thread.start()
        return self

    def stop(self) -> None:
        """
        Request the capture to stop.  Non-blocking — call wait() afterward.
        tshark writes the final count and closes the pcap cleanly on SIGTERM.
        """
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()

    def wait(self, timeout: float | None = None) -> bool:
        """
        Block until the capture finishes (or timeout expires).

        Returns True if tshark exited cleanly (exit 0) or was stopped via
        stop() / SIGTERM (exit -15 on POSIX, 1 on Windows after terminate()).
        Raises CapturePermissionError or CaptureError on failure.
        """
        if self._stderr_thread:
            self._stderr_thread.join(timeout=timeout)
        if self._proc:
            try:
                self._proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait()

        rc = self._proc.returncode if self._proc else 0

        # Permission failure is always surfaced as its own exception type so
        # the GUI can show a specific remediation message.
        if self._permission_err:
            raise CapturePermissionError(
                f'tshark lacks capture permissions on this interface.\n\n'
                f'Detail: {self._permission_err}\n\n'
                f'Linux:   sudo setcap cap_net_raw,cap_net_admin=eip $(which tshark)\n'
                f'         or run install.sh (does this automatically).\n'
                f'macOS:   run with sudo, or add yourself to the access_bpf group.\n'
                f'Windows: reinstall Npcap from https://npcap.com/ with WinPcap-compatible mode.'
            )

        # A non-zero exit that isn't SIGTERM and isn't permission-related
        _sigterm_codes = {-15, 1}   # POSIX SIGTERM / Windows terminate()
        if rc not in (0, *_sigterm_codes):
            stderr_tail = '\n'.join(self._stderr_lines[-5:]).strip()
            raise CaptureError(
                f'tshark exited with code {rc}.\n'
                f'{stderr_tail or "(no stderr output)"}'
            )

        return True

    # ── properties ────────────────────────────────────────────────────────────

    @property
    def is_running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    @property
    def packets_captured(self) -> int:
        with self._lock:
            return self._pkts

    @property
    def output_path(self) -> Path:
        return self._output_path

    # ── internal ──────────────────────────────────────────────────────────────

    def _read_stderr(self) -> None:
        """Daemon thread: read tshark stderr, update packet count, detect errors."""
        buf = b''
        while True:
            chunk = self._proc.stderr.read(1)
            if not chunk:
                break
            buf += chunk
            if chunk in (b'\n', b'\r'):
                self._process_line(buf.decode('utf-8', errors='replace').strip())
                buf = b''
        if buf:
            self._process_line(buf.decode('utf-8', errors='replace').strip())

    def _process_line(self, line: str) -> None:
        if not line:
            return

        with self._lock:
            self._stderr_lines.append(line)

        # Permission error detection
        low = line.lower()
        if any(kw in low for kw in _PERMISSION_KEYWORDS):
            with self._lock:
                self._permission_err = line
            return

        # Packet count extraction
        for pat in _COUNT_PATTERNS:
            m = pat.search(line)
            if m:
                n = int(m.group(1))
                with self._lock:
                    self._pkts = n
                if self._on_progress:
                    try:
                        self._on_progress(n)
                    except Exception:
                        pass   # never let a progress callback crash the capture
                return


# ---------------------------------------------------------------------------
# Blocking convenience wrappers
# ---------------------------------------------------------------------------

def capture_to_file(
    interface:      str | int,
    output_path:    str | Path | None = None,
    duration:       int | None        = 60,
    packet_count:   int | None        = None,
    capture_filter: str | None        = None,
    on_progress:    Callable[[int], None] | None = None,
) -> Path:
    """
    Capture live traffic to a pcap file and return the file path.

    Parameters
    ----------
    interface      : interface name ('eth0') or index from list_interfaces().
    output_path    : destination file.  If None, a timestamped file is created
                     in ~/W1CK3DWizard/Captures/.
    duration       : stop after this many seconds (default 60).
    packet_count   : stop after this many packets (overrides duration if both set).
    capture_filter : BPF capture filter string (e.g. 'tcp port 443').
    on_progress    : called with the current packet count whenever it updates.

    Raises
    ------
    CapturePermissionError  if tshark lacks privileges on the interface.
    CaptureError            on any other tshark failure.
    """
    if output_path is None:
        CAPTURES_DIR.mkdir(parents=True, exist_ok=True)
        ts         = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        iface_safe = re.sub(r'[^\w\-]', '_', str(interface))
        output_path = CAPTURES_DIR / f'{ts}_{iface_safe}.pcap'
    else:
        output_path = Path(output_path)

    session = CaptureSession(
        interface, output_path,
        duration=duration, packet_count=packet_count,
        capture_filter=capture_filter, on_progress=on_progress,
    )
    session.start()
    session.wait()   # raises CaptureError / CapturePermissionError on failure

    # Guard: an empty file means tshark ran but captured nothing — analysis
    # would either crash or produce a meaningless zero-packet report.
    if not output_path.exists() or output_path.stat().st_size < 24:
        raise CaptureError(
            f'Capture produced an empty file at {output_path}.\n'
            'Possible causes: no traffic on the interface during the capture window, '
            'wrong interface selected, or a BPF filter that matched nothing.'
        )

    return output_path


def capture_and_analyze(
    interface:      str | int,
    duration:       int | None        = 60,
    packet_count:   int | None        = None,
    capture_filter: str | None        = None,
    on_progress:    Callable[[int], None] | None = None,
    save:           bool              = True,
    run_architect:  bool              = False,
) -> dict:
    """
    Capture live traffic, then immediately analyze the resulting pcap.

    Returns the same dict as cli.analyze_file().  The pcap is kept on disk
    in ~/W1CK3DWizard/Captures/ so it can be re-analyzed or re-opened later.

    Raises CapturePermissionError or CaptureError if capture fails.
    Raises RuntimeError if pyshark / tshark is missing for analysis.
    """
    pcap_path = capture_to_file(
        interface,
        duration=duration,
        packet_count=packet_count,
        capture_filter=capture_filter,
        on_progress=on_progress,
    )

    from cli import analyze_file  # deferred — no tkinter dependency
    return analyze_file(pcap_path, save=save, run_architect=run_architect)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog='live_capture.py',
        description=(
            'Capture live network traffic and (optionally) analyze it.\n'
            'Wraps tshark directly — no Wireshark GUI required.'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            'Examples:\n'
            '  python live_capture.py --list-interfaces\n'
            '  python live_capture.py -i eth0 -d 60\n'
            '  python live_capture.py -i eth0 -d 60 --analyze\n'
            '  python live_capture.py -i eth0 -d 60 --analyze --fail-on high\n'
            '  python live_capture.py -i 2 -c 5000 --out /tmp/my.pcap\n'
            '  python live_capture.py -i wlan0 -d 30 --filter "not arp"\n'
        ),
    )

    p.add_argument(
        '--list-interfaces', '-L',
        action='store_true',
        help='List available capture interfaces and exit.',
    )
    p.add_argument(
        '-i', '--interface', metavar='IFACE',
        help='Interface name or index number from --list-interfaces.',
    )
    p.add_argument(
        '-d', '--duration', type=int, default=60, metavar='SECONDS',
        help='Capture duration in seconds (default: 60).',
    )
    p.add_argument(
        '-c', '--count', type=int, default=None, metavar='N',
        help='Stop after capturing N packets (overrides --duration if both given).',
    )
    p.add_argument(
        '-f', '--filter', metavar='BPF', dest='capture_filter', default=None,
        help='BPF capture filter (e.g. "tcp port 443", "not arp").',
    )
    p.add_argument(
        '--out', metavar='PATH', default=None,
        help=(
            f'Output file path.  Default: ~/W1CK3DWizard/Captures/TIMESTAMP_IFACE.pcap'
        ),
    )
    p.add_argument(
        '--analyze',
        action='store_true',
        help='Analyze the captured pcap immediately after capture completes.',
    )
    p.add_argument(
        '--architect',
        action='store_true',
        help='(With --analyze) include a network architecture evaluation.',
    )
    p.add_argument(
        '--fail-on',
        choices=['info', 'low', 'medium', 'high', 'critical'],
        default=None, dest='fail_on',
        help='(With --analyze) exit 1 if findings reach this severity.',
    )
    p.add_argument(
        '--format',
        choices=['text', 'json', 'quiet'],
        default='text',
        help='(With --analyze) output format (default: text).',
    )
    p.add_argument(
        '--no-save',
        action='store_true',
        help='(With --analyze) do not save the report to the report store.',
    )

    return p


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args   = parser.parse_args(argv)

    # ── list interfaces ───────────────────────────────────────────────────────
    if args.list_interfaces:
        try:
            ifaces = list_interfaces()
        except CaptureError as exc:
            print(f'ERROR: {exc}', file=sys.stderr)
            return 2

        if not ifaces:
            print('No capture interfaces found.')
            return 0

        print(f'\nAvailable capture interfaces ({len(ifaces)} found):\n')
        for ifc in ifaces:
            print(f'  {ifc}')
        print()
        print('Use the index or name with -i / --interface.')
        print()
        return 0

    # ── need an interface for everything else ─────────────────────────────────
    if not args.interface:
        parser.error('specify an interface with -i / --interface  '
                     '(or use --list-interfaces to see options)')

    if not TSHARK_PATH:
        print(
            'ERROR: tshark is not installed or not on PATH.\n'
            'Install Wireshark from https://www.wireshark.org/download.html',
            file=sys.stderr,
        )
        return 2

    # ── capture ───────────────────────────────────────────────────────────────
    quiet = args.format == 'quiet'
    duration     = args.duration
    packet_count = args.count

    if not quiet:
        limit_desc = (f'{packet_count:,} packets' if packet_count
                      else f'{duration}s')
        print(f'Capturing on {args.interface} '
              f'({limit_desc}) — Ctrl+C to stop early…', flush=True)

    # Progress counter printed in-place on a single line (text mode only)
    _last_print = [0]
    def _on_progress(n: int) -> None:
        if quiet or args.format == 'json':
            return
        now = time.monotonic()
        if now - _last_print[0] >= 1.0:   # throttle to once per second
            print(f'\r  {n:>8,} packets captured', end='', flush=True)
            _last_print[0] = now

    session    = None
    pcap_path  = None

    def _on_sigint(sig, frame):
        if not quiet:
            print('\n\nStopping capture early…', flush=True)
        if session is not None:
            session.stop()

    old_sigint = signal.signal(signal.SIGINT, _on_sigint)

    try:
        # Build the output path (mirrors capture_to_file logic so we can show
        # the path before capture starts)
        if args.out:
            out_path = Path(args.out)
        else:
            CAPTURES_DIR.mkdir(parents=True, exist_ok=True)
            ts         = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
            iface_safe = re.sub(r'[^\w\-]', '_', str(args.interface))
            out_path   = CAPTURES_DIR / f'{ts}_{iface_safe}.pcap'

        if not quiet:
            print(f'  Output: {out_path}', flush=True)

        try:
            iface_name = _resolve_interface(args.interface)
        except CaptureError as exc:
            print(f'\nERROR: {exc}', file=sys.stderr)
            return 2

        session = CaptureSession(
            iface_name, out_path,
            duration=duration,
            packet_count=packet_count,
            capture_filter=args.capture_filter,
            on_progress=_on_progress,
        )
        session.start()
        session.wait()
        pcap_path = session.output_path

    except CapturePermissionError as exc:
        print(f'\n\nERROR (permission denied):\n{exc}', file=sys.stderr)
        return 2
    except CaptureError as exc:
        print(f'\n\nERROR: {exc}', file=sys.stderr)
        return 2
    finally:
        signal.signal(signal.SIGINT, old_sigint)

    n_pkts = session.packets_captured if session else 0
    if not quiet:
        print(f'\r  {n_pkts:>8,} packets captured')

    if pcap_path is None or not pcap_path.exists() or pcap_path.stat().st_size < 24:
        print(
            '\nERROR: Capture produced an empty file.\n'
            'Possible causes: no traffic, wrong interface, or BPF filter matched nothing.',
            file=sys.stderr,
        )
        return 2

    if not quiet:
        print(f'\nCapture complete: {n_pkts:,} packets → {pcap_path}')

    # ── optional immediate analysis ───────────────────────────────────────────
    if not args.analyze:
        return 0

    if not quiet:
        print('\nAnalyzing capture…', flush=True)

    try:
        from cli import analyze_file, exceeded_threshold, _print_text, _print_json
    except ImportError as exc:
        print(f'ERROR: could not import analysis module: {exc}', file=sys.stderr)
        return 2

    try:
        output = analyze_file(
            pcap_path,
            save=not args.no_save,
            run_architect=args.architect,
        )
    except RuntimeError as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 2

    if args.format == 'json':
        _print_json(output)
    else:
        _print_text(output, quiet=quiet, run_architect=args.architect)

    if args.fail_on and exceeded_threshold(output, args.fail_on):
        return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
