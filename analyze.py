#!/usr/bin/env python3
"""
analyze.py
----------
Entry point for the pcap analyzer. Reads a capture file, runs every
analyzer in a single pass over the packets, then generates a plain-
English HTML report plus a console summary.

Usage:
    python analyze.py capture.pcap
    python analyze.py capture.pcap --html report.html --json results.json

Dependencies:
    pip install pyshark manuf
    Plus tshark (ships with Wireshark) installed on PATH.
"""

import argparse
import json
import sys
import os
from pathlib import Path


# ---------------------------------------------------------------------------
# tshark discovery — safe to run at import time (no sys.exit, no heavy deps)
# ---------------------------------------------------------------------------

def _find_tshark():
    """Return the absolute path to tshark, or None if not found."""
    import shutil
    found = shutil.which('tshark')
    if found:
        return found
    candidates = [
        r'C:\Program Files\Wireshark\tshark.exe',
        r'C:\Program Files (x86)\Wireshark\tshark.exe',
        r'/Applications/Wireshark.app/Contents/MacOS/tshark',
        r'/usr/local/bin/tshark',
        r'/usr/bin/tshark',
    ]
    for exe in candidates:
        if os.path.exists(exe):
            # Patch PATH so child processes (e.g. pyshark's tshark calls) can
            # find it without requiring the user to set it manually.
            os.environ['PATH'] = (os.path.dirname(exe)
                                  + os.pathsep
                                  + os.environ.get('PATH', ''))
            return exe
    return None


TSHARK_PATH = _find_tshark()

# CREATE_NO_WINDOW flag for Windows subprocess calls — stored here so
# run_analysis() and live_capture.py can apply it selectively to tshark
# calls only, without patching subprocess.Popen globally.
_WINDOWS_NO_WINDOW = 0
if os.name == 'nt':
    import subprocess as _sp_nt
    _WINDOWS_NO_WINDOW = _sp_nt.CREATE_NO_WINDOW


# ---------------------------------------------------------------------------
# Deferred dependency check
# ---------------------------------------------------------------------------
# pyshark is NOT imported here.  Importing it at module level used to call
# sys.exit() on ImportError, which silently killed the GUI before the Tkinter
# window ever opened.  Instead we probe availability once and store the result.
# run_analysis() checks this sentinel and raises a descriptive RuntimeError
# that the GUI can catch and display in a messagebox.

def _probe_pyshark():
    """Return (available: bool, error_message: str | None)."""
    try:
        import pyshark  # noqa: F401
        return True, None
    except ImportError:
        return False, (
            "pyshark is not installed.\n\n"
            "Fix:  pip install pyshark\n\n"
            "pyshark also requires tshark on your PATH — tshark ships with "
            "Wireshark (https://www.wireshark.org/download.html)."
        )


PYSHARK_AVAILABLE, PYSHARK_ERROR = _probe_pyshark()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_analysis(pcap_path):
    """
    One pass over the pcap, feeding every packet to each analyzer.

    Raises
    ------
    RuntimeError
        If pyshark is not installed or tshark cannot be found.  The message
        is human-readable and suitable for display in a GUI messagebox or a
        CLI error line.
    """
    # --- dependency gate (deferred from module level) ----------------------
    if not PYSHARK_AVAILABLE:
        raise RuntimeError(PYSHARK_ERROR)

    if TSHARK_PATH is None:
        raise RuntimeError(
            "tshark was not found on your system.\n\n"
            "Fix:  install Wireshark (https://www.wireshark.org/download.html) "
            "and make sure tshark is on your PATH."
        )

    # --- safe to import now ------------------------------------------------
    import pyshark
    import asyncio

    from analyzer.devices   import DeviceAnalyzer
    from analyzer.network   import NetworkAnalyzer
    from analyzer.threats   import ThreatAnalyzer
    from analyzer.protocols import ProtocolAnalyzer
    from analyzer.report    import print_console_summary, generate_html_report  # noqa: F401

    try:
        asyncio.get_event_loop()
    except RuntimeError:
        asyncio.set_event_loop(asyncio.new_event_loop())

    device_a   = DeviceAnalyzer()
    network_a  = NetworkAnalyzer()
    threat_a   = ThreatAnalyzer()
    protocol_a = ProtocolAnalyzer()
    analyzers  = [device_a, network_a, threat_a, protocol_a]

    print(f"Reading {pcap_path} ...")
    cap_kwargs = dict(keep_packets=False, tshark_path=TSHARK_PATH)
    if _WINDOWS_NO_WINDOW:
        cap_kwargs['custom_parameters'] = ['-l']  # line-buffered; no window needed
    cap = pyshark.FileCapture(pcap_path, **cap_kwargs)

    total = 0
    try:
        for pkt in cap:
            total += 1
            if total % 2000 == 0:
                print(f"  ... {total:,} packets processed")
            for a in analyzers:
                try:
                    a.process_packet(pkt)
                except Exception as e:
                    # One malformed packet should not crash the whole analysis.
                    print(f"  (warning: {a.name} skipped a packet: {e})",
                          file=sys.stderr)
    finally:
        cap.close()

    print(f"Finished reading {total:,} packets. Running post-processing...")

    # Finalize — devices first so network/threat analyzers can use its output.
    # local_ips lets the threat analyzer recognise scans launched from THIS
    # machine (e.g. the built-in nmap tools) and not flag them as attacks.
    from analyzer.threats import get_local_ips
    context = {'devices_raw': device_a, 'local_ips': get_local_ips()}
    for a in analyzers:
        a.finalize(context=context)

    return {
        'devices':   device_a.results(),
        'network':   network_a.results(),
        'threats':   threat_a.results(),
        'protocols': protocol_a.results(),
    }, total


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description=(
            'Analyze a Wireshark capture and produce a plain-English report '
            'of devices, network layout, and security issues.'
        )
    )
    ap.add_argument('pcap', help='Path to the .pcap or .pcapng file')
    ap.add_argument(
        '--html', default=None,
        help='Path for the HTML report (default: <pcap>.report.html)',
    )
    ap.add_argument(
        '--json', default=None,
        help='Optional path to save full results as JSON',
    )
    args = ap.parse_args()

    if not os.path.isfile(args.pcap):
        sys.exit(f"ERROR: file not found: {args.pcap}")

    try:
        results, total = run_analysis(args.pcap)
    except RuntimeError as exc:
        # Dependency missing or tshark not found — clean CLI error.
        sys.exit(f"ERROR: {exc}")

    from analyzer.report import print_console_summary, generate_html_report

    # Console summary
    print_console_summary(results, args.pcap, total)

    # HTML report
    html_out = args.html or str(Path(args.pcap).with_suffix('.report.html'))
    generate_html_report(results, args.pcap, total, html_out)
    print(f"HTML report saved to: {html_out}")

    # Optional JSON dump
    if args.json:
        with open(args.json, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"JSON results saved to: {args.json}")


if __name__ == '__main__':
    main()
