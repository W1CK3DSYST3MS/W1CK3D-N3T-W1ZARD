#!/usr/bin/env python3
"""
cli.py — Headless / command-line interface for the W1CK3D_NET_WIZARD.

Can be used standalone or imported as a library by the scheduler and other
tools.  There is no tkinter dependency anywhere in this module.

Subcommands
-----------
  analyze   Analyze a pcap/pcapng file and produce a report.
  list      List previously saved reports.
  show      Open a saved report's HTML in the default browser.

Exit codes
----------
  0   Success; no findings at or above the --fail-on threshold (default: none).
  1   Analysis complete; at least one finding AT or ABOVE --fail-on severity.
  2   Fatal error (missing file, dependency not installed, bad arguments, etc.).

Usage examples
--------------
  python cli.py analyze capture.pcap
  python cli.py analyze capture.pcap --format json
  python cli.py analyze capture.pcap --fail-on high --quiet
  python cli.py analyze capture.pcap --architect --no-save
  python cli.py list
  python cli.py list --format json --limit 10
  python cli.py show 2025-01-15_10-30-00_capture
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import webbrowser
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Make the analyzer package importable when running this file directly
# ---------------------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).parent))

from analyze import run_analysis, PYSHARK_AVAILABLE, PYSHARK_ERROR, TSHARK_PATH  # noqa: E402
from analyzer.storage import ReportStore                                            # noqa: E402
from analyzer.report  import print_console_summary                                 # noqa: E402

DEFAULT_REPORTS_DIR = Path.home() / 'W1CK3DWizard' / 'Reports'

# Severity levels in ascending order of seriousness — used for --fail-on
_SEVERITY_ORDER = ['info', 'low', 'medium', 'high', 'critical']


# ---------------------------------------------------------------------------
# Public library API  (importable by the scheduler without going through main)
# ---------------------------------------------------------------------------

def analyze_file(
    pcap_path: str | Path,
    *,
    save: bool = True,
    reports_dir: Path | None = None,
    run_architect: bool = False,
) -> dict:
    """
    Analyze a pcap file and return a structured result dict.

    Parameters
    ----------
    pcap_path    : path to the .pcap or .pcapng file
    save         : persist the report to the ReportStore (default True)
    reports_dir  : override the default ~/W1CK3DWizard/Reports directory
    run_architect: include a network architecture evaluation in the result

    Returns
    -------
    dict with keys:
        pcap_path       str
        original_filename str
        total_packets   int
        results         dict  — raw analyzer output
        report_id       str | None  — set when save=True
        report_html     str | None  — absolute path to the saved HTML
        architect       dict | None — evaluate() output serialised, or None
        timestamp       str         — ISO-8601 timestamp of the run
        error           str | None  — set on failure; other keys may be absent

    Raises
    ------
    RuntimeError  if pyshark / tshark is missing (caller decides how to surface)
    FileNotFoundError  if pcap_path does not exist
    """
    pcap_path = Path(pcap_path)
    if not pcap_path.is_file():
        raise FileNotFoundError(f'Capture file not found: {pcap_path}')

    # run_analysis() raises RuntimeError with a human-readable message if
    # pyshark or tshark is missing — callers should catch and re-raise or log.
    results, total_packets = run_analysis(str(pcap_path))

    report_id   = None
    report_html = None

    if save:
        store = ReportStore(reports_dir or DEFAULT_REPORTS_DIR)
        report_id = store.save(pcap_path, results, total_packets)
        report_html = str(store.html_path(report_id))

    architect_data = None
    if run_architect:
        try:
            from analyzer.architect import evaluate  # lazy — only if asked
            overall, sections = evaluate(results)
            architect_data = {
                'overall': overall,
                'sections': [
                    {
                        'title':   s.title,
                        'status':  s.status,
                        'summary': s.summary,
                        'body':    s.body,
                        'steps':   s.steps,
                        'tip':     s.tip,
                    }
                    for s in sections
                ],
            }
        except Exception as exc:
            architect_data = {'error': str(exc)}

    return {
        'pcap_path':        str(pcap_path),
        'original_filename': pcap_path.name,
        'total_packets':    total_packets,
        'results':          results,
        'report_id':        report_id,
        'report_html':      report_html,
        'architect':        architect_data,
        'timestamp':        datetime.now().isoformat(timespec='seconds'),
        'error':            None,
    }


def findings_above(results: dict, severity: str) -> list[dict]:
    """
    Return findings at or above *severity* from an analyze_file() result.

    Parameters
    ----------
    results  : the 'results' sub-dict from analyze_file() (i.e. results['results'])
    severity : one of info / low / medium / high / critical
    """
    if severity not in _SEVERITY_ORDER:
        raise ValueError(f'Unknown severity: {severity!r}. '
                         f'Use one of: {", ".join(_SEVERITY_ORDER)}')
    threshold = _SEVERITY_ORDER.index(severity)
    findings  = (results.get('threats') or {}).get('findings') or []
    return [
        f for f in findings
        if _SEVERITY_ORDER.index(f.get('severity', 'info')) >= threshold
    ]


def exceeded_threshold(output: dict, fail_on: str | None) -> bool:
    """
    Return True if the analysis result has findings at or above fail_on.
    Always returns False when fail_on is None.
    """
    if not fail_on:
        return False
    return bool(findings_above(output['results'], fail_on))


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

def _print_text(output: dict, *, quiet: bool = False, run_architect: bool = False):
    """Write a human-readable summary to stdout."""
    if quiet:
        return

    results = output['results']
    print_console_summary(results, output['pcap_path'], output['total_packets'])

    if output.get('report_id'):
        print(f"Report saved  :  {output['report_id']}")
    if output.get('report_html'):
        print(f"HTML report   :  {output['report_html']}")

    if run_architect and output.get('architect'):
        arch = output['architect']
        if 'error' in arch:
            print(f"\n[ARCHITECTURE]  (evaluation failed: {arch['error']})")
        else:
            print(f"\n[ARCHITECTURE]  Overall: {arch['overall'].upper()}")
            for sec in arch.get('sections', []):
                status_char = {'action': '✗', 'attention': '⚠', 'good': '✓'}.get(
                    sec['status'], '?')
                print(f"  {status_char}  {sec['title']:30s}  {sec['summary'][:80]}")


def _print_json(output: dict):
    """Write the full result as a single JSON object to stdout."""
    # Remove the raw results dict for brevity unless it's actually needed —
    # callers who want the raw data can load results.json from the report store.
    # We keep a compact summary here so the output is useful for scripting.
    threats = (output.get('results') or {}).get('threats') or {}
    devices = (output.get('results') or {}).get('devices') or {}

    compact = {
        'timestamp':        output.get('timestamp'),
        'pcap_path':        output.get('pcap_path'),
        'original_filename': output.get('original_filename'),
        'total_packets':    output.get('total_packets'),
        'report_id':        output.get('report_id'),
        'report_html':      output.get('report_html'),
        'device_count':     devices.get('count', 0),
        'finding_counts':   threats.get('counts_by_severity', {}),
        'total_findings':   threats.get('total', 0),
        'findings':         threats.get('findings', []),
        'architect':        output.get('architect'),
        'error':            output.get('error'),
    }
    print(json.dumps(compact, indent=2, default=str))


# ---------------------------------------------------------------------------
# Subcommand handlers
# ---------------------------------------------------------------------------

def _cmd_analyze(args: argparse.Namespace) -> int:
    """Handle: cli.py analyze ..."""
    quiet = args.format == 'quiet'

    # Dependency pre-flight — give a clear message before attempting anything
    if not PYSHARK_AVAILABLE:
        _fatal(PYSHARK_ERROR, as_json=(args.format == 'json'))
        return 2

    if TSHARK_PATH is None:
        _fatal(
            'tshark was not found. Install Wireshark and ensure tshark is on PATH.',
            as_json=(args.format == 'json'),
        )
        return 2

    pcap = Path(args.pcap)
    if not pcap.is_file():
        _fatal(f'File not found: {pcap}', as_json=(args.format == 'json'))
        return 2

    reports_dir = Path(args.reports_dir) if args.reports_dir else None

    if not quiet:
        print(f'Analyzing: {pcap}', flush=True)

    try:
        output = analyze_file(
            pcap,
            save=not args.no_save,
            reports_dir=reports_dir,
            run_architect=args.architect,
        )
    except RuntimeError as exc:
        _fatal(str(exc), as_json=(args.format == 'json'))
        return 2
    except Exception as exc:
        _fatal(f'Unexpected error during analysis: {exc}', as_json=(args.format == 'json'))
        return 2

    # Optional extra JSON / HTML outputs (independent of the ReportStore save)
    if args.json_out:
        try:
            Path(args.json_out).write_text(
                json.dumps(output['results'], indent=2, default=str),
                encoding='utf-8',
            )
            if not quiet:
                print(f'JSON results  :  {args.json_out}')
        except OSError as exc:
            _warn(f'Could not write JSON: {exc}')

    if args.html_out:
        try:
            from analyzer.report import generate_html_report
            generate_html_report(
                output['results'], output['pcap_path'],
                output['total_packets'], args.html_out,
            )
            if not quiet:
                print(f'HTML report   :  {args.html_out}')
        except OSError as exc:
            _warn(f'Could not write HTML: {exc}')

    # Format output
    if args.format == 'json':
        _print_json(output)
    else:
        _print_text(output, quiet=quiet, run_architect=args.architect)

    # Exit code
    if args.fail_on and exceeded_threshold(output, args.fail_on):
        return 1
    return 0


def _cmd_list(args: argparse.Namespace) -> int:
    """Handle: cli.py list ..."""
    reports_dir = Path(args.reports_dir) if args.reports_dir else DEFAULT_REPORTS_DIR
    store  = ReportStore(reports_dir)
    all_r  = store.list_all()

    limit = args.limit if args.limit and args.limit > 0 else len(all_r)
    shown = all_r[:limit]

    if args.format == 'json':
        print(json.dumps(shown, indent=2, default=str))
        return 0

    if not shown:
        print('No saved reports found.')
        if reports_dir != DEFAULT_REPORTS_DIR:
            print(f'  (looking in {reports_dir})')
        return 0

    col_w = 36
    print(f"\n{'ID':<{col_w}}  {'Packets':>8}  {'Devices':>7}  {'Findings':>8}  File")
    print('─' * (col_w + 40))
    for r in shown:
        counts  = r.get('finding_counts', {})
        total_f = r.get('total_findings', 0)
        sev_str = '  '.join(
            f"{sev[0].upper()}{counts[sev]}"
            for sev in ['critical', 'high', 'medium', 'low']
            if counts.get(sev)
        ) or 'none'
        print(
            f"{r['id']:<{col_w}}  "
            f"{r.get('total_packets', 0):>8,}  "
            f"{r.get('device_count', 0):>7}  "
            f"{total_f:>4} ({sev_str:20s})  "
            f"{r.get('original_filename', '?')}"
        )
    print()
    if len(all_r) > limit:
        print(f'  ({len(all_r) - limit} more not shown — use --limit to see more)')
    return 0


def _cmd_show(args: argparse.Namespace) -> int:
    """Handle: cli.py show REPORT_ID"""
    reports_dir = Path(args.reports_dir) if args.reports_dir else DEFAULT_REPORTS_DIR
    store = ReportStore(reports_dir)

    meta = store.get(args.report_id)
    if meta is None:
        _fatal(f'Report not found: {args.report_id!r}')
        return 2

    html_path = store.html_path(args.report_id)
    if not html_path.exists():
        _fatal(f'HTML report file missing: {html_path}')
        return 2

    url = html_path.as_uri()
    print(f'Opening: {html_path}')
    webbrowser.open(url)
    return 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fatal(message: str, *, as_json: bool = False):
    if as_json:
        print(json.dumps({'error': message}))
    else:
        print(f'ERROR: {message}', file=sys.stderr)


def _warn(message: str):
    print(f'WARNING: {message}', file=sys.stderr)


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog='cli.py',
        description=(
            'W1CK3D_NET_WIZARD — headless CLI.\n'
            'Analyze pcap files, list reports, and open saved results.\n'
            'Designed to run unattended under cron or Windows Task Scheduler.'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            'Exit codes:\n'
            '  0  Success (no findings at or above --fail-on threshold).\n'
            '  1  Analysis complete; findings at or above --fail-on threshold.\n'
            '  2  Fatal error (missing file, missing dependency, etc.).\n'
        ),
    )
    sub = root.add_subparsers(dest='command', metavar='COMMAND')
    sub.required = True

    # ── analyze ──────────────────────────────────────────────────────────────
    p_analyze = sub.add_parser(
        'analyze',
        help='Analyze a pcap/pcapng capture file.',
        description='Analyze a pcap file and save the report.',
    )
    p_analyze.add_argument(
        'pcap',
        metavar='PCAP_FILE',
        help='Path to the .pcap or .pcapng capture file.',
    )
    p_analyze.add_argument(
        '--format', choices=['text', 'json', 'quiet'], default='text',
        help=(
            'Output format. '
            '"text" (default): human-readable console summary. '
            '"json": machine-readable JSON on stdout (useful for scripting). '
            '"quiet": suppress all output (for cron — use exit code only).'
        ),
    )
    p_analyze.add_argument(
        '--fail-on',
        metavar='SEVERITY',
        choices=_SEVERITY_ORDER,
        default=None,
        help=(
            'Exit with code 1 if any finding is at or above SEVERITY. '
            'Choices: ' + ', '.join(_SEVERITY_ORDER) + '. '
            'Default: always exit 0 on success.'
        ),
    )
    p_analyze.add_argument(
        '--no-save',
        action='store_true',
        help='Do not save the report to the report store.',
    )
    p_analyze.add_argument(
        '--architect',
        action='store_true',
        help='Include a network architecture evaluation in the output.',
    )
    p_analyze.add_argument(
        '--html', dest='html_out', metavar='PATH', default=None,
        help='Also write a standalone HTML report to PATH.',
    )
    p_analyze.add_argument(
        '--json', dest='json_out', metavar='PATH', default=None,
        help='Also write raw JSON results to PATH.',
    )
    p_analyze.add_argument(
        '--reports-dir', metavar='DIR', default=None,
        help=f'Report storage directory. Default: {DEFAULT_REPORTS_DIR}',
    )

    # ── list ─────────────────────────────────────────────────────────────────
    p_list = sub.add_parser(
        'list',
        help='List saved reports.',
        description='List all saved analysis reports, newest first.',
    )
    p_list.add_argument(
        '--format', choices=['text', 'json'], default='text',
        help='"text" (default): table view.  "json": machine-readable list.',
    )
    p_list.add_argument(
        '--limit', type=int, default=20, metavar='N',
        help='Maximum number of reports to show (default: 20).',
    )
    p_list.add_argument(
        '--reports-dir', metavar='DIR', default=None,
        help=f'Report storage directory. Default: {DEFAULT_REPORTS_DIR}',
    )

    # ── show ─────────────────────────────────────────────────────────────────
    p_show = sub.add_parser(
        'show',
        help='Open a saved report in the default browser.',
        description='Open a saved report\'s HTML file in the system browser.',
    )
    p_show.add_argument(
        'report_id',
        metavar='REPORT_ID',
        help='Report ID from "cli.py list".',
    )
    p_show.add_argument(
        '--reports-dir', metavar='DIR', default=None,
        help=f'Report storage directory. Default: {DEFAULT_REPORTS_DIR}',
    )

    return root


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    """
    Parse *argv* (defaults to sys.argv[1:]) and dispatch to the correct handler.
    Returns an integer exit code — does NOT call sys.exit() itself, so callers
    can import and use this without spawning a subprocess.
    """
    parser = _build_parser()
    args   = parser.parse_args(argv)

    dispatch = {
        'analyze': _cmd_analyze,
        'list':    _cmd_list,
        'show':    _cmd_show,
    }

    handler = dispatch.get(args.command)
    if handler is None:
        parser.print_help()
        return 2

    return handler(args)


if __name__ == '__main__':
    sys.exit(main())
