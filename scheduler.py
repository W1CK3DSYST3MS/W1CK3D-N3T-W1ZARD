#!/usr/bin/env python3
"""
scheduler.py — Scheduled scanning for the W1CK3D_NET_WIZARD.

Registers a recurring analysis job with the operating system's native
scheduler (cron on Linux/macOS, Task Scheduler on Windows) and manages a
two-tier configuration system: IT admin policy overrides user preferences for
locked settings, while leaving the rest to the user.

Subcommands
-----------
  install     Configure and register the scheduled scan with the OS.
  uninstall   Remove the scheduled scan from the OS.
  status      Show schedule state, effective config, and recent run history.
  run         Execute a scheduled analysis now (called by cron / Task Scheduler).
  config      Print the effective merged configuration as JSON.

Configuration files
-------------------
  User config    ~/W1CK3DWizard/schedule.json
  Admin policy   /etc/w1ck3d-net-wizard/policy.json          (Linux / macOS)
                 C:\\ProgramData\\W1CK3DWizard\\policy.json  (Windows)

Run log
-------
  ~/W1CK3DWizard/scheduler.log   — JSON-lines, one record per run.
  Readable by the IT Admin settings panel without any extra parsing.

Usage examples
--------------
  python scheduler.py install --interval daily --time 02:00 --target /data/captures
  python scheduler.py install --interval weekly --day mon --time 03:00 --fail-on high
  python scheduler.py status
  python scheduler.py uninstall
  python scheduler.py run          # normally called by the OS, not directly
  python scheduler.py config       # show merged effective config as JSON
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta
from pathlib import Path

# ---------------------------------------------------------------------------
# Make the project importable when running this file directly
# ---------------------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).parent))

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

APP_DIR      = Path(__file__).parent.resolve()
APP_NAME     = 'W1CK3DWizard'
TASK_NAME    = r'W1CK3DWizard\ScheduledScan'   # Windows Task Scheduler path
CRON_MARKER  = '# W1CK3DWizard-managed'         # identifies our crontab line

USER_DATA_DIR   = Path.home() / APP_NAME
USER_CFG_PATH   = USER_DATA_DIR / 'schedule.json'
LOG_PATH        = USER_DATA_DIR / 'scheduler.log'
REPORTS_DIR     = USER_DATA_DIR / 'Reports'

IS_WINDOWS = platform.system() == 'Windows'

if IS_WINDOWS:
    ADMIN_POLICY_PATH = Path(os.environ.get('ProgramData', r'C:\ProgramData')) \
                        / APP_NAME / 'policy.json'
else:
    ADMIN_POLICY_PATH = Path('/etc/w1ck3d-net-wizard/policy.json')

# Valid schedule intervals and their display names
_INTERVALS = {'hourly': 'Every hour', 'daily': 'Every day', 'weekly': 'Every week'}

# Day-of-week names accepted on the CLI
_DOW_NAMES  = ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun']
# cron dow: 0=Sun … 6=Sat (we remap mon=1 … sun=0)
_DOW_TO_CRON = {'mon': 1, 'tue': 2, 'wed': 3, 'thu': 4, 'fri': 5, 'sat': 6, 'sun': 0}
# schtasks /d values
_DOW_TO_SCHTASKS = {d: d.upper() for d in _DOW_NAMES}

_PCAP_SUFFIXES = {'.pcap', '.pcapng'}


# ---------------------------------------------------------------------------
# Config — defaults, load, save, merge
# ---------------------------------------------------------------------------

_USER_DEFAULTS: dict = {
    'enabled':        True,
    'targets':        [],          # list of file/directory paths to analyze
    'interval':       'daily',     # hourly | daily | weekly
    'time':           '02:00',     # HH:MM — used for daily and weekly
    'day_of_week':    'mon',       # mon…sun — used for weekly only
    'fail_on':        None,        # None | info | low | medium | high | critical
    'architect':      False,       # run architecture evaluation
    'retention_days': 90,          # delete reports older than this (0 = keep forever)
}

_POLICY_DEFAULTS: dict = {
    # Keys present here with non-None values override the user config.
    # None means "not locked — user may choose".
    'locked_fail_on':        None,
    'locked_architect':      None,
    'locked_retention_days': None,
    'minimum_interval':      None,   # 'hourly' | 'daily' | 'weekly'
    'allow_disable':         True,
    'allow_target_change':   True,
}


def load_admin_policy() -> dict:
    """Load the admin policy file, returning defaults if absent or unreadable."""
    policy = dict(_POLICY_DEFAULTS)
    if ADMIN_POLICY_PATH.exists():
        try:
            raw = json.loads(ADMIN_POLICY_PATH.read_text(encoding='utf-8'))
            policy.update({k: v for k, v in raw.items() if k in _POLICY_DEFAULTS})
        except Exception:
            pass   # malformed policy — silently fall back to defaults
    return policy


def load_user_config() -> dict:
    """Load the user schedule config, returning defaults if absent or unreadable."""
    cfg = dict(_USER_DEFAULTS)
    if USER_CFG_PATH.exists():
        try:
            raw = json.loads(USER_CFG_PATH.read_text(encoding='utf-8'))
            cfg.update({k: v for k, v in raw.items() if k in _USER_DEFAULTS})
        except Exception:
            pass
    return cfg


def save_user_config(cfg: dict) -> None:
    """Atomically write the user config (only known keys, merged with defaults)."""
    USER_DATA_DIR.mkdir(parents=True, exist_ok=True)
    merged = {**_USER_DEFAULTS, **{k: v for k, v in cfg.items() if k in _USER_DEFAULTS}}
    fd, tmp = tempfile.mkstemp(dir=USER_DATA_DIR, suffix='.json.tmp')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(merged, f, indent=2)
        Path(tmp).replace(USER_CFG_PATH)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def effective_config() -> dict:
    """
    Return the merged configuration.

    Admin policy locked keys always win over user preferences.
    The result dict is what the scheduler should actually act on.
    """
    user   = load_user_config()
    policy = load_admin_policy()

    cfg = dict(user)

    # Apply locked keys from admin policy
    if policy['locked_fail_on'] is not None:
        cfg['fail_on'] = policy['locked_fail_on']
    if policy['locked_architect'] is not None:
        cfg['architect'] = policy['locked_architect']
    if policy['locked_retention_days'] is not None:
        cfg['retention_days'] = policy['locked_retention_days']

    # Enforce minimum interval (admin cannot force more frequent scans than user wants,
    # but can prevent overly frequent ones)
    _interval_order = ['weekly', 'daily', 'hourly']   # least → most frequent
    min_int = policy.get('minimum_interval')
    if min_int and min_int in _interval_order:
        if _interval_order.index(cfg['interval']) > _interval_order.index(min_int):
            cfg['interval'] = min_int   # downgrade to the maximum allowed frequency

    cfg['_policy'] = policy   # carry policy along for UI rendering
    return cfg


# ---------------------------------------------------------------------------
# Run log
# ---------------------------------------------------------------------------

def _log_run(entry: dict) -> None:
    """Append a JSON-lines entry to the run log."""
    USER_DATA_DIR.mkdir(parents=True, exist_ok=True)
    entry.setdefault('timestamp', datetime.now().isoformat(timespec='seconds'))
    try:
        with LOG_PATH.open('a', encoding='utf-8') as f:
            f.write(json.dumps(entry) + '\n')
    except OSError:
        pass   # log failure must never crash a scheduled run


def load_run_log(limit: int = 50) -> list[dict]:
    """Return the most recent *limit* run log entries, newest first."""
    if not LOG_PATH.exists():
        return []
    entries = []
    try:
        lines = LOG_PATH.read_text(encoding='utf-8').splitlines()
        for line in reversed(lines):
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
            if len(entries) >= limit:
                break
    except OSError:
        pass
    return entries


# ---------------------------------------------------------------------------
# Target resolution
# ---------------------------------------------------------------------------

def find_target_pcap(target: str) -> Path | None:
    """
    Resolve a target string to a concrete .pcap/.pcapng file.

    If *target* is a regular file, return it directly.
    If *target* is a directory, return the most recently modified pcap in it.
    Returns None if nothing is found (caller should treat as 'skip').
    """
    p = Path(target)
    if p.is_file() and p.suffix.lower() in _PCAP_SUFFIXES:
        return p
    if p.is_dir():
        candidates = sorted(
            (f for f in p.iterdir() if f.suffix.lower() in _PCAP_SUFFIXES),
            key=lambda f: f.stat().st_mtime,
            reverse=True,
        )
        return candidates[0] if candidates else None
    return None


# ---------------------------------------------------------------------------
# Retention pruning
# ---------------------------------------------------------------------------

def prune_old_reports(retention_days: int) -> int:
    """
    Delete reports older than *retention_days* from the default report store.
    Returns the number of reports deleted.  Does nothing when retention_days <= 0.
    """
    if retention_days <= 0:
        return 0
    from analyzer.storage import ReportStore
    store    = ReportStore(REPORTS_DIR)
    cutoff   = datetime.now() - timedelta(days=retention_days)
    deleted  = 0
    for meta in store.list_all():
        try:
            ts = datetime.fromisoformat(meta.get('timestamp', ''))
        except ValueError:
            continue
        if ts < cutoff:
            try:
                store.delete(meta['id'])
                deleted += 1
            except Exception:
                pass
    return deleted


# ---------------------------------------------------------------------------
# OS scheduler integration — cron (Linux / macOS)
# ---------------------------------------------------------------------------

def _cron_schedule(cfg: dict) -> str:
    """Build the cron time spec (first 5 fields) from the effective config."""
    interval = cfg.get('interval', 'daily')
    t        = cfg.get('time', '02:00')
    try:
        hh, mm = (int(x) for x in t.split(':'))
    except Exception:
        hh, mm = 2, 0

    if interval == 'hourly':
        return '0 * * * *'
    if interval == 'weekly':
        dow = _DOW_TO_CRON.get(cfg.get('day_of_week', 'mon'), 1)
        return f'{mm} {hh} * * {dow}'
    # default: daily
    return f'{mm} {hh} * * *'


def _cron_command() -> str:
    python = sys.executable
    script = str(APP_DIR / 'scheduler.py')
    return f'cd {APP_DIR} && {python} {script} run'


def _read_crontab() -> list[str]:
    """Return current crontab lines, or [] if none exists."""
    result = subprocess.run(
        ['crontab', '-l'],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        return []   # no crontab yet
    return result.stdout.splitlines()


def _write_crontab(lines: list[str]) -> None:
    content = '\n'.join(lines) + '\n'
    proc = subprocess.run(
        ['crontab', '-'],
        input=content, text=True, capture_output=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f'crontab write failed: {proc.stderr.strip()}')


def install_cron(cfg: dict) -> None:
    lines    = [l for l in _read_crontab() if CRON_MARKER not in l]
    schedule = _cron_schedule(cfg)
    command  = _cron_command()
    lines.append(f'{schedule} {command}  {CRON_MARKER}')
    _write_crontab(lines)


def uninstall_cron() -> bool:
    """Remove the W1CK3DWizard cron entry. Returns True if one was found."""
    lines   = _read_crontab()
    cleaned = [l for l in lines if CRON_MARKER not in l]
    if len(cleaned) == len(lines):
        return False   # nothing to remove
    _write_crontab(cleaned)
    return True


def cron_is_installed() -> bool:
    return any(CRON_MARKER in l for l in _read_crontab())


# ---------------------------------------------------------------------------
# OS scheduler integration — Task Scheduler (Windows)
# ---------------------------------------------------------------------------

def _schtasks_trigger(cfg: dict) -> list[str]:
    """Return the /sc … /st … /d … arguments for schtasks /create."""
    interval = cfg.get('interval', 'daily')
    t        = cfg.get('time', '02:00')
    dow      = _DOW_TO_SCHTASKS.get(cfg.get('day_of_week', 'mon'), 'MON')

    if interval == 'hourly':
        return ['/sc', 'HOURLY', '/mo', '1']
    if interval == 'weekly':
        return ['/sc', 'WEEKLY', '/d', dow, '/st', t]
    return ['/sc', 'DAILY', '/st', t]


def install_task(cfg: dict) -> None:
    python = sys.executable
    script = str(APP_DIR / 'scheduler.py')
    action = f'"{python}" "{script}" run'
    trigger = _schtasks_trigger(cfg)

    cmd = [
        'schtasks', '/create',
        '/tn', TASK_NAME,
        '/tr', action,
        '/ru', '',            # run as current user
        '/f',                 # overwrite if exists
    ] + trigger

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            f'schtasks /create failed:\n{result.stdout}\n{result.stderr}'
        )


def uninstall_task() -> bool:
    """Delete the Windows scheduled task. Returns True if it existed."""
    result = subprocess.run(
        ['schtasks', '/query', '/tn', TASK_NAME],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        return False   # task doesn't exist
    del_result = subprocess.run(
        ['schtasks', '/delete', '/tn', TASK_NAME, '/f'],
        capture_output=True, text=True,
    )
    if del_result.returncode != 0:
        raise RuntimeError(
            f'schtasks /delete failed:\n{del_result.stderr.strip()}'
        )
    return True


def task_is_installed() -> bool:
    result = subprocess.run(
        ['schtasks', '/query', '/tn', TASK_NAME],
        capture_output=True, text=True,
    )
    return result.returncode == 0


# ---------------------------------------------------------------------------
# Cross-platform wrappers
# ---------------------------------------------------------------------------

def install_schedule(cfg: dict) -> None:
    if IS_WINDOWS:
        install_task(cfg)
    else:
        install_cron(cfg)


def uninstall_schedule() -> bool:
    if IS_WINDOWS:
        return uninstall_task()
    return uninstall_cron()


def schedule_is_installed() -> bool:
    if IS_WINDOWS:
        return task_is_installed()
    return cron_is_installed()


# ---------------------------------------------------------------------------
# Next-run calculation (pure Python — no OS query needed)
# ---------------------------------------------------------------------------

def next_run_time(cfg: dict) -> datetime | None:
    """Compute the next scheduled run time from the effective config."""
    if not cfg.get('enabled', True):
        return None
    interval = cfg.get('interval', 'daily')
    t        = cfg.get('time', '02:00')
    try:
        hh, mm = (int(x) for x in t.split(':'))
    except Exception:
        hh, mm = 2, 0

    now = datetime.now()

    if interval == 'hourly':
        candidate = now.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
        return candidate

    if interval == 'weekly':
        dow_name = cfg.get('day_of_week', 'mon')
        target_dow = _DOW_NAMES.index(dow_name)        # mon=0 … sun=6
        # Python weekday(): mon=0 … sun=6 — convenient match
        days_ahead = (target_dow - now.weekday()) % 7
        candidate  = (now + timedelta(days=days_ahead)).replace(
            hour=hh, minute=mm, second=0, microsecond=0)
        if candidate <= now:
            candidate += timedelta(weeks=1)
        return candidate

    # daily
    candidate = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
    if candidate <= now:
        candidate += timedelta(days=1)
    return candidate


# ---------------------------------------------------------------------------
# Subcommand: run  (called by the OS scheduler)
# ---------------------------------------------------------------------------

def cmd_run(_args: argparse.Namespace) -> int:
    """
    Execute a scheduled analysis for every configured target.
    Writes one JSON-lines entry to the run log regardless of outcome.
    Stdout is intentionally quiet — errors go to the log, not stderr,
    so cron doesn't send noise emails on successful runs.
    """
    cfg = effective_config()

    if not cfg.get('enabled', True):
        _log_run({'status': 'skipped', 'reason': 'Schedule is disabled in user config.'})
        return 0

    targets = cfg.get('targets') or []
    if not targets:
        _log_run({'status': 'skipped', 'reason': 'No targets configured.'})
        return 0

    # Import analysis library (deferred — no tkinter, no GUI)
    try:
        from cli import analyze_file, exceeded_threshold
    except ImportError as exc:
        _log_run({'status': 'error', 'error': f'Could not import cli module: {exc}'})
        return 2

    overall_exit = 0

    for target_str in targets:
        t_start = time.monotonic()
        pcap    = find_target_pcap(target_str)

        if pcap is None:
            _log_run({
                'status': 'skipped',
                'target': target_str,
                'reason': 'No pcap file found at target path.',
            })
            continue

        try:
            output = analyze_file(
                pcap,
                save=True,
                reports_dir=REPORTS_DIR,
                run_architect=cfg.get('architect', False),
            )
            duration = round(time.monotonic() - t_start, 1)

            threats = (output.get('results') or {}).get('threats') or {}
            log_entry = {
                'status':      'ok',
                'target':      target_str,
                'pcap':        str(pcap),
                'packets':     output.get('total_packets', 0),
                'findings':    threats.get('total', 0),
                'counts':      threats.get('counts_by_severity', {}),
                'report_id':   output.get('report_id'),
                'duration_s':  duration,
            }
            if cfg.get('architect') and output.get('architect'):
                log_entry['architect_overall'] = output['architect'].get('overall')

            _log_run(log_entry)

            fail_on = cfg.get('fail_on')
            if fail_on and exceeded_threshold(output, fail_on):
                overall_exit = 1

        except Exception as exc:
            _log_run({
                'status':  'error',
                'target':  target_str,
                'pcap':    str(pcap) if pcap else None,
                'error':   str(exc),
            })
            overall_exit = max(overall_exit, 2)

    # Retention pruning — runs after all targets, non-fatal if it fails
    ret_days = cfg.get('retention_days', 90)
    if ret_days and ret_days > 0:
        try:
            pruned = prune_old_reports(ret_days)
            if pruned:
                _log_run({'status': 'pruned', 'deleted_reports': pruned})
        except Exception:
            pass

    return overall_exit


# ---------------------------------------------------------------------------
# Subcommand: install
# ---------------------------------------------------------------------------

def cmd_install(args: argparse.Namespace) -> int:
    policy = load_admin_policy()

    if not policy.get('allow_disable', True) and not args.enabled:
        print('ERROR: Admin policy does not allow disabling the schedule.', file=sys.stderr)
        return 2

    if not policy.get('allow_target_change', True) and args.target:
        print('ERROR: Admin policy does not allow changing scan targets.', file=sys.stderr)
        return 2

    # Load existing config and merge in CLI overrides
    cfg = load_user_config()

    if args.interval:
        cfg['interval'] = args.interval
    if args.time:
        cfg['time'] = args.time
    if args.day:
        cfg['day_of_week'] = args.day
    if args.target:
        cfg['targets'] = args.target   # list from nargs='+'
    if args.fail_on:
        cfg['fail_on'] = args.fail_on
    if args.architect is not None:
        cfg['architect'] = args.architect
    if args.retention_days is not None:
        cfg['retention_days'] = args.retention_days
    cfg['enabled'] = True

    # Validate
    if not cfg['targets']:
        print('ERROR: No targets specified. Use --target PATH [PATH ...]', file=sys.stderr)
        return 2

    for t in cfg['targets']:
        if not Path(t).exists():
            print(f'WARNING: Target path does not yet exist: {t}', file=sys.stderr)

    save_user_config(cfg)

    try:
        install_schedule(cfg)
    except RuntimeError as exc:
        print(f'ERROR installing schedule: {exc}', file=sys.stderr)
        return 2

    eff = effective_config()
    interval_label = _INTERVALS.get(eff['interval'], eff['interval'])
    print(f'Schedule installed.')
    print(f'  Interval   : {interval_label}', end='')
    if eff['interval'] != 'hourly':
        print(f'  at {eff["time"]}', end='')
    if eff['interval'] == 'weekly':
        print(f'  on {eff["day_of_week"].capitalize()}', end='')
    print()
    print(f'  Targets    : {", ".join(eff["targets"])}')
    if eff.get('fail_on'):
        print(f'  Alert on   : {eff["fail_on"]} severity and above')
    nxt = next_run_time(eff)
    if nxt:
        print(f'  Next run   : {nxt.strftime("%Y-%m-%d %H:%M")}')
    return 0


# ---------------------------------------------------------------------------
# Subcommand: uninstall
# ---------------------------------------------------------------------------

def cmd_uninstall(_args: argparse.Namespace) -> int:
    try:
        found = uninstall_schedule()
    except RuntimeError as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 2

    if found:
        print('Scheduled scan removed from the OS scheduler.')
    else:
        print('No scheduled scan was registered — nothing to remove.')

    # Leave the user config in place so re-installing is easy
    return 0


# ---------------------------------------------------------------------------
# Subcommand: status
# ---------------------------------------------------------------------------

def cmd_status(_args: argparse.Namespace) -> int:
    installed = schedule_is_installed()
    eff       = effective_config()
    policy    = eff.pop('_policy', {})
    log       = load_run_log(limit=5)

    # ── Schedule state ──
    state = 'INSTALLED' if installed else 'NOT INSTALLED'
    print(f'\nSchedule status:  {state}')

    if installed:
        interval_label = _INTERVALS.get(eff['interval'], eff['interval'])
        print(f'  Interval     : {interval_label}', end='')
        if eff['interval'] != 'hourly':
            print(f'  at {eff["time"]}', end='')
        if eff['interval'] == 'weekly':
            print(f'  on {eff["day_of_week"].capitalize()}', end='')
        print()

        nxt = next_run_time(eff)
        if nxt:
            print(f'  Next run     : {nxt.strftime("%Y-%m-%d %H:%M")}')

        print(f'  Targets      : {", ".join(eff.get("targets") or ["(none)"]) }')
        print(f'  Fail-on      : {eff.get("fail_on") or "(not set)"}')
        print(f'  Architect    : {"yes" if eff.get("architect") else "no"}')
        print(f'  Retention    : {eff.get("retention_days", 90)} days')

    # ── Admin policy summary ──
    locked = [
        f'fail_on={policy["locked_fail_on"]}' if policy.get('locked_fail_on') else None,
        f'architect={policy["locked_architect"]}' if policy.get('locked_architect') is not None else None,
        f'retention={policy["locked_retention_days"]}d' if policy.get('locked_retention_days') else None,
        f'min_interval={policy["minimum_interval"]}' if policy.get('minimum_interval') else None,
    ]
    locked = [l for l in locked if l]
    if locked:
        print(f'  Admin locks  : {", ".join(locked)}')
    else:
        print(f'  Admin policy : no locks applied')

    # ── Recent runs ──
    print()
    if log:
        print('Recent runs:')
        for entry in log:
            ts      = entry.get('timestamp', '?')[:16]
            status  = entry.get('status', '?').upper()
            detail  = ''
            if entry.get('status') == 'ok':
                detail = (f'{entry.get("packets", 0):,} pkts  '
                          f'{entry.get("findings", 0)} finding(s)  '
                          f'{entry.get("duration_s", "?")}s')
            elif entry.get('status') == 'error':
                detail = entry.get('error', '')[:80]
            elif entry.get('status') == 'skipped':
                detail = entry.get('reason', '')
            elif entry.get('status') == 'pruned':
                detail = f'deleted {entry.get("deleted_reports", 0)} old report(s)'
            pcap = Path(entry['pcap']).name if entry.get('pcap') else ''
            print(f'  {ts}  {status:<8}  {pcap:<30}  {detail}')
    else:
        print('No run history yet.')

    print()
    return 0


# ---------------------------------------------------------------------------
# Subcommand: config
# ---------------------------------------------------------------------------

def cmd_config(_args: argparse.Namespace) -> int:
    """Print the effective merged configuration as JSON (for the admin panel)."""
    cfg = effective_config()
    cfg.pop('_policy', None)
    print(json.dumps(cfg, indent=2))
    return 0


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog='scheduler.py',
        description='W1CK3D_NET_WIZARD — scheduled scanning manager.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = root.add_subparsers(dest='command', metavar='COMMAND')
    sub.required = True

    # ── install ───────────────────────────────────────────────────────────────
    p_inst = sub.add_parser('install', help='Install or update the scheduled scan.')
    p_inst.add_argument(
        '--target', nargs='+', metavar='PATH',
        help='One or more file or directory paths to scan. '
             'Directories are scanned for the newest .pcap/.pcapng file.',
    )
    p_inst.add_argument(
        '--interval', choices=list(_INTERVALS), default=None,
        help='How often to run (default: daily).',
    )
    p_inst.add_argument(
        '--time', metavar='HH:MM', default=None,
        help='Time of day for daily/weekly runs (default: 02:00).',
    )
    p_inst.add_argument(
        '--day', choices=_DOW_NAMES, default=None,
        metavar='DAY',
        help='Day of week for weekly interval (mon … sun).',
    )
    p_inst.add_argument(
        '--fail-on', choices=['info', 'low', 'medium', 'high', 'critical'],
        default=None, dest='fail_on',
        help='Log exit code 1 when findings reach this severity.',
    )
    p_inst.add_argument(
        '--architect', action='store_true', default=None,
        help='Include network architecture evaluation in each run.',
    )
    p_inst.add_argument(
        '--retention-days', type=int, default=None, dest='retention_days',
        metavar='N',
        help='Delete reports older than N days after each run (0 = keep forever).',
    )
    p_inst.add_argument(
        '--enabled', action='store_true', default=True,
        help='(default) Mark schedule as enabled.',
    )

    # ── uninstall ─────────────────────────────────────────────────────────────
    sub.add_parser('uninstall', help='Remove the scheduled scan from the OS.')

    # ── status ────────────────────────────────────────────────────────────────
    sub.add_parser('status', help='Show schedule state and recent run history.')

    # ── run ───────────────────────────────────────────────────────────────────
    sub.add_parser(
        'run',
        help='Execute a scheduled scan now (normally called by the OS, not directly).',
    )

    # ── config ────────────────────────────────────────────────────────────────
    sub.add_parser('config', help='Print the effective merged configuration as JSON.')

    return root


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args   = parser.parse_args(argv)

    dispatch = {
        'install':   cmd_install,
        'uninstall': cmd_uninstall,
        'status':    cmd_status,
        'run':       cmd_run,
        'config':    cmd_config,
    }

    handler = dispatch.get(args.command)
    if handler is None:
        parser.print_help()
        return 2

    return handler(args)


if __name__ == '__main__':
    sys.exit(main())
