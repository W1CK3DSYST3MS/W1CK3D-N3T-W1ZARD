"""
admin_panel.py — IT Admin Settings panel for the W1CK3D_NET_WIZARD.

Provides a four-tab Toplevel window covering:
  Schedule   — configure and install/uninstall the scheduled scan
  Policy     — set admin policy locks that override user preferences
  Run Log    — view the scheduler's JSON-lines run history
  System     — diagnostic info (paths, versions, config locations)

Usage (from app.py)::

    from admin_panel import AdminSettingsPanel
    AdminSettingsPanel(self)   # self = the main Tk window

The panel imports directly from scheduler.py — no subprocess spawning.
All writes are atomic.  PermissionError on policy save is handled
gracefully with a copy-paste-ready sudo command shown to the admin.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import threading
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import theme                     # W1CK3D SYST3MS theme
from theme import C              # semantic colour palette

# ---------------------------------------------------------------------------
# Scheduler imports — wrapped so the panel degrades gracefully if scheduler.py
# is absent (should never happen in a complete installation).
# ---------------------------------------------------------------------------
try:
    import scheduler as _sched
    _SCHED_OK = True
except ImportError:
    _SCHED_OK = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SEVERITY_CHOICES  = ['info', 'low', 'medium', 'high', 'critical']
_INTERVAL_CHOICES  = ['hourly', 'daily', 'weekly']
_DOW_CHOICES       = ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun']
_DOW_LABELS        = ['Monday', 'Tuesday', 'Wednesday', 'Thursday',
                      'Friday', 'Saturday', 'Sunday']

_CLR_OK      = C['secure']       # green
_CLR_WARN    = C['warning']      # amber
_CLR_ERR     = C['critical']     # red
_CLR_MUTED   = C['muted']        # grey
_CLR_BLUE    = C['accent_glow']  # purple accent (was blue)


def _section(parent, title: str) -> ttk.LabelFrame:
    return ttk.LabelFrame(parent, text=f'  {title}  ', padding=(10, 6))


def _row(parent, label: str, col_weight: int = 1) -> tuple[ttk.Frame, ttk.Label]:
    row = ttk.Frame(parent)
    row.pack(fill='x', pady=3)
    lbl = ttk.Label(row, text=label, width=22, anchor='w')
    lbl.pack(side='left')
    row.columnconfigure(1, weight=col_weight)
    return row, lbl


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class AdminSettingsPanel(tk.Toplevel):
    """IT Admin settings panel — four-tab Toplevel dialog."""

    def __init__(self, parent: tk.Misc):
        super().__init__(parent)
        self.title('IT Admin Settings')
        self.geometry('780x620')
        self.minsize(680, 520)
        self.resizable(True, True)
        self.transient(parent)

        # Bring to front but don't grab (so the main window stays usable)
        self.lift()
        self.focus_force()

        self._status_var = tk.StringVar(value='')
        self._build_ui()
        self._refresh_all()

    # ── top-level layout ─────────────────────────────────────────────────────

    def _build_ui(self):
        # Notebook
        nb = ttk.Notebook(self)
        nb.pack(fill='both', expand=True, padx=8, pady=(8, 0))

        self._build_schedule_tab(nb)
        self._build_policy_tab(nb)
        self._build_log_tab(nb)
        self._build_system_tab(nb)

        # Bottom status bar
        bar = ttk.Frame(self)
        bar.pack(fill='x', padx=8, pady=6)
        self._status_lbl = ttk.Label(bar, textvariable=self._status_var,
                                     foreground=_CLR_MUTED,
                                     font=('TkDefaultFont', 9))
        self._status_lbl.pack(side='left')
        ttk.Button(bar, text='  Close  ',
                   command=self.destroy).pack(side='right')

    # ── Schedule tab ─────────────────────────────────────────────────────────

    def _build_schedule_tab(self, nb: ttk.Notebook):
        outer = ttk.Frame(nb, padding=10)
        nb.add(outer, text='  Schedule  ')

        if not _SCHED_OK:
            ttk.Label(outer, text='scheduler.py not found — cannot manage schedules.',
                      foreground=_CLR_ERR).pack(anchor='w')
            return

        # ── status header ──
        hdr = ttk.Frame(outer)
        hdr.pack(fill='x', pady=(0, 8))
        ttk.Label(hdr, text='Schedule status:',
                  font=('TkDefaultFont', 10, 'bold')).pack(side='left')
        self._sched_status_lbl = ttk.Label(hdr, text='…', foreground=_CLR_MUTED,
                                           font=('TkDefaultFont', 10, 'bold'))
        self._sched_status_lbl.pack(side='left', padx=(8, 0))
        self._next_run_lbl = ttk.Label(hdr, text='', foreground=_CLR_MUTED,
                                       font=('TkDefaultFont', 9))
        self._next_run_lbl.pack(side='left', padx=(16, 0))

        # ── configuration section ──
        cfg_sec = _section(outer, 'Configuration')
        cfg_sec.pack(fill='x', pady=(0, 8))

        # Interval
        r, _ = _row(cfg_sec, 'Interval:')
        self._interval_var = tk.StringVar(value='daily')
        cb_interval = ttk.Combobox(r, textvariable=self._interval_var,
                                   values=_INTERVAL_CHOICES, state='readonly', width=12)
        cb_interval.pack(side='left')
        cb_interval.bind('<<ComboboxSelected>>', self._on_interval_change)

        # Time
        r, _ = _row(cfg_sec, 'Time (HH:MM):')
        self._time_var = tk.StringVar(value='02:00')
        self._time_entry = ttk.Entry(r, textvariable=self._time_var, width=10)
        self._time_entry.pack(side='left')
        self._time_note = ttk.Label(r, text='for daily / weekly runs',
                                    foreground=_CLR_MUTED,
                                    font=('TkDefaultFont', 8))
        self._time_note.pack(side='left', padx=(8, 0))

        # Day of week
        r, _ = _row(cfg_sec, 'Day of week:')
        self._dow_var = tk.StringVar(value='Monday')
        self._dow_cb  = ttk.Combobox(r, textvariable=self._dow_var,
                                     values=_DOW_LABELS, state='readonly', width=12)
        self._dow_cb.pack(side='left')
        self._dow_note = ttk.Label(r, text='for weekly runs only',
                                   foreground=_CLR_MUTED,
                                   font=('TkDefaultFont', 8))
        self._dow_note.pack(side='left', padx=(8, 0))

        # Alert severity
        r, _ = _row(cfg_sec, 'Alert on severity:')
        self._failon_var = tk.StringVar(value='(none)')
        ttk.Combobox(r, textvariable=self._failon_var,
                     values=['(none)'] + _SEVERITY_CHOICES,
                     state='readonly', width=12).pack(side='left')
        ttk.Label(r, text='exit code 1 when findings reach this level',
                  foreground=_CLR_MUTED,
                  font=('TkDefaultFont', 8)).pack(side='left', padx=(8, 0))

        # Architect evaluation
        r, _ = _row(cfg_sec, 'Options:')
        self._architect_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(r, text='Run architecture evaluation with each scan',
                        variable=self._architect_var).pack(side='left')

        # Retention
        r, _ = _row(cfg_sec, 'Retain reports:')
        self._retention_var = tk.StringVar(value='90')
        ttk.Entry(r, textvariable=self._retention_var, width=6).pack(side='left')
        ttk.Label(r, text='days   (0 = keep forever)',
                  foreground=_CLR_MUTED,
                  font=('TkDefaultFont', 8)).pack(side='left', padx=(6, 0))

        # ── targets section ──
        tgt_sec = _section(outer, 'Scan Targets')
        tgt_sec.pack(fill='both', expand=True, pady=(0, 8))
        ttk.Label(tgt_sec,
                  text='Paths to scan (files or directories — directories use the newest .pcap found).',
                  foreground=_CLR_MUTED,
                  font=('TkDefaultFont', 8)).pack(anchor='w', pady=(0, 4))

        tgt_frame = ttk.Frame(tgt_sec)
        tgt_frame.pack(fill='both', expand=True)

        self._targets_lb = tk.Listbox(tgt_frame, height=4, selectmode='single',
                                      font=('TkFixedFont', 9))
        tgt_vsb = ttk.Scrollbar(tgt_frame, orient='vertical',
                                 command=self._targets_lb.yview)
        self._targets_lb.configure(yscrollcommand=tgt_vsb.set)
        self._targets_lb.pack(side='left', fill='both', expand=True)
        tgt_vsb.pack(side='left', fill='y')

        tgt_btn = ttk.Frame(tgt_sec)
        tgt_btn.pack(fill='x', pady=(4, 0))
        ttk.Button(tgt_btn, text='Add file…',
                   command=self._add_target_file).pack(side='left')
        ttk.Button(tgt_btn, text='Add folder…',
                   command=self._add_target_dir).pack(side='left', padx=(4, 0))
        ttk.Button(tgt_btn, text='Remove',
                   command=self._remove_target).pack(side='left', padx=(4, 0))

        # ── action buttons ──
        btn_row = ttk.Frame(outer)
        btn_row.pack(fill='x')
        self._install_btn = ttk.Button(btn_row,
                                       text='  Install / Update Schedule  ',
                                       command=self._on_install_schedule)
        self._install_btn.pack(side='left')
        self._uninstall_btn = ttk.Button(btn_row,
                                         text='  Uninstall Schedule  ',
                                         command=self._on_uninstall_schedule)
        self._uninstall_btn.pack(side='left', padx=(8, 0))

        self._on_interval_change()

    def _on_interval_change(self, *_):
        interval = self._interval_var.get()
        if not hasattr(self, '_time_entry'):
            return
        if interval == 'hourly':
            self._time_entry.config(state='disabled')
            self._dow_cb.config(state='disabled')
            self._time_note.config(foreground=C['muted'])
            self._dow_note.config(foreground=C['muted'])
        elif interval == 'daily':
            self._time_entry.config(state='normal')
            self._dow_cb.config(state='disabled')
            self._time_note.config(foreground=_CLR_MUTED)
            self._dow_note.config(foreground=C['muted'])
        else:  # weekly
            self._time_entry.config(state='normal')
            self._dow_cb.config(state='readonly')
            self._time_note.config(foreground=_CLR_MUTED)
            self._dow_note.config(foreground=_CLR_MUTED)

    def _add_target_file(self):
        path = filedialog.askopenfilename(
            parent=self,
            title='Select pcap file',
            filetypes=[('Capture files', '*.pcap *.pcapng'), ('All files', '*.*')],
        )
        if path:
            self._targets_lb.insert('end', path)

    def _add_target_dir(self):
        path = filedialog.askdirectory(parent=self, title='Select captures directory')
        if path:
            self._targets_lb.insert('end', path)

    def _remove_target(self):
        sel = self._targets_lb.curselection()
        if sel:
            self._targets_lb.delete(sel[0])

    def _on_install_schedule(self):
        if not _SCHED_OK:
            return

        targets = list(self._targets_lb.get(0, 'end'))
        if not targets:
            messagebox.showwarning('No targets',
                                   'Add at least one scan target before installing.',
                                   parent=self)
            return

        # Validate time format
        t = self._time_var.get().strip()
        try:
            hh, mm = (int(x) for x in t.split(':'))
            assert 0 <= hh <= 23 and 0 <= mm <= 59
        except Exception:
            messagebox.showerror('Invalid time',
                                 f'Time must be in HH:MM format (e.g. 02:00).  Got: {t!r}',
                                 parent=self)
            return

        interval = self._interval_var.get()
        dow_label = self._dow_var.get()
        dow = _DOW_CHOICES[_DOW_LABELS.index(dow_label)] if dow_label in _DOW_LABELS else 'mon'

        fail_on_val = self._failon_var.get()
        fail_on = None if fail_on_val == '(none)' else fail_on_val

        try:
            retention = int(self._retention_var.get())
        except ValueError:
            retention = 90

        cfg = {
            'enabled':        True,
            'targets':        targets,
            'interval':       interval,
            'time':           t,
            'day_of_week':    dow,
            'fail_on':        fail_on,
            'architect':      self._architect_var.get(),
            'retention_days': retention,
        }

        try:
            _sched.save_user_config(cfg)
            _sched.install_schedule(cfg)
        except RuntimeError as exc:
            messagebox.showerror('Install failed', str(exc), parent=self)
            self._set_status(f'Install failed: {exc}', _CLR_ERR)
            return
        except Exception as exc:
            messagebox.showerror('Unexpected error', str(exc), parent=self)
            return

        self._refresh_schedule_status()
        self._set_status('Schedule installed successfully.', _CLR_OK)

    def _on_uninstall_schedule(self):
        if not _SCHED_OK:
            return
        if not messagebox.askyesno('Uninstall schedule',
                                   'Remove the scheduled scan from the OS scheduler?\n\n'
                                   'The configuration will be kept — you can reinstall later.',
                                   parent=self):
            return
        try:
            found = _sched.uninstall_schedule()
        except RuntimeError as exc:
            messagebox.showerror('Uninstall failed', str(exc), parent=self)
            return
        msg = 'Schedule removed.' if found else 'No schedule was installed.'
        self._refresh_schedule_status()
        self._set_status(msg, _CLR_OK if found else _CLR_MUTED)

    def _refresh_schedule_status(self):
        if not _SCHED_OK or not hasattr(self, '_sched_status_lbl'):
            return
        installed = _sched.schedule_is_installed()
        eff       = _sched.effective_config()
        eff.pop('_policy', None)

        if installed:
            self._sched_status_lbl.config(text='● INSTALLED', foreground=_CLR_OK)
            nxt = _sched.next_run_time(eff)
            if nxt:
                self._next_run_lbl.config(
                    text=f'Next run: {nxt.strftime("%Y-%m-%d %H:%M")}')
        else:
            self._sched_status_lbl.config(text='○ NOT INSTALLED', foreground=_CLR_MUTED)
            self._next_run_lbl.config(text='')

        # Populate form fields from effective config
        self._interval_var.set(eff.get('interval', 'daily'))
        self._time_var.set(eff.get('time', '02:00'))
        dow = eff.get('day_of_week', 'mon')
        if dow in _DOW_CHOICES:
            self._dow_var.set(_DOW_LABELS[_DOW_CHOICES.index(dow)])
        self._failon_var.set(eff.get('fail_on') or '(none)')
        self._architect_var.set(eff.get('architect', False))
        self._retention_var.set(str(eff.get('retention_days', 90)))

        self._targets_lb.delete(0, 'end')
        for t in (eff.get('targets') or []):
            self._targets_lb.insert('end', t)

        self._on_interval_change()

    # ── Policy tab ───────────────────────────────────────────────────────────

    def _build_policy_tab(self, nb: ttk.Notebook):
        outer = ttk.Frame(nb, padding=10)
        nb.add(outer, text='  Policy  ')

        # Policy file path
        policy_path = str(_sched.ADMIN_POLICY_PATH) if _SCHED_OK else '(scheduler not available)'
        info_row = ttk.Frame(outer)
        info_row.pack(fill='x', pady=(0, 8))
        ttk.Label(info_row, text='Policy file:', font=('TkDefaultFont', 9, 'bold')).pack(side='left')
        ttk.Label(info_row, text=f'  {policy_path}',
                  foreground=_CLR_MUTED,
                  font=('TkFixedFont', 8)).pack(side='left')

        # ── locked settings ──
        lock_sec = _section(outer, 'Locked Settings  (override user preferences)')
        lock_sec.pack(fill='x', pady=(0, 8))

        ttk.Label(lock_sec,
                  text='Locked values are enforced at runtime regardless of what the user configures.',
                  foreground=_CLR_MUTED,
                  font=('TkDefaultFont', 8)).pack(anchor='w', pady=(0, 6))

        # fail_on lock
        r, _ = _row(lock_sec, 'Fail-on severity:')
        self._lock_failon_var = tk.StringVar(value='Not locked')
        ttk.Combobox(r, textvariable=self._lock_failon_var,
                     values=['Not locked'] + _SEVERITY_CHOICES,
                     state='readonly', width=14).pack(side='left')

        # architect lock
        r, _ = _row(lock_sec, 'Architecture eval:')
        self._lock_architect_var = tk.StringVar(value='Not locked')
        ttk.Combobox(r, textvariable=self._lock_architect_var,
                     values=['Not locked', 'Always ON', 'Always OFF'],
                     state='readonly', width=14).pack(side='left')

        # retention lock
        r, _ = _row(lock_sec, 'Retention days:')
        self._lock_retention_var = tk.StringVar(value='Not locked')
        ttk.Combobox(r, textvariable=self._lock_retention_var,
                     values=['Not locked', 'Lock to value:'],
                     state='readonly', width=14).pack(side='left')
        self._lock_retention_days_var = tk.StringVar(value='90')
        ttk.Entry(r, textvariable=self._lock_retention_days_var,
                  width=6).pack(side='left', padx=(6, 0))
        ttk.Label(r, text='days', foreground=_CLR_MUTED,
                  font=('TkDefaultFont', 8)).pack(side='left', padx=(4, 0))

        # minimum interval
        r, _ = _row(lock_sec, 'Minimum interval:')
        self._lock_interval_var = tk.StringVar(value='Not locked')
        ttk.Combobox(r, textvariable=self._lock_interval_var,
                     values=['Not locked', 'hourly', 'daily', 'weekly'],
                     state='readonly', width=14).pack(side='left')
        ttk.Label(r,
                  text='users cannot scan more frequently than this',
                  foreground=_CLR_MUTED,
                  font=('TkDefaultFont', 8)).pack(side='left', padx=(8, 0))

        # ── permissions ──
        perm_sec = _section(outer, 'User Permissions')
        perm_sec.pack(fill='x', pady=(0, 8))

        self._allow_disable_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(perm_sec,
                        text='Users can disable the scheduled scan',
                        variable=self._allow_disable_var).pack(anchor='w', pady=2)

        self._allow_target_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(perm_sec,
                        text='Users can change scan targets',
                        variable=self._allow_target_var).pack(anchor='w', pady=2)

        # ── save button ──
        btn_row = ttk.Frame(outer)
        btn_row.pack(fill='x', pady=(4, 0))
        ttk.Button(btn_row, text='  Save Policy  ',
                   command=self._on_save_policy).pack(side='left')
        self._policy_note = ttk.Label(btn_row,
                                      text='', foreground=_CLR_MUTED,
                                      font=('TkDefaultFont', 8), wraplength=420)
        self._policy_note.pack(side='left', padx=(12, 0))

    def _on_save_policy(self):
        if not _SCHED_OK:
            return

        # Build the policy dict from UI state
        fail_on_raw   = self._lock_failon_var.get()
        architect_raw = self._lock_architect_var.get()
        retention_raw = self._lock_retention_var.get()
        interval_raw  = self._lock_interval_var.get()

        policy = {
            'locked_fail_on':        fail_on_raw if fail_on_raw != 'Not locked' else None,
            'locked_architect':      (True  if architect_raw == 'Always ON'
                                      else False if architect_raw == 'Always OFF'
                                      else None),
            'locked_retention_days': None,
            'minimum_interval':      interval_raw if interval_raw != 'Not locked' else None,
            'allow_disable':         self._allow_disable_var.get(),
            'allow_target_change':   self._allow_target_var.get(),
        }

        if retention_raw == 'Lock to value:':
            try:
                policy['locked_retention_days'] = int(self._lock_retention_days_var.get())
            except ValueError:
                messagebox.showerror('Invalid value',
                                     'Retention days must be a whole number.', parent=self)
                return

        policy_path = _sched.ADMIN_POLICY_PATH
        policy_json = json.dumps(policy, indent=2)

        # Try writing directly first
        try:
            policy_path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=policy_path.parent, suffix='.tmp')
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                f.write(policy_json)
            Path(tmp).replace(policy_path)
            self._policy_note.config(text=f'Saved to {policy_path}', foreground=_CLR_OK)
            self._set_status('Policy saved.', _CLR_OK)
            return
        except PermissionError:
            pass
        except Exception as exc:
            messagebox.showerror('Save failed', str(exc), parent=self)
            return

        # Permission denied — write to a temp file and show sudo instructions
        try:
            fd, tmp_path = tempfile.mkstemp(suffix='.json', prefix='pcap_policy_')
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                f.write(policy_json)
        except Exception as exc:
            messagebox.showerror('Save failed',
                                 f'Could not write temp file: {exc}', parent=self)
            return

        if platform.system() == 'Windows':
            copy_cmd = (f'Copy-Item "{tmp_path}" "{policy_path}"  '
                        f'# Run in PowerShell as Administrator')
        else:
            copy_cmd = (f'sudo mkdir -p {policy_path.parent} && '
                        f'sudo cp "{tmp_path}" "{policy_path}"')

        msg = (
            f'Cannot write to {policy_path}\n\n'
            f'The policy was saved to a temporary file:\n{tmp_path}\n\n'
            f'To install it, run the following command:\n\n{copy_cmd}'
        )
        detail_win = tk.Toplevel(self)
        detail_win.title('Save Policy — Elevated Permissions Required')
        detail_win.geometry('620x300')
        detail_win.transient(self)

        ttk.Label(detail_win,
                  text='Admin permission required to write to the policy path.',
                  font=('TkDefaultFont', 10, 'bold'),
                  foreground=_CLR_WARN).pack(anchor='w', padx=12, pady=(12, 4))

        txt = tk.Text(detail_win, wrap='word', height=10,
                      font=('TkFixedFont', 9), relief='flat', padx=8, pady=8)
        txt.insert('1.0', msg)
        txt.config(state='disabled')
        txt.pack(fill='both', expand=True, padx=12)

        btn_r = ttk.Frame(detail_win)
        btn_r.pack(fill='x', padx=12, pady=8)

        def _copy():
            detail_win.clipboard_clear()
            detail_win.clipboard_append(copy_cmd)
            self._set_status('Command copied to clipboard.', _CLR_OK)

        ttk.Button(btn_r, text='Copy command', command=_copy).pack(side='left')
        ttk.Button(btn_r, text='Close', command=detail_win.destroy).pack(side='right')

        self._policy_note.config(
            text='Permission denied — see the popup for instructions.',
            foreground=_CLR_WARN)

    def _refresh_policy(self):
        if not _SCHED_OK or not hasattr(self, '_lock_failon_var'):
            return
        policy = _sched.load_admin_policy()

        fo = policy.get('locked_fail_on')
        self._lock_failon_var.set(fo if fo else 'Not locked')

        arch = policy.get('locked_architect')
        self._lock_architect_var.set(
            'Always ON' if arch is True else 'Always OFF' if arch is False else 'Not locked')

        ret = policy.get('locked_retention_days')
        if ret is not None:
            self._lock_retention_var.set('Lock to value:')
            self._lock_retention_days_var.set(str(ret))
        else:
            self._lock_retention_var.set('Not locked')

        mi = policy.get('minimum_interval')
        self._lock_interval_var.set(mi if mi else 'Not locked')

        self._allow_disable_var.set(policy.get('allow_disable', True))
        self._allow_target_var.set(policy.get('allow_target_change', True))

    # ── Run Log tab ──────────────────────────────────────────────────────────

    def _build_log_tab(self, nb: ttk.Notebook):
        outer = ttk.Frame(nb, padding=10)
        nb.add(outer, text='  Run Log  ')

        # Toolbar
        bar = ttk.Frame(outer)
        bar.pack(fill='x', pady=(0, 6))
        ttk.Button(bar, text='Refresh', command=self._refresh_log).pack(side='left')
        ttk.Button(bar, text='Clear log…',
                   command=self._on_clear_log).pack(side='left', padx=(6, 0))
        ttk.Button(bar, text='Open reports folder',
                   command=self._open_reports_folder).pack(side='left', padx=(6, 0))

        self._log_count_lbl = ttk.Label(bar, text='', foreground=_CLR_MUTED,
                                        font=('TkDefaultFont', 8))
        self._log_count_lbl.pack(side='right')

        # Treeview
        cols = ('timestamp', 'status', 'pcap', 'packets', 'findings', 'duration')
        self._log_tv = ttk.Treeview(outer, columns=cols, show='headings',
                                    selectmode='browse', height=16)
        vsb = ttk.Scrollbar(outer, orient='vertical', command=self._log_tv.yview)
        self._log_tv.configure(yscrollcommand=vsb.set)

        self._log_tv.heading('timestamp', text='Timestamp')
        self._log_tv.heading('status',    text='Status')
        self._log_tv.heading('pcap',      text='File')
        self._log_tv.heading('packets',   text='Packets')
        self._log_tv.heading('findings',  text='Findings')
        self._log_tv.heading('duration',  text='Duration')

        self._log_tv.column('timestamp', width=140, anchor='w')
        self._log_tv.column('status',    width=80,  anchor='center')
        self._log_tv.column('pcap',      width=200, anchor='w')
        self._log_tv.column('packets',   width=80,  anchor='e')
        self._log_tv.column('findings',  width=80,  anchor='center')
        self._log_tv.column('duration',  width=80,  anchor='center')

        self._log_tv.tag_configure('ok',      foreground=_CLR_OK)
        self._log_tv.tag_configure('error',   foreground=_CLR_ERR)
        self._log_tv.tag_configure('skipped', foreground=_CLR_MUTED)
        self._log_tv.tag_configure('pruned',  foreground=_CLR_BLUE)
        self._log_tv.tag_configure('warn',    foreground=_CLR_WARN)

        tv_frame = ttk.Frame(outer)
        tv_frame.pack(fill='both', expand=True)
        self._log_tv.pack(in_=tv_frame, side='left', fill='both', expand=True)
        vsb.pack(in_=tv_frame, side='left', fill='y')

        # Detail panel for selected entry
        self._log_detail = tk.Text(outer, height=4, wrap='word',
                                   font=('TkFixedFont', 8),
                                   relief='flat', padx=6, pady=4,
                                   background=C['inset'],
                                   state='disabled')
        self._log_detail.pack(fill='x', pady=(4, 0))
        self._log_tv.bind('<<TreeviewSelect>>', self._on_log_select)

    def _refresh_log(self):
        if not _SCHED_OK or not hasattr(self, '_log_tv'):
            return
        self._log_tv.delete(*self._log_tv.get_children())
        entries = _sched.load_run_log(limit=200)

        for entry in entries:
            status   = entry.get('status', '?')
            ts       = entry.get('timestamp', '')[:16]
            pcap     = Path(entry['pcap']).name if entry.get('pcap') else ''
            packets  = f"{entry.get('packets', ''):,}" if entry.get('packets') else ''
            duration = f"{entry.get('duration_s', '')}s" if entry.get('duration_s') else ''

            counts  = entry.get('counts', {})
            total_f = entry.get('findings', 0)
            if total_f:
                sev_parts = [
                    f"{counts.get(s, 0)}{s[0].upper()}"
                    for s in ['critical', 'high', 'medium', 'low']
                    if counts.get(s)
                ]
                findings_str = f"{total_f} ({'/'.join(sev_parts)})" if sev_parts else str(total_f)
            else:
                findings_str = '0' if status == 'ok' else ''

            tag = {'ok': 'ok', 'error': 'error', 'skipped': 'skipped',
                   'pruned': 'pruned'}.get(status, 'warn')

            self._log_tv.insert('', 'end', tags=(tag,),
                                values=(ts, status.upper(), pcap,
                                        packets, findings_str, duration),
                                iid=str(id(entry)))
            # Store full entry for detail view
            self._log_tv.set(str(id(entry)), 'timestamp', ts)

        if entries:
            self._log_count_lbl.config(
                text=f'{len(entries)} run{"s" if len(entries) != 1 else ""} in log')
        else:
            self._log_count_lbl.config(text='No runs logged yet.')
            self._log_tv.insert('', 'end', tags=('skipped',),
                                values=('', 'No runs yet', '', '', '', ''))

        # Store entries for detail lookup
        self._log_entries = {str(id(e)): e for e in entries}

    def _on_log_select(self, _event=None):
        sel = self._log_tv.selection()
        if not sel or not hasattr(self, '_log_entries'):
            return
        entry = self._log_entries.get(sel[0])
        if not entry:
            return
        self._log_detail.config(state='normal')
        self._log_detail.delete('1.0', 'end')
        self._log_detail.insert('end', json.dumps(entry, indent=2))
        self._log_detail.config(state='disabled')

    def _on_clear_log(self):
        if not _SCHED_OK:
            return
        log_path = _sched.LOG_PATH
        if not log_path.exists():
            messagebox.showinfo('Nothing to clear', 'The run log is already empty.', parent=self)
            return
        if messagebox.askyesno('Clear log',
                               f'Delete all entries from the run log?\n\n{log_path}',
                               parent=self):
            try:
                log_path.write_text('', encoding='utf-8')
                self._refresh_log()
                self._set_status('Run log cleared.', _CLR_OK)
            except OSError as exc:
                messagebox.showerror('Error', str(exc), parent=self)

    def _open_reports_folder(self):
        folder = str(_sched.REPORTS_DIR) if _SCHED_OK else str(Path.home() / 'W1CK3DWizard' / 'Reports')
        if platform.system() == 'Windows':
            os.startfile(folder)
        elif platform.system() == 'Darwin':
            subprocess.Popen(['open', folder])
        else:
            subprocess.Popen(['xdg-open', folder])

    # ── System tab ───────────────────────────────────────────────────────────

    def _build_system_tab(self, nb: ttk.Notebook):
        outer = ttk.Frame(nb, padding=10)
        nb.add(outer, text='  System  ')

        self._sys_text = tk.Text(outer, wrap='word', font=('TkFixedFont', 9),
                                 relief='flat', padx=8, pady=8,
                                 background=C['inset'], state='disabled')
        vsb = ttk.Scrollbar(outer, orient='vertical', command=self._sys_text.yview)
        self._sys_text.configure(yscrollcommand=vsb.set)

        self._sys_text.pack(side='left', fill='both', expand=True)
        vsb.pack(side='left', fill='y')

        for tag, cfg in {
            'h':    {'font': ('TkDefaultFont', 10, 'bold')},
            'kv':   {'font': ('TkFixedFont', 9)},
            'ok':   {'foreground': _CLR_OK},
            'warn': {'foreground': _CLR_WARN},
            'muted': {'foreground': _CLR_MUTED, 'font': ('TkFixedFont', 8)},
        }.items():
            self._sys_text.tag_configure(tag, **cfg)

    def _refresh_system(self):
        if not hasattr(self, '_sys_text'):
            return

        def _gather():
            lines: list[tuple[str, str]] = []

            def w(text, tag='kv'):
                lines.append((text, tag))

            w('Tools\n', 'h')
            # tshark
            from analyze import TSHARK_PATH
            if TSHARK_PATH:
                try:
                    r = subprocess.run([TSHARK_PATH, '--version'],
                                       capture_output=True, text=True, timeout=5)
                    ver = r.stdout.splitlines()[0] if r.stdout else '(unknown version)'
                except Exception:
                    ver = '(could not query version)'
                w(f'  tshark   {TSHARK_PATH}\n')
                w(f'           {ver}\n', 'muted')
            else:
                w('  tshark   NOT FOUND\n', 'warn')

            # nmap
            nmap = shutil.which('nmap')
            if nmap:
                try:
                    r = subprocess.run([nmap, '--version'],
                                       capture_output=True, text=True, timeout=5)
                    ver = r.stdout.splitlines()[0] if r.stdout else '(unknown version)'
                except Exception:
                    ver = '(could not query version)'
                w(f'  nmap     {nmap}\n')
                w(f'           {ver}\n', 'muted')
            else:
                w('  nmap     NOT FOUND\n', 'warn')

            w('\nPython\n', 'h')
            w(f'  {sys.version}\n')
            w(f'  {sys.executable}\n', 'muted')

            w('\nPaths\n', 'h')
            dirs = {
                'App dir':      str(Path(__file__).parent),
                'Reports':      str(_sched.REPORTS_DIR if _SCHED_OK else Path.home() / 'W1CK3DWizard' / 'Reports'),
                'Captures':     str(Path.home() / 'W1CK3DWizard' / 'Captures'),
                'User config':  str(_sched.USER_CFG_PATH if _SCHED_OK else '—'),
                'Admin policy': str(_sched.ADMIN_POLICY_PATH if _SCHED_OK else '—'),
                'Run log':      str(_sched.LOG_PATH if _SCHED_OK else '—'),
            }
            for label, path in dirs.items():
                exists = Path(path).exists()
                marker = '✓' if exists else '✗'
                tag    = 'ok' if exists else 'muted'
                w(f'  {marker} {label:<14}  {path}\n', tag)

            w('\nPlatform\n', 'h')
            w(f'  {platform.platform()}\n')

            return lines

        def _done(lines):
            t = self._sys_text
            t.config(state='normal')
            t.delete('1.0', 'end')
            for text, tag in lines:
                t.insert('end', text, tag)
            t.config(state='disabled')

        def _worker():
            lines = _gather()
            self.after(0, lambda: _done(lines))

        threading.Thread(target=_worker, daemon=True).start()

    # ── unified refresh ───────────────────────────────────────────────────────

    def _refresh_all(self):
        self._refresh_schedule_status()
        self._refresh_policy()
        self._refresh_log()
        self._refresh_system()

    # ── status bar ────────────────────────────────────────────────────────────

    def _set_status(self, msg: str, color: str = _CLR_MUTED):
        self._status_var.set(msg)
        self._status_lbl.config(foreground=color)
        # Fade back to muted after 5 s
        self.after(5000, lambda: self._status_lbl.config(foreground=_CLR_MUTED))
