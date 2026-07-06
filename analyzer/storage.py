"""
storage.py — Persistent report storage under ~/W1CK3DWizard/Reports/.

Each report lives in its own timestamped folder:
    <root>/<timestamp>_<slug>/
        metadata.json   — quick summary for list views
        results.json    — full analyzer output
        report.html     — self-contained HTML report
"""

import json
import re
import shutil
from datetime import datetime
from pathlib import Path

from .report import generate_html_report

_SAFE_ID = re.compile(r'^[A-Za-z0-9_\-.]+$')


def _slug(name, max_len=30):
    """Turn a filename into a safe, readable slug component."""
    stem = Path(name).stem
    slug = re.sub(r'[^A-Za-z0-9]+', '-', stem).strip('-')
    return slug[:max_len] or 'capture'


class ReportStore:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def save(self, pcap_path, results, total_packets, original_filename=None):
        """
        Persist a completed analysis.  Returns the report ID (folder name).
        """
        pcap_path = Path(pcap_path)
        original_filename = original_filename or pcap_path.name
        ts = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        slug = _slug(original_filename)
        report_id = f'{ts}_{slug}'

        folder = self.root / report_id
        folder.mkdir(parents=True, exist_ok=True)

        # metadata.json
        devices = results['devices']
        threats = results['threats']
        metadata = {
            'id': report_id,
            'timestamp': datetime.now().isoformat(timespec='seconds'),
            'original_filename': original_filename,
            'total_packets': total_packets,
            'device_count': devices.get('count', 0),
            'finding_counts': threats.get('counts_by_severity', {}),
            'total_findings': threats.get('total', 0),
        }
        (folder / 'metadata.json').write_text(
            json.dumps(metadata, indent=2), encoding='utf-8'
        )

        # results.json
        (folder / 'results.json').write_text(
            json.dumps(results, indent=2, default=str), encoding='utf-8'
        )

        # report.html
        generate_html_report(
            results, original_filename, total_packets,
            str(folder / 'report.html'),
        )

        return report_id

    def list_all(self):
        """Return list of metadata dicts, newest first."""
        reports = []
        for folder in sorted(self.root.iterdir(), reverse=True):
            if not folder.is_dir():
                continue
            meta_path = folder / 'metadata.json'
            if not meta_path.exists():
                continue
            try:
                meta = json.loads(meta_path.read_text(encoding='utf-8'))
                reports.append(meta)
            except Exception:
                pass
        return reports

    def get(self, report_id):
        """Return metadata dict for a single report, or None."""
        if not _SAFE_ID.match(report_id):
            return None
        meta_path = self.root / report_id / 'metadata.json'
        if not meta_path.exists():
            return None
        try:
            return json.loads(meta_path.read_text(encoding='utf-8'))
        except Exception:
            return None

    def html_path(self, report_id) -> Path:
        return self.root / report_id / 'report.html'

    def json_path(self, report_id) -> Path:
        return self.root / report_id / 'results.json'

    def delete(self, report_id):
        """Remove a report folder from disk."""
        if not _SAFE_ID.match(report_id):
            raise ValueError(f'Invalid report ID: {report_id!r}')
        folder = self.root / report_id
        # Verify the resolved path is actually inside self.root
        if folder.resolve().parent != self.root.resolve():
            raise ValueError('Path traversal attempt detected')
        if folder.exists():
            shutil.rmtree(folder)
