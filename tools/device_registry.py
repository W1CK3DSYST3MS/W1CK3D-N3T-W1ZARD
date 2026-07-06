"""
device_registry.py — Persistent cross-report device tracking.

Stores a registry at ~/W1CK3DWizard/device_registry.json keyed by MAC address.
Each entry tracks: user label, first_seen, last_seen, seen_count, ip_addresses,
and the auto-detected device type.

Public API
----------
update_from_report(results) -> list[str]
    Update the registry from a report results dict.
    Returns a list of MAC addresses being seen for the first time.

load_registry() -> dict
set_label(mac, label) -> None
"""

import json
from datetime import datetime, timezone
from pathlib import Path

REGISTRY_PATH = Path.home() / 'W1CK3DWizard' / 'device_registry.json'


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S')


def load_registry() -> dict:
    try:
        return json.loads(REGISTRY_PATH.read_text(encoding='utf-8'))
    except Exception:
        return {}


def save_registry(reg: dict):
    REGISTRY_PATH.parent.mkdir(parents=True, exist_ok=True)
    REGISTRY_PATH.write_text(json.dumps(reg, indent=2, ensure_ascii=False),
                             encoding='utf-8')


def set_label(mac: str, label: str):
    """Assign a user-visible label to a MAC address."""
    reg = load_registry()
    if mac in reg:
        reg[mac]['label'] = label.strip()
        save_registry(reg)


def update_from_report(results: dict) -> list:
    """
    Update the registry with every device in *results*.
    Returns a sorted list of MAC addresses that are brand-new (first time seen).
    """
    reg = load_registry()
    new_macs = []
    now = _now_iso()

    for device in results.get('devices', {}).get('devices', []):
        mac = device.get('mac', '').strip()
        if not mac:
            continue

        ips   = list(device.get('ip_addresses') or [])
        dtype = device.get('likely_type', '') or 'Unknown Device'

        if mac not in reg:
            new_macs.append(mac)
            reg[mac] = {
                'label':        '',
                'first_seen':   now,
                'last_seen':    now,
                'seen_count':   1,
                'ip_addresses': ips,
                'device_type':  dtype,
            }
        else:
            entry = reg[mac]
            entry['last_seen']  = now
            entry['seen_count'] = entry.get('seen_count', 0) + 1

            # Merge IP addresses
            known = set(entry.get('ip_addresses') or [])
            known.update(ips)
            entry['ip_addresses'] = sorted(known)

            # Upgrade device_type if we have a better guess now
            if (dtype and dtype != 'Unknown Device'
                    and entry.get('device_type', 'Unknown Device') == 'Unknown Device'):
                entry['device_type'] = dtype

    save_registry(reg)
    return sorted(new_macs)
