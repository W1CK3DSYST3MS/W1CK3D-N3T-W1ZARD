"""
802.11 management-frame threat analyzer.

Reads a pcap captured on a monitor-mode interface and detects:
  - Deauthentication / disassociation floods  (disconnect attacks)
  - Probe request sweeps  (device scanning many SSIDs — war-driving signature)
  - Multiple BSSIDs advertising the same SSID  (evil-twin / rogue AP)
"""

import collections

# ── Frame subtype constants ────────────────────────────────────────────────
_SUBTYPE_NAMES = {
    0:  'Association Request',
    1:  'Association Response',
    2:  'Reassociation Request',
    3:  'Reassociation Response',
    4:  'Probe Request',
    5:  'Probe Response',
    6:  'Timing Advertisement',
    8:  'Beacon',
    9:  'ATIM',
    10: 'Disassociation',
    11: 'Authentication',
    12: 'Deauthentication',
    13: 'Action',
    14: 'Action No Ack',
}

# Detection thresholds
_DEAUTH_FLOOD_MIN   = 20   # deauth+disassoc frames from one source
_PROBE_SWEEP_MIN    = 10   # unique SSIDs probed by one device


# ── Helpers ────────────────────────────────────────────────────────────────

def _subtype(pkt) -> int:
    """Return the 802.11 FC type_subtype as an integer, or -1 on failure."""
    try:
        raw = pkt.wlan.fc_type_subtype
        return int(raw, 16) if str(raw).startswith(('0x', '0X')) else int(raw)
    except Exception:
        return -1


def _mac(pkt, *fields) -> str:
    """Pull the first available MAC address field from pkt.wlan."""
    for f in fields:
        try:
            v = getattr(pkt.wlan, f, None)
            if v:
                return str(v).lower().strip()
        except Exception:
            pass
    return ''


def _ssid(pkt) -> str:
    """Extract SSID string from a management frame, empty string if absent."""
    for layer_name in ('wlan_mgt', 'wlan'):
        try:
            layer = getattr(pkt, layer_name)
        except Exception:
            continue
        for field in ('ssid', 'wlan_ssid'):
            try:
                v = getattr(layer, field, None)
                if v is not None:
                    s = str(v).strip()
                    return s if s else '<wildcard>'
            except Exception:
                pass
    return ''


# ── Main analysis function ─────────────────────────────────────────────────

def analyze_80211_pcap(path: str) -> dict:
    """
    Analyze *path* for 802.11 management-frame anomalies.

    Returns:
        {
          'findings':    list of finding dicts (severity/title/description/evidence/remediation),
          'raw_counts':  {frame_type_name: count},
          'ssids_seen':  sorted list of SSIDs seen in beacons/probe-responses,
          'ap_map':      {ssid: [bssid, ...]},
          'frame_total': int,
          'error':       str or None,
        }
    """
    try:
        import pyshark
    except ImportError:
        return {
            'findings': [], 'raw_counts': {}, 'ssids_seen': [],
            'ap_map': {}, 'frame_total': 0,
            'error': 'pyshark is not installed — run:  pip install pyshark',
        }

    deauth_count   = collections.Counter()          # src_mac → frame count
    deauth_targets = collections.defaultdict(set)   # src_mac → {target_mac}
    probe_ssids    = collections.defaultdict(set)   # src_mac → {ssid}
    ap_map         = collections.defaultdict(set)   # ssid → {bssid}
    raw_counts     = collections.Counter()
    frame_total    = 0
    error          = None

    try:
        cap = pyshark.FileCapture(
            path,
            display_filter='wlan.fc.type == 0',   # management frames only
            keep_packets=False,
        )
        for pkt in cap:
            try:
                st = _subtype(pkt)
                if st < 0:
                    continue
                frame_total += 1
                raw_counts[_SUBTYPE_NAMES.get(st, f'subtype_{st}')] += 1

                src  = _mac(pkt, 'sa', 'ta')
                dst  = _mac(pkt, 'da', 'ra')
                bssid = _mac(pkt, 'bssid')

                if st in (10, 12):   # Disassociation or Deauthentication
                    if src:
                        deauth_count[src] += 1
                        if dst:
                            deauth_targets[src].add(dst)

                elif st == 4:        # Probe Request
                    s = _ssid(pkt)
                    if src and s:
                        probe_ssids[src].add(s)

                elif st in (5, 8):   # Probe Response or Beacon
                    s = _ssid(pkt)
                    if bssid and s and s != '<wildcard>':
                        ap_map[s].add(bssid)

            except Exception:
                continue
        cap.close()

    except Exception as exc:
        error = str(exc)

    # ── Build findings ─────────────────────────────────────────────────────
    findings = []

    # Deauth / disassoc floods
    for src, count in sorted(deauth_count.items(), key=lambda x: -x[1]):
        if count < _DEAUTH_FLOOD_MIN:
            continue
        targets   = deauth_targets[src]
        broadcast = 'ff:ff:ff:ff:ff:ff' in targets
        severity  = 'high' if (broadcast or count >= 50 or len(targets) > 5) else 'medium'
        findings.append({
            'severity': severity,
            'title': 'Deauthentication Flood',
            'description': (
                f'{src} sent {count} deauth/disassociation frames targeting '
                f'{len(targets)} unique MAC address(es). '
                'A high volume of deauth frames from a single source is the fingerprint of a '
                'wireless disconnect attack — used to force clients off the network, often to '
                'capture a WPA handshake for offline cracking.'
            ),
            'evidence': {
                'source_mac':     src,
                'frame_count':    count,
                'unique_targets': len(targets),
                'broadcast':      broadcast,
                'targets_sample': sorted(targets)[:10],
            },
            'remediation': (
                '1. Compare the source MAC against your device list — is it a device you own?\n'
                '2. If unknown, this is an active wireless attack originating within RF range (~100 m).\n'
                '3. Enable 802.11w (Management Frame Protection) on your AP — this cryptographically '
                'authenticates management frames, blocking forged deauth attacks.\n'
                '   Look for it in your AP admin panel under: Wireless Security → PMF / MFP.\n'
                '4. Modern routers (WPA3 or WPA2 with PMF) are immune to this attack once MFP is on.\n'
                '5. If the attack is ongoing, the device is physically nearby — scan with a phone '
                'running a WiFi analyzer app to triangulate signal strength.'
            ),
        })

    # Probe sweeps
    for src, ssids in sorted(probe_ssids.items(), key=lambda x: -len(x[1])):
        if len(ssids) < _PROBE_SWEEP_MIN:
            continue
        findings.append({
            'severity': 'low',
            'title': 'Probe Request Sweep',
            'description': (
                f'{src} sent probe requests for {len(ssids)} different network names. '
                'A device probing this many SSIDs is consistent with a wireless scanner or '
                'war-driving tool. Normal devices only probe for networks they have previously joined.'
            ),
            'evidence': {
                'source_mac':  src,
                'ssid_count':  len(ssids),
                'ssids_sample': sorted(ssids)[:15],
            },
            'remediation': (
                '1. Identify the device by its MAC address — check your router\'s DHCP table or '
                'compare against known devices.\n'
                '2. If it is your own device, disable "Ask to join new networks" / auto-scan in '
                'your WiFi settings to stop broadcasting your location history.\n'
                '3. If unknown, monitor whether it associates with any AP on your network and '
                'block it at your router if it does.'
            ),
        })

    # Multiple BSSIDs for same SSID (possible evil twin)
    for ssid, bssids in sorted(ap_map.items(), key=lambda x: -len(x[1])):
        if len(bssids) < 2:
            continue
        findings.append({
            'severity': 'medium',
            'title': f'Multiple APs Advertising "{ssid}"',
            'description': (
                f'The network name "{ssid}" was seen from {len(bssids)} different access points '
                f'(BSSIDs): {", ".join(sorted(bssids)[:5])}{"..." if len(bssids) > 5 else ""}. '
                'On a single-AP network this is unexpected. A second device advertising the same '
                'SSID may be a rogue or evil-twin AP attempting to intercept traffic.'
            ),
            'evidence': {
                'ssid':        ssid,
                'bssid_count': len(bssids),
                'bssids':      sorted(bssids),
            },
            'remediation': (
                '1. Check your router/AP label or admin panel — your legitimate BSSID is usually '
                'printed on the device or shown under Wireless Status.\n'
                '2. Compare against the list above to identify the unknown BSSID.\n'
                '3. If you have a multi-AP mesh network, multiple BSSIDs for the same SSID is normal.\n'
                '4. If the extra BSSID is genuinely unknown: the device is within RF range. '
                'Walk around with a WiFi analyzer app to locate it by signal strength.\n'
                '5. Enable rogue AP detection if your AP firmware supports it.'
            ),
        })

    return {
        'findings':    findings,
        'raw_counts':  dict(raw_counts),
        'ssids_seen':  sorted(ap_map.keys()),
        'ap_map':      {k: sorted(v) for k, v in ap_map.items()},
        'frame_total': frame_total,
        'error':       error,
    }
