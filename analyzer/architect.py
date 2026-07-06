"""
architect.py — Automated network architecture evaluator.

Analyses the full results dict from a pcap analysis and produces a
plain-English evaluation with prioritised recommendations. Designed for
users who can follow instructions but don't have deep networking knowledge.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Tuple

GOOD      = 'good'
ATTENTION = 'attention'
ACTION    = 'action'

_STATUS_ORDER = [ACTION, ATTENTION, GOOD]

# Well-known privacy-respecting / malware-blocking public DNS servers
_SECURE_DNS = {
    '1.1.1.1', '1.0.0.1',                   # Cloudflare
    '8.8.8.8', '8.8.4.4',                   # Google
    '9.9.9.9', '149.112.112.112',            # Quad9
    '208.67.222.222', '208.67.220.220',      # OpenDNS
    '94.140.14.14', '94.140.15.15',          # AdGuard
    '185.228.168.9', '185.228.169.9',        # CleanBrowsing
}

# Keywords that suggest a device is IoT / smart-home rather than a PC/server
_IOT_KEYWORDS = {
    'camera', 'smart', 'iot', 'thermostat', 'hub', 'bulb', 'plug',
    'sensor', 'tv', 'printer', 'nas', 'media', 'streaming', 'amazon',
    'google home', 'apple tv', 'roku', 'chromecast', 'ring', 'nest',
    'philips', 'hue', 'sonos', 'lifx', 'wemo',
}


@dataclass
class Section:
    title:   str
    status:  str          # GOOD / ATTENTION / ACTION
    summary: str          # one or two sentence overview shown at top
    body:    List[str] = field(default_factory=list)   # explanation paragraphs
    steps:   List[str] = field(default_factory=list)   # numbered action steps
    tip:     str = ''                                   # grey closing note


# ── public API ──────────────────────────────────────────────────────────────

def evaluate(results: dict) -> Tuple[str, List[Section]]:
    """
    Evaluate the network architecture from a pcap analysis results dict.
    Returns (overall_status, sections_sorted_worst_first).
    overall_status is one of: 'action', 'attention', 'good'.
    """
    devices_data = results.get('devices', {}) or {}
    net          = results.get('network', {}) or {}
    threats      = results.get('threats', {}) or {}

    sections = [
        _eval_security(threats),
        _eval_segmentation(devices_data, net),
        _eval_dns(net),
        _eval_gateway(net, devices_data),
        _eval_external_traffic(net),
        _eval_devices(devices_data, net),
    ]

    sections.sort(key=lambda s: _STATUS_ORDER.index(s.status))
    overall = sections[0].status if sections else GOOD
    return overall, sections


# ── individual section evaluators ───────────────────────────────────────────

def _eval_security(threats: dict) -> Section:
    findings = threats.get('findings', []) or []
    counts   = threats.get('counts_by_severity', {}) or {}

    n_crit   = counts.get('critical', 0)
    n_high   = counts.get('high', 0)
    n_medium = counts.get('medium', 0)

    def _match(f, *keywords):
        haystack = (f.get('title', '') + ' ' + f.get('category', '')).lower()
        return any(k in haystack for k in keywords)

    cleartext = [f for f in findings if _match(f,
        'plaintext', 'ftp in use', 'telnet', 'pop3', 'imap', 'rlogin', 'rsh', 'tftp')]
    legacy    = [f for f in findings if _match(f, 'smbv1', 'llmnr', 'netbios', 'nbt-ns')]
    tls       = [f for f in findings if _match(f, 'weak tls', 'ssl')]
    malware   = [f for f in findings if _match(f, 'beacon', 'c2', 'dga', 'dns tunnel')]
    recon     = [f for f in findings if _match(f, 'port scan', 'host sweep')]
    arp       = [f for f in findings if _match(f, 'arp spoof', 'man-in-the-middle')]
    exfil     = [f for f in findings if _match(f, 'large outbound')]

    if n_crit + n_high > 0:
        status = ACTION
        n = n_crit + n_high
        summary = (
            f'Your network has {n} high-severity security '
            f'issue{"s" if n > 1 else ""} that need immediate attention. '
            'These represent real risks that an attacker on the same network '
            'could exploit right now.'
        )
    elif n_medium > 0:
        status = ATTENTION
        summary = (
            f'{n_medium} medium-severity finding{"s" if n_medium > 1 else ""} detected. '
            'These aren\'t emergencies but represent weak spots worth addressing.'
        )
    else:
        return Section(
            title='Security Posture', status=GOOD,
            summary=(
                'No significant security issues were detected in this capture. '
                'The network protocols visible in this session look reasonably secure.'
            ),
            tip=(
                'This analysis only covers traffic visible during the capture window. '
                'Run captures at different times of day for broader coverage.'
            ),
        )

    body  = []
    steps = []

    if malware:
        body.append(
            'Suspicious traffic patterns consistent with malware or command-and-control '
            '(C2) communication were detected. A device on your network may be '
            'infected and calling home to an attacker.'
        )
        steps.append(
            'PRIORITY — Identify the affected device from the Findings tab details. '
            'Disconnect it from the network immediately. '
            'Run a full scan using Malwarebytes Free (malwarebytes.com). '
            'Change passwords for all accounts used on that device, from a '
            'separate clean device.'
        )

    if arp:
        body.append(
            'ARP spoofing detected — a device may be impersonating your router to '
            'intercept all traffic on the network. This is an active man-in-the-middle attack.'
        )
        steps.append(
            'Disconnect from the network immediately. Check your router\'s connected '
            'device list for any unfamiliar MAC addresses. Identify the device claiming '
            'to be your gateway and remove it. Scan all devices for malware after reconnecting.'
        )

    if cleartext:
        names = ', '.join(f['title'] for f in cleartext[:4])
        body.append(
            f'Unencrypted credentials detected ({names}). Login details are being '
            'transmitted in plain text — anyone on the same network with a packet '
            'capture tool can read usernames and passwords.'
        )
        steps.append(
            'Replace Telnet with SSH (use PuTTY on Windows — free at putty.org). '
            'Replace FTP with SFTP or FTPS (FileZilla or WinSCP are free options). '
            'For email: switch POP3 to port 995 with SSL/TLS, and IMAP to port 993 with SSL/TLS — '
            'change this in your email client\'s account settings. '
            'If a device only supports the old protocol, prioritise replacing it.'
        )

    if legacy:
        names = ', '.join(f['title'] for f in legacy[:3])
        body.append(
            f'Legacy protocols detected ({names}). These were retired because of '
            'known security weaknesses and should be disabled everywhere.'
        )
        steps.append(
            'Disable SMBv1: open PowerShell as Administrator on each Windows machine and run:\n'
            '    Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol\n'
            'Disable LLMNR via Group Policy: run gpedit.msc → '
            'Computer Configuration → Administrative Templates → Network → '
            'DNS Client → "Turn off multicast name resolution" → Enabled.\n'
            'Disable NetBIOS: open ncpa.cpl → right-click your adapter → '
            'Properties → IPv4 → Advanced → WINS tab → '
            '"Disable NetBIOS over TCP/IP".'
        )

    if tls:
        body.append(
            'Outdated TLS/SSL configuration detected. Older versions (TLS 1.0, 1.1, SSL 3.0) '
            'have well-documented vulnerabilities and should not be in use.'
        )
        steps.append(
            'For any web servers you control: configure them to require TLS 1.2 or '
            'TLS 1.3 as the minimum. '
            'Test any public-facing web services for free at ssllabs.com/ssltest — '
            'it gives a letter grade and exact configuration steps for Apache, Nginx, and IIS. '
            'On Windows Server: use IIS Crypto (free tool) to disable old TLS versions with one click.'
        )

    if recon:
        body.append(
            'Reconnaissance activity detected — port scanning or host sweeping was '
            'observed. This could be a device on your network probing others, '
            'or an external scan reaching in.'
        )
        steps.append(
            'Check your router firewall logs to identify the source. '
            'If scanning came from inside your network, run a malware scan on that device. '
            'If external: confirm your router firewall is enabled and blocking '
            'unsolicited inbound connections (it should be on by default on all modern routers).'
        )

    if exfil:
        body.append(
            'Unusually large outbound data transfers detected. This could be legitimate '
            '(cloud backup, OS updates) or could indicate data exfiltration.'
        )
        steps.append(
            'Check the Findings tab for the specific transfer details and the IP destination. '
            'Use the Investigate tab to identify who owns that IP. '
            'If it\'s not a service you recognise (Google, Microsoft, Dropbox, etc.), '
            'investigate which device is responsible.'
        )

    return Section(
        title='Security Posture', status=status, summary=summary,
        body=body, steps=steps,
        tip='Re-run a capture after making changes to confirm issues are resolved.',
    )


def _eval_segmentation(devices_data: dict, net: dict) -> Section:
    devices  = devices_data.get('devices', []) or []
    subnets  = net.get('subnets', []) or []
    gw_ip    = net.get('gateway_ip', '') or '192.168.1.1'
    n_dev    = len(devices)
    n_sub    = len(subnets)

    has_iot = any(
        any(kw in (d.get('likely_type') or '').lower() for kw in _IOT_KEYWORDS)
        for d in devices
    )
    is_flat = n_sub <= 1 and n_dev > 3

    if is_flat and has_iot:
        status  = ACTION
        summary = (
            f'All {n_dev} devices are on a single flat network. This includes IoT '
            'and smart-home devices sharing the same segment as your computers — '
            'a significant security risk.'
        )
        body = [
            'On a flat network every device can communicate directly with every other. '
            'If a smart TV, camera, printer, or any IoT device is compromised, the '
            'attacker has a direct route to your computers and data. '
            'IoT devices are notoriously poorly secured and rarely receive updates.',
            'The fix is to split devices into separate network zones. IoT devices '
            'get internet access but cannot reach your computers.',
        ]
        steps = [
            'Today (5 minutes): enable the Guest WiFi network on your router. '
            'Move all smart TVs, cameras, printers, smart speakers, and other IoT '
            'devices onto it. Guest networks isolate traffic from the main LAN '
            'by default on most routers.',
            f'Log into your router at http://{gw_ip} and look for "Guest Network" '
            'or "Wireless" settings. Enable a second SSID and connect IoT devices to it.',
            'Longer term: if your router supports VLANs (look for "VLAN" or '
            '"Network Zones" in advanced settings), create dedicated VLANs for '
            'IoT, trusted devices, and guests. '
            'UniFi (Ubiquiti), TP-Link Omada, or pfSense/OPNsense are strong '
            'upgrade options if your router doesn\'t support VLANs.',
        ]
        tip = (
            'A guest network provides meaningful isolation and takes about 5 minutes '
            'to set up — you don\'t need new hardware to start.'
        )

    elif is_flat:
        status  = ATTENTION
        summary = (
            f'All {n_dev} devices share one network '
            f'({", ".join(subnets[:2]) if subnets else "single subnet"}). '
            'This is common for small networks but worth improving as more devices are added.'
        )
        body = [
            'A flat network is fine for a small number of trusted devices. '
            'As you add IoT, smart-home, or guest devices, putting them on '
            'a separate segment significantly reduces your risk.'
        ]
        steps = [
            f'Enable a Guest WiFi network on your router ({gw_ip}) for IoT and '
            'smart-home devices — this is the easiest first step.',
            'If you run any servers, NAS, or security cameras: consider a separate VLAN '
            'or at minimum add firewall rules restricting which devices can reach them.',
        ]
        tip = f'Router admin panel: http://{gw_ip}'

    else:
        status  = GOOD
        summary = (
            f'Multiple network segments detected ({n_sub} subnets). '
            'Your network already has some level of segmentation in place — good.'
        )
        body  = []
        steps = []
        tip   = (
            'Review periodically that devices are still in the right segments, '
            'especially after adding new hardware.'
        )

    return Section(
        title='Network Segmentation', status=status, summary=summary,
        body=body, steps=steps,
        tip=tip or f'Router admin panel: http://{gw_ip}',
    )


def _eval_dns(net: dict) -> Section:
    dns_servers = net.get('dns_servers', []) or []
    gw_ip       = net.get('gateway_ip', '') or ''

    if not dns_servers:
        return Section(
            title='DNS Configuration', status=ATTENTION,
            summary='No DNS servers were identified in this capture.',
            body=[
                'DNS converts domain names like "google.com" into IP addresses. '
                'Your choice of DNS server affects your privacy '
                '(ISPs can see and log all domain lookups) and security '
                '(some DNS providers actively block malware and phishing domains).'
            ],
            steps=[
                'Check your router DNS settings and consider switching to: '
                '1.1.1.1 / 1.0.0.1 (Cloudflare — fast, private) or '
                '9.9.9.9 / 149.112.112.112 (Quad9 — blocks malware domains).'
            ],
        )

    using_secure  = [s for s in dns_servers if s in _SECURE_DNS]
    using_gateway = [s for s in dns_servers if gw_ip and s == gw_ip]

    if using_gateway and not using_secure:
        status  = ATTENTION
        summary = (
            f'Your router ({gw_ip}) is acting as the DNS server. '
            'Most home routers simply forward DNS requests to your ISP by default — '
            'no privacy protection, no malware filtering.'
        )
        body = [
            'When the router handles DNS it typically passes every lookup to '
            'your ISP\'s servers. Your ISP sees every domain name your devices '
            'visit — and in many countries logs or monetises this data.',
        ]
        steps = [
            f'Log into your router at http://{gw_ip}, find DNS settings '
            '(usually under WAN, Internet, or Advanced), and change to:\n'
            '    Primary:    1.1.1.1   (Cloudflare — fast, no logging)\n'
            '    Secondary:  1.0.0.1\n'
            'Or use Quad9 (9.9.9.9 / 149.112.112.112) which also blocks malware domains.',
            'For full network-wide ad and malware blocking: install Pi-hole on '
            'a Raspberry Pi or spare machine. It acts as a local DNS server '
            'with a dashboard showing all queries. Setup guide at pi-hole.net.',
        ]

    elif using_secure:
        status  = GOOD
        summary = (
            f'Using well-known secure DNS servers: {", ".join(using_secure)}. '
            'These provide good privacy and in some cases malware domain blocking.'
        )
        body  = []
        steps = []

    else:
        status  = ATTENTION
        summary = (
            f'DNS servers in use: {", ".join(dns_servers[:3])}. '
            'These don\'t match any known public DNS providers and are likely '
            'your ISP\'s servers.'
        )
        body = [
            'ISP-provided DNS servers log your browsing and typically don\'t '
            'block malware or phishing domains.'
        ]
        steps = [
            'Switch to 1.1.1.1 (Cloudflare) or 9.9.9.9 (Quad9). Change the setting '
            + (f'in your router at http://{gw_ip} under DNS / WAN settings.' if gw_ip
               else 'in your router\'s WAN or DNS settings.')
        ]

    return Section(
        title='DNS Configuration', status=status, summary=summary,
        body=body, steps=steps,
    )


def _eval_gateway(net: dict, devices_data: dict) -> Section:
    gw_ip   = net.get('gateway_ip', '') or ''
    gw_mac  = net.get('gateway_mac', '') or ''
    devices = devices_data.get('devices', []) or []

    if not gw_ip:
        return Section(
            title='Gateway / Router', status=ATTENTION,
            summary='No gateway was identified in this capture.',
            body=[
                'The gateway is your router — every byte of internet traffic passes '
                'through it. Keeping it updated and hardened is the single '
                'highest-value action for home and small office network security.'
            ],
        )

    gw_dev = next((d for d in devices if d.get('is_gateway')), None)
    vendor = (gw_dev or {}).get('vendor', '') or ''

    id_str = gw_ip
    if gw_mac:
        id_str += f'  (MAC {gw_mac}'
        if vendor:
            id_str += f',  {vendor}'
        id_str += ')'

    body = [
        f'Gateway: {id_str}.',
        'Your router is the most important device on the network from a security '
        'standpoint. It controls access between your devices and the internet, '
        'and is the first target in most home network attacks.',
    ]
    steps = [
        f'Firmware: log into http://{gw_ip}, find "Firmware" or "Software Update" '
        'and install any available updates. Enable automatic updates if the option exists.',
        'Admin password: if you haven\'t changed the factory default password, '
        'do it now. Default credentials for every router model are published online '
        'and are routinely exploited.',
        'Disable remote management (also called "WAN-side access" or "Remote Admin" '
        'in your router settings) unless you have a specific reason to use it. '
        'This prevents anyone on the internet reaching the admin panel.',
        'Review port forwarding rules: open the Port Forwarding or Virtual Server '
        'section and remove any rules you don\'t actively use.',
        'Confirm the firewall/NAT is enabled — it should be on by default but '
        'is worth checking, especially on older routers.',
    ]

    return Section(
        title='Gateway / Router', status=GOOD,
        summary=f'Gateway identified at {gw_ip}. Maintenance checklist below.',
        body=body, steps=steps,
        tip=f'Router admin panel: http://{gw_ip}',
    )


def _eval_external_traffic(net: dict) -> Section:
    int_pkt   = net.get('internal_packets', 0) or 0
    ext_pkt   = net.get('external_packets', 0) or 0
    ext_bytes = net.get('bytes_external', 0) or 0
    top_ext   = net.get('top_external_ips', []) or []
    total     = int_pkt + ext_pkt

    if total == 0:
        return Section(title='External Traffic', status=GOOD,
                       summary='No traffic statistics available for this capture.')

    def _fmt(b: float) -> str:
        for u in ('B', 'KB', 'MB', 'GB'):
            if b < 1024:
                return f'{b:.1f} {u}'
            b /= 1024
        return f'{b:.1f} TB'

    ext_pct = round(100 * ext_pkt / total)

    if ext_pct > 65:
        status  = ATTENTION
        summary = (
            f'{ext_pct}% of captured traffic was internet-bound '
            f'({_fmt(ext_bytes)} outbound) — higher than typical for most networks.'
        )
        body = [
            'Heavy external traffic can be normal (cloud backup, OS updates, streaming) '
            'but is also how data exfiltration and malware callbacks look. '
            'If you don\'t recognise the top destinations, investigate them.'
        ]
        steps = [
            'Use the Investigate tab to look up any unfamiliar IP addresses in the '
            'top destination list.',
            'Check the Devices tab to identify which device is generating the most '
            'external traffic.',
            'Common legitimate causes: Windows Update, iCloud/OneDrive/Google Drive sync, '
            'antivirus cloud scanning, streaming services. '
            'If none of these explain it, investigate further.',
        ]
    else:
        status  = GOOD
        summary = (
            f'{ext_pct}% of traffic was internet-bound '
            f'({_fmt(ext_bytes)} outbound) — within normal range.'
        )
        body  = []
        steps = []

    if top_ext:
        dest_str = 'Top external destinations: ' + ', '.join(ip for ip, _ in top_ext[:6])
        body.append(dest_str)

    return Section(
        title='External Traffic', status=status, summary=summary,
        body=body, steps=steps,
        tip='Use the Investigate tab to look up any unfamiliar external IPs.',
    )


def _eval_devices(devices_data: dict, net: dict) -> Section:
    devices = devices_data.get('devices', []) or []
    gw_ip   = net.get('gateway_ip', '') or '192.168.1.1'
    n_total = len(devices)

    if n_total == 0:
        return Section(title='Device Inventory', status=ATTENTION,
                       summary='No devices were identified in this capture.')

    unknown = [
        d for d in devices
        if (not d.get('is_gateway'))
        and ('unknown' in (d.get('likely_type') or '').lower()
             or not d.get('vendor'))
    ]
    n_unk = len(unknown)

    if n_unk > max(2, n_total * 0.35):
        status  = ATTENTION
        summary = (
            f'{n_unk} of {n_total} devices could not be fully identified. '
            'You should be able to account for every device on your network.'
        )
        body = [
            'Unidentified devices could be forgotten IoT gadgets, a neighbour\'s '
            'device that joined your WiFi, or in rare cases an unauthorised connection. '
            'Either way, unknown devices represent unmanaged risk.'
        ]
        steps = [
            f'Open your router admin at http://{gw_ip} and check "Connected Devices" '
            'or "DHCP Client List" — routers often show device names that a packet '
            'capture can\'t see, making identification much easier.',
            'Cross-reference MAC addresses with physical devices: the first 6 characters '
            'of a MAC identify the manufacturer — look them up at macvendors.com.',
            'Any device you can\'t identify should be temporarily blocked in the '
            'router (or disconnected) to see what stops working.',
            'Consider rotating your WiFi password every 6–12 months to flush '
            'forgotten or old devices off the network.',
        ]
    else:
        status  = GOOD
        summary = (
            f'{n_total} device{"s" if n_total != 1 else ""} on the network, '
            'most successfully identified.'
        )
        body  = []
        steps = []

    return Section(
        title='Device Inventory', status=status, summary=summary,
        body=body, steps=steps,
    )
