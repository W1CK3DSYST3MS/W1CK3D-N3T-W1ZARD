"""
scan_profiles.py
----------------
Scan profile definitions and nmap output parser for the Scan Task Wizard.

Each profile defines a labelled task with one or more sequential nmap steps.
The wizard UI in app.py walks the user through the steps, evaluates each
result, and reports plain-English findings.
"""

import re

# ─────────────────────────────── risky service flags ─────────────────────────

RISKY_SERVICES = {
    'telnet':       ('HIGH',   'Telnet sends usernames and passwords in cleartext — '
                               'anyone on the network can intercept them.'),
    'ftp':          ('MEDIUM', 'FTP sends credentials in cleartext. '
                               'Replace with SFTP or FTPS.'),
    'vnc':          ('MEDIUM', 'VNC remote desktop is accessible. '
                               'Verify strong authentication is configured.'),
    'rdp':          ('HIGH',   'Remote Desktop (RDP) is exposed. '
                               'Brute-force attacks are extremely common — '
                               'ensure strong passwords and Network Level Authentication are enabled.'),
    'microsoft-ds': ('MEDIUM', 'SMB file sharing is exposed. '
                               'Verify EternalBlue patch (MS17-010) has been applied.'),
    'netbios-ssn':  ('LOW',    'NetBIOS session service — legacy Windows file-sharing protocol.'),
    'mysql':        ('HIGH',   'MySQL database port is exposed. '
                               'Databases should never be directly internet-accessible.'),
    'postgresql':   ('HIGH',   'PostgreSQL database port is exposed. '
                               'Should not be directly accessible from untrusted networks.'),
    'mongodb':      ('HIGH',   'MongoDB port is exposed. '
                               'Has no authentication by default and is frequently exploited.'),
    'redis':        ('HIGH',   'Redis is exposed. '
                               'No authentication by default — frequently exploited for '
                               'remote code execution.'),
    'memcached':    ('HIGH',   'Memcached is exposed — no authentication; '
                               'commonly abused for DDoS amplification attacks.'),
    'smtp':         ('LOW',    'Mail server (SMTP) is accessible — '
                               'expected on a mail server, otherwise investigate.'),
    'pop3':         ('MEDIUM', 'Unencrypted mail retrieval (POP3) — '
                               'credentials are sent in cleartext. Use POP3S instead.'),
    'imap':         ('MEDIUM', 'Unencrypted mail access (IMAP) — '
                               'credentials are sent in cleartext. Use IMAPS instead.'),
    'rsh':          ('HIGH',   'Remote Shell (rsh) — obsolete protocol, '
                               'no encryption, highly dangerous.'),
    'rlogin':       ('HIGH',   'Remote Login (rlogin) — obsolete, no encryption.'),
    'tftp':         ('HIGH',   'TFTP has no authentication — any file can be read or written.'),
    'snmp':         ('MEDIUM', 'SNMP v1/v2c uses community strings sent in cleartext. '
                               'Use SNMPv3 with authentication.'),
    'ldap':         ('MEDIUM', 'LDAP directory service is exposed — '
                               'verify authentication is enforced.'),
    'x11':          ('HIGH',   'X11 display is exposed — can allow full remote desktop '
                               'access with no authentication.'),
    'nfs':          ('HIGH',   'NFS file share exposed — check export rules carefully; '
                               'misconfigured NFS is commonly exploited.'),
    'rsync':        ('HIGH',   'rsync exposed — can allow unauthenticated file access '
                               'if not properly secured.'),
    'docker':       ('HIGH',   'Docker API exposed — full container and host compromise risk.'),
    'kubernetes':   ('HIGH',   'Kubernetes API exposed — full cluster compromise risk.'),
}

# ─────────────────────────────── profile definitions ─────────────────────────

SCAN_PROFILES = [

    # ── Home Network ──────────────────────────────────────────────────────────
    {
        'id': 'home_discover',
        'label': 'Find all devices on my network',
        'category': 'Home Network',
        'description': (
            'Sends a fast ping sweep across your local network to find every active device. '
            'No ports are scanned — this is the quickest and least intrusive way to see '
            'what is connected.\n\n'
            'Target: your local network range (e.g. 192.168.1.0/24 or 10.0.0.0/24).'
        ),
        'requires_target': 'range',
        'target_hint': '192.168.1.0/24',
        'steps': [
            {
                'label': 'Ping sweep — discover live hosts',
                'description': 'Sends ICMP pings and ARP requests across the range to find active devices.',
                'args': ['-sn', '-T4'],
                'parse': 'hosts',
            }
        ],
    },
    {
        'id': 'home_arp',
        'label': 'ARP scan (finds devices that block pings)',
        'category': 'Home Network',
        'description': (
            'Uses ARP (Address Resolution Protocol) to find devices on your local network. '
            'More reliable than a ping sweep because devices cannot block ARP requests. '
            'May require running as administrator / root.\n\n'
            'Target: your local network range (e.g. 192.168.1.0/24).'
        ),
        'requires_target': 'range',
        'target_hint': '192.168.1.0/24',
        'steps': [
            {
                'label': 'ARP host discovery',
                'description': 'Finds every device on the local segment using ARP — works even if ICMP is blocked.',
                'args': ['-PR', '-sn', '-T4'],
                'parse': 'hosts',
            }
        ],
    },
    {
        'id': 'home_audit',
        'label': 'Full home network audit  [3 steps]',
        'category': 'Home Network',
        'description': (
            'A three-step check of everything connected to your home network:\n'
            '  1. Find all active devices\n'
            '  2. Scan the most common ports on each device\n'
            '  3. Identify the exact software running on open ports\n\n'
            'Flags any services that are unexpected or risky on a home network.\n\n'
            'Target: your network range (e.g. 192.168.1.0/24). Takes 3–8 minutes.'
        ),
        'requires_target': 'range',
        'target_hint': '192.168.1.0/24',
        'steps': [
            {
                'label': 'Step 1 — Discover all live hosts',
                'description': 'Maps every active device on the network.',
                'args': ['-sn', '-T4'],
                'parse': 'hosts',
            },
            {
                'label': 'Step 2 — Scan common ports',
                'description': 'Checks the 100 most common ports across all discovered hosts.',
                'args': ['-F', '-T4'],
                'parse': 'ports',
                'target_from_hosts': True,
            },
            {
                'label': 'Step 3 — Identify services and versions',
                'description': 'Identifies the exact software and version running on each open port.',
                'args': ['-sV', '-F', '-T4'],
                'parse': 'services',
                'target_from_hosts': True,
            },
        ],
    },

    # ── Security Assessment ───────────────────────────────────────────────────
    {
        'id': 'vuln_check',
        'label': 'Vulnerability check — single host  [3 steps]',
        'category': 'Security Assessment',
        'description': (
            'A thorough three-step vulnerability assessment of a single device:\n'
            '  1. Fast port scan — finds what is open\n'
            '  2. Service version detection — identifies exact software versions\n'
            '  3. Vulnerability scripts — checks for known CVEs and misconfigurations\n\n'
            'Target: a single IP address. Takes 5–15 minutes depending on the host.'
        ),
        'requires_target': 'ip',
        'steps': [
            {
                'label': 'Step 1 — Fast port discovery',
                'description': 'Quickly finds open ports before running heavier checks.',
                'args': ['-F', '-T4'],
                'parse': 'ports',
            },
            {
                'label': 'Step 2 — Service and version detection',
                'description': 'Identifies exact software versions — needed for CVE matching.',
                'args': ['-sV', '-T4', '-p', '{open_ports}'],
                'parse': 'services',
            },
            {
                'label': 'Step 3 — Vulnerability scripts',
                'description': "Runs nmap's built-in scripts to detect known vulnerabilities.",
                'args': ['-sV', '--script', 'vuln', '-T4', '-p', '{open_ports}'],
                'parse': 'vulns',
            },
        ],
    },
    {
        'id': 'mgmt_ports',
        'label': 'Check for open management ports',
        'category': 'Security Assessment',
        'description': (
            'Scans specifically for ports used by remote management and admin interfaces:\n'
            '  SSH (22), Telnet (23), HTTP/HTTPS (80/443), RDP (3389),\n'
            '  VNC (5900), WinRM (5985/5986), and common admin panels (8080/8443).\n\n'
            'Finding these on an unexpected device is a security concern.\n\n'
            'Target: a single IP address or network range.'
        ),
        'requires_target': 'ip',
        'steps': [
            {
                'label': 'Management port scan',
                'description': 'Scans for remote access and admin interfaces with service identification.',
                'args': ['-p', '22,23,80,443,3389,5900,5985,5986,8080,8443,2222,4444', '-sV', '-T4'],
                'parse': 'services',
            }
        ],
    },
    {
        'id': 'full_vuln',
        'label': 'Deep scan — all ports + vulnerabilities  [2 steps]',
        'category': 'Security Assessment',
        'description': (
            'Scans all 65,535 ports, then checks every open service for known vulnerabilities.\n'
            'Very thorough but slow — expect 15–45 minutes.\n\n'
            'Target: a single IP address. Best run when you have time to wait.'
        ),
        'requires_target': 'ip',
        'steps': [
            {
                'label': 'Step 1 — Full port scan (all 65,535 ports)',
                'description': 'Finds services running on non-standard ports — nothing is missed.',
                'args': ['-p-', '-T4'],
                'parse': 'ports',
            },
            {
                'label': 'Step 2 — Service detection + vulnerability check',
                'description': 'Identifies every service version and checks for known CVEs.',
                'args': ['-sV', '--script', 'vuln', '-T4', '-p', '{open_ports}'],
                'parse': 'vulns',
            },
        ],
    },

    # ── Reconnaissance ────────────────────────────────────────────────────────
    {
        'id': 'recon_quick',
        'label': 'Quick port survey',
        'category': 'Reconnaissance',
        'description': (
            'Scans the 100 most common ports as fast as possible. '
            'Good first step when investigating a suspicious IP — '
            'tells you what services are running within about 10–30 seconds.\n\n'
            'Target: a single IP address.'
        ),
        'requires_target': 'ip',
        'steps': [
            {
                'label': 'Quick scan — top 100 ports',
                'description': 'Fast check of the 100 most commonly used ports.',
                'args': ['-F', '-T4'],
                'parse': 'ports',
            }
        ],
    },
    {
        'id': 'recon_fingerprint',
        'label': 'OS and service fingerprint  [2 steps]',
        'category': 'Reconnaissance',
        'description': (
            'Identifies the operating system a device is running and the exact '
            'software on every open port.\n'
            '  Step 1 does a standard port scan.\n'
            '  Step 2 runs OS detection and service version identification.\n\n'
            'OS detection may require administrator / root privileges.\n\n'
            'Target: a single IP address.'
        ),
        'requires_target': 'ip',
        'steps': [
            {
                'label': 'Step 1 — Port scan',
                'description': 'Finds open ports before running deeper detection.',
                'args': ['-T4', '-F'],
                'parse': 'ports',
            },
            {
                'label': 'Step 2 — OS and service fingerprint',
                'description': 'Identifies the operating system and exact service versions on open ports.',
                'args': ['-O', '-sV', '-T4', '-p', '{open_ports}'],
                'parse': 'services',
            },
        ],
    },
    {
        'id': 'recon_aggressive',
        'label': 'Aggressive full recon  (-A)',
        'category': 'Reconnaissance',
        'description': (
            "Runs nmap's aggressive mode: OS detection, version detection, "
            'default scripts, and traceroute — all in one pass.\n\n'
            'Comprehensive but noisy — will appear in firewall and IDS logs. '
            'Only use on hosts you own or have explicit permission to scan.\n\n'
            'Target: a single IP address.'
        ),
        'requires_target': 'ip',
        'steps': [
            {
                'label': 'Aggressive recon scan',
                'description': 'Full OS + service + script scan in one pass.',
                'args': ['-A', '-T4'],
                'parse': 'services',
            }
        ],
    },

    # ── Incident Response ─────────────────────────────────────────────────────
    {
        'id': 'incident_device',
        'label': 'Investigate suspicious device  [3 steps]',
        'category': 'Incident Response',
        'description': (
            'Targeted three-step investigation of a device showing suspicious activity:\n'
            '  1. Finds what ports are open on the device\n'
            '  2. Identifies all running services\n'
            '  3. Checks for default credentials and common misconfigurations\n\n'
            'Target: the IP address of the suspicious device.'
        ),
        'requires_target': 'ip',
        'steps': [
            {
                'label': 'Step 1 — Port survey',
                'description': 'Checks what ports this device has open.',
                'args': ['-F', '-T4'],
                'parse': 'ports',
            },
            {
                'label': 'Step 2 — Service identification',
                'description': 'Identifies every service — confirms what this device is doing.',
                'args': ['-sV', '-T4', '-p', '{open_ports}'],
                'parse': 'services',
            },
            {
                'label': 'Step 3 — Default credential check',
                'description': 'Tests for default passwords and common misconfigurations.',
                'args': ['-sV', '--script', 'default,auth', '-T4', '-p', '{open_ports}'],
                'parse': 'vulns',
            },
        ],
    },
    {
        'id': 'incident_exposure',
        'label': 'Internet exposure check  [2 steps]',
        'category': 'Incident Response',
        'description': (
            'Checks what a host is exposing: scans all ports and flags anything '
            'that should not be publicly accessible — databases, admin panels, '
            'file shares, remote access protocols.\n\n'
            'Use on an external IP to see what an attacker can see, or on an '
            'internal device you suspect is acting as a server.\n\n'
            'Target: a single IP address.'
        ),
        'requires_target': 'ip',
        'steps': [
            {
                'label': 'Step 1 — Full port scan (open ports only)',
                'description': 'Finds every open port, including non-standard ones.',
                'args': ['-p-', '-T4', '--open'],
                'parse': 'ports',
            },
            {
                'label': 'Step 2 — Service and exposure analysis',
                'description': 'Identifies every service and flags dangerous exposures.',
                'args': ['-sV', '-T4', '-p', '{open_ports}'],
                'parse': 'services',
            },
        ],
    },

    # ── Network Mapping ───────────────────────────────────────────────────────
    {
        'id': 'map_traceroute',
        'label': 'Trace route to target',
        'category': 'Network Mapping',
        'description': (
            'Traces the network path from your machine to a target IP, showing '
            'every router hop along the way. Useful for understanding how traffic '
            'reaches a destination and spotting unexpected routing.\n\n'
            'Target: any IP address (internal or external).'
        ),
        'requires_target': 'ip',
        'steps': [
            {
                'label': 'Traceroute scan',
                'description': 'Maps every network hop between you and the target.',
                'args': ['-sn', '--traceroute', '-T4'],
                'parse': 'hosts',
            }
        ],
    },
    {
        'id': 'map_subnet',
        'label': 'Subnet map + open ports  [2 steps]',
        'category': 'Network Mapping',
        'description': (
            'Two-step network map:\n'
            '  1. Finds all active devices on the subnet\n'
            '  2. Scans the most common ports on every device\n\n'
            'Gives a quick picture of what is on the network and what each '
            'device is offering as services.\n\n'
            'Target: your network range (e.g. 192.168.1.0/24).'
        ),
        'requires_target': 'range',
        'target_hint': '192.168.1.0/24',
        'steps': [
            {
                'label': 'Step 1 — Discover live hosts',
                'description': 'Finds all active devices on the subnet.',
                'args': ['-sn', '-T4'],
                'parse': 'hosts',
            },
            {
                'label': 'Step 2 — Common port scan',
                'description': 'Scans the most common ports across all discovered devices.',
                'args': ['-F', '-T4'],
                'parse': 'ports',
                'target_from_hosts': True,
            },
        ],
    },
]

ALL_CATEGORIES = []
_seen_cats: set = set()
for _p in SCAN_PROFILES:
    if _p['category'] not in _seen_cats:
        ALL_CATEGORIES.append(_p['category'])
        _seen_cats.add(_p['category'])


def get_profiles_by_category() -> dict:
    result: dict = {}
    for p in SCAN_PROFILES:
        result.setdefault(p['category'], []).append(p)
    return result


def build_step_args(step: dict, context: dict, options: dict = None) -> list:
    """
    Return the nmap arg list for a step, substituting runtime values and
    merging any user-selected scan options.

    context keys:
        open_ports  – comma-joined port list from previous steps
        hosts       – list of host IPs discovered in previous steps

    options (optional) – dict from default_options(): user toggles, timing,
        and custom flags. When None, sensible defaults apply (notably -Pn on
        port scans so firewalled hosts aren't falsely reported "down").
    """
    args = []
    for a in step['args']:
        if '{open_ports}' in a:
            ports = context.get('open_ports', '')
            a = a.replace('{open_ports}', ports if ports else '1-1000')
        args.append(a)

    is_discovery = '-sn' in args

    if options is None:
        # Default behaviour (no user customisation): skip nmap's host-discovery
        # ping on port scans by adding -Pn. Many devices — home routers,
        # firewalled hosts, most Windows machines — don't answer nmap's default
        # ping probes, so without -Pn nmap decides the host is "down" and skips
        # the scan entirely: a fast, confusing false negative. We never add it to
        # pure discovery sweeps (-sn), where finding live hosts is the point.
        if not is_discovery and '-Pn' not in args:
            args.insert(0, '-Pn')
        return args

    return _apply_options(args, is_discovery, options)


# ─────────────────────────────── scan options ────────────────────────────────
# Data-driven advanced options the UI exposes as checkboxes. Adding an option
# here makes it appear in the Scan Profiles dialog automatically.
#   key    – stable identifier used in the options dict
#   label  – plain-English checkbox label
#   flags  – nmap flags this option adds
#   default– checked by default
#   admin  – True if it needs administrator/root (raw sockets) to work
#   help   – one-line explanation shown under the checkbox
SCAN_OPTIONS = [
    {'key': 'Pn', 'label': 'Skip host discovery  (-Pn)', 'flags': ['-Pn'],
     'default': True, 'admin': False,
     'help': "Scan even if the host doesn't answer a ping. Fixes the common "
             "'host seems down' false negative on routers and firewalled devices."},
    {'key': 'sV', 'label': 'Detect service versions  (-sV)', 'flags': ['-sV'],
     'default': False, 'admin': False,
     'help': 'Identify the exact software and version on each open port.'},
    {'key': 'O', 'label': 'Detect operating system  (-O)', 'flags': ['-O'],
     'default': False, 'admin': True,
     'help': 'Guess the target OS. Needs administrator/root (raw sockets).'},
    {'key': 'open', 'label': 'Show only open ports  (--open)', 'flags': ['--open'],
     'default': False, 'admin': False,
     'help': 'Hide closed and filtered ports from the results.'},
    {'key': 'vuln', 'label': 'Check known vulnerabilities  (--script vuln)',
     'flags': ['--script', 'vuln'], 'default': False, 'admin': False,
     'help': "Run nmap's vulnerability-detection scripts. Slower and noisier."},
]

# Timing template dropdown (slower/quieter → faster/noisier). Default -T4.
SCAN_TIMING = [
    ('-T2', 'Polite (T2) — slower, quieter'),
    ('-T3', 'Normal (T3)'),
    ('-T4', 'Fast (T4) — default'),
    ('-T5', 'Insane (T5) — fastest, noisiest'),
]

_TIMING_RE = re.compile(r'^-T[0-5]$')


def default_options() -> dict:
    """The starting options dict (defaults from SCAN_OPTIONS + -T4)."""
    return {
        'toggles': {o['key']: o['default'] for o in SCAN_OPTIONS},
        'timing':  '-T4',
        'extra':   [],   # custom nmap flags (list of tokens)
    }


def _apply_options(args: list, is_discovery: bool, options: dict) -> list:
    """Merge user-selected options into a step's base args.

    Port-scan toggles (-Pn/-sV/-O/--open/vuln) are skipped for -sn discovery
    sweeps, where they'd be meaningless; timing and custom flags always apply.
    Everything is de-duplicated so a profile that already includes a flag never
    gets it twice.
    """
    args = list(args)
    toggles = options.get('toggles', {})
    flag_map = {o['key']: o['flags'] for o in SCAN_OPTIONS}

    if not is_discovery:
        for key, flags in flag_map.items():
            if not toggles.get(key):
                continue
            # skip if any of this option's flags are already present
            if any(f in args for f in flags):
                continue
            if key == 'Pn':
                args = flags + args      # -Pn reads best at the front
            else:
                args += flags

    # Timing override: replace any existing -T* with the chosen template.
    timing = options.get('timing')
    if timing:
        args = [a for a in args if not _TIMING_RE.match(a)]
        args.append(timing)

    # Custom flags (power users) — appended verbatim, de-duplicated.
    for tok in options.get('extra', []):
        if tok and tok not in args:
            args.append(tok)

    return args


# ─────────────────────────────── output parser ───────────────────────────────

_RE_REPORT   = re.compile(r'Nmap scan report for (?:(.+) \()?([0-9a-f.:]+)\)?')
_RE_PORT     = re.compile(r'^(\d+)/(tcp|udp)\s+(open|filtered)\s+(\S+)(?:\s+(.*))?', re.M)
_RE_OS       = re.compile(r'OS details?: (.+)')
_RE_CVE      = re.compile(r'(CVE-\d{4}-\d+)', re.I)
_RE_VULN_ST  = re.compile(r'State:\s*(VULNERABLE|LIKELY VULNERABLE)', re.I)
_RE_HOSTS_UP = re.compile(r'(\d+) hosts? up')

_OLD_VERSIONS = [
    (r'Apache[/ ]([12]\.\d+\.\d+)',   'Apache HTTP Server'),
    (r'OpenSSH_([1-6]\.\d)',          'OpenSSH'),
    (r'vsftpd ([12]\.\d)',            'vsftpd FTP'),
    (r'nginx/1\.(0|1|2|3|4|5|6|7|8|9|10|11|12|13|14)\.',  'nginx'),
    (r'ProFTPD 1\.[0-2]\.',           'ProFTPD FTP'),
    (r'Samba ([23]\.\d)',             'Samba'),
]


def parse_nmap_output(output: str, parse_mode: str) -> dict:
    """
    Parse raw nmap stdout into structured findings.

    Returns a dict with:
        hosts       – list of str IPs found up
        open_ports  – list of int port numbers (open only)
        services    – list of (port, proto, service, version) tuples
        os_guesses  – list of str
        cves        – list of str CVE IDs mentioned
        vuln_states – list of str ('VULNERABLE' / 'LIKELY VULNERABLE')
        summary     – list of plain-English strings (key findings)
        warnings    – list of (severity, message) tuples
    """
    hosts:       list = []
    open_ports:  list = []
    services:    list = []
    os_guesses:  list = []
    warnings:    list = []
    summary:     list = []

    cves        = list(set(_RE_CVE.findall(output)))
    vuln_states = _RE_VULN_ST.findall(output)

    # Hosts up
    for m in _RE_REPORT.finditer(output):
        ip = m.group(2)
        if ip not in hosts:
            hosts.append(ip)

    m = _RE_HOSTS_UP.search(output)
    if m:
        summary.append(f'{m.group(1)} host(s) found active on the network.')

    # Ports / services
    for m in _RE_PORT.finditer(output):
        port  = int(m.group(1))
        proto = m.group(2)
        state = m.group(3)
        svc   = m.group(4)
        ver   = (m.group(5) or '').strip()
        if state == 'open':
            open_ports.append(port)
            services.append((port, proto, svc, ver))

    # OS detection
    for m in _RE_OS.finditer(output):
        os_guesses.append(m.group(1).strip())

    # Build summary
    if parse_mode == 'hosts' and hosts:
        summary.append(f'Found {len(hosts)} active host(s):')
        for h in hosts:
            summary.append(f'  • {h}')

    if open_ports:
        port_list = ', '.join(str(p) for p in sorted(open_ports))
        summary.append(f'{len(open_ports)} open port(s): {port_list}')

    if os_guesses:
        summary.append(f'OS detected: {os_guesses[0]}')

    # CVE / vuln findings
    if cves:
        summary.append(f'CVEs referenced: {", ".join(cves)}')
        warnings.append(('HIGH', f'Vulnerability script found {len(cves)} CVE reference(s): '
                                 f'{", ".join(cves)}'))
    if vuln_states:
        n = len(vuln_states)
        warnings.append(('HIGH', f'{n} vulnerability check(s) returned VULNERABLE status — '
                                 'review the raw output above for details.'))

    # Flag risky services
    flagged_svcs: set = set()
    for port, proto, svc, ver in services:
        svc_lower = svc.lower()
        if svc_lower in RISKY_SERVICES and svc_lower not in flagged_svcs:
            sev, msg = RISKY_SERVICES[svc_lower]
            warnings.append((sev, f'Port {port}/{proto} ({svc}): {msg}'))
            flagged_svcs.add(svc_lower)

        # Outdated version patterns
        if ver:
            for pattern, name in _OLD_VERSIONS:
                if re.search(pattern, ver, re.I):
                    warnings.append(('MEDIUM',
                                     f'Port {port}: {name} version "{ver}" may be outdated — '
                                     f'check for known CVEs.'))
                    break

    if not summary and not open_ports and not hosts:
        summary.append('Scan completed — no notable findings in this step.')

    return {
        'hosts':       hosts,
        'open_ports':  open_ports,
        'services':    services,
        'os_guesses':  os_guesses,
        'cves':        cves,
        'vuln_states': vuln_states,
        'summary':     summary,
        'warnings':    warnings,
    }
