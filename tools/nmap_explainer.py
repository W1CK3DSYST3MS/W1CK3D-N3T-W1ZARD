"""
nmap_explainer.py
-----------------
Plain-English interpretation engine for nmap scan results.

Given the raw output and parsed data from a scan step, this module:
  - Explains every open port in plain English (what it does, is it risky, what to do)
  - Identifies device types from OS hints, MAC vendor, and port signatures
  - Detects when a scan failed or produced poor results and suggests fixes
  - Recommends the most useful next scan with a pre-built command ready to run
  - Builds a text topology map from host discovery and traceroute results

All output is non-technical and aimed at users who understand their network
but do not have deep knowledge of protocols or nmap flags.
"""

import re

# ─────────────────────────────── port knowledge base ─────────────────────────

PORT_INFO: dict = {
    20:    {'name': 'FTP Data',
            'plain': 'File transfer data channel — part of FTP.',
            'concern': 'HIGH',
            'reason': 'FTP transfers files in cleartext. Any data, including passwords, is visible on the network.',
            'action': 'Replace FTP with SFTP (runs over SSH on port 22). FTP should not be used on any modern network.'},
    21:    {'name': 'FTP (File Transfer Protocol)',
            'plain': 'This device is sharing files. Anyone with credentials can upload or download files.',
            'concern': 'HIGH',
            'reason': 'FTP sends usernames and passwords in cleartext — anyone on the same network can intercept them.',
            'action': 'Replace with SFTP or FTPS. Disable FTP if file sharing is not needed.'},
    22:    {'name': 'SSH (Secure Shell)',
            'plain': 'Remote command-line access is enabled. Someone with credentials can log into and control this device remotely.',
            'concern': 'LOW',
            'reason': 'SSH is encrypted and secure. The concern is whether remote access should be open on this particular device.',
            'action': 'Verify this is intentional. Disable if not needed. Use SSH keys instead of passwords. Restrict access by IP if possible.'},
    23:    {'name': 'Telnet',
            'plain': 'Remote command-line access using an old, completely insecure protocol. All commands and passwords are sent in plain text.',
            'concern': 'HIGH',
            'reason': 'Telnet has no encryption whatsoever. Passwords can be read by anyone on the same network with a packet capture tool.',
            'action': 'Disable Telnet immediately. Replace with SSH (port 22). There is no legitimate reason to use Telnet on a modern network.'},
    25:    {'name': 'SMTP (Email Sending)',
            'plain': 'This device is configured to send email.',
            'concern': 'MEDIUM',
            'reason': 'An SMTP server on an unexpected device could be malware using it to send spam, or a misconfigured relay.',
            'action': 'Expected only on a mail server. On any other device, investigate immediately. Check if this device has been sending unusual email.'},
    53:    {'name': 'DNS (Domain Name System)',
            'plain': 'This device is acting as a DNS server — it translates website names (like google.com) into IP addresses for other devices.',
            'concern': 'LOW',
            'reason': 'DNS is normal on routers and corporate servers. Unexpected on regular devices.',
            'action': 'Expected on your router or a corporate DNS server. On any other device — especially a PC — investigate whether it was deliberately configured or is being used for DNS hijacking.'},
    67:    {'name': 'DHCP Server (UDP)',
            'plain': 'This device is handing out IP addresses to other devices on your network.',
            'concern': 'MEDIUM',
            'reason': 'Only one device should be the DHCP server on a network — usually the router. A second DHCP server (a "rogue DHCP server") can redirect all network traffic.',
            'action': 'Verify only your router runs DHCP. If another device is answering DHCP requests, investigate it immediately.'},
    80:    {'name': 'HTTP (Web Server — unencrypted)',
            'plain': 'This device is running a website or web admin panel. All data — including login passwords — is sent without encryption.',
            'concern': 'MEDIUM',
            'reason': 'HTTP traffic can be read by anyone on the network. Passwords entered on HTTP pages are visible in plain text.',
            'action': 'Check if this is a device admin panel (router, NAS, printer). Log in and verify it belongs to you. Switch to HTTPS where possible.'},
    110:   {'name': 'POP3 (Email — unencrypted)',
            'plain': 'This device is serving incoming email using an old, unencrypted protocol.',
            'concern': 'MEDIUM',
            'reason': 'POP3 sends email credentials in cleartext.',
            'action': 'Use POP3S (port 995) instead, which encrypts the connection.'},
    111:   {'name': 'RPC Port Mapper',
            'plain': 'A service directory used by NFS (network file sharing) and other RPC services.',
            'concern': 'MEDIUM',
            'reason': 'The port mapper itself is not dangerous, but NFS and other RPC services can be if misconfigured.',
            'action': 'Check what RPC services are registered (run: rpcinfo -p <ip>). Ensure NFS exports are restricted to trusted hosts only.'},
    135:   {'name': 'Windows RPC (Remote Procedure Call)',
            'plain': 'A core Windows networking service used for communication between Windows programs and services.',
            'concern': 'LOW',
            'reason': 'Normal on Windows machines. Should not be exposed to the internet.',
            'action': 'Normal on Windows PCs on a local network. Block at your router/firewall — this port should never be reachable from the internet.'},
    137:   {'name': 'NetBIOS Name Service',
            'plain': 'Legacy Windows service for network name resolution — older version of DNS for Windows file sharing.',
            'concern': 'LOW',
            'reason': 'Legacy protocol. Can leak machine names and domain information.',
            'action': 'Normal on older Windows networks. Disable NetBIOS over TCP/IP if not needed (Network adapter settings → Advanced).'},
    139:   {'name': 'NetBIOS Session Service (Legacy File Sharing)',
            'plain': 'An older Windows file-sharing protocol. Shares files and printers using NetBIOS.',
            'concern': 'MEDIUM',
            'reason': 'Legacy protocol with historical vulnerabilities. Should never be exposed externally.',
            'action': 'Block at your router. Consider migrating to SMB over port 445 only, then disabling NetBIOS.'},
    143:   {'name': 'IMAP (Email — unencrypted)',
            'plain': 'This device is providing email access using an unencrypted protocol.',
            'concern': 'MEDIUM',
            'reason': 'IMAP sends email credentials in cleartext.',
            'action': 'Use IMAPS (port 993) instead.'},
    389:   {'name': 'LDAP (Directory Service — unencrypted)',
            'plain': 'This device is running a user directory service — used for centralised login on corporate networks.',
            'concern': 'MEDIUM',
            'reason': 'Unencrypted LDAP sends credentials in cleartext. If this is a domain controller, this is expected but should be secured.',
            'action': 'Use LDAPS (port 636). Restrict access to authorised servers only.'},
    443:   {'name': 'HTTPS (Secure Web Server)',
            'plain': 'This device is running an encrypted web server or admin panel.',
            'concern': 'NONE',
            'reason': 'HTTPS is the secure standard for web access.',
            'action': 'Normal. Log in and verify this is your device\'s admin panel if unexpected. Check the SSL certificate is valid and not self-signed for a public service.'},
    445:   {'name': 'SMB (Windows File Sharing)',
            'plain': 'This device is sharing files or printers using the Windows SMB protocol. Other computers on the network can access shared resources.',
            'concern': 'HIGH',
            'reason': ('SMB has been the target of major cyberattacks. WannaCry ransomware (2017) infected '
                       'hundreds of thousands of machines via SMB port 445. The vulnerability (MS17-010) still exists on unpatched systems.'),
            'action': ('Verify all Windows updates are installed. Check what is being shared — open File Explorer and browse to \\\\<ip>. '
                       'Block port 445 at your router — it should NEVER be accessible from the internet.')},
    465:   {'name': 'SMTPS (Secure Email Sending)',
            'plain': 'Encrypted email sending service.',
            'concern': 'NONE',
            'reason': 'Secure version of SMTP.',
            'action': 'Normal on a mail server.'},
    514:   {'name': 'Syslog (UDP)',
            'plain': 'This device is receiving system log messages from other devices.',
            'concern': 'LOW',
            'reason': 'Syslog servers collect log data. Unencrypted by default.',
            'action': 'Expected on a log server. Ensure access is restricted to authorised devices.'},
    515:   {'name': 'LPD (Line Printer Daemon)',
            'plain': 'This device is a printer or print server.',
            'concern': 'LOW',
            'reason': 'Printer protocol. Some older printers have security issues.',
            'action': 'Expected on a printer. Ensure firmware is up to date. Check manufacturer for known vulnerabilities.'},
    554:   {'name': 'RTSP (Real-Time Streaming)',
            'plain': 'This device is streaming audio or video — typically an IP camera or media server.',
            'concern': 'MEDIUM',
            'reason': 'IP cameras are frequently targeted and often have default passwords.',
            'action': ('Change the default password immediately. Check if the stream is accessible without a password. '
                       'Block this port at your router if the camera should only be accessible locally.')},
    587:   {'name': 'SMTP Submission (Email)',
            'plain': 'Email submission port — used by email clients to send email.',
            'concern': 'LOW',
            'reason': 'Standard email submission port.',
            'action': 'Normal on a mail server. Unexpected on other devices.'},
    631:   {'name': 'IPP (Internet Printing Protocol)',
            'plain': 'This device is a printer or print server using a modern printing protocol.',
            'concern': 'LOW',
            'reason': 'IPP is the modern standard printing protocol.',
            'action': 'Expected on printers. Keep firmware updated.'},
    636:   {'name': 'LDAPS (Secure Directory Service)',
            'plain': 'Encrypted user directory service — used for centralised login on corporate networks.',
            'concern': 'LOW',
            'reason': 'Encrypted LDAP is the preferred standard.',
            'action': 'Normal on a domain controller. Restrict access to authorised servers.'},
    993:   {'name': 'IMAPS (Secure Email Access)',
            'plain': 'This device is providing encrypted email access.',
            'concern': 'NONE',
            'reason': 'Encrypted IMAP is the standard.',
            'action': 'Normal on a mail server.'},
    995:   {'name': 'POP3S (Secure Email Retrieval)',
            'plain': 'This device is providing encrypted email retrieval.',
            'concern': 'NONE',
            'reason': 'Encrypted POP3 is the standard.',
            'action': 'Normal on a mail server.'},
    1194:  {'name': 'OpenVPN (UDP)',
            'plain': 'A VPN (Virtual Private Network) server is running on this device.',
            'concern': 'LOW',
            'reason': 'VPN servers are intentional. Ensure it is configured correctly and only trusted users have access.',
            'action': 'Expected if you run your own VPN. Verify the VPN config — especially allowed user accounts and which networks clients can access.'},
    1433:  {'name': 'Microsoft SQL Server',
            'plain': 'A Microsoft SQL database is running and accepting remote connections.',
            'concern': 'HIGH',
            'reason': 'Databases should never be directly accessible from the internet or untrusted networks.',
            'action': 'Block this port at your firewall immediately. Database connections should only be allowed from the application server on the same network.'},
    1521:  {'name': 'Oracle Database',
            'plain': 'An Oracle database is running and accepting connections.',
            'concern': 'HIGH',
            'reason': 'Same principle — databases should not be directly internet-accessible.',
            'action': 'Block at firewall. Restrict to application server access only.'},
    2049:  {'name': 'NFS (Network File System)',
            'plain': 'This device is sharing its filesystem using NFS — a Unix/Linux file sharing protocol.',
            'concern': 'HIGH',
            'reason': 'Misconfigured NFS shares can expose entire filesystems with no authentication.',
            'action': ('Run: showmount -e <ip> to see what is shared. '
                       'Check /etc/exports to ensure shares use root_squash and are restricted to trusted IPs. '
                       'Never expose NFS to the internet.')},
    2222:  {'name': 'SSH (Non-standard port)',
            'plain': 'SSH remote access running on port 2222 instead of the standard port 22, often to reduce automated attack attempts.',
            'concern': 'LOW',
            'reason': 'Moving SSH to a non-standard port reduces bot traffic but is not a security control on its own.',
            'action': 'Same precautions as port 22: use SSH keys, disable password authentication, restrict by IP if possible.'},
    3306:  {'name': 'MySQL Database',
            'plain': 'A MySQL database is running and accepting remote connections.',
            'concern': 'HIGH',
            'reason': 'MySQL on port 3306 is a very common target. Many MySQL breach incidents involve exposed port 3306.',
            'action': ('Block port 3306 at your firewall immediately. '
                       'In the MySQL configuration file (my.cnf), add: bind-address = 127.0.0.1 '
                       'to stop MySQL from accepting remote connections.')},
    3389:  {'name': 'RDP (Windows Remote Desktop)',
            'plain': 'Windows Remote Desktop is enabled — someone can control this computer remotely through a full graphical interface.',
            'concern': 'HIGH',
            'reason': ('RDP is one of the most actively attacked services on the internet. '
                       'Automated bots scan constantly for open RDP and attempt to brute-force passwords. '
                       'Ransomware groups frequently use exposed RDP as their entry point.'),
            'action': ('If this is internet-facing: disable immediately or place behind a VPN. '
                       'Enable Network Level Authentication (NLA). '
                       'Use a strong, unique password. '
                       'Add a Windows Firewall rule restricting access to known IP addresses.')},
    4444:  {'name': 'Common Backdoor / Metasploit Port',
            'plain': 'Port 4444 is most commonly associated with remote access tools and attack frameworks.',
            'concern': 'HIGH',
            'reason': 'This port is the default listener for Metasploit and many other remote-access exploits. Legitimate services rarely use it.',
            'action': 'Investigate this device immediately. Check running processes. Run an antivirus scan. Consider isolating the device from the network.'},
    5432:  {'name': 'PostgreSQL Database',
            'plain': 'A PostgreSQL database is accepting remote connections.',
            'concern': 'HIGH',
            'reason': 'Databases should not be directly accessible from untrusted networks.',
            'action': 'Block at firewall. Restrict to the application server only. In postgresql.conf, set listen_addresses to localhost.'},
    5900:  {'name': 'VNC (Remote Desktop)',
            'plain': 'VNC remote desktop is enabled — this device can be controlled remotely through a graphical interface.',
            'concern': 'HIGH',
            'reason': ('VNC is commonly found with weak or no authentication. '
                       'Unlike RDP, VNC has no account lockout by default, making password guessing trivial.'),
            'action': ('Verify authentication is enabled and uses a strong password. '
                       'Never expose VNC directly to the internet. '
                       'Place behind a VPN. Consider switching to SSH with X forwarding instead.')},
    5985:  {'name': 'WinRM HTTP (Windows Remote Management)',
            'plain': 'Windows Remote Management is enabled — allows PowerShell remote access to this Windows machine.',
            'concern': 'MEDIUM',
            'reason': 'WinRM allows full remote command execution. Should only be accessible to administrators.',
            'action': 'Restrict to management IPs only using Windows Firewall. Use WinRM HTTPS (port 5986) instead.'},
    5986:  {'name': 'WinRM HTTPS (Windows Remote Management)',
            'plain': 'Encrypted Windows Remote Management — allows secure remote PowerShell access.',
            'concern': 'LOW',
            'reason': 'Encrypted WinRM is the preferred method. Still restrict access.',
            'action': 'Restrict to administrator machines and management network only.'},
    6379:  {'name': 'Redis',
            'plain': 'A Redis data store is accepting remote connections.',
            'concern': 'HIGH',
            'reason': ('Redis has no authentication by default. '
                       'Exposed Redis instances have been used in numerous major breaches — '
                       'attackers can read all stored data and in some configurations achieve full server takeover.'),
            'action': ('Block port 6379 at your firewall immediately. '
                       'In redis.conf, add: requirepass <strong-password> and bind 127.0.0.1. '
                       'This is critical — do not delay.')},
    8080:  {'name': 'HTTP Alternate / Admin Panel (unencrypted)',
            'plain': 'A web server or admin panel is running on port 8080, without encryption.',
            'concern': 'MEDIUM',
            'reason': 'Often used for router or device admin panels. Unencrypted like port 80.',
            'action': 'Check if this is a router, NAS, or printer admin panel. Ensure a strong password is set. Switch to HTTPS.'},
    8443:  {'name': 'HTTPS Alternate',
            'plain': 'An encrypted web server or admin panel on a non-standard port.',
            'concern': 'LOW',
            'reason': 'HTTPS on an alternate port. Could be a router admin panel.',
            'action': 'Identify what service this is and verify it belongs to you.'},
    8554:  {'name': 'RTSP Alternate (IP Camera)',
            'plain': 'An alternate streaming port — typically an IP security camera.',
            'concern': 'MEDIUM',
            'reason': 'Same concerns as port 554 — IP cameras frequently have default passwords.',
            'action': 'Change the default password. Block from internet access at your router.'},
    9100:  {'name': 'JetDirect (HP Printer)',
            'plain': 'This is an HP printer or print server accepting print jobs.',
            'concern': 'LOW',
            'reason': 'Printer protocol. Printers are often overlooked for security.',
            'action': 'Check the printer admin panel and change the default password. Keep firmware updated.'},
    9200:  {'name': 'Elasticsearch',
            'plain': 'An Elasticsearch search engine database is accepting connections.',
            'concern': 'HIGH',
            'reason': ('Elasticsearch has no authentication by default. '
                       'Thousands of Elasticsearch instances are exposed publicly with no password — '
                       'many have been involved in major data breaches.'),
            'action': ('Block port 9200 at your firewall immediately. '
                       'Enable Elasticsearch security (xpack.security.enabled: true in elasticsearch.yml). '
                       'This is critical.')},
    27017: {'name': 'MongoDB',
            'plain': 'A MongoDB database is accepting remote connections.',
            'concern': 'HIGH',
            'reason': ('MongoDB has no authentication in its default configuration. '
                       'Has been involved in many large-scale data breaches — '
                       'entire databases have been wiped and ransomed.'),
            'action': ('Block port 27017 at your firewall immediately. '
                       'Enable authentication in mongod.conf: security.authorization: enabled. '
                       'This is critical.')},
    27018: {'name': 'MongoDB (Shard)',
            'plain': 'A MongoDB database shard is accepting connections.',
            'concern': 'HIGH',
            'reason': 'Same as MongoDB port 27017.',
            'action': 'Block at firewall. Enable authentication.'},
}

# ─────────────────────────────── device identification ───────────────────────

_ROUTER_VENDORS = {
    'tp-link', 'netgear', 'd-link', 'asus', 'linksys', 'cisco',
    'ubiquiti', 'mikrotik', 'zyxel', 'huawei', 'tenda', 'belkin',
    'actiontec', 'arris', 'motorola', 'technicolor', 'sagemcom',
    'buffalo', 'edgewater', 'aerohive', 'ruckus', 'unifi',
}
_APPLE_VENDORS = {'apple'}
_SAMSUNG_VENDORS = {'samsung'}
_PRINTER_VENDORS = {'hp', 'hewlett-packard', 'lexmark', 'brother', 'canon', 'epson', 'xerox', 'ricoh', 'kyocera'}
_CAMERA_VENDORS = {'axis', 'hikvision', 'dahua', 'hanwha', 'foscam', 'reolink', 'amcrest', 'uniview'}
_PI_VENDORS = {'raspberry pi'}


def identify_device(os_guess: str, mac_vendor: str, open_ports: list) -> tuple:
    """
    Returns (device_type: str, confidence: str, explanation: str).
    confidence is 'high', 'medium', or 'low'.
    """
    os_l      = os_guess.lower()
    vendor_l  = mac_vendor.lower()
    ports     = set(open_ports)

    # Router / gateway
    if any(v in vendor_l for v in _ROUTER_VENDORS):
        return ('Router / Gateway',
                'high',
                f'The hardware manufacturer ({mac_vendor}) makes networking equipment.')

    if any(x in os_l for x in ('openwrt', 'dd-wrt', 'tomato', 'routeros', 'vyos',
                                'junos', 'ios xr', 'pix firewall', 'asa')):
        return ('Router / Firewall / Network Device',
                'high',
                'Operating system signature matches embedded router or firewall firmware.')

    # IP Camera
    if any(v in vendor_l for v in _CAMERA_VENDORS):
        return ('IP Camera / Security Camera',
                'high',
                f'The hardware manufacturer ({mac_vendor}) makes surveillance cameras.')
    if {554, 8554} & ports and not {22, 445, 3389} & ports:
        return ('IP Camera or Media Streaming Device',
                'medium',
                'RTSP streaming is open with no typical PC services — consistent with an IP camera.')

    # Printer
    if any(v in vendor_l for v in _PRINTER_VENDORS):
        return ('Printer / Print Server',
                'high',
                f'The hardware manufacturer ({mac_vendor}) makes printers.')
    if {515, 631, 9100} & ports:
        return ('Printer / Print Server',
                'high',
                'Standard printer ports (LPD, IPP, JetDirect) are open.')

    # Raspberry Pi
    if any(v in vendor_l for v in _PI_VENDORS):
        return ('Raspberry Pi',
                'high',
                'MAC address is registered to the Raspberry Pi Foundation.')

    # Apple devices
    if any(v in vendor_l for v in _APPLE_VENDORS):
        if {548, 5009} & ports:
            return ('Apple Mac (Desktop/Laptop)',
                    'high',
                    'Apple hardware with Mac-specific services (AFP file sharing, AirPlay).')
        return ('Apple Device (Mac, iPhone, or iPad)',
                'medium',
                'Apple hardware manufacturer — could be any Apple device.')

    # Windows
    if 'windows' in os_l:
        label = 'Windows PC'
        if 3389 in ports:
            label = 'Windows PC or Server (Remote Desktop enabled)'
        if any(x in os_l for x in ('server 2008', 'server 2012', 'server 2016', 'server 2019', 'server 2022')):
            label = 'Windows Server'
        return (label, 'high', f'Operating system identified as {os_guess}.')

    # Linux
    if 'linux' in os_l:
        if {3306, 5432, 27017, 9200} & ports:
            return ('Linux Database Server',
                    'high',
                    'Linux OS with database ports open.')
        if {80, 443} & ports and 22 in ports:
            return ('Linux Web Server',
                    'high',
                    'Linux OS with web server and SSH access.')
        if 22 in ports and len(ports) <= 3:
            return ('Linux Server / Embedded Device',
                    'medium',
                    'Linux OS with minimal exposed services.')
        return ('Linux Device', 'medium', f'Operating system identified as {os_guess}.')

    # NAS / file server
    if {445, 2049} & ports and {80, 443, 22} & ports:
        return ('NAS / File Server',
                'high',
                'File sharing services (SMB/NFS) combined with a web admin panel.')

    # IoT / smart home (many ports 80/443/8080 but no PC services)
    if {80, 8080} & ports and not {22, 445, 3389, 135} & ports:
        return ('Smart Home Device / IoT',
                'low',
                'Web interface present without typical computer services.')

    return ('Unknown Device',
            'low',
            'Not enough information to identify the device type confidently.')


# ─────────────────────────────── traceroute parser ───────────────────────────

_RE_HOP = re.compile(
    r'^\s*(\d+)\s+([\d.]+\s+ms|[\d.]+\s+ms\s+[\d.]+\s+ms\s+[\d.]+\s+ms|\*)\s+(.+)?',
    re.M
)
_RE_TRACERT_LINE = re.compile(
    r'TRACEROUTE.*?(?=Nmap done|\Z)', re.S
)
_RE_HOP_SIMPLE = re.compile(
    r'^\s+(\d+)\s+[\d.]+\s+ms\s+(.+)', re.M
)


def parse_traceroute(output: str) -> list:
    """
    Returns list of (hop_num, address) tuples from nmap --traceroute output.
    """
    hops = []
    # nmap traceroute format: "  1   1.23 ms  192.168.1.1"
    for m in _RE_HOP_SIMPLE.finditer(output):
        hop_num = int(m.group(1))
        addr    = m.group(2).strip()
        if addr and addr != '*':
            hops.append((hop_num, addr))
    return hops


def build_topology(hosts: list, hops: list, gateway_hint: str = '') -> str:
    """
    Build a text network topology display from discovered hosts and traceroute data.
    """
    lines = []

    if hops:
        lines.append('Network Path (how traffic travels)')
        lines.append('─' * 44)
        lines.append('  [ You ]')
        for hop_num, addr in hops:
            lines.append(f'      │')
            hop_label = f'Hop {hop_num}: {addr}'
            if hop_num == 1 or (gateway_hint and addr == gateway_hint):
                hop_label += '  ← your gateway/router'
            lines.append(f'      ▼  {hop_label}')
        lines.append(f'      │')
        lines.append(f'      ▼  [ Destination ]')
        lines.append('')

    if hosts:
        lines.append(f'Discovered Devices  ({len(hosts)} active)')
        lines.append('─' * 44)
        for h in hosts:
            # Mark likely gateway (.1 or .254 addresses)
            last_octet = h.rsplit('.', 1)[-1] if '.' in h else ''
            note = ''
            if last_octet in ('1', '254'):
                note = '  ← likely gateway/router'
            lines.append(f'  • {h}{note}')

    return '\n'.join(lines) if lines else ''


# ──────────────────────────────── issue detection ────────────────────────────

def detect_issues(output: str, args: list, target: str, parsed: dict) -> list:
    """
    Detect when a scan did not produce useful results and suggest fixes.
    Returns list of dicts: {issue, why, fix, command}
    """
    issues  = []
    out_low = output.lower()
    args_str = ' '.join(args)

    # Host blocked ping / appears down
    if 'host seems down' in out_low or 'note: host seems down' in out_low:
        fixed_args = [a for a in args if a not in ('-PE', '-PP', '-PS', '-PA')]
        fixed_cmd  = 'nmap -Pn ' + ' '.join(fixed_args) + ' ' + target
        issues.append({
            'issue': 'Target appears offline — but it may just be blocking pings',
            'why':   ('nmap sends an ICMP ping before scanning to check if a host is up. '
                      'Many firewalls and devices block ICMP pings entirely, '
                      'which causes nmap to assume the host is down and skip the scan.'),
            'fix':   'Add -Pn to skip the ping check and scan anyway.',
            'command': fixed_cmd,
        })

    # No results at all
    if '0 hosts up' in out_low and parsed.get('hosts') == []:
        issues.append({
            'issue': 'No devices found — the network range may be wrong',
            'why':   'The scan returned zero results. This usually means the target range is incorrect, or all devices are blocking pings.',
            'fix':   'Verify your network range. On Windows run: ipconfig. On Linux/Mac: ip addr or ifconfig. Look for your IP and subnet mask.',
            'command': f'nmap -sn -PR {target}  (ARP scan — more reliable on local networks)',
        })

    # No open ports but host is alive
    if not parsed.get('open_ports') and parsed.get('hosts') and 'filtered' not in out_low:
        issues.append({
            'issue': 'Host is alive but no open ports found on the scanned range',
            'why':   ('The host responded to ping but no open ports were found. '
                      'Services may be running on non-standard ports, or a firewall may be blocking the probe packets.'),
            'fix':   'Scan all 65,535 ports to look for services on non-standard ports.',
            'command': f'nmap -p- -T4 {target}',
        })

    # Heavy filtering
    filtered = out_low.count('filtered')
    if filtered > 15:
        issues.append({
            'issue': f'Many ports appear filtered ({filtered} filtered ports detected)',
            'why':   ('A firewall is dropping the scan packets without responding. '
                      'The ports might be open, but the firewall is hiding them. '
                      'This is common on cloud servers and corporate networks.'),
            'fix':   'Try a SYN scan (requires running as administrator/root). Or scan from inside the network.',
            'command': f'nmap -sS -T4 {target}  (requires administrator / root)',
        })

    # OS detection failed
    if '-O' in args and 'os details' not in out_low and 'running:' not in out_low and 'os cpe' not in out_low:
        issues.append({
            'issue': 'OS detection could not identify the operating system',
            'why':   ('OS detection requires at least one open and one closed port, '
                      'and may require administrator/root privileges to send raw packets. '
                      'Some hardened systems actively prevent OS fingerprinting.'),
            'fix':   'Run as administrator and add --osscan-guess to accept the best guess even with low confidence.',
            'command': f'nmap -O --osscan-guess -T4 {target}  (run as administrator)',
        })

    # Vuln scripts returned nothing useful
    if '--script' in args_str and 'vuln' in args_str:
        if not parsed.get('cves') and not parsed.get('vuln_states') and parsed.get('open_ports'):
            issues.append({
                'issue': 'Vulnerability scripts completed but found no known CVEs',
                'why':   ('This is generally positive — the services may be patched. '
                          'However, nmap vulnerability scripts only check for issues they have scripts for. '
                          'A clean result does not mean a system is fully secure.'),
                'fix':   'For a deeper check, run specific targeted scripts or use a dedicated scanner like OpenVAS.',
                'command': (f'nmap --script "vuln and not dos and not brute" '
                            f'-sV -T4 -p {",".join(str(p) for p in parsed["open_ports"])} {target}'),
            })

    # Scan timed out
    if 'timed out' in out_low or 'timeout' in out_low:
        issues.append({
            'issue': 'Scan timed out',
            'why':   'The scan ran too long — this often happens with full-port scans or slow targets.',
            'fix':   'Reduce the port range or increase the timing. T4 is usually good; T3 is more reliable on slow networks.',
            'command': f'nmap -F -T3 {target}  (top 100 ports, slower/more reliable timing)',
        })

    return issues


# ──────────────────────────────── next-step recommender ──────────────────────

_HIGH_RISK_SVCS = {'telnet', 'ftp', 'vnc', 'rdp', 'microsoft-ds', 'rsh', 'rlogin',
                   'redis', 'mongodb', 'mysql', 'postgresql', 'elasticsearch'}


def recommend_next(parsed: dict, target: str, current_args: list,
                   profile_id: str) -> list:
    """
    Recommend the most useful next scan actions based on results so far.
    Returns list (up to 3) of dicts: {reason, label, command, command_list}
    """
    recs       = []
    args_str   = ' '.join(current_args)
    ports      = parsed.get('open_ports', [])
    services   = parsed.get('services', [])   # list of (port, proto, svc, ver)
    hosts      = parsed.get('hosts', [])
    warnings   = parsed.get('warnings', [])

    ports_str  = ','.join(str(p) for p in sorted(ports)) if ports else ''

    # ── Have ports but no service versions
    has_versions = any(ver for _, _, _, ver in services if ver and ver not in
                       ('', 'tcpwrapped', 'unknown'))
    if ports and not has_versions and '-sV' not in args_str:
        recs.append({
            'reason': (f'{len(ports)} open port(s) found but the software running on them is not identified yet. '
                       'Knowing the exact version is needed to check for vulnerabilities.'),
            'label':  'Identify software on open ports',
            'command': f'nmap -sV -T4 -p {ports_str} {target}',
            'command_list': ['nmap', '-sV', '-T4', '-p', ports_str, target],
        })

    # ── Have versions but no vuln check
    if has_versions and '--script' not in args_str and 'vuln' not in args_str:
        recs.append({
            'reason': ('Software versions are identified — the next step is to check them '
                       'against the database of known vulnerabilities (CVEs).'),
            'label':  'Check for known vulnerabilities (CVE scan)',
            'command': f'nmap -sV --script vuln -T4 -p {ports_str} {target}',
            'command_list': ['nmap', '-sV', '--script', 'vuln', '-T4', '-p', ports_str, target],
        })

    # ── High-risk services found
    risky = [(str(p), s) for p, _, s, _ in services if s.lower() in _HIGH_RISK_SVCS]
    if risky:
        risky_ports = ','.join(r[0] for r in risky)
        risky_names = ', '.join(f'{r[1]}({r[0]})' for r in risky[:3])
        recs.append({
            'reason': (f'High-risk service(s) detected: {risky_names}. '
                       'These should be tested for default credentials and misconfigurations.'),
            'label':  'Test for default credentials on risky services',
            'command': f'nmap --script default,auth -sV -T4 -p {risky_ports} {target}',
            'command_list': ['nmap', '--script', 'default,auth', '-sV', '-T4',
                             '-p', risky_ports, target],
        })

    # ── Only common ports scanned, suggest full scan
    if ports and len(ports) < 10 and '-p-' not in args_str:
        recs.append({
            'reason': (f'Only {len(ports)} port(s) found in the common port range. '
                       'Services on non-standard ports (above 1024) would be missed by this scan.'),
            'label':  'Scan ALL ports to find hidden services',
            'command': f'nmap -p- -T4 {target}',
            'command_list': ['nmap', '-p-', '-T4', target],
        })

    # ── Multiple hosts found — suggest scanning them
    if hosts and len(hosts) > 1 and not ports:
        hosts_str = ' '.join(hosts[:10])
        recs.append({
            'reason': (f'{len(hosts)} active device(s) found. '
                       'The next step is to check what services each device is running.'),
            'label':  'Scan common ports on all discovered devices',
            'command': f'nmap -F -T4 {hosts_str}',
            'command_list': ['nmap', '-F', '-T4'] + hosts[:10],
        })

    # ── No recommendations formed — offer a general next step
    if not recs and ports:
        recs.append({
            'reason': ('The scan found open ports. A full aggressive scan will gather '
                       'OS fingerprint, service versions, and run default scripts in one pass.'),
            'label':  'Run a full detailed scan (-A)',
            'command': f'nmap -A -T4 -p {ports_str} {target}',
            'command_list': ['nmap', '-A', '-T4', '-p', ports_str, target],
        })

    return recs[:3]


# ──────────────────────────────── main explainer ─────────────────────────────

def explain_results(parsed: dict, output: str, step_args: list,
                    target: str, parse_mode: str) -> dict:
    """
    Full plain-English interpretation of one nmap step result.

    Returns:
        port_details  – list of dicts, one per open port
        device_ids    – list of dicts, one per discovered host
        topology      – str (text map)
        issues        – list of dicts (scan problems + fixes)
        recommendations – list of dicts (next-step suggestions)
    """
    port_details = []
    for port, proto, svc, ver in parsed.get('services', []):
        info = PORT_INFO.get(port)
        if not info:
            # Try common name match
            svc_l = svc.lower()
            info = next(
                (v for v in PORT_INFO.values()
                 if svc_l and svc_l in v['name'].lower()),
                None
            )

        detail: dict = {
            'port':    port,
            'proto':   proto,
            'service': svc,
            'version': ver,
        }
        if info:
            detail['name']    = info['name']
            detail['plain']   = info['plain']
            detail['concern'] = info['concern']
            detail['reason']  = info['reason']
            detail['action']  = info['action']
        else:
            detail['name']    = svc.upper() if svc else f'Port {port}'
            detail['plain']   = (f'A service called "{svc}" is running on port {port}. '
                                 f'This port is not in the known-port database — '
                                 f'check the Protocol Library tab to look it up or add it.')
            detail['concern'] = 'UNKNOWN'
            detail['reason']  = 'Port not found in built-in knowledge base.'
            detail['action']  = (f'Search for "{svc} port {port}" to understand what this service is. '
                                 f'If it is unexpected on this device, investigate.')

        if ver:
            detail['plain'] += f'\n    Running: {ver}'

        port_details.append(detail)

    # Device identification — one entry per discovered host
    device_ids = []
    # Extract MAC vendor hints from nmap output (e.g. "MAC Address: AA:BB:CC (TP-Link)")
    mac_vendors: dict = {}
    for m in re.finditer(r'MAC Address: [0-9A-F:]+\s+\(([^)]+)\)', output, re.I):
        # Associate with the most recently mentioned IP
        vendor = m.group(1)
        # Find the IP just before this line
        pos = m.start()
        prev_chunk = output[:pos]
        ip_m = re.findall(r'(\d{1,3}(?:\.\d{1,3}){3})', prev_chunk)
        if ip_m:
            mac_vendors[ip_m[-1]] = vendor

    os_per_host: dict = {}
    for m in re.finditer(
            r'Nmap scan report for (?:.+ \()?(\d[\d.]+)\)?\n.*?(?:OS details?: ([^\n]+))?',
            output, re.S):
        ip = m.group(1)
        os_guess = m.group(2) or ''
        os_per_host[ip] = os_guess.strip()

    for host in parsed.get('hosts', []):
        os_guess = os_per_host.get(host, '')
        vendor   = mac_vendors.get(host, '')
        host_ports = parsed.get('open_ports', [])  # if host scan, use all
        dtype, conf, why = identify_device(os_guess, vendor, host_ports)
        device_ids.append({
            'ip':         host,
            'type':       dtype,
            'confidence': conf,
            'why':        why,
            'os':         os_guess,
            'vendor':     vendor,
        })

    # If no host-discovery but we have a target and services, do single-host ID
    if not device_ids and parsed.get('services'):
        # Extract OS from output
        os_m = re.search(r'OS details?: (.+)', output)
        os_guess = os_m.group(1).strip() if os_m else ''
        vendor_m = re.search(r'MAC Address: [0-9A-F:]+\s+\(([^)]+)\)', output, re.I)
        vendor = vendor_m.group(1) if vendor_m else ''
        dtype, conf, why = identify_device(os_guess, vendor, parsed.get('open_ports', []))
        device_ids.append({
            'ip': target, 'type': dtype, 'confidence': conf,
            'why': why, 'os': os_guess, 'vendor': vendor,
        })

    # Topology
    hops     = parse_traceroute(output)
    gateway  = ''
    if parsed.get('hosts'):
        for h in parsed['hosts']:
            last = h.rsplit('.', 1)[-1]
            if last in ('1', '254'):
                gateway = h
                break
    topology = build_topology(parsed.get('hosts', []), hops, gateway)

    # Issues and recommendations
    issues  = detect_issues(output, step_args, target, parsed)
    recs    = recommend_next(parsed, target, step_args, '')

    return {
        'port_details':    port_details,
        'device_ids':      device_ids,
        'topology':        topology,
        'issues':          issues,
        'recommendations': recs,
    }
