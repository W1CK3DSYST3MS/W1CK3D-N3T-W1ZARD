import collections
import ipaddress
import math
import socket
from .base import Analyzer, Finding


def get_local_ips():
    """Best-effort set of this machine's own IPv4 addresses (all interfaces).

    Used to recognise the computer running this tool, so that scans launched
    from this machine (e.g. the built-in nmap scan tools) are not flagged as a
    hostile port scan / network sweep. Never raises.
    """
    ips = {'127.0.0.1'}
    try:
        host = socket.gethostname()
        try:
            ips.update(socket.gethostbyname_ex(host)[2])
        except Exception:
            pass
        # Primary outbound interface IP (UDP connect sends no packets).
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect(('8.8.8.8', 80))
                ips.add(s.getsockname()[0])
            finally:
                s.close()
        except Exception:
            pass
    except Exception:
        pass
    return {ip for ip in ips if ip}


def _shannon_entropy(s):
    if not s:
        return 0.0
    counts = collections.Counter(s.lower())
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _is_private(ip_str):
    try:
        return ipaddress.ip_address(ip_str).is_private
    except ValueError:
        return False


def _is_global(ip_str):
    try:
        return ipaddress.ip_address(ip_str).is_global
    except ValueError:
        return False


class ThreatAnalyzer(Analyzer):
    name = 'threats'

    def __init__(self):
        self._findings = []
        self._seen_keys = set()

        # Port / network scan tracking
        self._syn_ports = collections.defaultdict(set)   # src_ip -> {dst_port}
        self._syn_hosts = collections.defaultdict(set)   # src_ip -> {dst_ip}
        self._syn_counts = collections.Counter()          # src_ip -> total SYNs

        # Beaconing: (src_ip, dst_ip, dst_port) -> [timestamps]
        self._beacon_times = collections.defaultdict(list)

        # Large outbound transfers: (src_ip, dst_ip) -> bytes
        self._transfer_bytes = collections.defaultdict(int)

        # ARP: ip -> set of MACs (tracked independently so ThreatAnalyzer is self-contained)
        self._arp_claims = collections.defaultdict(set)

        # LLMNR / NBT-NS: dedupe per source MAC
        self._llmnr_macs = set()
        self._nbns_macs = set()

        # Weak TLS: dedupe per version string
        self._weak_tls_seen = set()

        # Insecure protocol ports: dedupe per (src_mac, port)
        self._insecure_proto_seen = set()

    def _emit(self, finding):
        key = (finding.severity, finding.category, finding.title, finding.device_mac)
        if key not in self._seen_keys:
            self._seen_keys.add(key)
            self._findings.append(finding)

    def _src_mac(self, pkt):
        try:
            return pkt.eth.src
        except AttributeError:
            return None

    def process_packet(self, pkt):
        try:
            self._check_credentials(pkt)
        except Exception:
            pass
        try:
            self._check_insecure_protocols(pkt)
        except Exception:
            pass
        try:
            self._check_weak_tls(pkt)
        except Exception:
            pass
        try:
            self._check_llmnr_nbns(pkt)
        except Exception:
            pass
        try:
            self._check_arp(pkt)
        except Exception:
            pass
        try:
            self._check_dns(pkt)
        except Exception:
            pass
        try:
            self._track_syn(pkt)
        except Exception:
            pass
        try:
            self._track_beacon(pkt)
        except Exception:
            pass
        try:
            self._track_transfer(pkt)
        except Exception:
            pass

    # ---------------------------------------------------------------- credentials
    def _check_credentials(self, pkt):
        if not hasattr(pkt, 'http'):
            return
        auth = getattr(pkt.http, 'authorization', None)
        if auth and auth.lower().startswith('basic '):
            mac = self._src_mac(pkt)
            self._emit(Finding(
                severity='high',
                category='credentials',
                title='Plaintext HTTP Basic Authentication',
                description=(
                    'A device sent a username and password in plain text over HTTP. '
                    'Anyone on the same network who can capture traffic — including '
                    'another device on the same Wi-Fi — can read those credentials.'
                ),
                technical=f'HTTP Authorization header observed (Basic scheme)',
                device_mac=mac,
                recommendation=(
                    '1. Identify the device or service making this request (see Affected device).\n'
                    '2. Log into its admin panel and find the HTTPS or TLS setting.\n'
                    '3. Enable HTTPS — most modern routers and NAS devices support it built-in.\n'
                    '4. For websites or internal tools, install a free TLS certificate via '
                    'Let\'s Encrypt (letsencrypt.org).\n'
                    '5. Once HTTPS is active, configure it to redirect all HTTP traffic '
                    'automatically so credentials are always encrypted.'
                ),
                evidence={'auth_preview': auth[:80]},
            ))

        ftp_cmd = getattr(getattr(pkt, 'ftp', None), 'request_command', None)
        if ftp_cmd and ftp_cmd.upper() in ('USER', 'PASS'):
            mac = self._src_mac(pkt)
            self._emit(Finding(
                severity='high',
                category='credentials',
                title='Plaintext FTP Credentials',
                description=(
                    'FTP transmits usernames and passwords with no encryption. '
                    'Any device on the network path can capture and replay them.'
                ),
                technical='FTP USER or PASS command observed in plain text',
                device_mac=mac,
                recommendation=(
                    '1. Identify the device or software using FTP (see Affected device).\n'
                    '2. Switch to SFTP (port 22) — it encrypts both credentials and file data.\n'
                    '   - Windows: FileZilla or WinSCP both support SFTP for free.\n'
                    '   - NAS / server: enable the SSH/SFTP service in the admin panel.\n'
                    '3. Alternatively, use FTPS (FTP over TLS) on port 990.\n'
                    '4. Once the secure alternative is working, disable plain FTP on the server.'
                ),
                evidence={'ftp_command': ftp_cmd},
            ))

    # ------------------------------------------------------- insecure protocols
    _INSECURE_PORTS = {
        23:  ('Telnet in Use',
              'Telnet sends everything — including passwords — in plain text. '
              'Anyone on the network can read the session.',
              '1. Identify the device using Telnet (see Affected device).\n'
              '2. Log into it via its web interface or local console.\n'
              '3. Find Remote Access or Management settings and enable SSH.\n'
              '4. Disable Telnet — it is usually a toggle in the same settings area.\n'
              '5. Connect in future using an SSH client: PuTTY (Windows) or Terminal (macOS/Linux).',
              'protocol'),
        21:  ('FTP in Use',
              'FTP transfers files and credentials without any encryption.',
              '1. Identify the device or software using FTP (see Affected device).\n'
              '2. Switch to SFTP (port 22) — it is encrypted and supported everywhere.\n'
              '   - Windows: FileZilla or WinSCP both support SFTP for free.\n'
              '3. Alternatively, use FTPS (FTP over TLS) on port 990.\n'
              '4. Update any scripts or scheduled tasks that reference FTP.\n'
              '5. Disable plain FTP on the server once SFTP is confirmed working.',
              'protocol'),
        69:  ('TFTP in Use',
              'TFTP (Trivial FTP) has no authentication or encryption and is '
              'sometimes abused by attackers to stage payloads.',
              '1. Check whether TFTP is intentionally in use (some printers and '
              'network equipment use it for firmware updates).\n'
              '2. If not intentional, find which device is running a TFTP server '
              'and disable it.\n'
              '   - Windows: open Services (services.msc) and stop/disable '
              '"Trivial FTP Daemon".\n'
              '   - Network equipment: disable TFTP in admin settings.\n'
              '3. If TFTP is required, add a firewall rule to restrict it to '
              'known hosts only.',
              'protocol'),
        110: ('POP3 Email in Plain Text',
              'POP3 without encryption exposes your email and password to anyone '
              'on the network path.',
              '1. Open your email client\'s account settings.\n'
              '2. Change the incoming mail server port from 110 to 995.\n'
              '3. Set the connection security to SSL/TLS.\n'
              '4. Save and test — you should still receive email normally.\n'
              '5. If using webmail only, contact your provider — most now block '
              'unencrypted access by default.',
              'protocol'),
        143: ('IMAP Email in Plain Text',
              'IMAP without encryption exposes your email and password.',
              '1. Open your email client\'s account settings.\n'
              '2. Change the incoming mail server port from 143 to 993.\n'
              '3. Set connection security to SSL/TLS.\n'
              '4. Save and test — the setting is usually labelled "Secure '
              'Connection" or "Encryption".\n'
              '5. Most providers (Gmail, Outlook, etc.) now require TLS '
              'and will reject plain IMAP connections.',
              'protocol'),
        513: ('rlogin in Use',
              'rlogin is a 1980s remote-login protocol with no encryption. '
              'It was officially deprecated in favor of SSH.',
              '1. Identify the device using rlogin (see Affected device).\n'
              '2. Ensure an SSH server is installed and running on that device.\n'
              '3. Disable rlogin on Linux: '
              'sudo systemctl disable rlogin && sudo systemctl stop rlogin\n'
              '4. On network equipment: disable rlogin in the remote access settings.\n'
              '5. Replace all rlogin usage with SSH: ssh user@<device-ip>',
              'protocol'),
        514: ('rsh (Remote Shell) in Use',
              'rsh provides remote shell access with no encryption and minimal '
              'authentication.',
              '1. Identify the device using rsh (see Affected device).\n'
              '2. Ensure SSH is installed and running on that device.\n'
              '3. Disable rsh on Linux: '
              'sudo systemctl disable rsh && sudo systemctl stop rsh\n'
              '4. Replace all rsh usage with SSH commands: ssh user@<device-ip>',
              'protocol'),
    }

    def _check_insecure_protocols(self, pkt):
        dst_port = None
        try:
            dst_port = int(pkt.tcp.dstport)
        except Exception:
            try:
                dst_port = int(pkt.udp.dstport)
            except Exception:
                pass

        mac = self._src_mac(pkt)

        if dst_port in self._INSECURE_PORTS:
            key = (mac, dst_port)
            if key not in self._insecure_proto_seen:
                self._insecure_proto_seen.add(key)
                title, desc, rec, cat = self._INSECURE_PORTS[dst_port]
                self._emit(Finding(
                    severity='medium',
                    category=cat,
                    title=title,
                    description=desc,
                    technical=f'Traffic observed on port {dst_port}',
                    device_mac=mac,
                    recommendation=rec,
                    evidence={'port': dst_port},
                ))

        # SMBv1 detection
        if hasattr(pkt, 'smb') and not hasattr(pkt, 'smb2'):
            key = (mac, 'smb1')
            if key not in self._insecure_proto_seen:
                self._insecure_proto_seen.add(key)
                self._emit(Finding(
                    severity='medium',
                    category='protocol',
                    title='SMBv1 Protocol in Use',
                    description=(
                        'SMBv1 is an obsolete file-sharing protocol with serious '
                        'security flaws. It was the attack vector for the WannaCry '
                        'and NotPetya ransomware outbreaks.'
                    ),
                    technical='SMBv1 traffic observed (no SMB2/3 layer present)',
                    device_mac=mac,
                    recommendation=(
                        '1. On each Windows computer, open PowerShell as Administrator and run:\n'
                        '   Set-SmbServerConfiguration -EnableSMB1Protocol $false\n'
                        '2. Also disable it via Windows Features:\n'
                        '   Control Panel → Programs → Turn Windows features on or off\n'
                        '   → Uncheck "SMB 1.0/CIFS File Sharing Support" → OK → Restart.\n'
                        '3. Check all devices on the network — NAS drives and older printers '
                        'may also advertise SMBv1.\n'
                        '4. If an old device requires SMBv1, isolate it on a separate network '
                        'segment so it cannot reach other computers.'
                    ),
                    evidence={'protocol': 'SMBv1'},
                ))

    # ----------------------------------------------------------------- weak TLS
    _WEAK_TLS = {
        '0x0300': ('SSLv3', 'critical'),
        '0x0301': ('TLS 1.0', 'medium'),
        '0x0302': ('TLS 1.1', 'medium'),
    }

    def _check_weak_tls(self, pkt):
        if not hasattr(pkt, 'tls'):
            return
        version = getattr(pkt.tls, 'record_version', None) or \
                  getattr(pkt.tls, 'handshake_version', None)
        if not version or version not in self._WEAK_TLS:
            return
        if version in self._weak_tls_seen:
            return
        self._weak_tls_seen.add(version)
        ver_name, severity = self._WEAK_TLS[version]
        mac = self._src_mac(pkt)
        self._emit(Finding(
            severity=severity,
            category='protocol',
            title=f'Weak TLS Version in Use: {ver_name}',
            description=(
                f'{ver_name} is an outdated encryption protocol with known cryptographic '
                f'weaknesses. An attacker in a position to intercept traffic (e.g., on '
                f'the same Wi-Fi) may be able to downgrade or decrypt the connection.'
            ),
            technical=f'TLS version field: {version} ({ver_name})',
            device_mac=mac,
            recommendation=(
                '1. Identify the server or service using old TLS '
                '(see Affected device and Technical detail).\n'
                '2. Update the software running that service to a current version.\n'
                '3. Windows IIS: download the free IIS Crypto tool (nartac.com/Products/IISCrypto),'
                ' apply the "Best Practices" template, and restart IIS.\n'
                '4. Apache: add to ssl.conf:  SSLProtocol -all +TLSv1.2 +TLSv1.3\n'
                '5. Nginx: set in your server block:  ssl_protocols TLSv1.2 TLSv1.3;\n'
                '6. Test the result at: https://www.ssllabs.com/ssltest/'
            ),
            evidence={'tls_version_field': version, 'version_name': ver_name},
        ))

    # --------------------------------------------------- LLMNR / NetBIOS (NBT-NS)
    def _check_llmnr_nbns(self, pkt):
        mac = self._src_mac(pkt)

        if hasattr(pkt, 'udp'):
            dport = getattr(pkt.udp, 'dstport', None)
            if dport == '5355' and mac and mac not in self._llmnr_macs:
                self._llmnr_macs.add(mac)
                self._emit(Finding(
                    severity='low',
                    category='network',
                    title='LLMNR Name Resolution in Use',
                    description=(
                        'LLMNR (Link-Local Multicast Name Resolution) is a Windows '
                        'fallback name resolution protocol that broadcasts queries on the '
                        'local network. A tool like Responder can answer these queries '
                        'with a fake reply and capture Windows NTLM credential hashes '
                        'without any interaction from the victim.'
                    ),
                    technical='LLMNR query observed on UDP port 5355',
                    device_mac=mac,
                    recommendation=(
                        '1. Open the Group Policy Editor: press Win+R, type gpedit.msc, press Enter.\n'
                        '2. Navigate to:\n'
                        '   Computer Configuration → Administrative Templates\n'
                        '   → Network → DNS Client\n'
                        '3. Double-click "Turn off multicast name resolution" '
                        '→ set to Enabled → OK.\n'
                        '4. On a domain network: deploy this as a Group Policy Object (GPO) '
                        'to cover all computers at once.\n'
                        '5. Restart affected computers for the change to take effect.\n'
                        '6. Also consider disabling NetBIOS over TCP/IP (see any '
                        'NetBIOS finding for steps).'
                    ),
                    evidence={'protocol': 'LLMNR', 'port': 5355},
                ))
            if dport == '137' and mac and mac not in self._nbns_macs:
                self._nbns_macs.add(mac)
                self._emit(Finding(
                    severity='low',
                    category='network',
                    title='NetBIOS Name Service (NBT-NS) in Use',
                    description=(
                        'NetBIOS Name Service is a legacy Windows broadcast name '
                        'resolution protocol. Like LLMNR, it can be spoofed by Responder '
                        'to capture NTLM credential hashes from any Windows device that '
                        'tries to resolve a name on the network.'
                    ),
                    technical='NBT-NS query on UDP port 137',
                    device_mac=mac,
                    recommendation=(
                        '1. Open Network Connections: press Win+R → type ncpa.cpl → Enter.\n'
                        '2. Right-click your network adapter → Properties.\n'
                        '3. Select "Internet Protocol Version 4 (TCP/IPv4)" → Properties.\n'
                        '4. Click Advanced → WINS tab → '
                        'select "Disable NetBIOS over TCP/IP" → OK.\n'
                        '5. Repeat for every network adapter on every Windows computer.\n'
                        '6. For bulk rollout: push via DHCP scope option 001 (value 0x2) '
                        'so all devices on the network are covered automatically.'
                    ),
                    evidence={'protocol': 'NBT-NS', 'port': 137},
                ))

    # ---------------------------------------------------------------- ARP spoofing
    def _check_arp(self, pkt):
        if not hasattr(pkt, 'arp'):
            return
        op = getattr(pkt.arp, 'opcode', None)
        if op not in ('2', '0x00000002'):
            return
        claimed_ip = getattr(pkt.arp, 'src_proto_ipv4', None)
        sender_mac = getattr(pkt.arp, 'src_hw_mac', None)
        if claimed_ip and sender_mac:
            self._arp_claims[claimed_ip].add(sender_mac)

    # ----------------------------------------------------------------- DNS checks
    def _check_dns(self, pkt):
        if not hasattr(pkt, 'dns'):
            return
        if getattr(pkt.dns, 'flags_response', '1') != '0':
            return
        name = getattr(pkt.dns, 'qry_name', None)
        if not name:
            return
        mac = self._src_mac(pkt)
        labels = name.split('.')

        for label in labels[:-1]:
            if len(label) > 40:
                self._emit(Finding(
                    severity='medium',
                    category='dns',
                    title='Possible DNS Tunneling / Data Exfiltration',
                    description=(
                        'An unusually long DNS query label was detected. Attackers encode '
                        'data in DNS queries to exfiltrate files or maintain covert '
                        'command-and-control channels — DNS traffic passes through most '
                        'firewalls without inspection.'
                    ),
                    technical=f'Query: {name[:120]}, label length: {len(label)} chars',
                    device_mac=mac,
                    recommendation=(
                        '1. Identify the source device using the IP in Technical detail.\n'
                        '2. Run a full malware scan on that device '
                        '(Windows Defender + Malwarebytes free).\n'
                        '3. Block the destination domain at your DNS resolver:\n'
                        '   - Pi-hole: add to block list.\n'
                        '   - Router: add to DNS blacklist if supported.\n'
                        '   - Windows hosts file: add  0.0.0.0 <domain>  to\n'
                        '     C:\\Windows\\System32\\drivers\\etc\\hosts\n'
                        '4. Monitor for repeat queries — if they continue after blocking, '
                        'the malware is likely still active.\n'
                        '5. If infection is confirmed, isolate the device and '
                        'consider a full OS reinstall.'
                    ),
                    evidence={'query': name[:200], 'long_label_len': len(label)},
                ))
                break

        if len(labels) >= 2:
            subdomain = labels[0]
            if len(subdomain) >= 10:
                entropy = _shannon_entropy(subdomain)
                if entropy > 3.8:
                    self._emit(Finding(
                        severity='medium',
                        category='dns',
                        title='High-Entropy DNS Subdomain — Possible DGA Malware',
                        description=(
                            'A DNS query contained a highly random-looking subdomain. '
                            'Malware often generates random domain names (Domain '
                            'Generation Algorithms) to reach command-and-control servers '
                            'while evading static blacklists.'
                        ),
                        technical=(
                            f'Query: {name[:120]}, subdomain: {subdomain}, '
                            f'Shannon entropy: {entropy:.2f}'
                        ),
                        device_mac=mac,
                        recommendation=(
                            '1. Run a full antivirus and malware scan on the source '
                            'device immediately.\n'
                            '2. Open Task Manager → look for unfamiliar processes '
                            'with high network usage.\n'
                            '3. Block the queried domain at your router\'s DNS settings '
                            'or via Pi-hole.\n'
                            '4. Check recently installed programs for anything you '
                            'did not install yourself.\n'
                            '5. If queries continue after scanning, run Malwarebytes '
                            '(free) for a second opinion.\n'
                            '6. If infection is confirmed: isolate the device and '
                            'consider a full OS reinstall to ensure it is clean.'
                        ),
                        evidence={
                            'query': name[:200],
                            'subdomain': subdomain,
                            'entropy': round(entropy, 3),
                        },
                    ))

    # -------------------------------------------- port / network scan tracking
    def _track_syn(self, pkt):
        if not hasattr(pkt, 'tcp') or not hasattr(pkt, 'ip'):
            return
        try:
            flags = int(pkt.tcp.flags, 16)
        except (ValueError, TypeError, AttributeError):
            return
        if not (flags & 0x02) or (flags & 0x10):  # SYN but not SYN-ACK
            return
        src_ip = pkt.ip.src
        dst_ip = pkt.ip.dst
        dst_port = getattr(pkt.tcp, 'dstport', None)
        if src_ip and dst_port:
            self._syn_counts[src_ip] += 1
            self._syn_ports[src_ip].add(dst_port)
            if dst_ip:
                self._syn_hosts[src_ip].add(dst_ip)

    # ------------------------------------------------- beaconing packet tracking
    def _track_beacon(self, pkt):
        if not hasattr(pkt, 'tcp') or not hasattr(pkt, 'ip'):
            return
        try:
            flags = int(pkt.tcp.flags, 16)
        except (ValueError, TypeError, AttributeError):
            return
        if not (flags & 0x02) or (flags & 0x10):
            return
        src_ip = pkt.ip.src
        dst_ip = pkt.ip.dst
        dst_port = getattr(pkt.tcp, 'dstport', None)
        try:
            ts = float(pkt.sniff_timestamp)
        except Exception:
            return
        key = (src_ip, dst_ip, dst_port)
        times = self._beacon_times[key]
        if len(times) < 200:  # cap memory per connection tuple
            times.append(ts)

    # --------------------------------------------- outbound transfer tracking
    def _track_transfer(self, pkt):
        if not hasattr(pkt, 'ip'):
            return
        src_ip = pkt.ip.src
        dst_ip = pkt.ip.dst
        if not (_is_private(src_ip) and _is_global(dst_ip)):
            return
        try:
            self._transfer_bytes[(src_ip, dst_ip)] += int(pkt.length)
        except Exception:
            pass

    # ============================================================== finalize
    def finalize(self, context=None):
        device_a = context.get('devices_raw') if context else None
        # This machine's own IPs — so scans WE launched aren't flagged as attacks.
        local_ips = set((context or {}).get('local_ips') or []) or get_local_ips()

        def _mac_for_ip(ip):
            if not device_a:
                return None
            for mac, dev in device_a._devices.items():
                if ip in (dev.get('ip_addresses') or []):
                    return mac
            return None

        # ARP spoofing
        for ip, macs in self._arp_claims.items():
            if len(macs) > 1:
                self._emit(Finding(
                    severity='critical',
                    category='network',
                    title='ARP Spoofing / Possible Man-in-the-Middle Attack',
                    description=(
                        f'Multiple MAC addresses are claiming to be {ip}. In a normal '
                        'network, each IP belongs to exactly one device. When multiple '
                        'MACs claim the same IP, it usually means one device is '
                        'impersonating another — the classic "ARP poisoning" technique '
                        'used to intercept all traffic meant for the victim device, '
                        'including router traffic.'
                    ),
                    technical=f'IP {ip} claimed by MACs: {", ".join(sorted(macs))}',
                    device_mac=None,
                    recommendation=(
                        '1. Stop using this network immediately — all traffic '
                        'may be visible to the attacker.\n'
                        '2. Check your router\'s connected devices or ARP table '
                        'to identify which device has the unexpected MAC address.\n'
                        '3. Disconnect the suspicious device from the network.\n'
                        '4. Run a full antivirus/malware scan on all devices '
                        'that were active during this capture.\n'
                        '5. Change passwords for any accounts used on this network '
                        '(email, banking, work logins).\n'
                        '6. Long-term: enable Dynamic ARP Inspection (DAI) on managed switches.\n'
                        '7. Add a static ARP entry for your gateway/router to prevent '
                        'future poisoning: arp -s <gateway-ip> <gateway-mac>'
                    ),
                    evidence={'ip': ip, 'claiming_macs': sorted(macs)},
                ))

        # Port / network scans
        for src_ip, count in self._syn_counts.items():
            unique_ports = len(self._syn_ports[src_ip])
            unique_hosts = len(self._syn_hosts[src_ip])
            if count < 50:
                continue
            mac = _mac_for_ip(src_ip)

            # Recognise this computer's own scans (e.g. you ran the built-in
            # nmap tools, or captured your own machine). Report it as an
            # informational note instead of a high-risk attack, so users aren't
            # alarmed by their own activity.
            if src_ip in local_ips and (unique_ports >= 20 or unique_hosts >= 20):
                self._emit(Finding(
                    severity='info',
                    category='network',
                    title='Scan traffic from this computer (your own device)',
                    description=(
                        'This computer — the one running W1CK3D NET WIZARD — sent '
                        f'scan-like traffic ({unique_ports} port(s) across '
                        f'{unique_hosts} host(s)). This is exactly what you would '
                        'expect if you ran the built-in scan tools (or any scanner) '
                        'from this machine. It is your own activity, not an outside '
                        'attacker, so it is not a threat.'
                    ),
                    technical=(
                        f'{src_ip} (this device) → {unique_ports} unique ports on '
                        f'{unique_hosts} host(s), {count} total SYNs'
                    ),
                    device_mac=mac,
                    recommendation=(
                        'No action needed if you ran a scan yourself.\n'
                        'If you did NOT run any scanning tool, a program on this '
                        'computer may be scanning the network without your knowledge — '
                        'review your running applications and run a full antivirus scan.'
                    ),
                    evidence={
                        'src_ip': src_ip, 'total_syns': count,
                        'unique_ports': unique_ports, 'unique_hosts': unique_hosts,
                        'local_device': True,
                    },
                ))
                continue

            if unique_ports >= 20:
                self._emit(Finding(
                    severity='high',
                    category='network',
                    title='Port Scan Detected',
                    description=(
                        f'A device sent SYN packets to {unique_ports} different ports — '
                        'the textbook signature of a port scan. This maps what services '
                        'are running on a target and is typically the first step in '
                        'finding something to attack. May be an authorized scanner, '
                        'but worth verifying.'
                    ),
                    technical=(
                        f'{src_ip} → {unique_ports} unique ports on '
                        f'{unique_hosts} host(s), {count} total SYNs'
                    ),
                    device_mac=mac,
                    recommendation=(
                        '1. Find the device: check your router\'s DHCP table for the '
                        'IP address shown in Technical detail above.\n'
                        '2. If you do not recognise it, disconnect it from the '
                        'network immediately.\n'
                        '3. If it is your own device, check it for unauthorised software:\n'
                        '   - Windows: open Task Manager → check Startup and running processes.\n'
                        '   - Run a full antivirus scan.\n'
                        '4. If this was an authorised scan (e.g., you ran nmap yourself), '
                        'this finding can be ignored.\n'
                        '5. Add a firewall rule on your router to alert or block unexpected '
                        'outbound port scanning activity.'
                    ),
                    evidence={
                        'src_ip': src_ip, 'total_syns': count,
                        'unique_ports': unique_ports, 'unique_hosts': unique_hosts,
                    },
                ))
            elif unique_hosts >= 20:
                self._emit(Finding(
                    severity='high',
                    category='network',
                    title='Network Host Sweep Detected',
                    description=(
                        f'A device probed {unique_hosts} different hosts — consistent '
                        'with a network sweep to discover live machines. This is '
                        'reconnaissance and may precede targeted attacks.'
                    ),
                    technical=f'{src_ip} → {unique_hosts} unique hosts, {count} SYNs',
                    device_mac=mac,
                    recommendation=(
                        '1. Find the device: check your router\'s DHCP/connected '
                        'devices list for the IP in Technical detail.\n'
                        '2. If you do not recognise the device, disconnect it '
                        'from the network immediately.\n'
                        '3. If it is a known device, check it for malware or '
                        'unauthorised network scanning tools.\n'
                        '4. Consider whether this could be lateral movement — '
                        'a compromised device mapping the network before attacking others.\n'
                        '5. Enable logging on your router or firewall to monitor '
                        'future activity from this device.'
                    ),
                    evidence={
                        'src_ip': src_ip, 'total_syns': count, 'unique_hosts': unique_hosts,
                    },
                ))

        # Beaconing
        BEACON_MIN_INTERVAL = 5
        BEACON_MAX_INTERVAL = 3600
        BEACON_MIN_SAMPLES = 8
        BEACON_MAX_CV = 0.1

        for (src_ip, dst_ip, dst_port), times in self._beacon_times.items():
            if len(times) < BEACON_MIN_SAMPLES:
                continue
            times_sorted = sorted(times)
            intervals = [
                t2 - t1 for t1, t2 in zip(times_sorted, times_sorted[1:])
                if BEACON_MIN_INTERVAL <= t2 - t1 <= BEACON_MAX_INTERVAL
            ]
            if len(intervals) < BEACON_MIN_SAMPLES - 1:
                continue
            mean_iv = sum(intervals) / len(intervals)
            if mean_iv == 0:
                continue
            std_iv = (sum((i - mean_iv) ** 2 for i in intervals) / len(intervals)) ** 0.5
            cv = std_iv / mean_iv
            if cv < BEACON_MAX_CV:
                mac = _mac_for_ip(src_ip)
                self._emit(Finding(
                    severity='medium',
                    category='network',
                    title='Regular Beaconing Detected — Possible C2 Traffic',
                    description=(
                        f'A device is connecting to {dst_ip}:{dst_port} every '
                        f'~{mean_iv:.0f} seconds with very consistent timing '
                        f'(CV={cv:.3f}). This regular check-in pattern is characteristic '
                        f'of malware communicating with a command-and-control server. '
                        f'Note: many legitimate apps (Slack, iCloud, push services) also '
                        f'beacon regularly — this is a lead, not a verdict.'
                    ),
                    technical=(
                        f'{src_ip} → {dst_ip}:{dst_port} | '
                        f'{len(times)} connections | '
                        f'mean interval {mean_iv:.1f}s | CV {cv:.3f}'
                    ),
                    device_mac=mac,
                    recommendation=(
                        '1. Use the Investigate tab (right-click this finding) to '
                        'look up the destination IP and identify the service/owner.\n'
                        '2. On the source device, find which process is responsible:\n'
                        '   - Windows: open Resource Monitor (Win+R → resmon.exe) '
                        '→ Network tab → find the destination IP.\n'
                        '   - macOS/Linux: run  lsof -i | grep <dst_ip>\n'
                        '3. Search online for the process name to confirm it is legitimate '
                        '(many apps like Slack, iCloud, and push services beacon normally).\n'
                        '4. If the process is unfamiliar: run a full antivirus/malware scan '
                        '(Malwarebytes free version is a good second opinion).\n'
                        '5. If confirmed malicious: isolate the device, change all passwords '
                        'used on it, and consider a full OS reinstall.'
                    ),
                    evidence={
                        'src_ip': src_ip, 'dst_ip': dst_ip, 'dst_port': dst_port,
                        'sample_count': len(times),
                        'mean_interval_s': round(mean_iv, 1),
                        'cv': round(cv, 3),
                    },
                ))

        # Large outbound transfers
        LARGE_BYTES = 10 * 1024 * 1024  # 10 MB

        for (src_ip, dst_ip), total_bytes in self._transfer_bytes.items():
            if total_bytes < LARGE_BYTES:
                continue
            mac = _mac_for_ip(src_ip)
            mb = total_bytes / (1024 * 1024)
            self._emit(Finding(
                severity='medium',
                category='network',
                title=f'Large Outbound Data Transfer ({mb:.1f} MB)',
                description=(
                    f'{mb:.1f} MB was sent from your network to {dst_ip}. A large '
                    'transfer to a single external address is worth verifying — it '
                    'could be a cloud backup, OS update, or video upload, but it is '
                    'also the signature of data exfiltration.'
                ),
                technical=f'{src_ip} → {dst_ip}: {total_bytes:,} bytes',
                device_mac=mac,
                recommendation=(
                    '1. Use the Investigate tab (right-click this finding) to look '
                    'up the destination IP and identify the service or organisation.\n'
                    '2. On the source device, identify which process is responsible:\n'
                    '   - Windows: open Resource Monitor (Win+R → resmon.exe) '
                    '→ Network tab → locate the destination IP.\n'
                    '   - macOS/Linux: run  lsof -i | grep <dst_ip>\n'
                    '3. Common legitimate causes: cloud backup (OneDrive, Dropbox, '
                    'Backblaze), OS updates, video upload.\n'
                    '4. If the process or destination is unfamiliar, run a full '
                    'antivirus scan on the source device.\n'
                    '5. If unexplained after scanning, block the destination IP on '
                    'your firewall and monitor whether the transfer attempts recur.'
                ),
                evidence={'src_ip': src_ip, 'dst_ip': dst_ip,
                          'bytes': total_bytes, 'mb': round(mb, 1)},
            ))

    def results(self):
        findings = [f.to_dict() for f in self._findings]
        counts = {}
        for f in self._findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return {
            'total': len(findings),
            'counts_by_severity': counts,
            'findings': findings,
        }
