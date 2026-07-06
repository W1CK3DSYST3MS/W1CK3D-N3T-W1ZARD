"""
ip_investigate.py — Look up an IP address and return plain-English results.

Uses:
  - socket.gethostbyaddr()      — reverse DNS (built-in, no deps)
  - ip-api.com                  — free GeoIP, no API key, 45 req/min
  - ipwhois                     — WHOIS/ASN data (pip install ipwhois)
  - internetdb.shodan.io        — free Shodan port/CVE data, no key required
  - shodan API (optional)       — richer service banners (pip install shodan, paid key)
"""

import ipaddress
import json
import re
import socket
import urllib.request

_IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

# Common port → friendly service name for plain-English display
_PORT_NAMES = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
    3306: 'MySQL', 3389: 'RDP (Remote Desktop)', 5900: 'VNC',
    6379: 'Redis', 8080: 'HTTP-alt', 8443: 'HTTPS-alt',
    9200: 'Elasticsearch', 27017: 'MongoDB',
}

_RISKY_PORTS = {23, 21, 3389, 5900, 445, 1433, 3306, 6379, 9200, 27017}

_TAG_EXPLANATIONS = {
    'cloud':       'hosted on a cloud platform (AWS, Azure, GCP, etc.)',
    'vpn':         'associated with a VPN service',
    'tor':         'a Tor exit node — traffic may be anonymised',
    'scanner':     'known internet scanner (e.g. Shodan, security researchers)',
    'cdn':         'part of a content delivery network',
    'honeypot':    'flagged as a honeypot',
    'malware':     'associated with malware activity',
    'compromised': 'previously reported as compromised',
    'c2':          'linked to command-and-control infrastructure',
}


def _is_public(ip: str) -> bool:
    """Return True only if the IP is a routable public address."""
    try:
        obj = ipaddress.ip_address(ip)
        return not (obj.is_private or obj.is_loopback or obj.is_link_local
                    or obj.is_reserved or obj.is_multicast or obj.is_unspecified)
    except ValueError:
        return False


def extract_ips(finding: dict) -> list:
    """Pull every IP-looking string out of a finding dict."""
    ips = set()

    evidence = finding.get('evidence') or {}
    for val in evidence.values():
        if isinstance(val, str):
            ips.update(_IP_RE.findall(val))
        elif isinstance(val, (list, tuple)):
            for item in val:
                if isinstance(item, str):
                    ips.update(_IP_RE.findall(item))

    for field in ('technical', 'description'):
        ips.update(_IP_RE.findall(finding.get(field) or ''))

    valid = []
    for ip in sorted(ips):
        parts = ip.split('.')
        if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
            valid.append(ip)
    return valid


def _rdns(ip: str):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def _geoip(ip: str):
    try:
        url = (f'http://ip-api.com/json/{ip}'
               f'?fields=status,message,country,regionName,city,isp,org,as,query')
        with urllib.request.urlopen(url, timeout=6) as resp:
            data = json.loads(resp.read().decode())
        if data.get('status') == 'success':
            return data
    except Exception:
        pass
    return None


def _whois(ip: str):
    try:
        from ipwhois import IPWhois
        rdap = IPWhois(ip).lookup_rdap(depth=1)
        return {
            'asn':      rdap.get('asn'),
            'asn_desc': rdap.get('asn_description', ''),
            'asn_cidr': rdap.get('asn_cidr', ''),
            'country':  rdap.get('asn_country_code', ''),
            'net_name': (rdap.get('network') or {}).get('name', ''),
        }
    except ImportError:
        return {'error': 'ipwhois not installed'}
    except Exception as e:
        return {'error': str(e)}


def _extract_domain(hostname: str) -> str:
    """Return the registrable domain from a hostname (last two labels)."""
    if not hostname:
        return ''
    parts = hostname.rstrip('.').split('.')
    return '.'.join(parts[-2:]) if len(parts) >= 2 else hostname


def _whois_is(query: str, api_key: str = None) -> dict:
    """
    Look up domain or IP registration data via the whois.is API.
    Free tier works without a key at lower rate limits.
    """
    try:
        url = f'https://api.whois.is/?q={urllib.request.quote(query)}'
        if api_key:
            url += f'&apiKey={urllib.request.quote(api_key)}'
        req = urllib.request.Request(url, headers={'Accept': 'application/json'})
        with urllib.request.urlopen(req, timeout=8) as resp:
            raw = resp.read().decode('utf-8', errors='replace')
        data = json.loads(raw)

        # Normalise — whois.is wraps everything under 'WhoisRecord'
        rec = data.get('WhoisRecord') or data
        if not rec or rec.get('dataError'):
            return {'error': rec.get('dataError', 'No record found')}

        registrant = rec.get('registrant') or {}
        admin      = rec.get('administrativeContact') or {}
        ns_obj     = rec.get('nameServers') or {}
        nameservers = ns_obj.get('hostNames') or ns_obj.get('nameServers') or []

        return {
            'domain':        rec.get('domainName', query),
            'registrar':     rec.get('registrarName', ''),
            'created':       rec.get('createdDate') or rec.get('registrationDate', ''),
            'updated':       rec.get('updatedDate', ''),
            'expires':       rec.get('expiresDate') or rec.get('expirationDate', ''),
            'status':        rec.get('status', ''),
            'registrant_name': registrant.get('name', ''),
            'registrant_org':  registrant.get('organization', ''),
            'registrant_country': registrant.get('country', ''),
            'admin_email':   admin.get('email', ''),
            'nameservers':   nameservers[:6],
            'raw':           rec.get('rawText', ''),
        }
    except urllib.error.HTTPError as e:
        return {'error': f'HTTP {e.code}: {e.reason}'}
    except Exception as e:
        return {'error': str(e)}


def _bgpview(ip: str) -> dict:
    """
    Look up BGP/ASN ownership data via BGPView API — completely free, no key.
    Returns the owning organisation, ASN, prefix, and PTR record.
    https://bgpview.io/
    """
    try:
        url = f'https://api.bgpview.io/ip/{ip}'
        req = urllib.request.Request(
            url,
            headers={'Accept': 'application/json',
                     'User-Agent': 'W1CK3DNetWizard/1.0'},
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode())
        if data.get('status') != 'ok':
            return {'error': 'No BGP data available'}
        d        = data.get('data') or {}
        prefixes = d.get('prefixes') or []
        rir      = (d.get('rir_allocation') or {}).get('rir_name', '')
        ptr      = d.get('ptr_record') or ''
        asn_info = {}
        if prefixes:
            asn_raw  = prefixes[0].get('asn') or {}
            asn_info = {
                'asn':         asn_raw.get('asn'),
                'name':        asn_raw.get('name', ''),
                'description': asn_raw.get('description', ''),
                'country':     asn_raw.get('country_code', ''),
                'prefix':      prefixes[0].get('prefix', ''),
            }
        return {'ptr': ptr, 'asn': asn_info, 'rir': rir}
    except urllib.error.HTTPError as e:
        return {'error': f'HTTP {e.code}'}
    except Exception as e:
        return {'error': str(e)}


def _abuseipdb(ip: str, api_key: str) -> dict:
    """
    Query AbuseIPDB for abuse confidence score and report history.
    Free tier: 1,000 checks/day. https://www.abuseipdb.com/api
    """
    try:
        url = ('https://api.abuseipdb.com/api/v2/check'
               f'?ipAddress={urllib.request.quote(ip)}&maxAgeInDays=90')
        req = urllib.request.Request(
            url,
            headers={'Key': api_key.strip(), 'Accept': 'application/json'},
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode())
        d = data.get('data') or {}
        return {
            'score':          d.get('abuseConfidenceScore', 0),
            'total_reports':  d.get('totalReports', 0),
            'distinct_users': d.get('numDistinctUsers', 0),
            'last_reported':  d.get('lastReportedAt') or '',
            'isp':            d.get('isp', ''),
            'domain':         d.get('domain', ''),
            'usage_type':     d.get('usageType', ''),
            'country_code':   d.get('countryCode', ''),
            'is_whitelisted': d.get('isWhitelisted', False),
            'is_tor':         d.get('isTor', False),
        }
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return {'error': 'Invalid API key — check File → Settings'}
        if e.code == 422:
            return {'error': 'Invalid IP address format'}
        if e.code == 429:
            return {'error': 'Rate limit reached — free tier allows 1,000 checks/day'}
        return {'error': f'HTTP {e.code}: {e.reason}'}
    except Exception as e:
        return {'error': str(e)}


def _internetdb(ip: str) -> dict:
    """
    Query Shodan InternetDB — completely free, no API key needed.
    Returns ports, hostnames, tags, CVEs, and CPEs for any public IP.
    https://internetdb.shodan.io/<ip>
    """
    try:
        url = f'https://internetdb.shodan.io/{ip}'
        req = urllib.request.Request(url, headers={'Accept': 'application/json'})
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode())
        if 'detail' in data:
            # {"detail": "No information available"} — valid response for clean IPs
            return {'ports': [], 'hostnames': [], 'tags': [], 'vulns': [], 'cpes': []}
        return {
            'ports':     sorted(data.get('ports') or []),
            'hostnames': data.get('hostnames') or [],
            'tags':      data.get('tags') or [],
            'vulns':     sorted(data.get('vulns') or []),
            'cpes':      data.get('cpes') or [],
        }
    except Exception as e:
        return {'error': str(e)}


def _shodan(ip: str, api_key: str):
    try:
        import shodan
        api = shodan.Shodan(api_key.strip())
        try:
            api.info()  # validates the key before the host lookup
        except shodan.APIError as e:
            return {'error': f'API key rejected: {e}  — check your key in File → Settings'}
        host = api.host(ip)
        services = []
        for s in host.get('data', []):
            services.append({
                'port':      s.get('port'),
                'transport': s.get('transport', 'tcp'),
                'product':   s.get('product', ''),
                'version':   s.get('version', ''),
                'banner':    (s.get('data') or '')[:200].strip(),
            })
        return {
            'hostnames':   host.get('hostnames', []),
            'org':         host.get('org', ''),
            'isp':         host.get('isp', ''),
            'country':     host.get('country_name', ''),
            'city':        host.get('city', ''),
            'asn':         host.get('asn', ''),
            'os':          host.get('os'),
            'ports':       sorted(host.get('ports', [])),
            'tags':        host.get('tags', []),
            'vulns':       sorted((host.get('vulns') or {}).keys()),
            'services':    services,
            'last_update': host.get('last_update', ''),
        }
    except ImportError:
        return {'error': 'shodan not installed — run: pip install shodan'}
    except Exception as e:
        msg = str(e)
        if '403' in msg or 'forbidden' in msg.lower():
            return {'error': f'Access denied (403) — invalid API key or plan limitation.\n  Key used: {api_key[:6]}…  Check in File → Settings'}
        return {'error': msg}


def lookup_ip(ip: str, api_keys: dict = None) -> dict:
    """
    Run all lookups for *ip* and return a result dict.
    api_keys: optional dict with keys 'shodan' and/or 'whois_is'.
    Safe to call from a background thread.
    """
    api_keys = api_keys or {}
    rdns     = _rdns(ip)

    if not _is_public(ip):
        return {
            'ip':      ip,
            'rdns':    rdns,
            'private': True,
        }

    result = {
        'ip':        ip,
        'rdns':      rdns,
        'geo':       _geoip(ip),
        'whois':     _whois(ip),
        'internetdb': _internetdb(ip),  # always free, no key
        'bgpview':   _bgpview(ip),      # always free, no key — ASN/org ownership
    }

    if api_keys.get('shodan'):
        result['shodan'] = _shodan(ip, api_keys['shodan'])

    if api_keys.get('abuseipdb'):
        result['abuseipdb'] = _abuseipdb(ip, api_keys['abuseipdb'])

    # whois.is — look up the domain from reverse DNS (or the IP itself)
    # A key is optional; free tier works without one at lower rate limits
    whois_is_key = api_keys.get('whois_is')  # None = try free tier

    # Prefer paid Shodan hostnames → InternetDB hostnames → reverse DNS
    sh_hostnames = (result.get('shodan') or {}).get('hostnames') or []
    idb_hostnames = (result.get('internetdb') or {}).get('hostnames') or []
    all_hostnames = sh_hostnames or idb_hostnames

    domain_to_lookup = None
    if all_hostnames:
        domain_to_lookup = _extract_domain(all_hostnames[0])
    elif rdns:
        domain_to_lookup = _extract_domain(rdns)

    if domain_to_lookup:
        result['whois_is'] = _whois_is(domain_to_lookup, whois_is_key)
        result['whois_is']['_queried'] = domain_to_lookup
    elif whois_is_key:
        # No hostname but key present — fall back to IP lookup
        result['whois_is'] = _whois_is(ip, whois_is_key)
        result['whois_is']['_queried'] = ip

    return result


def _format_port_block(out, tags, ports, services, os_name, vulns):
    """Append port/tag/vuln lines to *out* (shared by Shodan API and InternetDB)."""
    if tags:
        out.append(('  Flags:  ', 'label'))
        tag_parts = []
        for t in tags:
            expl = _TAG_EXPLANATIONS.get(t.lower())
            tag_parts.append(f'{t} ({expl})' if expl else t)
        out.append((', '.join(tag_parts) + '\n', 'body'))

    if ports:
        out.append(('  Open ports:  ', 'label'))
        port_labels = []
        for p in ports:
            name = _PORT_NAMES.get(p)
            port_labels.append(f'{p}/{name}' if name else str(p))
        out.append((', '.join(port_labels) + '\n',
                    'risky' if any(p in _RISKY_PORTS for p in ports) else 'body'))

    if services:
        out.append(('  Services:\n', 'label'))
        for svc in services[:12]:
            port  = svc.get('port', '?')
            proto = svc.get('transport', 'tcp')
            prod  = svc.get('product', '')
            ver   = svc.get('version', '')
            name  = _PORT_NAMES.get(port, '')
            line  = f'    {port}/{proto}'
            if name:
                line += f'  {name}'
            if prod:
                line += f'  — {prod}'
                if ver:
                    line += f' {ver}'
            out.append((line + '\n', 'risky' if port in _RISKY_PORTS else 'body'))

    if os_name:
        out.append(('  OS detected:  ', 'label'))
        out.append((f'{os_name}\n', 'body'))

    if vulns:
        out.append(('  Known vulnerabilities:\n', 'label'))
        for cve in list(vulns)[:10]:
            out.append((f'    {cve}\n', 'vuln'))
        if len(vulns) > 10:
            out.append((f'    … and {len(vulns) - 10} more\n', 'tip'))
        out.append(('  These CVEs have been matched against services '
                    'running on this IP.\n', 'tip'))


def format_investigation(data: dict) -> list:
    """
    Return a list of (text, tag) tuples ready for a Tkinter Text widget.
    Tags: h1, h2, label, body, tip, warn, vuln, risky
    """
    out   = []
    ip    = data['ip']
    rdns  = data.get('rdns')

    out.append((f'IP Investigation: {ip}\n', 'h1'))

    # ------------------------------------------------- Private / local address
    if data.get('private'):
        try:
            obj  = ipaddress.ip_address(ip)
            kind = ('loopback (this machine)'   if obj.is_loopback   else
                    'link-local (APIPA)'         if obj.is_link_local else
                    'private / local network'    if obj.is_private    else
                    'reserved / special-purpose')
        except ValueError:
            kind = 'private / local network'

        out.append(('\nLocal Address\n', 'h2'))
        out.append((f'  {ip} is a {kind} address.\n', 'body'))
        out.append(('  External services like Shodan and GeoIP only work on '
                    'public internet addresses — this IP belongs to your local '
                    'network (or this machine) and is not visible on the internet.\n', 'tip'))
        if rdns:
            out.append(('\nHostname\n', 'h2'))
            out.append((f'  {rdns}\n', 'body'))

        out.append(('\nWhat you can do\n', 'h2'))
        out.append(('  • Check your router/firewall admin panel to identify this device.\n', 'body'))
        out.append(('  • Run an nmap scan on your local network to fingerprint it:\n', 'body'))
        out.append((f'    nmap -sV {ip}\n', 'tip'))
        out.append(('  • Check your DHCP lease table to find the hostname/MAC address.\n', 'body'))
        return out

    geo   = data.get('geo')       or {}
    whois = data.get('whois')     or {}
    sh    = data.get('shodan')
    idb   = data.get('internetdb') or {}

    # --------------------------------------------------------- Port Intelligence
    # Prefer paid Shodan (has banners/services), fall back to free InternetDB
    if sh and not sh.get('error'):
        out.append(('\nPort Intelligence  (Shodan API)\n', 'h2'))
        _format_port_block(out, sh.get('tags'), sh.get('ports'),
                           sh.get('services'), sh.get('os'), sh.get('vulns'))
        if sh.get('last_update'):
            out.append(('  Last scanned by Shodan:  ', 'label'))
            out.append((f'{sh["last_update"][:10]}\n', 'body'))

    elif sh and sh.get('error'):
        out.append(('\nShodan API\n', 'h2'))
        out.append((f'  {sh["error"]}\n', 'warn'))

    # InternetDB — always shown (it's free); skip if paid Shodan already covered it
    if not (sh and not sh.get('error')):
        idb_ports = idb.get('ports') or []
        idb_tags  = idb.get('tags')  or []
        idb_vulns = idb.get('vulns') or []
        idb_cpes  = idb.get('cpes')  or []
        has_idb   = any([idb_ports, idb_tags, idb_vulns, idb_cpes])

        if idb.get('error'):
            out.append(('\nPort Intelligence  (Shodan InternetDB)\n', 'h2'))
            out.append((f'  Could not reach InternetDB: {idb["error"]}\n', 'tip'))
        elif has_idb:
            out.append(('\nPort Intelligence  (Shodan InternetDB — free)\n', 'h2'))
            _format_port_block(out, idb_tags, idb_ports, None, None, idb_vulns)
            if idb_cpes:
                out.append(('  Software (CPEs):\n', 'label'))
                for cpe in idb_cpes[:6]:
                    # Strip the cpe:/ prefix for readability
                    out.append((f'    {cpe.replace("cpe:/", "").replace("cpe:2.3:", "")}\n', 'body'))
            out.append(('  Source: internetdb.shodan.io — free, no API key required.\n', 'tip'))
        else:
            out.append(('\nPort Intelligence  (Shodan InternetDB — free)\n', 'h2'))
            out.append(('  No open ports or threat flags found for this IP.\n', 'body'))
            out.append(('  This is a good sign — the IP has no known exposed services.\n', 'tip'))

    # --------------------------------------------------- BGPView — network owner
    bgp = data.get('bgpview') or {}
    if not bgp.get('error'):
        asn = bgp.get('asn') or {}
        if asn.get('asn') or asn.get('name') or asn.get('description'):
            out.append(('\nNetwork Owner  (BGPView)\n', 'h2'))
            org_line = asn.get('description') or asn.get('name') or ''
            country  = asn.get('country', '')
            if org_line:
                out.append(('  Organisation:  ', 'label'))
                disp = f'{org_line}'
                if country:
                    disp += f'  ({country})'
                out.append((disp + '\n', 'body'))
            if asn.get('asn'):
                out.append(('  ASN:           ', 'label'))
                name_part = f'  {asn["name"]}' if asn.get('name') and asn['name'] != org_line else ''
                out.append((f'AS{asn["asn"]}{name_part}\n', 'body'))
            if asn.get('prefix'):
                out.append(('  IP Block:      ', 'label'))
                out.append((f'{asn["prefix"]}\n', 'body'))
            if bgp.get('rir'):
                out.append(('  Registry:      ', 'label'))
                out.append((f'{bgp["rir"]}\n', 'body'))
            if bgp.get('ptr'):
                out.append(('  Reverse DNS:   ', 'label'))
                out.append((f'{bgp["ptr"]}\n', 'body'))
            out.append(('  This shows who owns the IP address block at the routing level — '
                        'the organisation responsible for this address range.\n', 'tip'))

    # --------------------------------------------------- AbuseIPDB
    abuse = data.get('abuseipdb')
    if abuse and not abuse.get('error'):
        score = abuse.get('score', 0)
        reports = abuse.get('total_reports', 0)
        users   = abuse.get('distinct_users', 0)
        last    = (abuse.get('last_reported') or '')[:10]

        if score >= 75:
            score_tag = 'warn'
        elif score >= 25:
            score_tag = 'risky'
        else:
            score_tag = 'body'

        out.append(('\nThreat Intelligence  (AbuseIPDB)\n', 'h2'))
        out.append(('  Abuse confidence:  ', 'label'))
        out.append((f'{score}%\n', score_tag))

        if reports:
            out.append(('  Reports:           ', 'label'))
            out.append((f'{reports} report{"s" if reports != 1 else ""} from '
                        f'{users} user{"s" if users != 1 else ""}\n', 'body'))
            if last:
                out.append(('  Last reported:     ', 'label'))
                out.append((f'{last}\n', 'body'))
        else:
            out.append(('  No abuse reports in the last 90 days.\n', 'body'))

        if abuse.get('is_tor'):
            out.append(('  ⚠  Listed as a Tor exit node on AbuseIPDB.\n', 'warn'))
        if abuse.get('usage_type'):
            out.append(('  Usage type:        ', 'label'))
            out.append((f'{abuse["usage_type"]}\n', 'body'))

        tip = ('  Score 0–24 = clean, 25–74 = suspicious, 75–100 = high risk. '
               'Checked against the last 90 days of community reports.\n')
        out.append((tip, 'tip'))

    elif abuse and abuse.get('error'):
        out.append(('\nThreat Intelligence  (AbuseIPDB)\n', 'h2'))
        out.append((f'  {abuse["error"]}\n', 'tip'))

    # ------------------------------------------------------- whois.is domain
    wi = data.get('whois_is')
    if wi and not wi.get('error'):
        queried = wi.get('_queried', '')
        out.append((f'\nDomain Registration  ({queried})\n', 'h2'))

        if wi.get('registrar'):
            out.append(('  Registrar:   ', 'label'))
            out.append((f'{wi["registrar"]}\n', 'body'))
        if wi.get('created'):
            out.append(('  Created:     ', 'label'))
            out.append((f'{wi["created"][:10]}\n', 'body'))
        if wi.get('expires'):
            out.append(('  Expires:     ', 'label'))
            out.append((f'{wi["expires"][:10]}\n', 'body'))
        if wi.get('updated'):
            out.append(('  Last updated:', 'label'))
            out.append((f' {wi["updated"][:10]}\n', 'body'))

        reg_name = wi.get('registrant_name', '')
        reg_org  = wi.get('registrant_org', '')
        reg_cc   = wi.get('registrant_country', '')
        registrant_line = '  '.join(filter(None, [reg_name, reg_org, reg_cc]))
        if registrant_line:
            out.append(('  Registrant:  ', 'label'))
            out.append((f'{registrant_line}\n', 'body'))
        else:
            out.append(('  Registrant:  ', 'label'))
            out.append(('Privacy protected / not disclosed\n', 'tip'))

        if wi.get('nameservers'):
            out.append(('  Name servers:\n', 'label'))
            for ns in wi['nameservers']:
                out.append((f'    {ns}\n', 'body'))

        if wi.get('status'):
            out.append(('  Status:      ', 'label'))
            out.append((f'{wi["status"]}\n', 'body'))

        out.append(('  This is the registration record for the domain name '
                    'associated with this IP address.\n', 'tip'))

    elif wi and wi.get('error'):
        out.append(('\nDomain Registration (whois.is)\n', 'h2'))
        out.append((f'  {wi["error"]}\n', 'tip'))

    # -------------------------------------------------------- Location / WHOIS
    out.append(('\nLocation & Ownership\n', 'h2'))

    if geo:
        loc_parts = [geo.get('city'), geo.get('regionName'), geo.get('country')]
        location  = ', '.join(p for p in loc_parts if p) or '—'
        out.append(('  Location:      ', 'label'))
        out.append((f'{location}\n', 'body'))
        out.append(('  ISP:           ', 'label'))
        out.append((f'{geo.get("isp") or "—"}\n', 'body'))
        out.append(('  Organisation:  ', 'label'))
        out.append((f'{geo.get("org") or "—"}\n', 'body'))
        out.append(('  AS Number:     ', 'label'))
        out.append((f'{geo.get("as") or "—"}\n', 'body'))
    elif not whois.get('error'):
        out.append(('  Country:  ', 'label'))
        out.append((f'{whois.get("country") or "—"}\n', 'body'))
        out.append(('  Network:  ', 'label'))
        out.append((f'{whois.get("net_name") or "—"}\n', 'body'))
        out.append(('  ASN:      ', 'label'))
        out.append((f'{whois.get("asn") or "—"}  {whois.get("asn_desc", "")}\n', 'body'))
    else:
        out.append(('  Could not retrieve location data.\n', 'warn'))

    if whois and not whois.get('error') and whois.get('asn_cidr'):
        out.append(('  Network block: ', 'label'))
        out.append((f'{whois["asn_cidr"]}\n', 'body'))

    # --------------------------------------------------------- Reverse DNS
    out.append(('\nHostname (Reverse DNS)\n', 'h2'))
    # Priority: paid Shodan → InternetDB → socket reverse DNS
    sh_hostnames  = (sh  or {}).get('hostnames') or []
    idb_hostnames = idb.get('hostnames') or []
    best_hostnames = sh_hostnames or idb_hostnames
    if best_hostnames:
        for h in best_hostnames[:3]:
            out.append((f'  {h}\n', 'body'))
    elif rdns:
        out.append((f'  {rdns}\n', 'body'))
        out.append(('  This is the name the IP resolves back to.\n', 'tip'))
    else:
        out.append(('  No reverse DNS record found.\n', 'body'))
        out.append(("  Many IPs don't have reverse DNS — not suspicious on its own.\n", 'tip'))

    # -------------------------------------------------------- Summary
    out.append(('\nSummary\n', 'h2'))

    country = (geo.get('country') or (sh or {}).get('country')
               or whois.get('country') or '').strip()
    org     = (geo.get('org') or geo.get('isp') or (sh or {}).get('org')
               or whois.get('asn_desc') or '').strip()

    if country or org:
        line = '  This IP address is'
        if org:
            line += f' operated by {org}'
        if country:
            line += f' and is registered in {country}'
        out.append((line + '.\n', 'body'))

    # Merge threat signals from paid Shodan and/or free InternetDB
    all_tags  = set(t.lower() for t in (sh or {}).get('tags') or []) | \
                set(t.lower() for t in idb.get('tags') or [])
    all_ports = set((sh or {}).get('ports') or []) | set(idb.get('ports') or [])
    all_vulns = list((sh or {}).get('vulns') or []) or list(idb.get('vulns') or [])

    if 'tor' in all_tags:
        out.append(('  ⚠  This is a Tor exit node. Traffic from this IP '
                    'could originate from anyone using the Tor network.\n', 'warn'))
    if 'malware' in all_tags or 'c2' in all_tags:
        out.append(('  ⚠  This IP has been flagged as associated with '
                    'malware or command-and-control infrastructure.\n', 'warn'))
    if all_vulns:
        out.append((f'  ⚠  {len(all_vulns)} known vulnerabilit'
                    f'{"y" if len(all_vulns) == 1 else "ies"} found on this host.\n', 'warn'))
    if all_ports & _RISKY_PORTS:
        risky = sorted(all_ports & _RISKY_PORTS)
        names = [_PORT_NAMES.get(p, str(p)) for p in risky]
        out.append((f'  ⚠  Exposes high-risk services: {", ".join(names)}.\n', 'warn'))

    out.append(('\n  Note: ownership data shows who holds the IP address '
                'block, not necessarily the individual using it right now.\n', 'tip'))

    return out
