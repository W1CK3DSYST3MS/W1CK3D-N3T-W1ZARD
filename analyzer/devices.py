import ipaddress
from .base import Analyzer

try:
    import manuf as _manuf_module
    _mac_parser = _manuf_module.MacParser()
except Exception:
    _mac_parser = None


def _vendor_lookup(mac):
    if not _mac_parser or not mac:
        return None
    try:
        return _mac_parser.get_manuf(mac)
    except Exception:
        return None


def guess_device_type(device):
    """Translate accumulated evidence into a friendly device label."""
    vendor = (device.get('vendor') or '').lower()
    hostnames = [h.lower() for h in device.get('hostnames', [])]
    user_agents = [ua.lower() for ua in device.get('user_agents', [])]
    services = set(device.get('services', []))
    dhcp_vendor = (device.get('dhcp_vendor_class') or '').lower()

    if device.get('is_gateway'):
        return 'Network device (router / switch / AP)'

    router_keywords = ['cisco', 'netgear', 'ubiquiti', 'asus', 'tp-link', 'zyxel',
                       'draytek', 'mikrotik', 'aruba', 'ruckus', 'fortinet',
                       'openwrt', 'd-link', 'linksys', 'buffalo', 'synology']
    if any(kw in vendor for kw in router_keywords):
        return 'Network device (router / switch / AP)'

    printer_keywords = ['hp', 'epson', 'canon', 'brother', 'lexmark', 'xerox',
                        'ricoh', 'kyocera']
    if any(kw in vendor for kw in printer_keywords):
        return 'Printer'
    if any(kw in h for kw in ['printer', 'print'] for h in hostnames):
        return 'Printer'
    if services & {'ipp', 'pdl-datastream', 'printer'}:
        return 'Printer'

    if 'apple' in vendor:
        for ua in user_agents:
            if 'iphone' in ua:
                name = next((h for h in hostnames if h), None)
                return f'iPhone ({name})' if name else 'iPhone'
            if 'ipad' in ua:
                return 'iPad'
            if 'macintosh' in ua or 'mac os x' in ua:
                return 'Mac'
        for h in hostnames:
            if 'iphone' in h:
                return 'iPhone'
            if 'ipad' in h:
                return 'iPad'
            if any(kw in h for kw in ['macbook', 'imac', 'mac-mini', 'mac-pro']):
                return 'Mac'
        return 'Apple device'

    for ua in user_agents:
        if 'android' in ua:
            return 'Android device'
    if any('android' in h for h in hostnames):
        return 'Android device'

    for ua in user_agents:
        if 'windows' in ua:
            return 'Windows PC'
    if any(kw in h for kw in ['desktop', 'laptop', 'workstation', 'pc'] for h in hostnames):
        return 'Windows PC'

    for ua in user_agents:
        if 'linux' in ua and 'android' not in ua:
            return 'Linux PC'

    smart_tv_keywords = ['samsung', 'lg electron', 'sony', 'vizio', 'roku', 'nvidia',
                         'amazon tech', 'amazon reg']
    if any(kw in vendor for kw in smart_tv_keywords):
        return 'Smart TV / streaming device'
    if any(kw in h for kw in ['tv', 'roku', 'firetv', 'chromecast', 'shield'] for h in hostnames):
        return 'Smart TV / streaming device'

    iot_keywords = ['espressif', 'raspberry', 'tuya', 'shelly', 'belkin', 'wemo',
                    'sonos', 'philips lighting', 'nest']
    if any(kw in vendor for kw in iot_keywords):
        return 'IoT / smart home device'

    if 'dhcpcd' in dhcp_vendor or 'android-dhcp' in dhcp_vendor:
        return 'Android device'
    if 'msft' in dhcp_vendor:
        return 'Windows PC'

    if vendor:
        return f'Unknown device ({vendor})'
    return 'Unknown device'


class DeviceAnalyzer(Analyzer):
    name = 'devices'

    def __init__(self):
        self._devices = {}  # mac -> device dict

    def _get_or_create(self, mac):
        if mac not in self._devices:
            self._devices[mac] = {
                'mac': mac,
                'vendor': _vendor_lookup(mac),
                'ip_addresses': set(),
                'hostnames': set(),
                'user_agents': set(),
                'dhcp_vendor_class': None,
                'services': set(),
                'packet_count': 0,
                'bytes_total': 0,
                'is_gateway': False,
                'likely_type': 'Unknown device',
            }
        return self._devices[mac]

    def _is_trackable_ip(self, ip_str):
        try:
            addr = ipaddress.ip_address(ip_str)
            return addr.is_private and not addr.is_loopback and not addr.is_link_local
        except ValueError:
            return False

    def process_packet(self, pkt):
        try:
            length = int(pkt.length)
        except Exception:
            length = 0

        src_mac = dst_mac = src_ip = dst_ip = None
        try:
            src_mac = pkt.eth.src
            dst_mac = pkt.eth.dst
        except AttributeError:
            pass
        try:
            src_ip = pkt.ip.src
            dst_ip = pkt.ip.dst
        except AttributeError:
            pass

        def _is_real_mac(mac):
            return mac and not mac.startswith('ff:') and mac != '00:00:00:00:00:00'

        if _is_real_mac(src_mac):
            dev = self._get_or_create(src_mac)
            dev['packet_count'] += 1
            dev['bytes_total'] += length
            if src_ip and self._is_trackable_ip(src_ip):
                dev['ip_addresses'].add(src_ip)

        if _is_real_mac(dst_mac):
            dev = self._get_or_create(dst_mac)
            if dst_ip and self._is_trackable_ip(dst_ip):
                dev['ip_addresses'].add(dst_ip)

        # DHCP: extract hostname, vendor class, assigned IP
        try:
            if hasattr(pkt, 'dhcp') and hasattr(pkt, 'bootp'):
                client_mac = getattr(pkt.bootp, 'hw_mac_addr', None)
                if client_mac and _is_real_mac(client_mac):
                    dev = self._get_or_create(client_mac)
                    try:
                        hn = pkt.dhcp.option_hostname
                        if hn:
                            dev['hostnames'].add(hn.strip())
                    except AttributeError:
                        pass
                    try:
                        vc = pkt.dhcp.option_vendor_class_id
                        if vc:
                            dev['dhcp_vendor_class'] = vc
                    except AttributeError:
                        pass
                    try:
                        ip = pkt.bootp.ip_your
                        if ip and ip != '0.0.0.0':
                            dev['ip_addresses'].add(ip)
                    except AttributeError:
                        pass
        except Exception:
            pass

        # HTTP User-Agent
        try:
            if hasattr(pkt, 'http') and _is_real_mac(src_mac):
                ua = getattr(pkt.http, 'user_agent', None)
                if ua:
                    self._get_or_create(src_mac)['user_agents'].add(ua)
        except Exception:
            pass

        # NetBIOS Name Service
        try:
            if hasattr(pkt, 'nbns') and _is_real_mac(src_mac):
                name = getattr(pkt.nbns, 'name', None)
                if name:
                    clean = name.strip().rstrip('\x00').strip()
                    if clean:
                        self._get_or_create(src_mac)['hostnames'].add(clean)
        except Exception:
            pass

        # mDNS — look at DNS answers in multicast traffic
        try:
            if (hasattr(pkt, 'dns') and hasattr(pkt, 'udp') and
                    getattr(pkt.udp, 'dstport', None) == '5353' and _is_real_mac(src_mac)):
                dev = self._get_or_create(src_mac)
                try:
                    name = pkt.dns.resp_name
                    if name:
                        clean = name.replace('.local', '').strip('.')
                        if clean:
                            dev['hostnames'].add(clean)
                except AttributeError:
                    pass
        except Exception:
            pass

        # SSDP / UPnP
        try:
            if hasattr(pkt, 'ssdp') and _is_real_mac(src_mac):
                dev = self._get_or_create(src_mac)
                dev['services'].add('ssdp')
                try:
                    server = pkt.ssdp.server
                    if server:
                        dev['user_agents'].add(server)
                except AttributeError:
                    pass
        except Exception:
            pass

    def finalize(self, context=None):
        for dev in self._devices.values():
            dev['ip_addresses'] = sorted(dev['ip_addresses'])
            dev['hostnames'] = sorted(h for h in dev['hostnames'] if h)
            dev['user_agents'] = list(dev['user_agents'])
            dev['services'] = list(dev['services'])
            dev['likely_type'] = guess_device_type(dev)

    def results(self):
        return {
            'count': len(self._devices),
            'devices': list(self._devices.values()),
        }
