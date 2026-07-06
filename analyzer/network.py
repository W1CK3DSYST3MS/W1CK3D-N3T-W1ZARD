import collections
import ipaddress
from .base import Analyzer


def _is_private(ip_str):
    try:
        return ipaddress.ip_address(ip_str).is_private
    except ValueError:
        return False


def _is_global(ip_str):
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_global
    except ValueError:
        return False


def _subnet24(ip_str):
    try:
        parts = ip_str.split('.')
        if len(parts) == 4:
            return f'{parts[0]}.{parts[1]}.{parts[2]}.0/24'
    except Exception:
        pass
    return None


class NetworkAnalyzer(Analyzer):
    name = 'network'

    def __init__(self):
        self.gateway_ip = None
        self.gateway_mac = None
        self._dhcp_gateway = None

        self.dns_servers = collections.Counter()
        self.subnets = set()
        self.internal_packets = 0
        self.external_packets = 0
        self.bytes_internal = 0
        self.bytes_external = 0
        self.external_ip_counts = collections.Counter()
        self.dns_query_counts = collections.Counter()

        # ARP: ip -> set of MACs claiming that IP (used by ThreatAnalyzer)
        self.arp_claims = collections.defaultdict(set)

        # Heuristic gateway detection: which MAC bridges to external traffic
        self._external_src_mac_counts = collections.Counter()

    def process_packet(self, pkt):
        try:
            length = int(pkt.length)
        except Exception:
            length = 0

        src_ip = dst_ip = src_mac = None
        try:
            src_ip = pkt.ip.src
            dst_ip = pkt.ip.dst
        except AttributeError:
            pass
        try:
            src_mac = pkt.eth.src
        except AttributeError:
            pass

        # Traffic classification & external destination tracking
        if src_ip and dst_ip:
            src_priv = _is_private(src_ip)
            dst_priv = _is_private(dst_ip)

            if src_priv and dst_priv:
                self.internal_packets += 1
                self.bytes_internal += length
            else:
                self.external_packets += 1
                self.bytes_external += length
                if src_priv and _is_global(dst_ip):
                    self.external_ip_counts[dst_ip] += 1
                # When external IP is the source, the Ethernet src_mac arriving
                # at our capture point is the gateway (it rewrote the MAC)
                if not src_priv and dst_priv and src_mac:
                    self._external_src_mac_counts[src_mac] += 1

        # Subnet discovery
        for ip in (src_ip, dst_ip):
            if ip and _is_private(ip):
                subnet = _subnet24(ip)
                if subnet:
                    self.subnets.add(subnet)

        # DNS: track servers receiving queries and query names
        try:
            if hasattr(pkt, 'dns') and hasattr(pkt, 'udp'):
                dst_port = getattr(pkt.udp, 'dstport', None)
                if dst_port == '53' and dst_ip and _is_private(dst_ip):
                    self.dns_servers[dst_ip] += 1
                # Query names from DNS questions (flags_response == '0')
                if getattr(pkt.dns, 'flags_response', None) == '0':
                    qname = getattr(pkt.dns, 'qry_name', None)
                    if qname:
                        self.dns_query_counts[qname] += 1
        except Exception:
            pass

        # DHCP router option (option 3) — most reliable gateway source
        try:
            if hasattr(pkt, 'dhcp') and hasattr(pkt, 'bootp'):
                gw = getattr(pkt.dhcp, 'option_router', None)
                if gw and gw != '0.0.0.0':
                    self._dhcp_gateway = gw
        except Exception:
            pass

        # ARP replies: record which MAC claims each IP
        try:
            if hasattr(pkt, 'arp'):
                op = getattr(pkt.arp, 'opcode', None)
                if op in ('2', '0x00000002'):
                    claimed_ip = getattr(pkt.arp, 'src_proto_ipv4', None)
                    sender_mac = getattr(pkt.arp, 'src_hw_mac', None)
                    if claimed_ip and sender_mac:
                        self.arp_claims[claimed_ip].add(sender_mac)
        except Exception:
            pass

    def finalize(self, context=None):
        device_a = context.get('devices_raw') if context else None

        if self._dhcp_gateway:
            self.gateway_ip = self._dhcp_gateway
            if device_a:
                for mac, dev in device_a._devices.items():
                    if self.gateway_ip in (dev.get('ip_addresses') or set()):
                        self.gateway_mac = mac
                        dev['is_gateway'] = True
                        break
        elif self._external_src_mac_counts and device_a:
            # Fallback: the MAC most often seen carrying external→internal traffic
            gw_mac = self._external_src_mac_counts.most_common(1)[0][0]
            dev = device_a._devices.get(gw_mac)
            if dev:
                ips = sorted(dev.get('ip_addresses') or [])
                self.gateway_ip = ips[0] if ips else None
                self.gateway_mac = gw_mac
                dev['is_gateway'] = True

    def results(self):
        return {
            'gateway_ip': self.gateway_ip,
            'gateway_mac': self.gateway_mac,
            'dns_servers': [ip for ip, _ in self.dns_servers.most_common(3)],
            'subnets': sorted(self.subnets),
            'internal_packets': self.internal_packets,
            'external_packets': self.external_packets,
            'bytes_internal': self.bytes_internal,
            'bytes_external': self.bytes_external,
            'top_external_ips': self.external_ip_counts.most_common(10),
            'top_dns_queries': self.dns_query_counts.most_common(20),
            'arp_claims': {ip: list(macs) for ip, macs in self.arp_claims.items()},
        }
