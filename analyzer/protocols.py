import collections
from .base import Analyzer

# Layer names that are pure transport/framing infrastructure — we skip these
# so the protocol tab only shows application-layer protocols.
_SKIP_LAYERS = frozenset({
    'eth', 'ip', 'ipv6', 'tcp', 'udp', 'icmp', 'icmpv6', 'arp',
    'frame', 'data', 'data-text-lines', 'radiotap', 'wlan', 'wlan_mgt',
    'wlan_radio', 'ppi', 'geninfo', 'wireshark_json', 'expert', 'malformed',
    'json', 'mime_multipart', 'media', 'pkix1explicit', 'pkix1implicit',
    'x509af', 'x509ce', 'x509if', 'x509sat',
})


class ProtocolAnalyzer(Analyzer):
    """
    Single-pass analyzer that inventories every application-layer protocol
    and destination port seen in the capture.

    Results are raw counts — the UI cross-references the protocol library
    at render time so user-added entries are reflected immediately.
    """

    name = 'protocols'

    def __init__(self):
        self._tcp_ports = collections.Counter()   # dst port -> packet count
        self._udp_ports = collections.Counter()   # dst port -> packet count
        self._layers    = collections.Counter()   # layer name -> packet count

    def process_packet(self, pkt):
        # Track all named application layers (exclude base infrastructure)
        try:
            for layer in pkt.layers:
                lname = layer.layer_name.lower()
                if lname not in _SKIP_LAYERS:
                    self._layers[lname] += 1
        except Exception:
            pass

        # Track destination ports — these fill in for protocols with no named layer
        try:
            self._tcp_ports[int(pkt.tcp.dstport)] += 1
        except Exception:
            pass
        try:
            self._udp_ports[int(pkt.udp.dstport)] += 1
        except Exception:
            pass

    def finalize(self, context=None):
        pass

    def results(self) -> dict:
        return {
            'layers':    dict(self._layers),
            'tcp_ports': {str(p): c for p, c in self._tcp_ports.items()},
            'udp_ports': {str(p): c for p, c in self._udp_ports.items()},
        }
