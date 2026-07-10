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
    # additional framing / infrastructure / data-format noise
    'vlan', 'llc', 'sll', 'null', 'loop', 'xml', 'vssmonitoring',
    'fake-field-wrapper', 'tcp.segments', 'ip.fragments', 'short',
})


def _is_noise_layer(name: str) -> bool:
    """True for framing/pseudo layers that aren't real application protocols.

    Filters Wireshark internal pseudo-layers (``_ws.malformed``, ``_ws.expert``
    …) and anything in _SKIP_LAYERS, so the protocol inventory and the auto-learn
    step only ever see genuine application protocols.
    """
    n = name.lower()
    return (n in _SKIP_LAYERS or n.startswith('_ws.') or n.startswith('_')
            or 'malformed' in n or 'expert' in n or 'segment' in n)


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
        # "tcp:443" -> Counter({'tls': 900}) — which decoded protocol rides on
        # each port, so a port can be named by what Wireshark actually saw.
        self._port_layers = collections.defaultdict(collections.Counter)

    def process_packet(self, pkt):
        # Track all named application layers (exclude base infrastructure)
        app_layers = []
        try:
            for layer in pkt.layers:
                lname = layer.layer_name.lower()
                if not _is_noise_layer(lname):
                    self._layers[lname] += 1
                    app_layers.append(lname)
        except Exception:
            pass

        # Track destination port + transport (fills in for unnamed protocols).
        port = tp = None
        try:
            port = int(pkt.tcp.dstport); tp = 'tcp'
            self._tcp_ports[port] += 1
        except Exception:
            pass
        if port is None:
            try:
                port = int(pkt.udp.dstport); tp = 'udp'
                self._udp_ports[port] += 1
            except Exception:
                pass

        # Correlate the most-specific decoded layer with the destination port.
        if port is not None and app_layers:
            self._port_layers[f'{tp}:{port}'][app_layers[-1]] += 1

    def finalize(self, context=None):
        pass

    def results(self) -> dict:
        return {
            'layers':    dict(self._layers),
            'tcp_ports': {str(p): c for p, c in self._tcp_ports.items()},
            'udp_ports': {str(p): c for p, c in self._udp_ports.items()},
            'port_layers': {k: dict(v) for k, v in self._port_layers.items()},
        }
