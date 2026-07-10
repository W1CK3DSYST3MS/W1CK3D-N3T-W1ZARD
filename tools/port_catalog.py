"""
tools/port_catalog.py
─────────────────────
A compact, offline catalogue of common ports that are NOT in the curated
protocol library, used to *identify* traffic automatically rather than leave it
as "Unknown". The OS services file (used by socket.getservbyport) is thin — only
a few hundred entries and no descriptions — so this fills the practical gaps a
home / small-office / enthusiast capture actually hits: gaming, streaming,
mobile, cloud, IoT, P2P, messaging.

Kept intentionally standalone (no imports from protocol_library) so it can be
reused and unit-tested on its own. Categories use the same strings as
protocol_library.ALL_CATEGORIES so the UI filter stays consistent.

Each entry: port -> {name, full_name, category, risk, transport, plain_english}
risk is one of 'none' / 'low' / 'medium' / 'high'.
"""

# Category strings mirror protocol_library CAT_* constants.
_NORMAL, _MEDIA, _MEDIA_SRV = 'Normal', 'Media', 'Media Server'
_IOT, _VOIP, _VPN, _REMOTE = 'IoT', 'VoIP', 'VPN', 'Remote Access'
_DB, _MGMT, _P2P, _LEGACY = 'Database', 'Management', 'P2P', 'Legacy'

EXTENDED_PORTS: dict[int, dict] = {
    # ── Gaming (shown under Media so users can filter it out as entertainment) ──
    3074:  {'name': 'Xbox Live', 'full_name': 'Xbox Live / Teredo gaming', 'category': _MEDIA,
           'risk': 'none', 'transport': ['udp', 'tcp'],
           'plain_english': 'Microsoft Xbox Live online gaming and party chat traffic. Normal if an Xbox or the Xbox app is in use.'},
    3478:  {'name': 'STUN / TURN', 'full_name': 'STUN/TURN NAT traversal', 'category': _VOIP,
           'risk': 'none', 'transport': ['udp', 'tcp'],
           'plain_english': 'Helps voice/video and gaming apps punch through your router (NAT). Used by Discord, WhatsApp, FaceTime, game consoles.'},
    27015: {'name': 'Source / Steam', 'full_name': 'Valve Source engine / Steam', 'category': _MEDIA,
            'risk': 'none', 'transport': ['udp', 'tcp'],
            'plain_english': 'Valve Steam and Source-engine games (CS, TF2, etc.). Normal on a PC running Steam.'},
    25565: {'name': 'Minecraft', 'full_name': 'Minecraft Java server', 'category': _MEDIA,
            'risk': 'low', 'transport': ['tcp'],
            'plain_english': 'Default Minecraft (Java) server port. Expected if someone plays or hosts Minecraft; unexpected on a device that should not.'},
    3724:  {'name': 'Blizzard / WoW', 'full_name': 'Blizzard Battle.net games', 'category': _MEDIA,
           'risk': 'none', 'transport': ['tcp', 'udp'],
           'plain_english': 'Blizzard Battle.net games (World of Warcraft and others).'},

    # ── Streaming / casting / media servers ──
    32400: {'name': 'Plex', 'full_name': 'Plex Media Server', 'category': _MEDIA_SRV,
            'risk': 'low', 'transport': ['tcp'],
            'plain_english': 'Plex media server — streams your movies/TV to other devices. Normal if you run Plex; note it can be exposed to the internet.'},
    8096:  {'name': 'Jellyfin / Emby', 'full_name': 'Jellyfin / Emby media server', 'category': _MEDIA_SRV,
           'risk': 'low', 'transport': ['tcp'],
           'plain_english': 'Jellyfin or Emby home media server web interface.'},
    8008:  {'name': 'Chromecast', 'full_name': 'Google Cast (control)', 'category': _MEDIA,
           'risk': 'none', 'transport': ['tcp'],
           'plain_english': 'Google Chromecast / Cast device control channel.'},
    8009:  {'name': 'Chromecast', 'full_name': 'Google Cast (TLS)', 'category': _MEDIA,
           'risk': 'none', 'transport': ['tcp'],
           'plain_english': 'Google Chromecast / Cast encrypted control channel.'},
    1900:  {'name': 'SSDP / UPnP', 'full_name': 'Simple Service Discovery Protocol', 'category': _NORMAL,
           'risk': 'low', 'transport': ['udp'],
           'plain_english': 'How smart-home and media devices announce themselves on the network (UPnP discovery). Common, but UPnP port-forwarding can expose devices — worth knowing what is using it.'},
    7000:  {'name': 'AirPlay', 'full_name': 'AirPlay / AirTunes', 'category': _MEDIA,
           'risk': 'none', 'transport': ['tcp'],
           'plain_english': 'Apple AirPlay streaming to Apple TV / HomePod / AirPlay speakers.'},

    # ── Mobile / cloud push ──
    5228:  {'name': 'Google FCM', 'full_name': 'Firebase Cloud Messaging', 'category': _NORMAL,
           'risk': 'none', 'transport': ['tcp'],
           'plain_english': 'Google push notifications (Android, Chrome, many apps). Extremely common background traffic from Android/Google devices.'},
    5223:  {'name': 'Apple APNs', 'full_name': 'Apple Push Notification service', 'category': _NORMAL,
           'risk': 'none', 'transport': ['tcp'],
           'plain_english': 'Apple push notifications for iPhone/iPad/Mac. Normal background traffic from Apple devices.'},
    5222:  {'name': 'XMPP', 'full_name': 'XMPP client (Jabber)', 'category': _NORMAL,
           'risk': 'none', 'transport': ['tcp'],
           'plain_english': 'XMPP/Jabber messaging, also used by some push and IoT services.'},
    62078: {'name': 'iPhone sync', 'full_name': 'Apple iOS lockdown/usbmux', 'category': _NORMAL,
            'risk': 'none', 'transport': ['tcp'],
            'plain_english': 'Apple iOS device sync/pairing service. Normal near iPhones/iPads.'},

    # ── IoT / smart home ──
    8883:  {'name': 'MQTT (TLS)', 'full_name': 'Secure MQTT', 'category': _IOT,
           'risk': 'none', 'transport': ['tcp'],
           'plain_english': 'Encrypted MQTT — the messaging protocol many smart-home and IoT devices use to talk to their cloud/hub.'},
    5683:  {'name': 'CoAP', 'full_name': 'Constrained Application Protocol', 'category': _IOT,
           'risk': 'low', 'transport': ['udp'],
           'plain_english': 'Lightweight IoT protocol (like HTTP for tiny devices). Normal from smart-home gear; unexpected elsewhere.'},
    1982:  {'name': 'LIFX', 'full_name': 'LIFX smart bulbs', 'category': _IOT,
           'risk': 'none', 'transport': ['udp'],
           'plain_english': 'LIFX smart light bulbs discovery/control.'},
    9999:  {'name': 'TP-Link Kasa', 'full_name': 'TP-Link Kasa smart devices', 'category': _IOT,
           'risk': 'low', 'transport': ['tcp', 'udp'],
           'plain_english': 'TP-Link Kasa smart plugs/bulbs local control. Known for weak/no encryption — fine on a trusted LAN.'},
    56700: {'name': 'LIFX', 'full_name': 'LIFX LAN protocol', 'category': _IOT,
            'risk': 'none', 'transport': ['udp'],
            'plain_english': 'LIFX smart bulb LAN control protocol.'},

    # ── Remote access / management / dev ──
    5900:  {'name': 'VNC', 'full_name': 'Virtual Network Computing', 'category': _REMOTE,
           'risk': 'medium', 'transport': ['tcp'],
           'plain_english': 'Remote desktop screen sharing. Legitimate for support, but an exposed/unexpected VNC is a real security concern.'},
    5901:  {'name': 'VNC', 'full_name': 'VNC display :1', 'category': _REMOTE,
           'risk': 'medium', 'transport': ['tcp'],
           'plain_english': 'A second VNC remote-desktop display. Same cautions as VNC.'},
    2222:  {'name': 'SSH (alt)', 'full_name': 'SSH on alternate port', 'category': _REMOTE,
           'risk': 'medium', 'transport': ['tcp'],
           'plain_english': 'Secure Shell remote login on a non-standard port. Fine if you set it up; suspicious if you did not.'},
    5985:  {'name': 'WinRM', 'full_name': 'Windows Remote Management (HTTP)', 'category': _MGMT,
           'risk': 'medium', 'transport': ['tcp'],
           'plain_english': 'Windows remote administration. Powerful — should only be seen between managed Windows machines.'},
    5986:  {'name': 'WinRM (TLS)', 'full_name': 'Windows Remote Management (HTTPS)', 'category': _MGMT,
           'risk': 'medium', 'transport': ['tcp'],
           'plain_english': 'Encrypted Windows remote administration. Same cautions as WinRM.'},
    9000:  {'name': 'Dev/App server', 'full_name': 'Common app/dev server port', 'category': _NORMAL,
           'risk': 'low', 'transport': ['tcp'],
           'plain_english': 'A catch-all used by many app frameworks and dev servers (PHP-FPM, SonarQube, etc.). Context-dependent.'},
    3000:  {'name': 'Dev server', 'full_name': 'Node/React/Grafana dev port', 'category': _NORMAL,
           'risk': 'low', 'transport': ['tcp'],
           'plain_english': 'Very common local development server port (Node, React, Grafana). Normal on a developer machine.'},
    8123:  {'name': 'Home Assistant', 'full_name': 'Home Assistant', 'category': _IOT,
           'risk': 'low', 'transport': ['tcp'],
           'plain_english': 'Home Assistant smart-home hub web interface.'},

    # ── P2P / file sharing ──
    6881:  {'name': 'BitTorrent', 'full_name': 'BitTorrent peer', 'category': _P2P,
           'risk': 'medium', 'transport': ['tcp', 'udp'],
           'plain_english': 'BitTorrent file sharing. Legal for Linux ISOs etc., but often unwanted on a household or work network.'},
    51413: {'name': 'BitTorrent', 'full_name': 'Transmission BitTorrent', 'category': _P2P,
            'risk': 'medium', 'transport': ['tcp', 'udp'],
            'plain_english': 'Default port for the Transmission BitTorrent client.'},

    # ── Databases / infrastructure sometimes unlisted ──
    6379:  {'name': 'Redis', 'full_name': 'Redis in-memory database', 'category': _DB,
           'risk': 'medium', 'transport': ['tcp'],
           'plain_english': 'Redis database. Often unauthenticated by default — an exposed Redis is a serious risk.'},
    9200:  {'name': 'Elasticsearch', 'full_name': 'Elasticsearch HTTP API', 'category': _DB,
           'risk': 'medium', 'transport': ['tcp'],
           'plain_english': 'Elasticsearch search database HTTP API. Should never be exposed to the internet unauthenticated.'},
    5432:  {'name': 'PostgreSQL', 'full_name': 'PostgreSQL database', 'category': _DB,
           'risk': 'low', 'transport': ['tcp'],
           'plain_english': 'PostgreSQL database server. Expected between apps and their database; not on the open internet.'},
    2049:  {'name': 'NFS', 'full_name': 'Network File System', 'category': _NORMAL,
           'risk': 'low', 'transport': ['tcp', 'udp'],
           'plain_english': 'Unix/Linux network file sharing. Normal on a NAS or between servers.'},

    # ── Discovery / misc common background ──
    5355:  {'name': 'LLMNR', 'full_name': 'Link-Local Multicast Name Resolution', 'category': _NORMAL,
           'risk': 'low', 'transport': ['udp'],
           'plain_english': 'Windows fallback name lookup. Common, but can be abused to steal credentials — many networks disable it.'},
    3702:  {'name': 'WS-Discovery', 'full_name': 'Web Services Discovery', 'category': _NORMAL,
           'risk': 'low', 'transport': ['udp'],
           'plain_english': 'How Windows and network printers/cameras discover each other (WSD). Very common background chatter.'},
    5357:  {'name': 'WSD (HTTP)', 'full_name': 'Web Services on Devices', 'category': _NORMAL,
           'risk': 'low', 'transport': ['tcp'],
           'plain_english': 'Windows Web Services on Devices — printer/scanner/device functions.'},
    1234:  {'name': 'Stream/misc', 'full_name': 'Common streaming/test port', 'category': _MEDIA,
           'risk': 'low', 'transport': ['udp', 'tcp'],
           'plain_english': 'Used by VLC/UDP streaming and various apps as a default. Context-dependent.'},
}


def lookup(port: int, transport: str = None) -> dict | None:
    """Return a catalogue entry for a port (optionally matching transport)."""
    e = EXTENDED_PORTS.get(port)
    if not e:
        return None
    if transport and e.get('transport') and transport.lower() not in e['transport']:
        return None
    return e
