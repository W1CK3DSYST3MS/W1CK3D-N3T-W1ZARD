"""
tools/protocol_library.py
─────────────────────────
Plain-English protocol reference library for the W1CK3D_NET_WIZARD.

Built-in entries cover the most common protocols seen in home, small-office,
and enthusiast captures.  Users can add their own entries via the app UI —
additions are stored in ~/W1CK3DWizard/protocol_library_user.json and merged
at load time.  A user entry with the same name overrides its built-in twin.

Three-tier lookup
-----------------
lookup_layer() / lookup_port()  →  full library entry or None
lookup_layer_hint()             →  lightweight hint dict or None (Tier 2)
lookup_port_iana()              →  IANA-derived hint dict or None (Tier 3)

Hint dicts carry '_hint': True so callers can render them differently from
full entries.  They have: name, plain_english, category, risk, _hint.
"""

import json
import socket
from pathlib import Path

_USER_PATH = Path.home() / 'W1CK3DWizard' / 'protocol_library_user.json'

# ── risk levels ───────────────────────────────────────────────────────────────
RISK_NONE   = 'none'
RISK_LOW    = 'low'
RISK_MEDIUM = 'medium'
RISK_HIGH   = 'high'

_RISK_ORDER = [RISK_NONE, RISK_LOW, RISK_MEDIUM, RISK_HIGH]

# ── categories ────────────────────────────────────────────────────────────────
CAT_NORMAL     = 'Normal'
CAT_MEDIA      = 'Media'
CAT_IOT        = 'IoT'
CAT_VOIP       = 'VoIP'
CAT_VPN        = 'VPN'
CAT_REMOTE     = 'Remote Access'
CAT_DATABASE   = 'Database'
CAT_MANAGEMENT = 'Management'
CAT_INDUSTRIAL = 'Industrial'
CAT_LEGACY     = 'Legacy'
CAT_P2P        = 'P2P'
CAT_EMAIL      = 'Email'
CAT_PRINT      = 'Printing'
CAT_MEDIA_SRV  = 'Media Server'

ALL_CATEGORIES = [
    CAT_NORMAL, CAT_EMAIL, CAT_MEDIA, CAT_MEDIA_SRV, CAT_PRINT,
    CAT_IOT, CAT_VOIP, CAT_VPN, CAT_REMOTE,
    CAT_DATABASE, CAT_MANAGEMENT, CAT_INDUSTRIAL,
    CAT_LEGACY, CAT_P2P,
]

_B = False  # user_added shorthand

# ── built-in protocol entries ─────────────────────────────────────────────────
BUILTIN_PROTOCOLS = [

    # ── Normal / Infrastructure ───────────────────────────────────────────────
    {
        'name': 'HTTPS',
        'full_name': 'Hypertext Transfer Protocol Secure',
        'ports': [443],
        'transport': ['tcp'],
        'layer_names': ['tls', 'ssl', 'http2'],
        'category': CAT_NORMAL,
        'risk': RISK_NONE,
        'plain_english': (
            'Encrypted web traffic. Every website with a padlock — online banking, '
            'shopping, email, social media — uses HTTPS. The content is encrypted '
            'so only you and the server can read it.'
        ),
        'expected_when': 'Always. Any device browsing the web or talking to online services generates HTTPS.',
        'unexpected_when': 'HTTPS itself is never suspicious, but the destination IP may be. Investigate unfamiliar destinations.',
        'action': 'Use the Investigate tab to look up unfamiliar destination IPs.',
        'user_added': _B,
    },
    {
        'name': 'HTTP',
        'full_name': 'Hypertext Transfer Protocol (Unencrypted)',
        'ports': [80, 8080, 8000, 8888],
        'transport': ['tcp'],
        'layer_names': ['http'],
        'category': CAT_NORMAL,
        'risk': RISK_LOW,
        'plain_english': (
            'Unencrypted web traffic. HTTP is the older version of HTTPS — no encryption. '
            'Any data sent over HTTP, including login credentials, can be read by anyone '
            'watching the network.'
        ),
        'expected_when': 'Older websites, internal admin panels, some IoT devices that do not support HTTPS.',
        'unexpected_when': 'Login credentials sent over HTTP are a serious risk. The Findings tab will flag these.',
        'action': 'Check if the destination supports HTTPS and switch. Never log into anything over HTTP on a shared network.',
        'user_added': _B,
    },
    {
        'name': 'DNS',
        'full_name': 'Domain Name System',
        'ports': [53],
        'transport': ['udp', 'tcp'],
        'layer_names': ['dns'],
        'category': CAT_NORMAL,
        'risk': RISK_NONE,
        'plain_english': (
            'The internet\'s phone book. Every time a device visits a website it first '
            'asks a DNS server to translate the domain name (e.g. google.com) into an IP '
            'address. DNS is generated constantly by every networked device.'
        ),
        'expected_when': 'Always — every device generates DNS queries whenever it uses the internet.',
        'unexpected_when': 'Unusually long query labels or highly random-looking subdomains. The Findings tab flags these automatically.',
        'action': 'Review the Findings tab for DNS-related security alerts.',
        'user_added': _B,
    },
    {
        'name': 'DNS over HTTPS (DoH)',
        'full_name': 'DNS over HTTPS',
        'ports': [853],
        'transport': ['tcp'],
        'layer_names': ['dot'],
        'category': CAT_NORMAL,
        'risk': RISK_NONE,
        'plain_english': (
            'An encrypted form of DNS. Instead of sending DNS queries in plain text, '
            'DoH and DNS over TLS (DoT) encrypt them so your ISP or others on the '
            'network cannot see which domains you are looking up. Used by modern browsers '
            'and privacy-focused DNS resolvers like Cloudflare 1.1.1.1.'
        ),
        'expected_when': 'Devices using privacy-focused DNS resolvers or browsers with DoH enabled.',
        'unexpected_when': 'Rarely suspicious — it is a privacy improvement. May bypass network-level DNS filtering.',
        'action': 'No action required unless you rely on DNS-based content filtering, in which case check whether DoH is bypassing it.',
        'user_added': _B,
    },
    {
        'name': 'DHCP',
        'full_name': 'Dynamic Host Configuration Protocol',
        'ports': [67, 68],
        'transport': ['udp'],
        'layer_names': ['dhcp', 'bootp'],
        'category': CAT_NORMAL,
        'risk': RISK_NONE,
        'plain_english': (
            'How devices get their IP address. When a device joins a network it broadcasts '
            'a DHCP request, and the router replies with an IP address, subnet mask, '
            'gateway, and DNS server to use.'
        ),
        'expected_when': 'Any time a device joins the network or its IP lease expires.',
        'unexpected_when': 'Multiple different DHCP servers responding could indicate a rogue DHCP server.',
        'action': 'If you see unexpected DHCP responses, check the Devices tab to identify the source.',
        'user_added': _B,
    },
    {
        'name': 'NTP',
        'full_name': 'Network Time Protocol',
        'ports': [123],
        'transport': ['udp'],
        'layer_names': ['ntp'],
        'category': CAT_NORMAL,
        'risk': RISK_NONE,
        'plain_english': (
            'Keeps clocks accurate. All internet-connected devices periodically check the '
            'time with an NTP server so their clocks stay synchronised. Accurate time is '
            'essential for security certificates, logs, and authentication.'
        ),
        'expected_when': 'Always — every device with internet access uses NTP.',
        'unexpected_when': 'Very high volumes of NTP traffic from a single device can indicate NTP amplification abuse.',
        'action': 'Usually safe to ignore. If NTP volume is very high, check which device is responsible.',
        'user_added': _B,
    },
    {
        'name': 'mDNS / Bonjour',
        'full_name': 'Multicast DNS / Apple Bonjour',
        'ports': [5353],
        'transport': ['udp'],
        'layer_names': ['mdns'],
        'category': CAT_NORMAL,
        'risk': RISK_NONE,
        'plain_english': (
            'Zero-configuration device discovery. mDNS lets devices find each other on '
            'the local network without needing a DNS server — it is how your Mac finds '
            'a printer, how a phone discovers a Chromecast, and how smart speakers '
            'announce themselves. Apple calls it Bonjour; it is also built into Android, '
            'Windows 10+, and Linux (Avahi). Traffic stays local and is completely normal.'
        ),
        'expected_when': 'Any Apple, Google, or smart home device on the network — practically universal on modern networks.',
        'unexpected_when': 'mDNS leaking outside the local subnet (should never cross routers). Very high volumes from one device.',
        'action': 'No action required in normal use. If you want to isolate device discovery between VLANs, block multicast 224.0.0.251 at the router.',
        'user_added': _B,
    },
    {
        'name': 'ICMP',
        'full_name': 'Internet Control Message Protocol (Ping)',
        'ports': [],
        'transport': [],
        'layer_names': ['icmp', 'icmpv6'],
        'category': CAT_NORMAL,
        'risk': RISK_NONE,
        'plain_english': (
            'Network diagnostics — the protocol behind the "ping" command. Used to check '
            'whether another device is reachable and measure network latency. Routers also '
            'use ICMP to report errors back to senders.'
        ),
        'expected_when': 'Occasional pings from devices checking connectivity or network tools.',
        'unexpected_when': 'Very high volumes from a single device can indicate a ping flood or reconnaissance sweep.',
        'action': 'Check the Devices tab if ICMP volume is unusually high from one source.',
        'user_added': _B,
    },
    {
        'name': 'IGMP',
        'full_name': 'Internet Group Management Protocol',
        'ports': [],
        'transport': [],
        'layer_names': ['igmp'],
        'category': CAT_NORMAL,
        'risk': RISK_NONE,
        'plain_english': (
            'Manages multicast group memberships on a local network. IGMP is how devices '
            'tell their router "I want to receive multicast traffic for this group". '
            'You see it whenever a device joins or leaves a multicast group — for example '
            'when watching multicast IPTV, using mDNS, or running certain streaming apps.'
        ),
        'expected_when': 'Any network with multicast traffic: IPTV, streaming apps, mDNS, UPnP, or network gaming.',
        'unexpected_when': 'Rarely suspicious on its own.',
        'action': 'No action required. High volumes can indicate a multicast-heavy application.',
        'user_added': _B,
    },
    {
        'name': 'QUIC',
        'full_name': 'Quick UDP Internet Connections (HTTP/3)',
        'ports': [443],
        'transport': ['udp'],
        'layer_names': ['quic', 'gquic'],
        'category': CAT_NORMAL,
        'risk': RISK_NONE,
        'plain_english': (
            'A modern encrypted transport protocol that makes web connections faster. '
            'QUIC runs over UDP instead of TCP. Chrome, YouTube, Google Drive, Cloudflare, '
            'and most modern browsers and apps use it by default. gQUIC is the older '
            'Google-proprietary variant; "QUIC" refers to the IETF-standardised version '
            'that powers HTTP/3.'
        ),
        'expected_when': 'Any device using Chrome, YouTube, Google services, or modern apps. Completely normal.',
        'unexpected_when': 'QUIC to destinations that are not Google, Cloudflare, or other major CDNs is worth checking.',
        'action': 'Use the Investigate tab to look up unfamiliar destination IPs.',
        'user_added': _B,
    },
    {
        'name': 'STUN / TURN',
        'full_name': 'Session Traversal Utilities for NAT',
        'ports': [3478, 3479, 5349],
        'transport': ['udp', 'tcp'],
        'layer_names': ['stun'],
        'category': CAT_NORMAL,
        'risk': RISK_NONE,
        'plain_english': (
            'A helper protocol that lets devices behind a NAT (like your router) establish '
            'direct peer-to-peer connections. Used heavily by video calling apps — WhatsApp, '
            'FaceTime, Zoom, Teams, WebRTC — to connect callers directly without a relay server.'
        ),
        'expected_when': 'Any device using video calling, WebRTC apps, or peer-to-peer gaming features.',
        'unexpected_when': 'Rarely suspicious — it is normal infrastructure for real-time communication.',
        'action': 'Usually safe to ignore. High sustained volumes may indicate a leaking video call.',
        'user_added': _B,
    },
    {
        'name': 'DTLS',
        'full_name': 'Datagram Transport Layer Security',
        'ports': [],
        'transport': ['udp'],
        'layer_names': ['dtls'],
        'category': CAT_NORMAL,
        'risk': RISK_NONE,
        'plain_english': (
            'TLS encryption applied to UDP traffic. Where TLS encrypts TCP connections, '
            'DTLS does the same for UDP-based protocols. Used by WebRTC, secure VoIP '
            '(DTLS-SRTP), and some VPN implementations.'
        ),
        'expected_when': 'Video calling, WebRTC, secure VoIP, or UDP-based encrypted protocols.',
        'unexpected_when': 'Rarely suspicious on its own.',
        'action': 'Check what application is generating DTLS traffic if unexpected.',
        'user_added': _B,
    },
    {
        'name': 'GRE Tunnel',
        'full_name': 'Generic Routing Encapsulation',
        'ports': [],
        'transport': [],
        'layer_names': ['gre'],
        'category': CAT_VPN,
        'risk': RISK_LOW,
        'plain_english': (
            'A tunnelling protocol that wraps one network protocol inside another. '
            'GRE is used in many VPN implementations (especially PPTP and some corporate '
            'VPNs), router-to-router tunnels, and network overlays. The tunnel itself '
            'provides no encryption — it is usually paired with IPSec for security.'
        ),
        'expected_when': 'Corporate network tunnels, PPTP VPN, or routers configured with GRE tunnels.',
        'unexpected_when': 'GRE from a workstation or IoT device without a known VPN configuration.',
        'action': 'Identify the source device and confirm the tunnel is intentional. GRE without encryption is plaintext.',
        'user_added': _B,
    },
    {
        'name': 'LLDP',
        'full_name': 'Link Layer Discovery Protocol',
        'ports': [],
        'transport': [],
        'layer_names': ['lldp'],
        'category': CAT_MANAGEMENT,
        'risk': RISK_NONE,
        'plain_english': (
            'A vendor-neutral protocol that lets network devices — switches, routers, '
            'access points, IP phones — advertise their identity and capabilities to '
            'their directly-connected neighbours. Used by network management tools to '
            'automatically build network maps.'
        ),
        'expected_when': 'Managed switches, enterprise access points, IP phones, and routers.',
        'unexpected_when': 'Rarely suspicious — it can reveal network topology to anyone capturing traffic on the segment.',
        'action': 'Consider disabling LLDP on ports connected to untrusted devices or public-facing segments.',
        'user_added': _B,
    },

    # ── Email ─────────────────────────────────────────────────────────────────
    {
        'name': 'SMTP',
        'full_name': 'Simple Mail Transfer Protocol',
        'ports': [25, 587, 465],
        'transport': ['tcp'],
        'layer_names': ['smtp'],
        'category': CAT_EMAIL,
        'risk': RISK_MEDIUM,
        'plain_english': (
            'How email is sent. Port 25 is used between mail servers. Port 587 is the '
            'submission port for email clients — it requires authentication. Port 465 '
            'is SMTP over TLS (SMTPS). Any device sending email generates SMTP traffic.'
        ),
        'expected_when': 'Mail servers, email clients (Outlook, Thunderbird), and email relay services.',
        'unexpected_when': 'SMTP on port 25 from a workstation or IoT device (not a mail server) indicates the device may be sending spam or is part of a botnet.',
        'action': 'Investigate any SMTP traffic from devices that should not be mail servers. Block outbound port 25 at the firewall for all devices except designated mail servers.',
        'user_added': _B,
    },
    {
        'name': 'IMAP',
        'full_name': 'Internet Message Access Protocol',
        'ports': [143, 993],
        'transport': ['tcp'],
        'layer_names': ['imap'],
        'category': CAT_EMAIL,
        'risk': RISK_LOW,
        'plain_english': (
            'How email clients retrieve messages from a mail server while keeping them '
            'on the server. IMAP is the modern standard — your email client downloads '
            'what it needs but the messages stay on the server so you can access them '
            'from multiple devices. Port 143 is unencrypted; 993 is IMAP over TLS (IMAPS).'
        ),
        'expected_when': 'Email clients (Outlook, Thunderbird, Apple Mail) connecting to a mail server.',
        'unexpected_when': 'Unencrypted IMAP (port 143) transmitting credentials or messages in plain text.',
        'action': 'Ensure your email client uses port 993 (IMAPS) with TLS. Avoid port 143 on untrusted networks.',
        'user_added': _B,
    },
    {
        'name': 'POP3',
        'full_name': 'Post Office Protocol 3',
        'ports': [110, 995],
        'transport': ['tcp'],
        'layer_names': ['pop'],
        'category': CAT_EMAIL,
        'risk': RISK_LOW,
        'plain_english': (
            'An older protocol for downloading email from a server. Unlike IMAP, POP3 '
            'downloads and deletes messages from the server, making multi-device access '
            'difficult. Port 110 is unencrypted; port 995 is POP3 over TLS (POP3S). '
            'Largely superseded by IMAP for modern use.'
        ),
        'expected_when': 'Older email clients or configurations that download mail via POP3.',
        'unexpected_when': 'Unencrypted POP3 (port 110) transmitting passwords in plain text.',
        'action': 'Switch to IMAP (993) if possible. If POP3 is needed, use port 995 (POP3S) with TLS.',
        'user_added': _B,
    },

    # ── Media / Streaming ─────────────────────────────────────────────────────
    {
        'name': 'RTSP',
        'full_name': 'Real Time Streaming Protocol',
        'ports': [554, 8554],
        'transport': ['tcp', 'udp'],
        'layer_names': ['rtsp'],
        'category': CAT_MEDIA,
        'risk': RISK_LOW,
        'plain_english': (
            'Used by IP cameras, security NVRs, and video streaming devices to send live '
            'video over a network. When you watch a camera feed on your phone or NVR '
            'screen, it is likely using RTSP under the hood.'
        ),
        'expected_when': 'You have IP security cameras, a Network Video Recorder (NVR), or RTSP-capable streaming devices.',
        'unexpected_when': 'If you have no cameras, an unexpected RTSP stream could mean an unauthorised device is streaming video.',
        'action': 'Check the Devices tab to identify the RTSP source. If unrecognised, investigate its IP immediately.',
        'user_added': _B,
    },
    {
        'name': 'RTP',
        'full_name': 'Real-time Transport Protocol',
        'ports': [],
        'transport': ['udp'],
        'layer_names': ['rtp'],
        'category': CAT_MEDIA,
        'risk': RISK_NONE,
        'plain_english': (
            'Carries the actual audio and video data in real-time calls and streams. '
            'RTP works alongside RTSP and SIP — those protocols set up the session, '
            'RTP carries the media itself. Active during any VoIP call or IP camera stream.'
        ),
        'expected_when': 'Active VoIP calls, IP camera streams, or video conferencing.',
        'unexpected_when': 'RTP traffic to external IPs you do not recognise could indicate an unauthorised stream.',
        'action': 'Pair with RTSP or SIP entries to identify the source. Investigate unfamiliar destination IPs.',
        'user_added': _B,
    },
    {
        'name': 'RTMP',
        'full_name': 'Real-Time Messaging Protocol',
        'ports': [1935],
        'transport': ['tcp'],
        'layer_names': ['rtmp'],
        'category': CAT_MEDIA,
        'risk': RISK_LOW,
        'plain_english': (
            'Used for live video streaming — most commonly OBS Studio streaming to '
            'Twitch, YouTube Live, or Facebook Live. Also used by some security cameras '
            'and media servers for outbound streaming.'
        ),
        'expected_when': 'You are live streaming with OBS, Streamlabs, or similar software.',
        'unexpected_when': 'RTMP traffic from a device not running streaming software. Could be a device sending data to an external server.',
        'action': 'Identify the source device. Investigate the destination IP to confirm it is a known streaming platform.',
        'user_added': _B,
    },

    # ── Media Servers ─────────────────────────────────────────────────────────
    {
        'name': 'Plex Media Server',
        'full_name': 'Plex Media Server',
        'ports': [32400],
        'transport': ['tcp'],
        'layer_names': [],
        'category': CAT_MEDIA_SRV,
        'risk': RISK_LOW,
        'plain_english': (
            'A personal media server that organises and streams your video, music, and photo '
            'collections to devices anywhere. Port 32400 is the main Plex web interface and '
            'API used by Plex apps on phones, TVs, and Roku devices.'
        ),
        'expected_when': 'You run Plex Media Server on a computer or NAS.',
        'unexpected_when': 'Plex on a device you did not set up as a media server.',
        'action': 'If Plex is internet-accessible, ensure your Plex account is secured with 2FA. Review which devices have access in Plex settings.',
        'user_added': _B,
    },
    {
        'name': 'Google Cast',
        'full_name': 'Google Cast Protocol (Chromecast)',
        'ports': [8008, 8009, 8443],
        'transport': ['tcp'],
        'layer_names': ['cast'],
        'category': CAT_MEDIA_SRV,
        'risk': RISK_NONE,
        'plain_english': (
            'The protocol used by Chromecast devices and Cast-enabled speakers (Google Home, '
            'Nest Audio). When you "cast" a video from your phone or laptop, your device '
            'uses Google Cast on port 8008/8009 to tell the Chromecast what to play. '
            'Port 8443 is the encrypted Cast interface on newer devices.'
        ),
        'expected_when': 'You own a Chromecast, Google TV, Google Home, Nest speaker, or Android TV device.',
        'unexpected_when': 'Cast traffic to an unexpected IP (it should stay on your local network).',
        'action': 'No action needed on a home network. If on a shared network, be aware others may be able to cast to your device.',
        'user_added': _B,
    },
    {
        'name': 'AirPlay',
        'full_name': 'Apple AirPlay',
        'ports': [7000, 7100, 49152],
        'transport': ['tcp'],
        'layer_names': [],
        'category': CAT_MEDIA_SRV,
        'risk': RISK_NONE,
        'plain_english': (
            'Apple\'s wireless audio and video streaming protocol. AirPlay lets iPhones, '
            'iPads, and Macs stream audio or mirror their screen to Apple TV, HomePod, '
            'or AirPlay-compatible speakers and TVs. Traffic is local-network-only.'
        ),
        'expected_when': 'Apple devices on the network streaming to Apple TV, HomePod, or AirPlay speakers.',
        'unexpected_when': 'AirPlay traffic to unexpected IP addresses.',
        'action': 'Enable AirPlay password protection on your Apple TV or speaker to prevent unauthorised casting.',
        'user_added': _B,
    },

    # ── Printing ──────────────────────────────────────────────────────────────
    {
        'name': 'IPP / CUPS',
        'full_name': 'Internet Printing Protocol',
        'ports': [631],
        'transport': ['tcp'],
        'layer_names': ['ipp'],
        'category': CAT_PRINT,
        'risk': RISK_LOW,
        'plain_english': (
            'The standard protocol for sending print jobs to modern printers. IPP is used '
            'by CUPS (the print system on macOS and Linux) and by most modern network '
            'printers and print servers. Port 631 is also used by the CUPS web admin '
            'interface on Linux.'
        ),
        'expected_when': 'Any device printing to a network printer — normal on most office and home networks.',
        'unexpected_when': 'IPP accessible from the internet could expose the printer admin interface.',
        'action': 'Ensure CUPS/printer admin is not accessible from outside your network. Keep printer firmware updated.',
        'user_added': _B,
    },
    {
        'name': 'JetDirect / Raw Printing',
        'full_name': 'HP JetDirect Raw Printing (Port 9100)',
        'ports': [9100],
        'transport': ['tcp'],
        'layer_names': [],
        'category': CAT_PRINT,
        'risk': RISK_LOW,
        'plain_english': (
            'A simple raw TCP protocol for sending print data directly to a printer — '
            'pioneered by HP JetDirect cards but now supported by almost all network '
            'printers. Most Windows and Linux systems use port 9100 for direct printer '
            'communication when not using IPP.'
        ),
        'expected_when': 'Printing to a network printer.',
        'unexpected_when': 'Port 9100 open on a device that is not a printer, or accessible from the internet.',
        'action': 'Block port 9100 from internet access. Keep printer firmware updated — printers with internet-facing port 9100 have been exploited.',
        'user_added': _B,
    },
    {
        'name': 'LPD / LPR',
        'full_name': 'Line Printer Daemon Protocol',
        'ports': [515],
        'transport': ['tcp'],
        'layer_names': ['lpd'],
        'category': CAT_PRINT,
        'risk': RISK_LOW,
        'plain_english': (
            'An older Unix printing protocol. LPD (port 515) was the standard way Unix '
            'and Linux systems submitted print jobs before IPP became common. Still used '
            'by some older printers and legacy print server configurations.'
        ),
        'expected_when': 'Older network printers or legacy Unix/Linux print queues.',
        'unexpected_when': 'LPD on a modern network without legacy printers is unusual.',
        'action': 'Prefer IPP (port 631) on modern printers. Ensure port 515 is not internet-accessible.',
        'user_added': _B,
    },

    # ── IoT ───────────────────────────────────────────────────────────────────
    {
        'name': 'MQTT',
        'full_name': 'Message Queuing Telemetry Transport',
        'ports': [1883, 8883],
        'transport': ['tcp'],
        'layer_names': ['mqtt'],
        'category': CAT_IOT,
        'risk': RISK_MEDIUM,
        'plain_english': (
            'The dominant messaging protocol for IoT devices. MQTT uses a publish/subscribe '
            'model — devices publish sensor data to a "broker" (server), and other devices '
            'or apps subscribe to receive it. Used by Home Assistant, Node-RED, Zigbee2MQTT, '
            'Tasmota smart plugs, and most DIY home automation. Port 1883 is unencrypted; '
            '8883 is MQTT over TLS.'
        ),
        'expected_when': 'Home automation hubs, smart plugs, environmental sensors, or any DIY IoT project.',
        'unexpected_when': 'MQTT broker accessible from the internet without authentication is a serious security risk.',
        'action': 'Never expose your MQTT broker (port 1883) to the internet. Enable username/password authentication and TLS (port 8883). Restrict which devices can publish/subscribe.',
        'user_added': _B,
    },
    {
        'name': 'SSDP / UPnP',
        'full_name': 'Simple Service Discovery Protocol / Universal Plug and Play',
        'ports': [1900],
        'transport': ['udp'],
        'layer_names': ['ssdp'],
        'category': CAT_IOT,
        'risk': RISK_LOW,
        'plain_english': (
            'Device discovery for the local network. SSDP is the discovery layer of UPnP — '
            'devices broadcast their presence and capabilities so other devices can find '
            'and use them automatically. Smart TVs, game consoles, printers, routers, '
            'media players, and most smart home devices advertise via SSDP.'
        ),
        'expected_when': 'Very common — most smart home devices, printers, smart TVs, and game consoles broadcast SSDP.',
        'unexpected_when': 'External SSDP traffic coming in from the internet is a risk. UPnP auto-opening unexpected ports.',
        'action': 'Consider disabling UPnP on your router if you do not need automatic port forwarding. Check router settings for unexpected UPnP port forwards.',
        'user_added': _B,
    },
    {
        'name': 'CoAP',
        'full_name': 'Constrained Application Protocol',
        'ports': [5683, 5684],
        'transport': ['udp'],
        'layer_names': ['coap'],
        'category': CAT_IOT,
        'risk': RISK_LOW,
        'plain_english': (
            'A lightweight protocol for very small IoT devices — sensors, actuators, '
            'and other constrained hardware that cannot handle full HTTP. Think of it '
            'as a stripped-down version of HTTP for tiny devices. Port 5684 is the '
            'encrypted (DTLS) version.'
        ),
        'expected_when': 'Low-power IoT sensors, some smart home devices, embedded systems.',
        'unexpected_when': 'Rarely seen on standard home networks. Unexpected CoAP — identify the source.',
        'action': 'Check which device is generating CoAP in the Devices tab. Prefer port 5684 (encrypted) over 5683.',
        'user_added': _B,
    },
    {
        'name': 'Android Debug Bridge',
        'full_name': 'Android Debug Bridge (ADB)',
        'ports': [5555],
        'transport': ['tcp'],
        'layer_names': [],
        'category': CAT_REMOTE,
        'risk': RISK_HIGH,
        'plain_english': (
            'A developer tool for controlling Android devices over a network. ADB over TCP '
            '(port 5555) lets a computer issue commands, install apps, and access files '
            'on an Android phone or tablet — with no authentication required by default. '
            'Attackers actively scan for open ADB ports to install malware or mine crypto '
            'on Android devices.'
        ),
        'expected_when': 'A developer deliberately enabling ADB over WiFi on an Android device for testing.',
        'unexpected_when': 'Any ADB traffic from a non-developer device. Any ADB traffic to or from the internet.',
        'action': 'Immediately disable ADB over WiFi on all Android devices unless you are actively developing: Developer Options → Wireless debugging → OFF. If unexpected, the device may be compromised.',
        'user_added': _B,
    },

    # ── VoIP ──────────────────────────────────────────────────────────────────
    {
        'name': 'SIP',
        'full_name': 'Session Initiation Protocol',
        'ports': [5060, 5061],
        'transport': ['tcp', 'udp'],
        'layer_names': ['sip'],
        'category': CAT_VOIP,
        'risk': RISK_LOW,
        'plain_english': (
            'The signalling protocol for VoIP (internet phone calls). SIP sets up, manages, '
            'and tears down voice and video calls. Once a call is established, the audio '
            'travels over RTP. Port 5060 is unencrypted; 5061 uses TLS.'
        ),
        'expected_when': 'You have a VoIP phone system, IP desk phones, or use a softphone application.',
        'unexpected_when': 'SIP scanning from external IPs — a common precursor to toll fraud attacks on PBX systems.',
        'action': 'Verify the source is a known VoIP device. Switch to port 5061 (TLS) where possible. Investigate any external SIP traffic.',
        'user_added': _B,
    },
    {
        'name': 'H.323',
        'full_name': 'H.323 Video Conferencing Protocol',
        'ports': [1720],
        'transport': ['tcp'],
        'layer_names': ['h323', 'h225'],
        'category': CAT_VOIP,
        'risk': RISK_LOW,
        'plain_english': (
            'An older video conferencing standard used by legacy video conferencing hardware '
            'and some older VoIP equipment. Largely replaced by SIP and modern protocols '
            'like those used by Zoom and Teams.'
        ),
        'expected_when': 'Older corporate video conferencing hardware, legacy VoIP PBX systems.',
        'unexpected_when': 'H.323 on a home network without specific hardware is unusual.',
        'action': 'Identify the device using H.323. Consider whether a modern replacement (SIP-based) is feasible.',
        'user_added': _B,
    },

    # ── VPN / Tunnelling ──────────────────────────────────────────────────────
    {
        'name': 'WireGuard',
        'full_name': 'WireGuard VPN Protocol',
        'ports': [51820],
        'transport': ['udp'],
        'layer_names': ['wireguard'],
        'category': CAT_VPN,
        'risk': RISK_NONE,
        'plain_english': (
            'A modern, fast, and highly secure VPN protocol. Used by Mullvad, ProtonVPN, '
            'and many self-hosted VPN setups. WireGuard creates encrypted tunnels between '
            'devices — either for remote access or privacy.'
        ),
        'expected_when': 'You or someone on the network uses a WireGuard-based VPN.',
        'unexpected_when': 'WireGuard from a device you did not configure with a VPN.',
        'action': 'Confirm the source device intentionally uses WireGuard. Investigate the destination IP.',
        'user_added': _B,
    },
    {
        'name': 'OpenVPN',
        'full_name': 'OpenVPN',
        'ports': [1194],
        'transport': ['udp', 'tcp'],
        'layer_names': ['openvpn'],
        'category': CAT_VPN,
        'risk': RISK_NONE,
        'plain_english': (
            'A widely-used open-source VPN protocol. Creates encrypted tunnels for secure '
            'remote access or privacy. Used by NordVPN, ExpressVPN, and many corporate VPNs.'
        ),
        'expected_when': 'A device on the network is connected to a VPN service or corporate VPN.',
        'unexpected_when': 'VPN traffic from a device you did not configure with a VPN.',
        'action': 'Confirm the source device is intentionally using a VPN. Investigate the destination IP.',
        'user_added': _B,
    },
    {
        'name': 'IPSec / IKE',
        'full_name': 'IP Security / Internet Key Exchange',
        'ports': [500, 4500],
        'transport': ['udp'],
        'layer_names': ['isakmp', 'esp'],
        'category': CAT_VPN,
        'risk': RISK_NONE,
        'plain_english': (
            'A suite of protocols for encrypting IP traffic at the network level. Used by '
            'many corporate VPNs, iOS/macOS built-in VPN (IKEv2), and site-to-site VPN '
            'tunnels between offices or routers.'
        ),
        'expected_when': 'Corporate VPN connections, iOS/macOS IKEv2 or L2TP/IPSec VPN, router-to-router VPN tunnels.',
        'unexpected_when': 'IPSec traffic you did not configure could indicate an unauthorised VPN tunnel.',
        'action': 'Confirm the source device and destination are expected VPN endpoints.',
        'user_added': _B,
    },
    {
        'name': 'L2TP',
        'full_name': 'Layer 2 Tunnelling Protocol',
        'ports': [1701],
        'transport': ['udp'],
        'layer_names': ['l2tp'],
        'category': CAT_VPN,
        'risk': RISK_LOW,
        'plain_english': (
            'A VPN tunnelling protocol commonly used with IPSec for encryption (L2TP/IPSec). '
            'Built into Windows, macOS, iOS, and Android as an optional VPN type. L2TP '
            'itself provides no encryption — it relies entirely on IPSec for security. '
            'Older and slower than WireGuard or OpenVPN, but universally supported.'
        ),
        'expected_when': 'Devices configured to use L2TP/IPSec VPN (often older corporate or ISP VPNs).',
        'unexpected_when': 'L2TP without accompanying IPSec traffic (unencrypted tunnel).',
        'action': 'Prefer WireGuard or OpenVPN for new VPN setups — they are faster and more secure.',
        'user_added': _B,
    },
    {
        'name': 'ZeroTier',
        'full_name': 'ZeroTier Virtual Network',
        'ports': [9993],
        'transport': ['udp'],
        'layer_names': [],
        'category': CAT_VPN,
        'risk': RISK_LOW,
        'plain_english': (
            'A software-defined networking platform that creates encrypted virtual networks '
            'between devices anywhere on the internet. Used for remote access, gaming with '
            'friends (virtual LAN), or connecting distributed networks without a traditional VPN server.'
        ),
        'expected_when': 'You use ZeroTier for remote access or virtual LAN.',
        'unexpected_when': 'ZeroTier from a device you did not configure.',
        'action': 'Confirm the source device is intentionally using ZeroTier. Check which network ID it is joining.',
        'user_added': _B,
    },
    {
        'name': 'Tailscale',
        'full_name': 'Tailscale Mesh VPN',
        'ports': [41641],
        'transport': ['udp'],
        'layer_names': [],
        'category': CAT_VPN,
        'risk': RISK_NONE,
        'plain_english': (
            'A modern mesh VPN service built on WireGuard. Tailscale creates a private '
            'network between your devices that works like a local network regardless of '
            'physical location. Very popular for home labs and remote access.'
        ),
        'expected_when': 'You use Tailscale for device connectivity or remote access.',
        'unexpected_when': 'Tailscale from a device you did not configure.',
        'action': 'Check your Tailscale admin console for connected devices.',
        'user_added': _B,
    },

    # ── Remote Access ─────────────────────────────────────────────────────────
    {
        'name': 'SSH',
        'full_name': 'Secure Shell',
        'ports': [22],
        'transport': ['tcp'],
        'layer_names': ['ssh'],
        'category': CAT_REMOTE,
        'risk': RISK_LOW,
        'plain_english': (
            'Encrypted remote terminal access. SSH lets you log into and control another '
            'computer over the network with full encryption. Used by system administrators '
            'to manage servers, and by developers working on remote machines.'
        ),
        'expected_when': 'You manage Linux/Unix servers, network equipment, a Raspberry Pi, or NAS with SSH enabled.',
        'unexpected_when': 'SSH from a device that should not be connecting to servers, or SSH from external IPs to internal devices.',
        'action': 'Confirm source and destination are expected. If SSH is internet-facing, use key-based authentication and disable password login.',
        'user_added': _B,
    },
    {
        'name': 'RDP',
        'full_name': 'Remote Desktop Protocol',
        'ports': [3389],
        'transport': ['tcp'],
        'layer_names': ['rdp'],
        'category': CAT_REMOTE,
        'risk': RISK_MEDIUM,
        'plain_english': (
            'Windows remote desktop. RDP lets you see and control another Windows computer '
            'as if you were sitting in front of it. Used by IT support, remote workers, '
            'and system administrators.'
        ),
        'expected_when': 'You use Windows Remote Desktop on your local network or to a work server via VPN.',
        'unexpected_when': 'RDP traffic to or from internet IPs. RDP exposed to the internet is one of the most common ransomware entry points.',
        'action': 'Ensure RDP is NOT exposed to the internet (no port forwarding to 3389). Use it only via VPN. Enable Network Level Authentication (NLA).',
        'user_added': _B,
    },
    {
        'name': 'VNC',
        'full_name': 'Virtual Network Computing',
        'ports': [5900, 5901, 5902],
        'transport': ['tcp'],
        'layer_names': ['vnc'],
        'category': CAT_REMOTE,
        'risk': RISK_MEDIUM,
        'plain_english': (
            'A cross-platform remote desktop tool. VNC lets you control another computer\'s '
            'desktop remotely — works on Windows, macOS, and Linux. Also used by some '
            'IoT devices and NAS units for administration.'
        ),
        'expected_when': 'You use VNC to remotely access computers on your local network.',
        'unexpected_when': 'VNC over the internet without a VPN is high risk. Many VNC implementations have weak or no authentication.',
        'action': 'Ensure VNC is not exposed to the internet. Use a VPN if remote access is needed. Enable password protection and TLS where available.',
        'user_added': _B,
    },
    {
        'name': 'Telnet',
        'full_name': 'Telnet Remote Terminal (Unencrypted)',
        'ports': [23],
        'transport': ['tcp'],
        'layer_names': ['telnet'],
        'category': CAT_REMOTE,
        'risk': RISK_HIGH,
        'plain_english': (
            'An ancient and completely unencrypted remote terminal protocol. Telnet sends '
            'every keystroke — including usernames and passwords — in plain text across '
            'the network. Anyone capturing traffic can read everything. Replaced by SSH '
            'in the 1990s but still active on some IoT devices, routers, and industrial '
            'equipment by default.'
        ),
        'expected_when': 'Almost never — only very old or misconfigured equipment uses Telnet intentionally.',
        'unexpected_when': 'Any Telnet traffic is a concern. Many Mirai botnet variants exploit Telnet with default credentials to hijack IoT devices.',
        'action': 'Disable Telnet on all devices and switch to SSH. Change default credentials on any device with Telnet enabled. The Findings tab will flag active Telnet.',
        'user_added': _B,
    },
    {
        'name': 'FTP',
        'full_name': 'File Transfer Protocol',
        'ports': [21, 20],
        'transport': ['tcp'],
        'layer_names': ['ftp', 'ftp-data'],
        'category': CAT_REMOTE,
        'risk': RISK_HIGH,
        'plain_english': (
            'An old file transfer protocol that sends data — and login credentials — '
            'in plain text. Port 21 is the FTP control channel (login, commands); '
            'port 20 is used for the data transfer itself in active mode. FTP has no '
            'encryption whatsoever. Replaced by SFTP (over SSH) and FTPS (FTP over TLS) '
            'for any situation where security matters.'
        ),
        'expected_when': 'Legacy file servers, some older NAS devices, or specific industrial equipment.',
        'unexpected_when': 'FTP is almost always worth investigating — most modern systems have no reason to use it.',
        'action': 'Switch to SFTP (port 22) or FTPS (port 990) immediately. Never use plain FTP on a shared or internet-connected network.',
        'user_added': _B,
    },
    {
        'name': 'TFTP',
        'full_name': 'Trivial File Transfer Protocol',
        'ports': [69],
        'transport': ['udp'],
        'layer_names': ['tftp'],
        'category': CAT_MANAGEMENT,
        'risk': RISK_MEDIUM,
        'plain_english': (
            'A stripped-down file transfer protocol with no authentication, no directory '
            'listing, and no security. TFTP is used to boot network devices — routers, '
            'switches, IP phones, and thin clients often use TFTP to download their '
            'firmware or configuration from a server on startup.'
        ),
        'expected_when': 'Network equipment booting via PXE, VoIP phones provisioning, or managed switch firmware updates.',
        'unexpected_when': 'TFTP from workstations or unexpected devices — it can be abused to exfiltrate files since it has no authentication.',
        'action': 'Restrict TFTP server access to expected clients by IP. Disable TFTP where not needed.',
        'user_added': _B,
    },

    # ── Database ──────────────────────────────────────────────────────────────
    {
        'name': 'MySQL / MariaDB',
        'full_name': 'MySQL / MariaDB Database Server',
        'ports': [3306],
        'transport': ['tcp'],
        'layer_names': ['mysql'],
        'category': CAT_DATABASE,
        'risk': RISK_MEDIUM,
        'plain_english': (
            'One of the most common database servers. MySQL and MariaDB store data for '
            'web applications, content management systems (like WordPress), and business '
            'software. Port 3306 is the standard MySQL/MariaDB port.'
        ),
        'expected_when': 'You run a web or application server with MySQL/MariaDB on the same network.',
        'unexpected_when': 'MySQL traffic from unexpected devices, or any MySQL traffic reachable from the internet.',
        'action': 'Ensure MySQL is bound to localhost or the internal network only. Never expose port 3306 to the internet. Use strong passwords and restrict access by IP.',
        'user_added': _B,
    },
    {
        'name': 'Redis',
        'full_name': 'Redis In-Memory Database',
        'ports': [6379],
        'transport': ['tcp'],
        'layer_names': ['redis'],
        'category': CAT_DATABASE,
        'risk': RISK_HIGH,
        'plain_english': (
            'A very fast in-memory data store used as a database, cache, and message broker. '
            'Older Redis versions have no authentication by default and are frequently '
            'found exposed to the internet — anyone who can connect can read and write '
            'all data without a password.'
        ),
        'expected_when': 'Application servers using Redis for caching or as a message queue.',
        'unexpected_when': 'Redis from unexpected devices, or any Redis traffic that could reach the internet.',
        'action': 'Immediately check if Redis is accessible from outside your local network. Add a strong password (requirepass in redis.conf). Bind Redis to localhost only.',
        'user_added': _B,
    },
    {
        'name': 'MongoDB',
        'full_name': 'MongoDB Document Database',
        'ports': [27017, 27018, 27019],
        'transport': ['tcp'],
        'layer_names': ['mongo'],
        'category': CAT_DATABASE,
        'risk': RISK_HIGH,
        'plain_english': (
            'A popular document database. Early versions had no authentication by default, '
            'leading to massive data breaches when accidentally exposed to the internet. '
            'Modern versions require authentication, but misconfiguration is still common.'
        ),
        'expected_when': 'Application servers using MongoDB as a backend database.',
        'unexpected_when': 'MongoDB from unexpected devices, or accessible from the internet.',
        'action': 'Ensure authentication is enabled and MongoDB is bound to the local network only. Never expose port 27017 to the internet.',
        'user_added': _B,
    },
    {
        'name': 'Microsoft SQL Server',
        'full_name': 'Microsoft SQL Server Database',
        'ports': [1433, 1434],
        'transport': ['tcp', 'udp'],
        'layer_names': ['tds'],
        'category': CAT_DATABASE,
        'risk': RISK_MEDIUM,
        'plain_english': (
            'Microsoft\'s enterprise database server. Used extensively in Windows '
            'environments with .NET applications, SharePoint, Dynamics, and other '
            'Microsoft software stacks.'
        ),
        'expected_when': 'Windows Server environments running SQL Server, or PCs with SQL Server Express installed.',
        'unexpected_when': 'SQL Server traffic from unexpected devices, or accessible from the internet.',
        'action': 'Ensure ports 1433/1434 are blocked from the internet at the firewall. Use Windows Authentication where possible.',
        'user_added': _B,
    },
    {
        'name': 'PostgreSQL',
        'full_name': 'PostgreSQL Database Server',
        'ports': [5432],
        'transport': ['tcp'],
        'layer_names': [],
        'category': CAT_DATABASE,
        'risk': RISK_MEDIUM,
        'plain_english': (
            'A powerful open-source database server used by many modern web applications '
            'and frameworks. Stores structured data and supports complex queries and transactions.'
        ),
        'expected_when': 'Applications using PostgreSQL as a backend database.',
        'unexpected_when': 'PostgreSQL traffic from unexpected devices, or accessible from the internet.',
        'action': 'Ensure PostgreSQL is only accessible on the local network or via localhost. Never expose port 5432 directly to the internet.',
        'user_added': _B,
    },
    {
        'name': 'Elasticsearch',
        'full_name': 'Elasticsearch Search Engine',
        'ports': [9200, 9300],
        'transport': ['tcp'],
        'layer_names': [],
        'category': CAT_DATABASE,
        'risk': RISK_HIGH,
        'plain_english': (
            'A search and analytics engine. Like MongoDB, Elasticsearch historically had '
            'no authentication by default and has caused numerous data breaches when '
            'accidentally exposed to the internet.'
        ),
        'expected_when': 'Application servers or a dedicated search cluster on your network.',
        'unexpected_when': 'Elasticsearch from unexpected devices, or any external access.',
        'action': 'Ensure authentication (X-Pack security) is enabled. Bind to localhost or internal network. Block ports 9200/9300 from the internet at the firewall.',
        'user_added': _B,
    },
    {
        'name': 'AMQP / RabbitMQ',
        'full_name': 'Advanced Message Queuing Protocol',
        'ports': [5672, 5671, 15672],
        'transport': ['tcp'],
        'layer_names': ['amqp'],
        'category': CAT_DATABASE,
        'risk': RISK_MEDIUM,
        'plain_english': (
            'A messaging protocol used by RabbitMQ and other message brokers. AMQP lets '
            'applications pass messages and events to each other reliably — used in '
            'microservices, background job processing, and event-driven systems. '
            'Port 5672 is plain AMQP; 5671 is AMQP over TLS; 15672 is the '
            'RabbitMQ web management console.'
        ),
        'expected_when': 'Application servers running RabbitMQ or another AMQP broker for async messaging.',
        'unexpected_when': 'AMQP from unexpected devices, or port 15672 accessible from the internet (exposes the management console).',
        'action': 'Restrict AMQP to the application network. Protect port 15672 with authentication and do not expose it to the internet.',
        'user_added': _B,
    },

    # ── Network Management ────────────────────────────────────────────────────
    {
        'name': 'SNMP',
        'full_name': 'Simple Network Management Protocol',
        'ports': [161, 162],
        'transport': ['udp'],
        'layer_names': ['snmp'],
        'category': CAT_MANAGEMENT,
        'risk': RISK_MEDIUM,
        'plain_english': (
            'Used to monitor and manage network devices like routers, switches, and printers. '
            'Older versions (SNMPv1/v2c) use a plain-text "community string" (password) '
            'that is often left at the default "public" — meaning anyone on the network '
            'can read device configuration and status.'
        ),
        'expected_when': 'Network monitoring software (PRTG, LibreNMS, Nagios), managed switches, or enterprise routers.',
        'unexpected_when': 'SNMP from unexpected devices, or the default community string "public" being used.',
        'action': 'Switch to SNMPv3 which uses proper authentication and encryption. Change default community strings. Restrict SNMP access to the monitoring server IP only.',
        'user_added': _B,
    },
    {
        'name': 'Syslog',
        'full_name': 'System Logging Protocol',
        'ports': [514],
        'transport': ['udp', 'tcp'],
        'layer_names': ['syslog'],
        'category': CAT_MANAGEMENT,
        'risk': RISK_LOW,
        'plain_english': (
            'How network devices and servers send log messages to a central log server. '
            'Routers, switches, firewalls, and servers all use Syslog to report events '
            'and errors. UDP port 514 is the traditional unencrypted version.'
        ),
        'expected_when': 'You have a syslog server, SIEM, or log aggregation tool receiving device logs.',
        'unexpected_when': 'Syslog going to an unexpected or external server could mean logs are being intercepted.',
        'action': 'Verify the destination IP is your intended log server. Use TLS syslog (port 6514) for sensitive environments.',
        'user_added': _B,
    },
    {
        'name': 'SMB',
        'full_name': 'Server Message Block (Windows File Sharing)',
        'ports': [445, 139],
        'transport': ['tcp'],
        'layer_names': ['smb', 'smb2'],
        'category': CAT_MANAGEMENT,
        'risk': RISK_LOW,
        'plain_english': (
            'Windows file and printer sharing. SMB is how Windows computers share files, '
            'printers, and other resources on a local network. When you access '
            '\\\\server\\share on Windows, it uses SMB. SMBv1 is a dangerous older version '
            '— the Findings tab will flag it separately.'
        ),
        'expected_when': 'Windows file shares, NAS devices, shared printers on the local network.',
        'unexpected_when': 'SMB traffic to or from the internet is extremely dangerous — it is how WannaCry and NotPetya ransomware spread.',
        'action': 'Ensure SMB is never exposed to the internet (block ports 445/139 at your firewall). Use SMBv3 with encryption.',
        'user_added': _B,
    },
    {
        'name': 'LDAP',
        'full_name': 'Lightweight Directory Access Protocol',
        'ports': [389, 636],
        'transport': ['tcp'],
        'layer_names': ['ldap'],
        'category': CAT_MANAGEMENT,
        'risk': RISK_MEDIUM,
        'plain_english': (
            'The protocol for accessing directory services like Microsoft Active Directory. '
            'LDAP is used for user authentication and looking up account information in '
            'corporate networks. Port 389 is unencrypted (LDAP); 636 uses TLS (LDAPS).'
        ),
        'expected_when': 'Corporate networks with Active Directory, or applications authenticating against an LDAP server.',
        'unexpected_when': 'Unencrypted LDAP (port 389) transmitting credentials in the clear.',
        'action': 'Switch from LDAP (389) to LDAPS (636) or use StartTLS. Ensure LDAP is not accessible from outside your network.',
        'user_added': _B,
    },
    {
        'name': 'Kerberos',
        'full_name': 'Kerberos Network Authentication',
        'ports': [88],
        'transport': ['tcp', 'udp'],
        'layer_names': ['kerberos'],
        'category': CAT_MANAGEMENT,
        'risk': RISK_NONE,
        'plain_english': (
            'The authentication protocol at the core of Microsoft Active Directory. When a '
            'Windows user logs in on a domain, their computer uses Kerberos to get "tickets" '
            'proving their identity to other network services.'
        ),
        'expected_when': 'Any Windows environment with Active Directory domain controllers.',
        'unexpected_when': 'Kerberos traffic to external IPs (should only be internal), or very high volumes of failed requests which can indicate credential attacks.',
        'action': 'Monitor for unusual volumes from a single source — can indicate Kerberoasting or password spraying attacks.',
        'user_added': _B,
    },
    {
        'name': 'RADIUS',
        'full_name': 'Remote Authentication Dial-In User Service',
        'ports': [1812, 1813, 1645, 1646],
        'transport': ['udp'],
        'layer_names': ['radius'],
        'category': CAT_MANAGEMENT,
        'risk': RISK_LOW,
        'plain_english': (
            'A centralised authentication protocol used in enterprise environments for '
            'Wi-Fi login (WPA2-Enterprise), VPN authentication, and network equipment '
            'login. Allows a single authentication server to manage access across many devices.'
        ),
        'expected_when': 'Enterprise WPA2-Enterprise Wi-Fi, corporate VPN, or managed network equipment.',
        'unexpected_when': 'RADIUS on a simple home network is unusual.',
        'action': 'Ensure the RADIUS server is accessible only from authorised network access servers. Verify shared secrets are strong.',
        'user_added': _B,
    },
    {
        'name': 'NFS',
        'full_name': 'Network File System',
        'ports': [2049, 111],
        'transport': ['tcp', 'udp'],
        'layer_names': ['nfs'],
        'category': CAT_MANAGEMENT,
        'risk': RISK_MEDIUM,
        'plain_english': (
            'A Unix/Linux file sharing protocol. NFS lets Linux and macOS systems mount '
            'remote directories as if they were local — used by NAS devices, Linux file '
            'servers, and development environments. Port 111 is the RPC portmapper used '
            'to negotiate the actual NFS port.'
        ),
        'expected_when': 'Linux/macOS systems with a NAS, file server, or shared home directories.',
        'unexpected_when': 'NFS accessible from the internet is critical — NFSv3 has no built-in authentication, meaning anyone who can connect can access all exported files.',
        'action': 'Never expose NFS to the internet. Use NFSv4 with Kerberos authentication where possible. Restrict exports by IP in /etc/exports.',
        'user_added': _B,
    },
    {
        'name': 'EAP / 802.1X',
        'full_name': 'Extensible Authentication Protocol / 802.1X Port-Based Access Control',
        'ports': [],
        'transport': [],
        'layer_names': ['eap', 'eapol'],
        'category': CAT_MANAGEMENT,
        'risk': RISK_NONE,
        'plain_english': (
            'The authentication framework used for WPA2-Enterprise Wi-Fi and 802.1X wired '
            'network access control. When an enterprise device connects to Wi-Fi or a '
            'managed switch port, EAP handles the identity verification — usually via '
            'certificates (EAP-TLS) or username/password (PEAP).'
        ),
        'expected_when': 'Enterprise WPA2-Enterprise Wi-Fi networks or 802.1X-enabled wired switch ports.',
        'unexpected_when': 'EAP on a simple home network is unusual and may indicate an enterprise device has connected.',
        'action': 'No action needed on enterprise networks. On home networks, identify the device that initiated EAP.',
        'user_added': _B,
    },
    {
        'name': 'MS-RPC / DCE-RPC',
        'full_name': 'Microsoft Remote Procedure Call / Distributed Computing Environment RPC',
        'ports': [135],
        'transport': ['tcp'],
        'layer_names': ['msrpc', 'dcerpc'],
        'category': CAT_MANAGEMENT,
        'risk': RISK_LOW,
        'plain_english': (
            'The foundation of Windows network communication. MS-RPC is used by almost '
            'every Windows service — Active Directory, Group Policy, WMI, DCOM, print '
            'spooling, and remote management all use RPC. Port 135 is the endpoint mapper '
            '(like a directory that tells clients which dynamic port a service is on).'
        ),
        'expected_when': 'Any Windows network. RPC is extremely common and normal in Windows environments.',
        'unexpected_when': 'High volumes of RPC errors or RPC traffic to external IPs can indicate exploitation attempts.',
        'action': 'Block port 135 from the internet. Monitor for unusually high RPC error rates.',
        'user_added': _B,
    },
    {
        'name': 'AFP',
        'full_name': 'Apple Filing Protocol',
        'ports': [548],
        'transport': ['tcp'],
        'layer_names': ['afp'],
        'category': CAT_MANAGEMENT,
        'risk': RISK_LOW,
        'plain_english': (
            'Apple\'s proprietary file sharing protocol, used in older macOS versions and '
            'some NAS devices. AFP allowed Macs to share files and printers before Apple '
            'transitioned to SMB. Modern macOS (10.9+) uses SMB by default, so AFP is '
            'now a legacy protocol.'
        ),
        'expected_when': 'Older Mac computers (pre-2014) or NAS devices with AFP enabled for Mac compatibility.',
        'unexpected_when': 'AFP on a modern all-Mac network where SMB should be in use.',
        'action': 'Consider switching to SMB for file sharing on modern Macs. AFP is no longer actively maintained.',
        'user_added': _B,
    },
    {
        'name': 'XMPP',
        'full_name': 'Extensible Messaging and Presence Protocol (Jabber)',
        'ports': [5222, 5223, 5269],
        'transport': ['tcp'],
        'layer_names': ['xmpp'],
        'category': CAT_NORMAL,
        'risk': RISK_NONE,
        'plain_english': (
            'An open messaging protocol used for instant messaging and presence. '
            'XMPP powers Jabber/Google Talk, many corporate chat systems, and some IoT '
            'notification services. Port 5222 is client-to-server; 5269 is server-to-server; '
            '5223 is the TLS variant.'
        ),
        'expected_when': 'Jabber/XMPP chat clients, some corporate messaging systems, or IoT notification frameworks.',
        'unexpected_when': 'XMPP to unexpected servers — check the destination to confirm it is a known chat server.',
        'action': 'Ensure TLS is in use (port 5223 or STARTTLS on 5222).',
        'user_added': _B,
    },
    {
        'name': 'IRC',
        'full_name': 'Internet Relay Chat',
        'ports': [6667, 6660, 6697, 7000],
        'transport': ['tcp'],
        'layer_names': ['irc'],
        'category': CAT_P2P,
        'risk': RISK_MEDIUM,
        'plain_english': (
            'A text-based group chat protocol from 1988 that is still actively used. '
            'IRC is popular in open-source communities and gaming. Importantly, IRC '
            'has historically been used by malware — botnets use IRC channels as command '
            'and control (C2) infrastructure, allowing an attacker to issue commands to '
            'thousands of compromised machines simultaneously.'
        ),
        'expected_when': 'A user intentionally using an IRC client (e.g. for open-source community participation).',
        'unexpected_when': 'IRC from a server, IoT device, or any device not expected to run chat software.',
        'action': 'Confirm which device and application is generating IRC traffic. If unexpected, the device may be part of a botnet.',
        'user_added': _B,
    },

    # ── Industrial / OT ───────────────────────────────────────────────────────
    {
        'name': 'Modbus',
        'full_name': 'Modbus Industrial Control Protocol',
        'ports': [502],
        'transport': ['tcp'],
        'layer_names': ['modbus'],
        'category': CAT_INDUSTRIAL,
        'risk': RISK_HIGH,
        'plain_english': (
            'A very old industrial protocol from 1979 used to communicate with PLCs '
            '(Programmable Logic Controllers), sensors, and industrial equipment. '
            'Modbus has no authentication or encryption whatsoever — any device that '
            'can reach a Modbus device can read and write to it freely.'
        ),
        'expected_when': 'Industrial facilities, building automation systems, solar inverters, industrial IoT gateways.',
        'unexpected_when': 'Modbus on a standard home or office network with no industrial equipment is a serious red flag.',
        'action': 'Isolate Modbus devices on a separate network segment. Never expose Modbus to the internet.',
        'user_added': _B,
    },
    {
        'name': 'BACnet',
        'full_name': 'Building Automation and Control Network',
        'ports': [47808],
        'transport': ['udp'],
        'layer_names': ['bacnet'],
        'category': CAT_INDUSTRIAL,
        'risk': RISK_HIGH,
        'plain_english': (
            'A protocol used in building automation systems — controlling HVAC, lighting, '
            'fire alarms, and access control in commercial buildings. Like Modbus, BACnet '
            'was designed for isolated networks and has minimal built-in security.'
        ),
        'expected_when': 'Commercial buildings, facilities management systems, smart building infrastructure.',
        'unexpected_when': 'BACnet on a home network or any network without building automation equipment.',
        'action': 'Isolate BACnet devices on a dedicated VLAN with strict firewall rules.',
        'user_added': _B,
    },
    {
        'name': 'DNP3',
        'full_name': 'Distributed Network Protocol 3 (SCADA)',
        'ports': [20000],
        'transport': ['tcp', 'udp'],
        'layer_names': ['dnp3'],
        'category': CAT_INDUSTRIAL,
        'risk': RISK_HIGH,
        'plain_english': (
            'A protocol used in electric grids, water treatment, and other critical '
            'infrastructure for SCADA systems. DNP3 was designed for reliability, not security.'
        ),
        'expected_when': 'Utilities, electric grid substations, water treatment, oil and gas infrastructure.',
        'unexpected_when': 'DNP3 on a non-industrial network is a serious red flag.',
        'action': 'This protocol should not be present on a standard network. Immediately identify the source and isolate affected devices.',
        'user_added': _B,
    },
    {
        'name': 'EtherNet/IP',
        'full_name': 'EtherNet/IP Industrial Protocol (ENIP)',
        'ports': [44818, 2222],
        'transport': ['tcp', 'udp'],
        'layer_names': ['enip', 'cip'],
        'category': CAT_INDUSTRIAL,
        'risk': RISK_HIGH,
        'plain_english': (
            'An industrial Ethernet protocol used by Allen-Bradley/Rockwell Automation '
            'PLCs and other industrial control systems. EtherNet/IP adapts the Common '
            'Industrial Protocol (CIP) to run over standard TCP/UDP networks. '
            'It has no built-in security and should only exist on isolated OT networks.'
        ),
        'expected_when': 'Factories and industrial sites with Allen-Bradley PLCs or Rockwell Automation equipment.',
        'unexpected_when': 'EtherNet/IP on a corporate IT network or any network without industrial equipment.',
        'action': 'Segment OT networks from the corporate IT network with a firewall or DMZ. Never allow EtherNet/IP traffic to cross to IT networks.',
        'user_added': _B,
    },
    {
        'name': 'Siemens S7 (SCADA)',
        'full_name': 'Siemens S7 PLC Communication Protocol',
        'ports': [102],
        'transport': ['tcp'],
        'layer_names': ['s7comm'],
        'category': CAT_INDUSTRIAL,
        'risk': RISK_HIGH,
        'plain_english': (
            'The proprietary communication protocol used by Siemens SIMATIC S7 PLCs — '
            'among the most widely deployed industrial controllers in the world. S7 '
            'communicates over ISO-TSAP on port 102 and was targeted by Stuxnet, the '
            'first known weapon-grade cyberattack on industrial infrastructure. '
            'It has no authentication or encryption.'
        ),
        'expected_when': 'Industrial facilities with Siemens SIMATIC PLCs and SCADA systems.',
        'unexpected_when': 'Any S7 traffic on a non-industrial network is a critical incident.',
        'action': 'Immediately isolate any network segment carrying S7 traffic from the corporate IT network.',
        'user_added': _B,
    },
    {
        'name': 'OPC UA',
        'full_name': 'OPC Unified Architecture (Industrial)',
        'ports': [4840],
        'transport': ['tcp'],
        'layer_names': ['opcua'],
        'category': CAT_INDUSTRIAL,
        'risk': RISK_LOW,
        'plain_english': (
            'The modern, secure successor to OPC Classic for industrial automation data '
            'exchange. Unlike older industrial protocols, OPC UA includes built-in '
            'security with authentication, authorisation, and encryption. Used to '
            'connect SCADA systems, historians, and MES software to PLCs and sensors.'
        ),
        'expected_when': 'Modern industrial environments with OPC UA-capable PLCs, SCADA, or MES software.',
        'unexpected_when': 'OPC UA on a non-industrial network is unusual.',
        'action': 'Verify the OPC UA connection uses signed and encrypted sessions. Restrict port 4840 to authorised clients.',
        'user_added': _B,
    },

    # ── Legacy ────────────────────────────────────────────────────────────────
    {
        'name': 'NetBIOS',
        'full_name': 'NetBIOS Name / Session / Datagram Services',
        'ports': [137, 138, 139],
        'transport': ['tcp', 'udp'],
        'layer_names': ['nbns', 'nbss', 'nbdgm', 'browser'],
        'category': CAT_LEGACY,
        'risk': RISK_LOW,
        'plain_english': (
            'A legacy Windows networking protocol from the 1980s. NetBIOS provides name '
            'resolution and session services for older Windows file sharing. Modern Windows '
            'networks do not need it, but it is often still active by default. The '
            '"browser" layer name refers to the NetBIOS browser service that announces '
            'file shares on the local segment.'
        ),
        'expected_when': 'Windows networks, especially with older devices or software requiring NetBIOS compatibility.',
        'unexpected_when': 'High volumes of NetBIOS broadcast traffic can indicate network misconfiguration or a Responder-style credential capture attack.',
        'action': 'Disable NetBIOS over TCP/IP: Network Connections → right-click adapter → Properties → IPv4 → Advanced → WINS tab → Disable NetBIOS.',
        'user_added': _B,
    },
    {
        'name': 'LLMNR',
        'full_name': 'Link-Local Multicast Name Resolution',
        'ports': [5355],
        'transport': ['udp'],
        'layer_names': ['llmnr'],
        'category': CAT_LEGACY,
        'risk': RISK_MEDIUM,
        'plain_english': (
            'A Windows name resolution fallback. When DNS fails, Windows broadcasts an '
            'LLMNR query asking the whole local network "who has this name?". A tool '
            'called Responder can answer these with fake replies and capture Windows '
            'NTLM password hashes — without any interaction from the victim.'
        ),
        'expected_when': 'Windows computers — it is enabled by default.',
        'unexpected_when': 'Any LLMNR traffic is worth noting. The Findings tab flags it separately.',
        'action': 'Disable LLMNR via Group Policy: gpedit.msc → Computer Configuration → Administrative Templates → Network → DNS Client → "Turn off multicast name resolution" → Enabled.',
        'user_added': _B,
    },

    # ── P2P ───────────────────────────────────────────────────────────────────
    {
        'name': 'BitTorrent',
        'full_name': 'BitTorrent Peer-to-Peer',
        'ports': [6881, 6882, 6883, 6884, 6885, 6886, 6887, 6888, 6889, 51413],
        'transport': ['tcp', 'udp'],
        'layer_names': ['bittorrent'],
        'category': CAT_P2P,
        'risk': RISK_MEDIUM,
        'plain_english': (
            'A peer-to-peer file sharing protocol. Used by torrent clients like qBittorrent, '
            'uTorrent, and Transmission. BitTorrent is widely used for legitimate purposes '
            '(Linux ISOs, open-source software) and pirated content.'
        ),
        'expected_when': 'Someone on the network is intentionally using a torrent client.',
        'unexpected_when': 'BitTorrent from a device that should not be running torrent software (servers, IoT devices).',
        'action': 'Identify which device is running torrent software from the Devices tab. Be aware that BitTorrent traffic exposes your IP address to all other peers in the swarm.',
        'user_added': _B,
    },
    {
        'name': 'Tor',
        'full_name': 'The Onion Router',
        'ports': [9001, 9030, 9050, 9051],
        'transport': ['tcp'],
        'layer_names': [],
        'category': CAT_P2P,
        'risk': RISK_MEDIUM,
        'plain_english': (
            'An anonymity network that routes traffic through multiple encrypted relays '
            'to hide the origin and destination. Used legitimately for privacy and '
            'bypassing censorship, but also by malware for command-and-control (C2) '
            'communications to evade detection.'
        ),
        'expected_when': 'Someone intentionally uses the Tor Browser or a Tor-enabled application for privacy.',
        'unexpected_when': 'Tor traffic from a device that should not be using it — especially servers or IoT devices. Some malware uses Tor for C2.',
        'action': 'Identify which device is generating Tor traffic. If unexpected, run a full malware scan immediately.',
        'user_added': _B,
    },
]


# ── Tier 2: Layer-name hints ──────────────────────────────────────────────────
# Lightweight descriptions for tshark layer names that appear in captures
# but do not warrant a full library entry.  lookup_layer_hint() uses this.
# Keys are lowercase tshark layer names.  Values are hint dicts.

_LAYER_HINTS: dict[str, dict] = {
    # Microsoft / Windows internals
    'dcerpc':       {'name': 'DCE/RPC',             'category': CAT_MANAGEMENT, 'risk': RISK_NONE,
                     'plain_english': 'Distributed Computing Environment RPC — low-level plumbing for Windows services including WMI, Active Directory replication, and print spooling. Normal on Windows networks.'},
    'msrpc':        {'name': 'MS-RPC',              'category': CAT_MANAGEMENT, 'risk': RISK_NONE,
                     'plain_english': 'Microsoft Remote Procedure Call. Foundation of Windows inter-service communication — Active Directory, Group Policy, DCOM, and WMI all use RPC. Completely normal on Windows networks.'},
    'ntlmssp':      {'name': 'NTLM Authentication', 'category': CAT_MANAGEMENT, 'risk': RISK_LOW,
                     'plain_english': 'Windows NTLM authentication protocol — used when Kerberos is unavailable. NTLM credentials captured in transit can be relayed or cracked offline. Monitor for unusual NTLM authentication from non-Windows devices.'},
    'smb':          {'name': 'SMB',                 'category': CAT_MANAGEMENT, 'risk': RISK_LOW,
                     'plain_english': 'Windows file sharing (Server Message Block). Normal for Windows file servers and NAS devices. See the full SMB entry in the library for security guidance.'},
    'smb2':         {'name': 'SMB2/3',              'category': CAT_MANAGEMENT, 'risk': RISK_NONE,
                     'plain_english': 'Modern Windows file sharing protocol. SMB2 and SMB3 are the secure, current versions replacing the vulnerable SMBv1. Normal traffic on Windows networks with file shares or printers.'},
    'krb5':         {'name': 'Kerberos (KRB5)',     'category': CAT_MANAGEMENT, 'risk': RISK_NONE,
                     'plain_english': 'Kerberos v5 authentication ticket exchange. See the Kerberos library entry.'},
    'gss-api':      {'name': 'GSSAPI',              'category': CAT_MANAGEMENT, 'risk': RISK_NONE,
                     'plain_english': 'Generic Security Services API — wraps Kerberos or NTLM for application-layer authentication. Normal in Windows networks.'},
    'browser':      {'name': 'NetBIOS Browser',     'category': CAT_LEGACY,     'risk': RISK_LOW,
                     'plain_english': 'NetBIOS Computer Browser service — announces Windows file shares on the local network segment. Legacy protocol; see the NetBIOS entry for more detail and remediation steps.'},
    'nbdgm':        {'name': 'NetBIOS Datagram',    'category': CAT_LEGACY,     'risk': RISK_LOW,
                     'plain_english': 'NetBIOS Datagram Service (port 138 UDP) — broadcasts Windows machine names and workgroup announcements. Normal on Windows networks; see the NetBIOS entry for details.'},
    'nbss':         {'name': 'NetBIOS Session',     'category': CAT_LEGACY,     'risk': RISK_LOW,
                     'plain_english': 'NetBIOS Session Service (port 139 TCP) — provides session-layer services for legacy Windows file sharing. See the NetBIOS entry for security guidance.'},

    # Discovery / multicast
    'mdns':         {'name': 'mDNS',                'category': CAT_NORMAL,     'risk': RISK_NONE,
                     'plain_english': 'Multicast DNS / Apple Bonjour. Zero-configuration device discovery — how Apple devices find printers and AirPlay targets, and how smart home devices announce themselves. See the mDNS/Bonjour library entry.'},
    'ssdp':         {'name': 'SSDP/UPnP',           'category': CAT_IOT,        'risk': RISK_LOW,
                     'plain_english': 'Simple Service Discovery Protocol — the discovery layer of UPnP. Used by smart TVs, printers, game consoles, and smart home devices to announce their presence. See the SSDP/UPnP library entry.'},
    'igmp':         {'name': 'IGMP',                'category': CAT_NORMAL,     'risk': RISK_NONE,
                     'plain_english': 'Internet Group Management Protocol. Manages multicast group subscriptions — used by devices joining mDNS, SSDP, IPTV, or streaming multicast groups. Normal on most networks.'},
    'llmnr':        {'name': 'LLMNR',               'category': CAT_LEGACY,     'risk': RISK_MEDIUM,
                     'plain_english': 'Link-Local Multicast Name Resolution — Windows DNS fallback. Can be exploited by Responder attacks. See the full LLMNR library entry for remediation.'},
    'lldp':         {'name': 'LLDP',                'category': CAT_MANAGEMENT, 'risk': RISK_NONE,
                     'plain_english': 'Link Layer Discovery Protocol — switches, APs, and IP phones advertise their identity to neighbours. Normal in managed network environments.'},
    'cdp':          {'name': 'Cisco CDP',           'category': CAT_MANAGEMENT, 'risk': RISK_LOW,
                     'plain_english': 'Cisco Discovery Protocol — Cisco switches and routers advertise themselves to neighbours. Leaks network topology; consider disabling on edge ports.'},

    # VPN / tunnelling
    'gre':          {'name': 'GRE Tunnel',          'category': CAT_VPN,        'risk': RISK_LOW,
                     'plain_english': 'Generic Routing Encapsulation tunnelling protocol. Wraps other protocols for transport — used in PPTP VPNs and router tunnels. Provides no encryption by itself. See the GRE library entry.'},
    'ppp':          {'name': 'PPP',                 'category': CAT_VPN,        'risk': RISK_LOW,
                     'plain_english': 'Point-to-Point Protocol — data link encapsulation used by dial-up, DSL, and VPN connections. Often seen in L2TP/PPTP VPN traffic.'},
    'pppoe':        {'name': 'PPPoE',               'category': CAT_NORMAL,     'risk': RISK_NONE,
                     'plain_english': 'PPP over Ethernet — how many DSL routers connect to the internet via your ISP. Normal for DSL router management traffic.'},
    'l2tp':         {'name': 'L2TP',                'category': CAT_VPN,        'risk': RISK_LOW,
                     'plain_english': 'Layer 2 Tunnelling Protocol — VPN tunnelling, typically paired with IPSec for encryption. See the L2TP library entry.'},
    'isakmp':       {'name': 'IKE / ISAKMP',        'category': CAT_VPN,        'risk': RISK_NONE,
                     'plain_english': 'Internet Key Exchange — negotiates encryption keys for IPSec VPN tunnels. Normal in corporate VPN and iOS/macOS IKEv2 VPN connections.'},
    'esp':          {'name': 'IPSec ESP',           'category': CAT_VPN,        'risk': RISK_NONE,
                     'plain_english': 'IPSec Encapsulating Security Payload — encrypted IPSec tunnel traffic. Contents are fully encrypted. Normal for VPN connections.'},

    # Authentication
    'eap':          {'name': 'EAP',                 'category': CAT_MANAGEMENT, 'risk': RISK_NONE,
                     'plain_english': 'Extensible Authentication Protocol — used for WPA2-Enterprise Wi-Fi and 802.1X network access control. See the EAP/802.1X library entry.'},
    'eapol':        {'name': 'EAPOL',               'category': CAT_MANAGEMENT, 'risk': RISK_NONE,
                     'plain_english': 'EAP over LAN — the handshake phase of 802.1X authentication or WPA/WPA2 Wi-Fi key exchange. Normal when devices connect to a Wi-Fi network (the 4-way handshake).'},
    'radius':       {'name': 'RADIUS',              'category': CAT_MANAGEMENT, 'risk': RISK_LOW,
                     'plain_english': 'Remote Authentication Dial-In User Service. See the RADIUS library entry.'},

    # Routing protocols (unexpected on endpoint networks)
    'ospf':         {'name': 'OSPF',                'category': CAT_MANAGEMENT, 'risk': RISK_LOW,
                     'plain_english': 'Open Shortest Path First — a routing protocol used between routers to exchange routing table information. Normal on core network infrastructure; unexpected on end-user segments.'},
    'bgp':          {'name': 'BGP',                 'category': CAT_MANAGEMENT, 'risk': RISK_MEDIUM,
                     'plain_english': 'Border Gateway Protocol — the routing protocol of the internet, used between autonomous systems. Should never appear on a home or small office network. May indicate a router misconfiguration or a compromised router running BGP hijacking software.'},
    'rip':          {'name': 'RIP',                 'category': CAT_MANAGEMENT, 'risk': RISK_LOW,
                     'plain_english': 'Routing Information Protocol — an old interior routing protocol. May appear from consumer routers with routing features enabled.'},
    'eigrp':        {'name': 'EIGRP',               'category': CAT_MANAGEMENT, 'risk': RISK_LOW,
                     'plain_english': 'Enhanced Interior Gateway Routing Protocol — Cisco proprietary routing protocol. Normal on Cisco router infrastructure.'},
    'vrrp':         {'name': 'VRRP',                'category': CAT_MANAGEMENT, 'risk': RISK_NONE,
                     'plain_english': 'Virtual Router Redundancy Protocol — allows multiple routers to share a virtual IP for failover. Normal in enterprise networks with redundant gateway pairs.'},
    'hsrp':         {'name': 'HSRP',                'category': CAT_MANAGEMENT, 'risk': RISK_NONE,
                     'plain_english': 'Hot Standby Router Protocol — Cisco router redundancy protocol. Normal on Cisco network infrastructure with failover pairs.'},
    'pim':          {'name': 'PIM',                 'category': CAT_MANAGEMENT, 'risk': RISK_NONE,
                     'plain_english': 'Protocol Independent Multicast — manages multicast routing between routers. Normal in networks with multicast video distribution (IPTV) or gaming.'},

    # Media / streaming
    'rtp':          {'name': 'RTP',                 'category': CAT_MEDIA,      'risk': RISK_NONE,
                     'plain_english': 'Real-time Transport Protocol — carries audio and video in calls and streams. See the RTP library entry.'},
    'rtcp':         {'name': 'RTCP',                'category': CAT_MEDIA,      'risk': RISK_NONE,
                     'plain_english': 'RTP Control Protocol — accompanies RTP streams to report quality statistics (packet loss, jitter, latency) during calls and video streams. Normal alongside any RTP traffic.'},
    'rtsp':         {'name': 'RTSP',                'category': CAT_MEDIA,      'risk': RISK_LOW,
                     'plain_english': 'Real Time Streaming Protocol — see the RTSP library entry.'},
    'cast':         {'name': 'Google Cast',         'category': CAT_MEDIA_SRV,  'risk': RISK_NONE,
                     'plain_english': 'Google Cast / Chromecast protocol. See the Google Cast library entry.'},

    # Database / messaging
    'tds':          {'name': 'TDS (SQL Server)',     'category': CAT_DATABASE,   'risk': RISK_MEDIUM,
                     'plain_english': 'Tabular Data Stream — the protocol used by Microsoft SQL Server. See the Microsoft SQL Server library entry.'},
    'amqp':         {'name': 'AMQP',                'category': CAT_DATABASE,   'risk': RISK_MEDIUM,
                     'plain_english': 'Advanced Message Queuing Protocol — see the AMQP/RabbitMQ library entry.'},

    # Industrial
    's7comm':       {'name': 'Siemens S7',          'category': CAT_INDUSTRIAL, 'risk': RISK_HIGH,
                     'plain_english': 'Siemens SIMATIC S7 PLC protocol — see the Siemens S7 library entry. Should only be present on isolated OT networks.'},
    'enip':         {'name': 'EtherNet/IP',         'category': CAT_INDUSTRIAL, 'risk': RISK_HIGH,
                     'plain_english': 'EtherNet/IP industrial protocol — see the EtherNet/IP library entry. Should only be present on isolated OT networks.'},
    'cip':          {'name': 'CIP (Industrial)',     'category': CAT_INDUSTRIAL, 'risk': RISK_HIGH,
                     'plain_english': 'Common Industrial Protocol — the application layer for EtherNet/IP. Should only exist on isolated OT networks.'},
    'modbus':       {'name': 'Modbus',              'category': CAT_INDUSTRIAL, 'risk': RISK_HIGH,
                     'plain_english': 'Modbus industrial control protocol — see the Modbus library entry. No authentication or encryption.'},
    'bacnet':       {'name': 'BACnet',              'category': CAT_INDUSTRIAL, 'risk': RISK_HIGH,
                     'plain_english': 'Building automation protocol. See the BACnet library entry.'},

    # Misc
    'ipp':          {'name': 'IPP / CUPS',          'category': CAT_PRINT,      'risk': RISK_LOW,
                     'plain_english': 'Internet Printing Protocol — see the IPP/CUPS library entry.'},
    'lpd':          {'name': 'LPD / LPR',           'category': CAT_PRINT,      'risk': RISK_LOW,
                     'plain_english': 'Line Printer Daemon — legacy Unix printing protocol. See the LPD/LPR library entry.'},
    'ftp':          {'name': 'FTP',                 'category': CAT_REMOTE,     'risk': RISK_HIGH,
                     'plain_english': 'File Transfer Protocol — plaintext, no encryption. See the FTP library entry.'},
    'telnet':       {'name': 'Telnet',              'category': CAT_REMOTE,     'risk': RISK_HIGH,
                     'plain_english': 'Completely unencrypted remote terminal. See the Telnet library entry.'},
    'tftp':         {'name': 'TFTP',                'category': CAT_MANAGEMENT, 'risk': RISK_MEDIUM,
                     'plain_english': 'Trivial File Transfer Protocol — no authentication. See the TFTP library entry.'},
    'afp':          {'name': 'AFP',                 'category': CAT_MANAGEMENT, 'risk': RISK_LOW,
                     'plain_english': 'Apple Filing Protocol — legacy Mac file sharing. See the AFP library entry.'},
    'tpkt':         {'name': 'TPKT',                'category': CAT_INDUSTRIAL, 'risk': RISK_LOW,
                     'plain_english': 'ISO Transport Service on top of TCP — used as a transport layer by industrial protocols including Siemens S7 (port 102) and some telecom protocols.'},
    'xmpp':         {'name': 'XMPP',                'category': CAT_NORMAL,     'risk': RISK_NONE,
                     'plain_english': 'Jabber/XMPP instant messaging protocol. See the XMPP library entry.'},
    'irc':          {'name': 'IRC',                 'category': CAT_P2P,        'risk': RISK_MEDIUM,
                     'plain_english': 'Internet Relay Chat. See the IRC library entry — also used by botnets for C2.'},
    'imf':          {'name': 'SMTP / Email',        'category': CAT_EMAIL,      'risk': RISK_MEDIUM,
                     'plain_english': 'Internet Message Format — the format of email messages as decoded from SMTP. Contains email headers, body, and attachments.'},
    'dot':          {'name': 'DNS over TLS',        'category': CAT_NORMAL,     'risk': RISK_NONE,
                     'plain_english': 'DNS over TLS (port 853) — encrypted DNS queries. See the DNS over HTTPS/DoT library entry.'},
}


# ── Port range classification ─────────────────────────────────────────────────
def _port_range_description(port: int) -> str:
    """Return a human-readable description of which port range a port falls in."""
    if port < 1024:
        return (f'Port {port} is a well-known port (0–1023). '
                'These are reserved by IANA for standard services. '
                'An unrecognised well-known port may indicate a non-standard '
                'service or a misconfigured application.')
    if port < 49152:
        return (f'Port {port} is a registered port (1024–49151). '
                'Registered with IANA for specific applications, though not all '
                'are widely deployed. This may be a niche application, middleware, '
                'or proprietary software.')
    return (f'Port {port} is a dynamic / ephemeral port (49152–65535). '
            'These are assigned temporarily by the OS for outgoing connections — '
            'high-numbered ports are typically the source side of a TCP connection, '
            'not a listening service. Seeing this as a destination port is unusual '
            'and may indicate a non-standard server or peer-to-peer application.')


# ── public API ────────────────────────────────────────────────────────────────

def load_library() -> list:
    """Return built-in protocols merged with user-added entries.
    User entries with the same name override built-ins.
    """
    lib = {e['name']: dict(e) for e in BUILTIN_PROTOCOLS}
    try:
        user_entries = json.loads(_USER_PATH.read_text(encoding='utf-8'))
        for e in user_entries:
            e['user_added'] = True
            lib[e['name']] = e
    except FileNotFoundError:
        pass
    except Exception:
        pass
    return list(lib.values())


def _load_user_entries() -> list:
    try:
        return json.loads(_USER_PATH.read_text(encoding='utf-8'))
    except Exception:
        return []


def save_user_entry(entry: dict):
    """Add or update a user-defined protocol entry (keyed by name)."""
    entries = _load_user_entries()
    entries = [e for e in entries if e.get('name') != entry.get('name')]
    entries.append(entry)
    _USER_PATH.parent.mkdir(parents=True, exist_ok=True)
    _USER_PATH.write_text(json.dumps(entries, indent=2, ensure_ascii=False), encoding='utf-8')


def delete_user_entry(name: str):
    """Remove a user-defined protocol entry by name (no-op for built-ins)."""
    entries = [e for e in _load_user_entries() if e.get('name') != name]
    _USER_PATH.parent.mkdir(parents=True, exist_ok=True)
    _USER_PATH.write_text(json.dumps(entries, indent=2, ensure_ascii=False), encoding='utf-8')


def lookup_port(port: int, transport: str, library: list = None) -> dict | None:
    """Find a full library entry matching the given port and transport.
    Returns None if not found — see lookup_port_iana() for a fallback.
    """
    if library is None:
        library = load_library()
    transport = transport.lower()
    for entry in library:
        if port in entry.get('ports', []) and transport in entry.get('transport', []):
            return entry
    return None


def lookup_layer(layer_name: str, library: list = None) -> dict | None:
    """Find a full library entry matching a pyshark layer name.
    Returns None if not found — see lookup_layer_hint() for a fallback.
    """
    if library is None:
        library = load_library()
    name = layer_name.lower()
    for entry in library:
        if name in [ln.lower() for ln in entry.get('layer_names', [])]:
            return entry
    return None


def lookup_layer_hint(layer_name: str) -> dict | None:
    """
    Tier 2 fallback: return a lightweight hint dict for a tshark layer name
    that is not in the full library.

    Returns None if the layer name is completely unknown.
    The returned dict has '_hint': True to signal partial data.
    """
    raw = _LAYER_HINTS.get(layer_name.lower())
    if raw is None:
        return None
    hint = dict(raw)
    hint['_hint'] = True
    hint.setdefault('risk', RISK_NONE)
    hint.setdefault('category', 'Unknown')
    return hint


def lookup_port_iana(port: int, transport: str) -> dict | None:
    """
    Tier 3 fallback: look up a port in the IANA service name database via
    the OS (socket.getservbyport).

    Returns a hint dict with '_hint': True on success, or None if the port
    is not registered.  Also includes a port-range description for context.
    """
    try:
        service_name = socket.getservbyport(port, transport.lower())
    except (OSError, OverflowError):
        service_name = None

    range_desc = _port_range_description(port)

    if service_name:
        display = service_name.upper().replace('-', ' ')
        return {
            'name':          f'{display} (port {port}/{transport.upper()})',
            'plain_english': (
                f'Port {port}/{transport.upper()} is registered with IANA as '
                f'"{service_name}". This is a formally assigned port number but '
                f'is not in the local protocol library — which means it is not '
                f'a common protocol for home or small-office networks. '
                f'{range_desc}'
            ),
            'category':      'Unknown',
            'risk':          RISK_NONE,
            '_hint':         True,
            '_iana_name':    service_name,
        }

    # Port not in IANA database either — return range description only
    transport_upper = transport.upper()
    return {
        'name':          f'{transport_upper}/{port} (unregistered)',
        'plain_english': (
            f'Port {port}/{transport_upper} is not registered with IANA and '
            f'is not in the local protocol library. {range_desc} '
            f'Use the Investigate tab to look up the IP addresses communicating '
            f'on this port. Right-click this row to add a description to the library.'
        ),
        'category':      'Unknown',
        'risk':          RISK_NONE,
        '_hint':         True,
        '_iana_name':    None,
    }


def risk_rank(risk: str) -> int:
    """Return a sortable rank for a risk string (higher = worse)."""
    try:
        return _RISK_ORDER.index(risk)
    except ValueError:
        return 0
