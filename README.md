# W1CK3D NET WIZARD

**A W1CK3D SYST3MS tool-wizard**

An offline desktop app that turns a raw network capture into a plain-English security report — what's on your network, what it's talking to, and what looks wrong.

`v3.2.0` · Windows · Linux · macOS (untested, run from source)

---

## Screenshots

> _Add screenshots of the Overview, Device Inventory, and Security Findings views here._

---

## What's new in v3.2.0

The first feature release since the initial `v3.1.3`.

- **Automatic protocol identification** — unknown protocols are now named offline by combining what Wireshark decoded on each port, a bundled port catalogue, IANA/OS service names, and port-range heuristics. No more dead-end "unknown" rows.
- **Self-building protocol library** — confident identifications are learned and remembered (protocol-level facts only, never IPs) and can be promoted to permanent, editable entries. A **Build library from this capture** action shows what it learned.
- **Ephemeral / client-port grouping** — on live captures the hundreds of short-lived high ports collapse into one summary row (toggle-able) so the real services stay readable.
- **Guided-scan Advanced Options** — customise any scan: skip host discovery (`-Pn`), version detection (`-sV`), OS detection (`-O`), only-open ports, vulnerability scripts, a timing template, and custom flags.
- **Scan fix — no more false "host down"** — port scans use `-Pn` by default, so firewalled hosts and home routers (which ignore nmap's ping) are actually scanned instead of wrongly reported offline.
- **Own-scan recognition** — the analyzer now knows when scan traffic comes from *this* computer, so running the built-in tools shows a calm informational note instead of a high-risk "Port Scan Detected" alert.

_Downloads are on the [v3.2.0 release](../../releases/tag/v3.2.0). Full history in the [releases list](../../releases)._

---

## What it is

W1CK3D NET WIZARD points at a packet capture (a `.pcap` / `.pcapng` file from Wireshark/tshark) — or runs a live capture — and produces a guided, readable security report. It's built for people who are **not** packet-analysis experts: every finding is explained in words, with why it matters and what to do about it.

Analysis is 100% local. The capture never leaves the machine.

## Features

- **Overview / recon** — gateway, DNS servers, subnets, internal-vs-external traffic split, top external destinations, device count, at-a-glance findings.
- **Device inventory** — every host seen, MAC vendor (via the `manuf` OUI database), a best-guess device type, hostnames/IPs, packet & byte counts, and new-device detection against a local device registry.
- **Protocol library** — a large built-in reference of ports/protocols/services with risk ratings and plain-English notes on what's expected vs. suspicious.
- **Security findings** — flags plaintext credentials (HTTP Basic, FTP, Telnet, POP3/IMAP), port scans, suspicious/legacy services, and more, each with a severity (critical / high / medium / low / info), a description, and a recommended action.
- **IP investigation** — look up any external IP against public intel sources (ip-api, BGPView, Shodan InternetDB, whois.is, AbuseIPDB). Works with no keys; optional API keys unlock richer data. This is the only feature that makes network calls, and it's always user-initiated.
- **Architect review** — a higher-level network posture pass with prioritized recommendations (DNS hardening, admin-password hygiene, WiFi practices, and more).
- **Guided nmap scans** — a step-by-step scan wizard with scan profiles and a plain-English nmap explainer, for probing targets you're authorized to test.
- **Compare reports** — diff two captures over time: resolved / new / persistent findings, added / removed devices.
- **Scheduling + admin panel** — schedule recurring scans, plus an admin panel for schedule management, policy locks, run-log, and system diagnostics.
- **Reports** — every analysis is saved to `~/W1CK3DWizard/Reports/` as a self-contained folder (HTML + JSON + metadata). The HTML opens in any browser, offline, forever, even if the app is uninstalled. Findings also export to CSV.

## Privacy & security posture

- **Offline-first.** All capture analysis runs locally. No telemetry, no phone-home.
- **Local storage only.** Reports, captures, config, and the device registry all live under your home directory (`~/W1CK3DWizard/`) — never in the install folder or this repo.
- **The one online feature (IP investigation) is opt-in.** It queries well-known public services; any API keys you provide are stored locally in `~/W1CK3DWizard/config.json` and never leave your machine except in the queries you initiate.

## Authorized use only

The active features in this tool — live capture and guided nmap scans — must only be used on networks and targets you own or are explicitly authorized to test. The app itself states this. You are responsible for how you use it.

## Quick start

Requires Python 3.8+ with tkinter (developed/tested on 3.12).

**Windows**
```
install.bat
```
Run it, then launch from the desktop shortcut it creates (or `launch.pyw`).

**Linux**
```
./install.sh
```
Installs dependencies (or a local venv) and checks for tkinter/tshark/nmap. Launch via `./net-wizard.sh` or the app-menu entry it creates.

**macOS**
No packaged installer yet — macOS hasn't been tested by the maintainer. It should run from source (below), but expect rough edges. Reports of what works (or doesn't) are welcome via an issue.

**Any OS, from source**
```
pip install pyshark manuf
python app.py
```

Optional external tools: [Wireshark/tshark](https://www.wireshark.org/) for capture analysis, [nmap](https://nmap.org/) for guided scans. The app detects when these are missing and points you to the installers.

See [INSTALL.md](INSTALL.md) for detailed per-OS steps and troubleshooting.

## Tech stack

Python 3.8+ · Tkinter/ttk GUI · `pyshark` · `manuf` · optional `tshark` and `nmap`

## License

MIT — see [LICENSE](LICENSE).

Bundled fonts (Orbitron, Chakra Petch, JetBrains Mono, Share Tech Mono, Black Ops One) are Google Fonts under the SIL Open Font License / Apache 2.0; see `assets/fonts/OFL.txt`.
