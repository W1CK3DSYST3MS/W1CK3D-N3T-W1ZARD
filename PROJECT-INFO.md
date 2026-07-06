# W1CK3D NET WIZARD — Project Info Sheet

## What it is

An offline desktop app that turns a raw network capture into a plain-English security report — what's on your network, what it's talking to, and what looks wrong. Point it at a `.pcap`/`.pcapng` file or run a live capture; it does the analysis and explains the findings in words, not just packet dumps.

A **W1CK3D SYST3MS** project — free tool-wizards and field guides that bridge beginners and complex security / networking / systems work.

**Category:** Network / security / analysis utility (defensive; educational).
**Version:** v3.1.3

## Who it's for

People who want to understand what's happening on their own network but aren't packet-analysis experts — home-lab tinkerers, IT generalists, students, and security beginners. Every finding comes with plain-English context: what it is, why it matters, and what to do about it.

## Feature matrix

| Area | What it covers |
|---|---|
| Overview / recon | Gateway, DNS servers, subnets, internal-vs-external split, top external destinations, device count |
| Device inventory | Host list, MAC vendor lookup (`manuf` OUI database), device-type guess, hostnames/IPs, packet & byte counts, new-device detection |
| Protocol library | Built-in reference of ports/protocols/services with risk ratings and plain-English notes |
| Security findings | Plaintext credentials (HTTP Basic, FTP, Telnet, POP3/IMAP), port scans, suspicious/legacy services — each with severity, description, and recommended action |
| IP investigation | External IP lookups via ip-api, BGPView, Shodan InternetDB, whois.is, AbuseIPDB — no keys required, optional keys unlock more |
| Architect review | Network posture pass with prioritized hardening recommendations |
| Guided nmap scans | Step-by-step scan wizard with profiles and a plain-English nmap explainer |
| Compare reports | Diff two captures over time — resolved/new/persistent findings, added/removed devices |
| Scheduling + admin panel | Recurring scans, policy locks, run-log, diagnostics |
| Reports | Self-contained HTML + JSON + metadata per run, saved locally, exports to CSV |

## Tech stack

- **Language:** Python 3.8+ (developed/tested on 3.12)
- **GUI:** Tkinter/ttk (standard library — no heavyweight GUI dependency)
- **Dependencies:** `pyshark`, `manuf`
- **Optional external tools:** `tshark` (Wireshark), `nmap` — the app degrades gracefully and points to installers if missing
- **Entry points:** `app.py` (GUI), `cli.py` (headless)

## Privacy & security posture

- Offline-first: all capture analysis runs locally, no telemetry, no phone-home.
- Local storage only: reports, captures, config, and device registry live under `~/W1CK3DWizard/`, never in the install folder or the repo.
- The only feature that makes network calls (IP investigation) is opt-in and user-initiated; any API keys are stored locally.
- Authorized use only: active features (live capture, nmap scans) are for networks/targets you own or are permitted to test.

## Platforms

Windows and Linux — each release package bundles the app plus that platform's installer. macOS is untested (no packaged installer); it should run from source but hasn't been verified by the maintainer.

## Roadmap

_Add planned features or a link to open issues/milestones here._

## License

MIT. Bundled fonts (Orbitron, Chakra Petch, JetBrains Mono, Share Tech Mono, Black Ops One) are under SIL OFL / Apache 2.0 — see `assets/fonts/OFL.txt`.
