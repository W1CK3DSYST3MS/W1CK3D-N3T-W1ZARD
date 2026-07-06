"""
report.py — Console summary and self-contained HTML report generation.
"""

import html
import json
from datetime import datetime
from pathlib import Path

from .base import SEVERITY_COLORS, SEVERITY_ORDER


# ------------------------------------------------------------------ console
def print_console_summary(results, pcap_path, total_packets):
    devices = results['devices']
    net = results['network']
    threats = results['threats']

    print()
    print('=' * 60)
    print(f'  NETWORK CAPTURE ANALYSIS REPORT')
    print(f'  File: {pcap_path}')
    print(f'  Packets: {total_packets:,}')
    print('=' * 60)

    print(f"\n[NETWORK]")
    print(f"  Gateway : {net.get('gateway_ip') or 'not identified'}"
          f"  (MAC {net.get('gateway_mac') or '?'})")
    print(f"  DNS     : {', '.join(net.get('dns_servers') or []) or 'not identified'}")
    print(f"  Subnets : {', '.join(net.get('subnets') or []) or 'none found'}")
    total_pkts = (net.get('internal_packets', 0) + net.get('external_packets', 0)) or 1
    ext_pct = 100 * net.get('external_packets', 0) // total_pkts
    print(f"  Traffic : {100 - ext_pct}% internal / {ext_pct}% external")

    print(f"\n[DEVICES]  {devices.get('count', 0)} found")
    for d in sorted(devices['devices'],
                    key=lambda x: (not x.get('is_gateway'), -x.get('packet_count', 0))):
        marker = ' [GATEWAY]' if d.get('is_gateway') else ''
        ips = ', '.join(d.get('ip_addresses', [])[:2]) or '—'
        host = ', '.join(d.get('hostnames', [])[:1]) or '—'
        print(f"  {d['likely_type']}{marker}")
        print(f"    MAC {d['mac']}  IP {ips}  hostname {host}")

    print(f"\n[SECURITY FINDINGS]  {threats.get('total', 0)} total")
    counts = threats.get('counts_by_severity', {})
    for sev in SEVERITY_ORDER:
        n = counts.get(sev, 0)
        if n:
            print(f"  {sev.upper():8s} {n}")
    if not threats.get('total'):
        print("  None — nothing obvious stood out.")

    for f in threats.get('findings', []):
        print(f"\n  [{f['severity'].upper()}] {f['title']}")
        print(f"  {f['description'][:120]}")
        if f.get('recommendation'):
            print(f"  → {f['recommendation'][:120]}")

    print()


# -------------------------------------------------------------------- HTML
def _e(s):
    return html.escape(str(s or ''))


def _fmt_bytes(n):
    n = float(n or 0)
    for unit in ('B', 'KB', 'MB', 'GB'):
        if n < 1024:
            return f'{n:.1f} {unit}'
        n /= 1024
    return f'{n:.1f} TB'


def generate_html_report(results, pcap_path, total_packets, output_path):
    devices = results['devices']
    net = results['network']
    threats = results['threats']

    now = datetime.now().strftime('%Y-%m-%d %H:%M')
    filename = Path(pcap_path).name

    total_pkts = (net.get('internal_packets', 0) + net.get('external_packets', 0)) or 1
    ext_pct = 100 * net.get('external_packets', 0) // total_pkts
    int_pct = 100 - ext_pct

    counts = threats.get('counts_by_severity', {})

    # ---- severity summary pills
    pills_html = ''
    for sev in SEVERITY_ORDER:
        n = counts.get(sev, 0)
        color = SEVERITY_COLORS[sev]
        pills_html += (
            f'<span style="background:{color};color:#fff;border-radius:4px;'
            f'padding:2px 10px;margin:0 4px;font-size:0.9em;font-weight:bold;">'
            f'{n} {sev}</span>'
        )

    # ---- devices table rows
    device_rows = ''
    for d in sorted(devices['devices'],
                    key=lambda x: (not x.get('is_gateway'), -x.get('packet_count', 0))):
        style = 'font-weight:bold;color:#9a3eff;' if d.get('is_gateway') else ''
        gw_label = ' <span style="color:#9a3eff;font-size:0.75em;">[GATEWAY]</span>' \
                   if d.get('is_gateway') else ''
        ips = ', '.join(d.get('ip_addresses', [])[:3]) or '—'
        hostnames = ', '.join(d.get('hostnames', [])[:2]) or '—'
        device_rows += f"""
        <tr style="{style}">
          <td>{_e(d['likely_type'])}{gw_label}</td>
          <td>{_e(hostnames)}</td>
          <td>{_e(ips)}</td>
          <td style="font-family:monospace;font-size:0.85em;">{_e(d.get('mac',''))}</td>
          <td>{_e(d.get('vendor') or '—')}</td>
          <td style="text-align:right;">{d.get('packet_count', 0):,}</td>
          <td style="text-align:right;">{_fmt_bytes(d.get('bytes_total', 0))}</td>
        </tr>"""

    # ---- findings sections
    findings_html = ''
    if not threats.get('findings'):
        findings_html = (
            '<p style="padding:16px;background:#0b0e13;border-radius:6px;'
            'border:1px solid #262c35;border-left:4px solid #0f9446;color:#3df085;">'
            'No security issues detected in this capture. This does not guarantee '
            'the network is clean — encrypted traffic can hide a lot — but nothing '
            'obvious stood out.'
            '</p>'
        )
    else:
        for f in threats['findings']:
            color = SEVERITY_COLORS.get(f['severity'], '#4b5563')
            sev_badge = (
                f'<span style="background:{color};color:#fff;border-radius:3px;'
                f'padding:1px 8px;font-size:0.8em;font-weight:bold;'
                f'text-transform:uppercase;">{_e(f["severity"])}</span>'
            )
            rec_block = ''
            if f.get('recommendation'):
                rec_block = (
                    f'<div style="background:#07090c;border-left:4px solid #561593;'
                    f'padding:10px 14px;margin:10px 0;border-radius:0 4px 4px 0;">'
                    f'<strong style="color:#9a3eff;">What to do</strong><br>'
                    f'<span style="color:#c2c8d2;">{_e(f["recommendation"])}</span>'
                    f'</div>'
                )
            tech_block = ''
            if f.get('technical') or f.get('evidence'):
                ev_json = _e(json.dumps(f.get('evidence', {}), indent=2))
                tech_content = ''
                if f.get('technical'):
                    tech_content += f'<p style="margin:4px 0;">{_e(f["technical"])}</p>'
                if f.get('evidence'):
                    tech_content += f'<pre style="margin:4px 0;white-space:pre-wrap;">{ev_json}</pre>'
                tech_block = (
                    f'<details style="margin-top:8px;">'
                    f'<summary style="cursor:pointer;color:#8b93a1;font-size:0.85em;">'
                    f'Technical details</summary>'
                    f'<div style="font-family:\'JetBrains Mono\',\'Consolas\',monospace;font-size:0.82em;'
                    f'color:#c2c8d2;background:#07090c;border:1px solid #1b1f26;'
                    f'padding:10px;border-radius:4px;margin-top:6px;">'
                    f'{tech_content}</div></details>'
                )
            findings_html += f"""
        <div style="background:#0b0e13;border:1px solid #262c35;border-left:4px solid {color};
                    border-radius:6px;padding:14px 16px;margin-bottom:12px;">
          {sev_badge} <strong style="font-size:1.05em;margin-left:8px;">{_e(f["title"])}</strong>
          <p style="margin:10px 0 6px;color:#c2c8d2;">{_e(f["description"])}</p>
          {rec_block}
          {tech_block}
        </div>"""

    # ---- top external IPs
    top_ext_rows = ''
    for ip, count in (net.get('top_external_ips') or [])[:8]:
        top_ext_rows += (
            f'<tr><td style="font-family:monospace;">{_e(ip)}</td>'
            f'<td style="text-align:right;">{count:,}</td></tr>'
        )

    # ---- full HTML
    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Network Capture Report — {_e(filename)}</title>
<style>
  /* W1CK3D SYST3MS theme — dark cyber/terminal (tokens: theme.py) */
  *{{box-sizing:border-box;}}
  body{{font-family:"Chakra Petch","Segoe UI",Roboto,-apple-system,sans-serif;
       background:#030405;color:#c2c8d2;margin:0;padding:20px;
       background-image:radial-gradient(1200px 500px at 50% -10%,#11151b 0%,#030405 60%);}}
  h1{{font-family:"Orbitron","Chakra Petch","Segoe UI",sans-serif;font-size:1.5rem;
      margin:0 0 4px;color:#eef1f5;letter-spacing:1.5px;}}
  h2{{font-family:"Orbitron","Chakra Petch","Segoe UI",sans-serif;font-size:1.05rem;
      color:#eef1f5;letter-spacing:1px;border-bottom:1px solid #262c35;
      padding-bottom:6px;margin:24px 0 12px;}}
  strong{{color:#eef1f5;}}
  a{{color:#9a3eff;}}
  .card{{background:#0b0e13;border:1px solid #262c35;border-radius:8px;
         box-shadow:0 1px 4px rgba(0,0,0,.55);padding:20px;margin-bottom:20px;}}
  table{{width:100%;border-collapse:collapse;font-size:0.9em;}}
  th{{background:#11151b;color:#eef1f5;text-align:left;padding:8px 10px;font-weight:600;
      letter-spacing:0.5px;border-bottom:2px solid #353c47;}}
  td{{padding:7px 10px;border-bottom:1px solid #1b1f26;vertical-align:top;}}
  tr:hover td{{background:#11151b;}}
  code,pre,.mono{{font-family:"JetBrains Mono","Share Tech Mono","Consolas",monospace;}}
  .meta{{color:#8b93a1;font-size:0.85em;}}
  .grid{{display:grid;grid-template-columns:1fr 1fr;gap:16px;}}
  @media(max-width:700px){{.grid{{grid-template-columns:1fr;}}}}
</style>
</head>
<body>

<div class="card">
  <h1>Network Capture Report</h1>
  <p class="meta">
    File: <strong>{_e(filename)}</strong> &nbsp;·&nbsp;
    Analyzed: {_e(now)} &nbsp;·&nbsp;
    Packets: <strong>{total_packets:,}</strong>
  </p>

  <div style="margin-top:14px;">
    <strong>Security findings: </strong>
    {pills_html if threats.get('total') else
     '<span style="color:#3df085;font-weight:bold;">None detected</span>'}
  </div>
</div>

<div class="grid">
  <div class="card">
    <h2>Network Overview</h2>
    <table>
      <tr><td class="meta">Gateway</td>
          <td><strong>{_e(net.get('gateway_ip') or '—')}</strong>
              <span class="meta"> MAC {_e(net.get('gateway_mac') or '?')}</span></td></tr>
      <tr><td class="meta">DNS server(s)</td>
          <td>{_e(', '.join(net.get('dns_servers') or []) or '—')}</td></tr>
      <tr><td class="meta">Subnets</td>
          <td>{_e(', '.join(net.get('subnets') or []) or '—')}</td></tr>
      <tr><td class="meta">Traffic split</td>
          <td>{int_pct}% internal &nbsp;·&nbsp; {ext_pct}% external
              <span class="meta">({_fmt_bytes(net.get('bytes_external',0))} outbound)</span>
          </td></tr>
      <tr><td class="meta">Devices found</td>
          <td><strong>{devices.get('count', 0)}</strong></td></tr>
    </table>
  </div>

  <div class="card">
    <h2>Top External Destinations</h2>
    {"<table><tr><th>IP Address</th><th>Packets</th></tr>" + top_ext_rows + "</table>"
      if top_ext_rows
      else '<p class="meta">No external traffic observed.</p>'}
  </div>
</div>

<div class="card">
  <h2>Device Inventory ({devices.get('count', 0)})</h2>
  <table>
    <tr>
      <th>Device type</th><th>Hostname</th><th>IP address</th>
      <th>MAC address</th><th>Vendor</th><th>Packets</th><th>Data</th>
    </tr>
    {device_rows}
  </table>
</div>

<div class="card">
  <h2>Security Findings ({threats.get('total', 0)})</h2>
  {findings_html}
</div>

<p class="meta" style="text-align:center;margin-top:8px;">
  Generated by W1CK3D_NET_WIZARD &nbsp;·&nbsp;
  Report is self-contained — readable offline in any browser
  &nbsp;·&nbsp; {_e(now)}
</p>

</body>
</html>
"""

    Path(output_path).write_text(page, encoding='utf-8')
