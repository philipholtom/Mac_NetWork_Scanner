"""Human-readable output: coloured terminal report, HTML and CSV export."""
from __future__ import annotations

import html as html_mod
import os
import sys
from typing import Dict, List, Optional

from . import services

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
COLORS = {
    "high": "\033[91m", "medium": "\033[93m", "low": "\033[96m", "info": "\033[90m",
    "green": "\033[92m", "blue": "\033[94m", "cyan": "\033[96m", "grey": "\033[90m",
    "yellow": "\033[93m", "magenta": "\033[95m",
}
SEVERITY_ICON = {"high": "!!", "medium": " !", "low": " ·", "info": "  "}


def supports_color(stream=sys.stdout) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return hasattr(stream, "isatty") and stream.isatty()


class Painter:
    def __init__(self, enabled: bool):
        self.enabled = enabled

    def __call__(self, text: str, color: str = "", bold: bool = False, dim: bool = False) -> str:
        if not self.enabled:
            return text
        prefix = ""
        if color:
            prefix += COLORS.get(color, "")
        if bold:
            prefix += BOLD
        if dim:
            prefix += DIM
        return f"{prefix}{text}{RESET}" if prefix else text


def render_terminal(document: dict, paint: Painter, verbose: bool = False) -> str:
    out: List[str] = []
    summary = document.get("summary", {})
    hosts = document.get("hosts", [])
    networks = document.get("networks", [])

    out.append("")
    out.append(paint("  NETWORK SCAN RESULTS", "cyan", bold=True))
    out.append(paint("  " + "─" * 76, "grey"))

    out.append(paint("  Networks scanned:", bold=True))
    for net in networks:
        detail = f"via {net['interface']}" if net.get("interface") else net.get("source", "")
        gw = f"  gateway {net['gateway']}" if net.get("gateway") else ""
        out.append(f"    {paint(net['cidr'].ljust(20), 'blue')} {detail}{gw}")

    counts = summary.get("findings_by_severity", {})
    out.append("")
    out.append(
        f"  {paint(str(summary.get('hosts_alive', 0)), 'green', bold=True)} hosts up · "
        f"{paint(str(summary.get('open_tcp_ports', 0)), 'yellow', bold=True)} open TCP ports · "
        f"{paint(str(summary.get('open_udp_ports', 0)), 'yellow')} UDP · "
        f"{paint(str(counts.get('high', 0)) + ' high', 'high')} / "
        f"{paint(str(counts.get('medium', 0)) + ' medium', 'medium')} findings · "
        f"{summary.get('duration', 0)}s"
    )

    by_network: Dict[str, List[dict]] = {}
    for host in hosts:
        by_network.setdefault(host.get("network") or "other", []).append(host)

    for network, group in by_network.items():
        out.append("")
        out.append(paint(f"  ▸ {network}  ({len(group)} hosts)", "cyan", bold=True))
        out.append(paint("  " + "─" * 76, "grey"))
        header = f"  {'ADDRESS':<16}{'NAME':<26}{'DEVICE':<22}{'PORTS':>6}"
        out.append(paint(header, bold=True))
        for host in group:
            name = (host.get("label") or "")[:25]
            device = (host.get("device_type") or host.get("vendor") or "")[:21]
            port_count = len(host.get("tcp_ports", []))
            risk = host.get("risk", "info")
            marker = paint(SEVERITY_ICON.get(risk, "  "), risk if risk != "info" else "grey")
            tag = ""
            if host.get("is_self"):
                tag = paint(" (this Mac)", "grey")
            elif host.get("is_gateway"):
                tag = paint(" (gateway)", "grey")
            line = (f"{marker}{host['ip']:<15}{name:<26}{device:<22}"
                    f"{paint(str(port_count).rjust(5), 'yellow' if port_count else 'grey')}")
            out.append(line + tag)

            if verbose or port_count:
                for entry in host.get("tcp_ports", [])[: (200 if verbose else 8)]:
                    out.append(_port_line(entry, paint))
                for entry in host.get("udp_ports", []):
                    out.append(_port_line(entry, paint, udp=True))
            extras = []
            if host.get("mac"):
                extras.append(f"MAC {host['mac']}")
            if host.get("vendor"):
                extras.append(host["vendor"])
            if host.get("model"):
                extras.append(f"model {host['model']}")
            if host.get("rtt_ms") is not None:
                extras.append(f"{host['rtt_ms']} ms")
            if host.get("discovery"):
                extras.append("via " + "/".join(host["discovery"]))
            if extras:
                out.append(paint("      " + " · ".join(extras), "grey"))
            bonjour = host.get("bonjour") or {}
            if bonjour:
                labels = [v.get("label", k) for k, v in bonjour.items()]
                out.append(paint("      Bonjour: " + ", ".join(labels[:8]), "grey"))

    findings = [(h, f) for h in hosts for f in h.get("findings", [])]
    if findings:
        out.append("")
        out.append(paint("  SECURITY NOTES", "yellow", bold=True))
        out.append(paint("  " + "─" * 76, "grey"))
        order = {"high": 0, "medium": 1, "low": 2, "info": 3}
        findings.sort(key=lambda item: order.get(item[1].get("severity", "info"), 3))
        for host, finding in findings[:60]:
            sev = finding.get("severity", "info")
            port_label = f":{finding.get('port', '')}" if finding.get("port") else ""
            tag = "" if finding.get("verified", True) else paint(" [unconfirmed]", "grey")
            out.append(
                "  " + paint(f"{sev.upper():<7}", sev) +
                f"{host['ip']:<16}" + paint(f"{port_label:<7}", "grey") + " " +
                str(finding.get("message", "")) + tag
            )
    out.append("")
    return "\n".join(out)


def _port_line(entry: dict, paint: Painter, udp: bool = False) -> str:
    port = entry.get("port")
    proto = "udp" if udp else "tcp"
    service = entry.get("service", "")
    severity = entry.get("severity", "info")
    detail_parts: List[str] = []
    product = entry.get("product")
    version = entry.get("version")
    if product:
        detail_parts.append(str(product))
    if version and str(version) not in str(product or ""):
        detail_parts.append(str(version))
    http = entry.get("http")
    if isinstance(http, dict):
        if http.get("title"):
            detail_parts.append(f'"{http["title"]}"')
        elif http.get("server"):
            detail_parts.append(str(http["server"]))
        if http.get("location"):
            detail_parts.append(f"-> {http['location']}")
    tls = entry.get("tls")
    if isinstance(tls, dict):
        bits = [str(tls.get("version") or "")]
        if tls.get("subject"):
            bits.append(str(tls["subject"]))
        if tls.get("days_until_expiry") is not None:
            bits.append(f"expires in {tls['days_until_expiry']}d")
        detail_parts.append("TLS " + " ".join(b for b in bits if b))
    if not detail_parts and entry.get("banner"):
        detail_parts.append(str(entry["banner"])[:70])
    if not detail_parts:
        detail_parts.append(entry.get("description", ""))

    has_evidence = bool(entry.get("banner") or entry.get("product") or
                        entry.get("http") or entry.get("tls") or entry.get("version"))
    if not has_evidence and service:
        service = f"{service}?"
    color = severity if severity in ("high", "medium") and has_evidence else "green"
    label = f"{port}/{proto}"
    return ("      " + paint(f"{label:<11}", color) +
            paint(f"{service:<16}", "cyan") +
            paint(" · ".join(detail_parts)[:88], "grey"))


def render_html(document: dict) -> str:
    e = html_mod.escape
    summary = document.get("summary", {})
    rows: List[str] = []
    for host in document.get("hosts", []):
        ports = "".join(
            f"<li><b>{p['port']}/{p['proto']}</b> {e(str(p.get('service','')))}"
            f" <span class=d>{e(_port_detail(p))}</span></li>"
            for p in host.get("tcp_ports", []) + host.get("udp_ports", [])
        )
        findings = "".join(
            f"<li class='f {e(f.get('severity','info'))}'>{e(f.get('severity','').upper())}"
            f" :{f.get('port','')} {e(f.get('message',''))}</li>"
            for f in host.get("findings", [])
        )
        rows.append(f"""
        <tr class="host">
          <td class="ip">{e(host['ip'])}</td>
          <td>{e(host.get('label') or '')}<div class=d>{e(host.get('vendor') or '')}</div></td>
          <td>{e(host.get('device_type') or '')}<div class=d>{e(host.get('model') or '')}</div></td>
          <td class=d>{e(host.get('mac') or '')}</td>
          <td><ul class=ports>{ports or '<li class=d>none</li>'}</ul>
              <ul class=findings>{findings}</ul></td>
        </tr>""")

    nets = "".join(f"<li>{e(n['cidr'])} <span class=d>{e(n.get('source',''))}</span></li>"
                   for n in document.get("networks", []))
    counts = summary.get("findings_by_severity", {})
    return f"""<!doctype html><meta charset="utf-8">
<title>Network scan {e(document.get('generated',''))}</title>
<style>
 :root{{color-scheme:light dark}}
 body{{font:14px -apple-system,BlinkMacSystemFont,'SF Pro Text',sans-serif;margin:0;padding:32px;
      background:#f6f6f8;color:#1c1c1e}}
 @media (prefers-color-scheme:dark){{body{{background:#161618;color:#e8e8ea}}
   table{{background:#202024!important}} th{{background:#2a2a30!important}}
   tr.host:hover{{background:#26262c!important}}}}
 h1{{font-size:22px;margin:0 0 4px}} .sub{{color:#777;margin-bottom:20px}}
 .cards{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px}}
 .card{{background:#fff;border-radius:10px;padding:12px 16px;min-width:110px;
        box-shadow:0 1px 3px rgba(0,0,0,.08)}}
 @media (prefers-color-scheme:dark){{.card{{background:#202024}}}}
 .card b{{display:block;font-size:22px}}
 table{{border-collapse:collapse;width:100%;background:#fff;border-radius:10px;overflow:hidden;
        box-shadow:0 1px 3px rgba(0,0,0,.08)}}
 th,td{{text-align:left;padding:10px 12px;vertical-align:top;border-bottom:1px solid rgba(128,128,128,.18)}}
 th{{background:#eee;font-size:12px;text-transform:uppercase;letter-spacing:.04em}}
 tr.host:hover{{background:#fafafa}}
 .ip{{font-family:'SF Mono',Menlo,monospace;white-space:nowrap}}
 .d{{color:#888;font-size:12px}}
 ul{{margin:0;padding-left:16px}} ul.ports li{{margin:2px 0}}
 .f{{list-style:none;margin-left:-16px;padding:2px 6px;border-radius:4px;margin-top:3px;font-size:12px}}
 .f.high{{background:rgba(255,59,48,.14);color:#c0392b}}
 .f.medium{{background:rgba(255,149,0,.14);color:#b8860b}}
 .f.low{{background:rgba(0,122,255,.12);color:#2c6fbb}}
</style>
<h1>Network scan</h1>
<div class=sub>{e(document.get('generated',''))} · {summary.get('duration',0)}s</div>
<div class=cards>
 <div class=card><b>{summary.get('hosts_alive',0)}</b>hosts</div>
 <div class=card><b>{summary.get('open_tcp_ports',0)}</b>open TCP</div>
 <div class=card><b>{summary.get('open_udp_ports',0)}</b>open UDP</div>
 <div class=card><b>{counts.get('high',0)}</b>high findings</div>
 <div class=card><b>{counts.get('medium',0)}</b>medium findings</div>
</div>
<p><b>Networks:</b></p><ul>{nets}</ul>
<table><tr><th>Address</th><th>Name</th><th>Device</th><th>MAC</th><th>Services</th></tr>
{''.join(rows)}</table>"""


def _port_detail(port: dict) -> str:
    parts = []
    for key in ("product", "version"):
        if port.get(key):
            parts.append(str(port[key]))
    http = port.get("http")
    if isinstance(http, dict):
        if http.get("title"):
            parts.append(f'"{http["title"]}"')
        if http.get("server") and http.get("server") not in parts:
            parts.append(str(http["server"]))
    tls = port.get("tls")
    if isinstance(tls, dict) and tls.get("subject"):
        parts.append(f"TLS {tls.get('version','')} {tls['subject']}")
    if not parts and port.get("banner"):
        parts.append(str(port["banner"])[:80])
    if not parts:
        parts.append(port.get("description", ""))
    return " · ".join(parts)


def render_csv(document: dict) -> str:
    import csv
    import io
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["ip", "name", "device_type", "vendor", "mac", "model", "network",
                     "rtt_ms", "proto", "port", "service", "product", "version",
                     "http_title", "tls_subject", "severity", "risk"])
    for host in document.get("hosts", []):
        base = [host["ip"], host.get("label", ""), host.get("device_type", ""),
                host.get("vendor", ""), host.get("mac", ""), host.get("model", ""),
                host.get("network", ""), host.get("rtt_ms", "")]
        entries = host.get("tcp_ports", []) + host.get("udp_ports", [])
        if not entries:
            writer.writerow(base + ["", "", "", "", "", "", "", "", ""])
        for port in entries:
            http = port.get("http") if isinstance(port.get("http"), dict) else {}
            tls = port.get("tls") if isinstance(port.get("tls"), dict) else {}
            writer.writerow(base + [
                port.get("proto", ""), port.get("port", ""), port.get("service", ""),
                port.get("product", ""), port.get("version", ""),
                http.get("title", ""), tls.get("subject", ""),
                port.get("severity", ""), port.get("risk", ""),
            ])
    return buf.getvalue()
