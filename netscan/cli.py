"""Command-line interface for netscan."""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from typing import List, Optional

from . import engine, interfaces, localhost, oui, report, services

VERSION = "1.0.0"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netscan",
        description="Scan every network this Mac can reach and report open ports and devices.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  netscan                        scan every network this Mac is on
  netscan --profile full         all 65,535 TCP ports
  netscan 192.168.1.0/24         scan one network
  netscan --probe-adjacent       also hunt for neighbouring subnets
  netscan --html report.html     write an HTML report
  netscan --self                 audit what this Mac exposes
  netscan --list-networks        show what would be scanned, then exit
""")
    parser.add_argument("targets", nargs="*", help="networks/hosts to scan (default: all local networks)")
    parser.add_argument("-p", "--ports", help="port spec, e.g. 22,80,8000-8100")
    parser.add_argument("--profile", choices=list(services.PROFILES), default="common",
                        help="port set to scan (default: common)")
    parser.add_argument("--no-udp", action="store_true", help="skip UDP probing")
    parser.add_argument("--no-fingerprint", action="store_true", help="skip service fingerprinting")
    parser.add_argument("--no-discover", action="store_true",
                        help="do not add subnets discovered via Bonjour/ARP")
    parser.add_argument("--probe-adjacent", action="store_true",
                        help="ping neighbouring /24 gateways to find more subnets")
    parser.add_argument("--timeout", type=float, default=1.2, help="TCP connect timeout (default 1.2s)")
    parser.add_argument("--concurrency", type=int, default=300, help="ports in flight per host")
    parser.add_argument("--hosts-parallel", type=int, default=32, help="hosts scanned at once")
    parser.add_argument("--max-hosts", type=int, default=8192, help="address cap (default 8192)")
    parser.add_argument("--bonjour-seconds", type=float, default=3.0, help="Bonjour browse time")

    out = parser.add_argument_group("output")
    out.add_argument("--json", metavar="FILE", nargs="?", const="-", help="write JSON (- for stdout)")
    out.add_argument("--ndjson", action="store_true", help="stream newline-delimited events (for the app)")
    out.add_argument("--html", metavar="FILE", help="write an HTML report")
    out.add_argument("--csv", metavar="FILE", help="write CSV")
    out.add_argument("-v", "--verbose", action="store_true", help="show every open port")
    out.add_argument("-q", "--quiet", action="store_true", help="suppress progress output")
    out.add_argument("--no-color", action="store_true", help="disable colour")

    misc = parser.add_argument_group("other modes")
    misc.add_argument("--list-networks", action="store_true", help="show scan plan and exit")
    misc.add_argument("--self", dest="self_audit", action="store_true",
                      help="report what this Mac is exposing")
    misc.add_argument("--update-oui", action="store_true", help="download the IEEE vendor database")
    misc.add_argument("--version", action="version", version=f"netscan {VERSION}")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if args.update_oui:
        ok, message = oui.update_from_ieee()
        print(message, file=sys.stderr if not ok else sys.stdout)
        return 0 if ok else 1

    if args.self_audit:
        return _self_audit(args)

    options = engine.ScanOptions(
        targets=args.targets,
        all_networks=not args.targets,
        discover_networks=not args.no_discover and not args.targets,
        probe_adjacent=args.probe_adjacent,
        profile=args.profile,
        ports=args.ports,
        udp=not args.no_udp,
        timeout=args.timeout,
        host_concurrency=args.hosts_parallel,
        port_concurrency=args.concurrency,
        fingerprint_enabled=not args.no_fingerprint,
        max_hosts=args.max_hosts,
        bonjour_seconds=args.bonjour_seconds,
    )

    if args.list_networks:
        scanner = engine.Scanner(options)
        plan = scanner.plan_targets()
        total = sum(n["hosts"] for n in plan)
        print(f"{len(plan)} networks, {total:,} addresses, {len(options.port_list()):,} ports each")
        for entry in plan:
            print(f"  {entry['cidr']:<20} {entry['hosts']:>6} hosts   {entry['source']}"
                  + (f"  [{entry['interface']}]" if entry.get("interface") else ""))
        return 0

    paint = report.Painter(report.supports_color(sys.stderr) and not args.no_color)
    ndjson = args.ndjson

    def emit(event: dict) -> None:
        if ndjson:
            sys.stdout.write(json.dumps(event, default=str) + "\n")
            sys.stdout.flush()
        elif not args.quiet:
            _print_progress(event, paint)

    scanner = engine.Scanner(options, emit=emit)
    try:
        asyncio.run(scanner.run())
    except KeyboardInterrupt:
        print(paint("\n  Scan interrupted — showing what was found so far", "yellow"),
              file=sys.stderr)

    document = scanner.result_document()

    if args.json:
        text = json.dumps(document, indent=2, default=str)
        if args.json == "-":
            print(text)
        else:
            with open(args.json, "w", encoding="utf-8") as fh:
                fh.write(text)
            print(f"  JSON written to {args.json}", file=sys.stderr)
    if args.html:
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(report.render_html(document))
        print(f"  HTML report written to {args.html}", file=sys.stderr)
    if args.csv:
        with open(args.csv, "w", encoding="utf-8") as fh:
            fh.write(report.render_csv(document))
        print(f"  CSV written to {args.csv}", file=sys.stderr)

    if not ndjson and args.json != "-":
        print(report.render_terminal(document, report.Painter(
            report.supports_color(sys.stdout) and not args.no_color), verbose=args.verbose))
    return 0


def _print_progress(event: dict, paint: report.Painter) -> None:
    kind = event.get("event")
    if kind == "phase":
        message = event.get("message") or event.get("phase", "")
        if message:
            print(f"  {paint('•', 'cyan')} {message}", file=sys.stderr)
    elif kind == "plan":
        nets = ", ".join(n["cidr"] for n in event.get("networks", []))
        print(f"  {paint('•', 'cyan')} Networks: {nets}", file=sys.stderr)
    elif kind == "networks_discovered":
        for net in event.get("networks", []):
            print(f"  {paint('+', 'green')} Found extra network {net['cidr']} ({net['source']})",
                  file=sys.stderr)
    elif kind == "discovery_progress":
        print(f"    {paint(event.get('method', ''), 'grey')}: {event.get('found', 0)} hosts",
              file=sys.stderr)
    elif kind == "host_ports":
        done, total = event.get("done", 0), event.get("total", 0)
        if total:
            count = len(event.get("ports", []))
            suffix = f"  {count} open" if count else ""
            print(f"\r    scanning hosts {done}/{total}{suffix}   ", end="", file=sys.stderr)
            if done == total:
                print(file=sys.stderr)
    elif kind == "warning":
        print(f"  {paint('!', 'yellow')} {event.get('message')}", file=sys.stderr)
    elif kind == "complete":
        pass


def _self_audit(args) -> int:
    if args.json:
        document = {
            "system": localhost.system_info(),
            "interfaces": [i.to_dict() for i in interfaces.enumerate_interfaces()],
            "firewall": localhost.firewall_status(),
            "sharing": localhost.sharing_services(),
            "sockets": localhost.listening_sockets(),
            "dns": interfaces.dns_servers(),
            "wifi": localhost.wifi_details(),
        }
        text = json.dumps(document, indent=2, default=str)
        if args.json == "-":
            print(text)
        else:
            with open(args.json, "w", encoding="utf-8") as fh:
                fh.write(text)
        return 0

    paint = report.Painter(report.supports_color(sys.stdout) and not args.no_color)
    info = localhost.system_info()
    print()
    print(paint("  THIS MAC", "cyan", bold=True))
    print(paint("  " + "─" * 70, "grey"))
    for key, value in info.items():
        print(f"    {key.replace('_', ' ').title():<18} {value}")

    fw = localhost.firewall_status()
    state = paint("on", "green") if fw["enabled"] else paint("OFF", "high")
    stealth = "on" if fw["stealth_mode"] else "off"
    print(f"    {'Firewall':<18} {state}   (stealth mode {stealth})")

    wifi = localhost.wifi_details()
    if wifi.get("ssid"):
        print(f"    {'Wi-Fi network':<18} {wifi['ssid']}")

    print()
    print(paint("  NETWORK INTERFACES", "cyan", bold=True))
    print(paint("  " + "─" * 70, "grey"))
    for iface in interfaces.enumerate_interfaces():
        if not iface.ipv4:
            continue
        line = f"    {iface.name:<11}{iface.kind:<10}{iface.ipv4:<16}{iface.cidr or '':<20}"
        if iface.gateway:
            line += f"gw {iface.gateway}"
        print(line)
        if iface.mac:
            print(paint(f"      MAC {iface.mac}   {oui.describe(iface.mac) or ''}", "grey"))

    sockets = localhost.listening_sockets()
    exposed = [s for s in sockets if s["exposed"]]
    print()
    print(paint(f"  LISTENING SERVICES  ({len(exposed)} reachable from the network, "
                f"{len(sockets) - len(exposed)} loopback only)", "cyan", bold=True))
    print(paint("  " + "─" * 70, "grey"))
    print(paint(f"    {'PORT':<12}{'PROCESS':<26}{'USER':<12}{'SCOPE'}", bold=True))
    for entry in exposed:
        info_svc = services.service_for(entry["port"], entry["proto"])
        severity = info_svc.severity
        label = f"{entry['port']}/{entry['proto']}"
        process = entry["process"].replace("\\x20", " ")[:25]
        colour = severity if severity in ("high", "medium") else "green"
        print(f"    {paint(f'{label:<12}', colour)}{process:<26}{entry['user'][:11]:<12}{entry['scope']}")
        if info_svc.risk:
            print(paint(f"      {info_svc.risk}", "grey"))
    print()
    return 0
