"""Bonjour/mDNS discovery via macOS's own mDNSResponder (the `dns-sd` tool).

Going through the system daemon means discovery keeps working even when the
process itself is not permitted to send multicast directly (macOS Local Network
privacy), and it reuses the cache mDNSResponder already maintains.
"""
from __future__ import annotations

import re
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Set, Tuple

DNS_SD = "/usr/bin/dns-sd"

# Service types worth resolving even if nothing advertises them in the browse.
SEED_TYPES = [
    "_device-info._tcp", "_airplay._tcp", "_raop._tcp", "_companion-link._tcp",
    "_googlecast._tcp", "_spotify-connect._tcp", "_http._tcp", "_https._tcp",
    "_ipp._tcp", "_ipps._tcp", "_printer._tcp", "_pdl-datastream._tcp",
    "_scanner._tcp", "_uscan._tcp", "_smb._tcp", "_afpovertcp._tcp",
    "_adisk._tcp", "_ssh._tcp", "_sftp-ssh._tcp", "_workstation._tcp",
    "_rfb._tcp", "_daap._tcp", "_home-sharing._tcp", "_hap._tcp",
    "_homekit._tcp", "_sonos._tcp", "_plexmediasvr._tcp", "_esphomelib._tcp",
    "_matter._tcp", "_matterc._udp", "_nvstream._tcp", "_touch-able._tcp",
]

# Friendly names for the service types users actually care about.
SERVICE_LABELS = {
    "_airplay._tcp": "AirPlay",
    "_raop._tcp": "AirPlay audio",
    "_companion-link._tcp": "Apple Continuity",
    "_googlecast._tcp": "Chromecast",
    "_spotify-connect._tcp": "Spotify Connect",
    "_http._tcp": "Web interface",
    "_https._tcp": "Web interface (TLS)",
    "_ipp._tcp": "Printer (IPP)",
    "_ipps._tcp": "Printer (IPP/TLS)",
    "_printer._tcp": "Printer (LPD)",
    "_pdl-datastream._tcp": "Printer (raw)",
    "_scanner._tcp": "Scanner",
    "_uscan._tcp": "Scanner (eSCL)",
    "_smb._tcp": "SMB file sharing",
    "_afpovertcp._tcp": "AFP file sharing",
    "_adisk._tcp": "Time Machine target",
    "_ssh._tcp": "SSH",
    "_sftp-ssh._tcp": "SFTP",
    "_workstation._tcp": "Workstation",
    "_rfb._tcp": "Screen sharing (VNC)",
    "_daap._tcp": "iTunes library",
    "_home-sharing._tcp": "Home Sharing",
    "_hap._tcp": "HomeKit accessory",
    "_homekit._tcp": "HomeKit",
    "_sonos._tcp": "Sonos",
    "_plexmediasvr._tcp": "Plex Media Server",
    "_esphomelib._tcp": "ESPHome device",
    "_matter._tcp": "Matter device",
    "_matterc._udp": "Matter commissioning",
    "_nvstream._tcp": "NVIDIA GameStream",
    "_touch-able._tcp": "Apple Remote target",
    "_device-info._tcp": "Device info",
}


def available() -> bool:
    import os
    return os.path.exists(DNS_SD)


def _run_timed(args: List[str], seconds: float) -> str:
    """Run a dns-sd command that never exits, and stop it after `seconds`."""
    try:
        proc = subprocess.Popen(
            args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
        )
    except OSError:
        return ""
    timer = threading.Timer(seconds, proc.kill)
    timer.start()
    try:
        out, _ = proc.communicate()
    except Exception:  # noqa: BLE001
        out = ""
    finally:
        timer.cancel()
    return out or ""


def browse_types(seconds: float = 2.5) -> Set[str]:
    """Discover which service types exist on the network."""
    text = _run_timed([DNS_SD, "-B", "_services._dns-sd._udp", "local"], seconds)
    types: Set[str] = set()
    for line in text.splitlines():
        parts = line.split()
        # Columns: time A/R Flags if Domain ServiceType InstanceName
        if len(parts) >= 7 and parts[1] in ("Add", "Rmv"):
            service_type, instance = parts[5], parts[6]
            if service_type.startswith("_") and instance.startswith("_"):
                proto = service_type.replace(".local.", "").strip(".")
                types.add(f"{instance}.{proto}")
    return types


_ZONE_SRV = re.compile(r"^(\S+)\s+SRV\s+(\d+)\s+(\d+)\s+(\d+)\s+(\S+?)\.?\s*(?:;.*)?$")
_ZONE_TXT = re.compile(r"^(\S+)\s+TXT\s+(.*)$")
_ZONE_CONT = re.compile(r'^\s+(?:TXT\s+)?(".*)$')


def resolve_type(service_type: str, seconds: float = 2.0) -> Dict[str, dict]:
    """`dns-sd -Z` a service type -> {instance: {host, port, txt}}."""
    text = _run_timed([DNS_SD, "-Z", service_type, "local"], seconds)
    services: Dict[str, dict] = {}
    last_instance: Optional[str] = None

    for raw in text.splitlines():
        line = raw.rstrip()
        if not line or line.lstrip().startswith(";"):
            continue
        m = _ZONE_SRV.match(line)
        if m:
            instance, _, _, port, host = m.groups()
            name = instance.split("._")[0].replace("\\032", " ").replace("\\ ", " ")
            entry = services.setdefault(instance, {})
            entry.update({
                "instance": name,
                "host": host.rstrip("."),
                "port": int(port),
                "type": service_type,
            })
            last_instance = instance
            continue
        m = _ZONE_TXT.match(line)
        if m:
            instance, txt = m.groups()
            entry = services.setdefault(instance, {"instance": instance.split("._")[0],
                                                   "type": service_type})
            entry.setdefault("txt", {}).update(_parse_txt_fields(txt))
            last_instance = instance
            continue
        m = _ZONE_CONT.match(raw)
        if m and last_instance:
            services[last_instance].setdefault("txt", {}).update(_parse_txt_fields(m.group(1)))
    return services


def _parse_txt_fields(blob: str) -> Dict[str, str]:
    fields: Dict[str, str] = {}
    for item in re.findall(r'"((?:[^"\\]|\\.)*)"', blob):
        item = item.replace('\\"', '"')
        key, sep, value = item.partition("=")
        key = key.strip()
        if key:
            fields[key] = value.strip() if sep else ""
    return fields


def resolve_hostname(host: str, seconds: float = 1.5) -> Optional[str]:
    """Resolve a .local hostname to an IPv4 address using dns-sd -G."""
    text = _run_timed([DNS_SD, "-G", "v4", host], seconds)
    for line in text.splitlines():
        m = re.search(r"\s(\d+\.\d+\.\d+\.\d+)\s", line)
        if m and " Add " in line:
            return m.group(1)
    for line in text.splitlines():
        m = re.search(r"\s(\d+\.\d+\.\d+\.\d+)\s", line)
        if m:
            return m.group(1)
    return None


def discover(browse_seconds: float = 2.5, resolve_seconds: float = 2.0,
             max_types: int = 40, workers: int = 12) -> Dict[str, dict]:
    """Full Bonjour sweep. Returns {ip: {names, services, model, txt}}."""
    if not available():
        return {}

    types = set(SEED_TYPES) | browse_types(browse_seconds)
    ordered = sorted(types, key=lambda t: (t not in SEED_TYPES, t))[:max_types]

    resolved: Dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for services in pool.map(lambda t: resolve_type(t, resolve_seconds), ordered):
            resolved.update(services)

    hosts = {s["host"] for s in resolved.values() if s.get("host")}
    host_ips: Dict[str, Optional[str]] = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for host, ip in zip(hosts, pool.map(resolve_hostname, hosts)):
            host_ips[host] = ip

    results: Dict[str, dict] = {}
    for entry in resolved.values():
        host = entry.get("host")
        ip = host_ips.get(host) if host else None
        if not ip:
            continue
        record = results.setdefault(ip, {"names": [], "services": {}, "model": None, "txt": {}})
        if host and host not in record["names"]:
            record["names"].append(host)
        stype = entry.get("type", "")
        label = SERVICE_LABELS.get(stype, stype)
        record["services"][stype] = {
            "label": label,
            "instance": entry.get("instance"),
            "port": entry.get("port"),
            "txt": entry.get("txt", {}),
        }
        txt = entry.get("txt", {})
        record["txt"].update(txt)
        for key in ("model", "md", "am", "ty", "product", "MD"):
            value = txt.get(key)
            if value and not record["model"]:
                record["model"] = value
    return results
