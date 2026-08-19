"""Host discovery: ICMP, ARP, mDNS/Bonjour, NetBIOS, SSDP/UPnP and reverse DNS."""
from __future__ import annotations

import os
import re
import select
import socket
import struct
import subprocess
import time
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set, Tuple

from . import dnsmsg, oui

MDNS_ADDR = "224.0.0.251"
MDNS_PORT = 5353
SSDP_ADDR = "239.255.255.250"
SSDP_PORT = 1900

# Bonjour service types worth browsing — each reveals device role and often model.
MDNS_SERVICES = [
    "_device-info._tcp.local", "_airplay._tcp.local", "_raop._tcp.local",
    "_homekit._tcp.local", "_hap._tcp.local", "_companion-link._tcp.local",
    "_googlecast._tcp.local", "_spotify-connect._tcp.local", "_http._tcp.local",
    "_https._tcp.local", "_ipp._tcp.local", "_ipps._tcp.local", "_printer._tcp.local",
    "_pdl-datastream._tcp.local", "_scanner._tcp.local", "_uscan._tcp.local",
    "_smb._tcp.local", "_afpovertcp._tcp.local", "_adisk._tcp.local",
    "_time-machine._tcp.local", "_ssh._tcp.local", "_sftp-ssh._tcp.local",
    "_workstation._tcp.local", "_daap._tcp.local", "_dacp._tcp.local",
    "_touch-able._tcp.local", "_nvstream._tcp.local", "_rdlink._tcp.local",
    "_sleep-proxy._udp.local", "_apple-mobdev2._tcp.local", "_sonos._tcp.local",
    "_plexmediasvr._tcp.local", "_nas._tcp.local", "_ewelink._tcp.local",
    "_esphomelib._tcp.local", "_hue._tcp.local", "_matter._tcp.local",
    "_matterc._udp.local", "_services._dns-sd._udp.local",
]


@dataclass
class DiscoveryData:
    """Everything discovery learned about one host, keyed by IP."""
    ip: str
    alive: bool = False
    methods: Set[str] = field(default_factory=set)
    mac: Optional[str] = None
    vendor: Optional[str] = None
    rtt_ms: Optional[float] = None
    hostname: Optional[str] = None          # reverse DNS
    mdns_name: Optional[str] = None         # foo.local
    netbios_name: Optional[str] = None
    workgroup: Optional[str] = None
    model: Optional[str] = None             # from mDNS TXT / SSDP
    services: Dict[str, dict] = field(default_factory=dict)   # bonjour services
    ssdp: Dict[str, str] = field(default_factory=dict)
    open_probe_ports: List[int] = field(default_factory=list)


# ---------------------------------------------------------------- ICMP sweep

def _icmp_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def icmp_available() -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
        s.close()
        return True
    except OSError:
        return False


def icmp_sweep(
    hosts: List[str],
    timeout: float = 1.0,
    retries: int = 1,
    pace: int = 256,
    progress=None,
) -> Dict[str, float]:
    """Ping every host. Returns {ip: round-trip milliseconds}.

    Uses macOS's unprivileged SOCK_DGRAM ICMP socket, so no sudo is required.
    """
    alive: Dict[str, float] = {}
    if not hosts:
        return alive
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
    except OSError:
        return alive

    sock.setblocking(False)
    ident = os.getpid() & 0xFFFF
    payload = b"netscan-" + struct.pack("!d", time.time())

    with sock:
        for attempt in range(retries + 1):
            pending = [h for h in hosts if h not in alive]
            if not pending:
                break
            sent_at: Dict[str, float] = {}
            for index, host in enumerate(pending):
                seq = index & 0xFFFF
                header = struct.pack("!BBHHH", 8, 0, 0, ident, seq)
                chk = _icmp_checksum(header + payload)
                packet = struct.pack("!BBHHH", 8, 0, chk, ident, seq) + payload
                try:
                    sock.sendto(packet, (host, 0))
                    sent_at[host] = time.perf_counter()
                except OSError:
                    continue
                if pace and index % pace == pace - 1:
                    time.sleep(0.01)
                    _drain_icmp(sock, alive, sent_at)

            deadline = time.perf_counter() + timeout
            while time.perf_counter() < deadline:
                remaining = deadline - time.perf_counter()
                ready, _, _ = select.select([sock], [], [], max(0.0, min(0.2, remaining)))
                if ready:
                    _drain_icmp(sock, alive, sent_at)
                if progress:
                    progress(len(alive))
                if len(alive) == len(hosts):
                    break
    return alive


def _drain_icmp(sock: socket.socket, alive: Dict[str, float], sent_at: Dict[str, float]) -> None:
    while True:
        try:
            data, addr = sock.recvfrom(2048)
        except (BlockingIOError, OSError):
            return
        ip = addr[0]
        # macOS may hand back the full IP packet; skip the IPv4 header if present.
        if data and (data[0] >> 4) == 4:
            ihl = (data[0] & 0x0F) * 4
            data = data[ihl:]
        if len(data) >= 8 and data[0] == 0 and ip in sent_at and ip not in alive:
            alive[ip] = (time.perf_counter() - sent_at[ip]) * 1000.0


# ------------------------------------------------------------------ ARP cache

def arp_table() -> Dict[str, str]:
    """Read the kernel ARP cache: {ip: mac}."""
    table: Dict[str, str] = {}
    try:
        out = subprocess.run(
            ["/usr/sbin/arp", "-an"], capture_output=True, text=True, timeout=10, check=False
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return table
    for line in out.splitlines():
        m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-fA-F:]+)", line)
        if not m:
            continue
        ip, mac = m.group(1), oui.normalize(m.group(2))
        if mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00") or "incomplete" in line:
            continue
        table[ip] = mac
    return table


def prime_arp(hosts: Iterable[str]) -> None:
    """Send a stray UDP datagram to each host so the kernel resolves its MAC."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except OSError:
        return
    sock.setblocking(False)
    with sock:
        for index, host in enumerate(hosts):
            try:
                sock.sendto(b"\x00", (host, 9))
            except OSError:
                pass
            if index % 256 == 255:
                time.sleep(0.01)


# --------------------------------------------------------------------- mDNS

def _open_mdns_socket() -> Optional[socket.socket]:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.bind(("", 0))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.setblocking(False)
        return sock
    except OSError:
        return None


def mdns_browse(duration: float = 3.0, source_ip: Optional[str] = None) -> Dict[str, dict]:
    """Browse Bonjour services on the LAN.

    Returns {ip: {"names": [...], "services": {...}, "model": str}} by resolving
    SRV targets to the A records seen in the same responses.
    """
    sock = _open_mdns_socket()
    if sock is None:
        return {}

    if source_ip:
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(source_ip))
        except OSError:
            pass

    a_records: Dict[str, str] = {}          # hostname.local -> ip
    ptr_instances: Dict[str, List[str]] = {}  # service type -> [instance names]
    srv_records: Dict[str, dict] = {}        # instance -> {target, port}
    txt_records: Dict[str, dict] = {}        # instance -> txt dict
    responders: Dict[str, Set[str]] = {}     # ip -> {names seen from it}

    with sock:
        questions = [(svc, dnsmsg.TYPE_PTR) for svc in MDNS_SERVICES]
        for i in range(0, len(questions), 6):
            packet = dnsmsg.build_query(questions[i:i + 6], unicast_reply=False)
            try:
                sock.sendto(packet, (MDNS_ADDR, MDNS_PORT))
            except OSError:
                pass

        deadline = time.perf_counter() + duration
        while time.perf_counter() < deadline:
            ready, _, _ = select.select([sock], [], [], max(0.0, min(0.3, deadline - time.perf_counter())))
            if not ready:
                continue
            try:
                data, addr = sock.recvfrom(9000)
            except OSError:
                continue
            src = addr[0]
            for rec in dnsmsg.parse_message(data):
                name = rec.name
                if rec.rtype == dnsmsg.TYPE_A and isinstance(rec.data, str):
                    a_records[name.lower()] = rec.data
                    responders.setdefault(rec.data, set()).add(name)
                elif rec.rtype == dnsmsg.TYPE_PTR and isinstance(rec.data, str):
                    ptr_instances.setdefault(name.lower(), []).append(rec.data)
                elif rec.rtype == dnsmsg.TYPE_SRV and isinstance(rec.data, dict):
                    srv_records[name.lower()] = rec.data
                elif rec.rtype == dnsmsg.TYPE_TXT and isinstance(rec.data, dict):
                    txt_records[name.lower()] = rec.data
                responders.setdefault(src, set())

    results: Dict[str, dict] = {}

    def entry(ip: str) -> dict:
        return results.setdefault(ip, {"names": [], "services": {}, "model": None})

    # Direct A records
    for host, ip in a_records.items():
        e = entry(ip)
        pretty = host[:-1] if host.endswith(".") else host
        if pretty not in e["names"]:
            e["names"].append(pretty)

    # Attach services via their SRV target
    for service_type, instances in ptr_instances.items():
        for instance in instances:
            key = instance.lower()
            srv = srv_records.get(key)
            txt = txt_records.get(key, {})
            target = (srv or {}).get("target", "").lower()
            ip = a_records.get(target) or a_records.get(target + ".")
            if not ip:
                continue
            e = entry(ip)
            label = instance.split("._")[0]
            e["services"][service_type.replace(".local", "").rstrip(".")] = {
                "instance": label,
                "port": (srv or {}).get("port"),
                "txt": txt,
            }
            for key_name in ("model", "md", "am", "ty", "product"):
                if txt.get(key_name) and not e["model"]:
                    e["model"] = txt[key_name]

    # Hosts that answered but produced no A record still count as seen.
    for ip in responders:
        entry(ip)
    return results


def mdns_reverse(ips: List[str], timeout: float = 1.5) -> Dict[str, str]:
    """Ask each host directly (unicast :5353) for its own .local name."""
    names: Dict[str, str] = {}
    if not ips:
        return names
    sock = _open_mdns_socket()
    if sock is None:
        return names
    with sock:
        for ip in ips:
            query = dnsmsg.build_query(
                [(dnsmsg.reverse_name(ip), dnsmsg.TYPE_PTR)], unicast_reply=True
            )
            try:
                sock.sendto(query, (ip, MDNS_PORT))
            except OSError:
                continue
        deadline = time.perf_counter() + timeout
        while time.perf_counter() < deadline:
            ready, _, _ = select.select([sock], [], [], max(0.0, min(0.25, deadline - time.perf_counter())))
            if not ready:
                continue
            try:
                data, addr = sock.recvfrom(4096)
            except OSError:
                continue
            for rec in dnsmsg.parse_message(data):
                if rec.rtype == dnsmsg.TYPE_PTR and isinstance(rec.data, str):
                    value = rec.data.rstrip(".")
                    if value and addr[0] not in names:
                        names[addr[0]] = value
    return names


# ------------------------------------------------------------------ NetBIOS

def netbios_query(ips: List[str], timeout: float = 1.5) -> Dict[str, dict]:
    """NetBIOS node status request (UDP 137) -> Windows/Samba name and workgroup."""
    results: Dict[str, dict] = {}
    if not ips:
        return results
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except OSError:
        return results
    sock.setblocking(False)

    # Node status request for the wildcard name '*'.
    encoded = b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00"
    packet = struct.pack("!HHHHHH", 0x4E53, 0x0000, 1, 0, 0, 0) + encoded + struct.pack("!HH", 0x21, 0x01)

    with sock:
        for ip in ips:
            try:
                sock.sendto(packet, (ip, 137))
            except OSError:
                continue
        deadline = time.perf_counter() + timeout
        while time.perf_counter() < deadline:
            ready, _, _ = select.select([sock], [], [], max(0.0, min(0.25, deadline - time.perf_counter())))
            if not ready:
                continue
            try:
                data, addr = sock.recvfrom(2048)
            except OSError:
                continue
            parsed = _parse_netbios(data)
            if parsed:
                results[addr[0]] = parsed
    return results


def _parse_netbios(data: bytes) -> Optional[dict]:
    try:
        if len(data) < 57:
            return None
        offset = 12
        while offset < len(data) and data[offset] != 0:
            offset += data[offset] + 1
        offset += 1 + 4 + 4 + 2      # null, type/class, ttl, rdlength
        if offset >= len(data):
            return None
        count = data[offset]
        offset += 1
        names, workgroup, computer = [], None, None
        for _ in range(count):
            if offset + 18 > len(data):
                break
            raw = data[offset:offset + 15].decode("ascii", "replace").strip()
            suffix = data[offset + 15]
            flags = struct.unpack("!H", data[offset + 16:offset + 18])[0]
            group = bool(flags & 0x8000)
            names.append({"name": raw, "suffix": suffix, "group": group})
            if suffix == 0x00 and not group and computer is None:
                computer = raw
            if suffix == 0x00 and group and workgroup is None:
                workgroup = raw
            offset += 18
        mac = None
        if offset + 6 <= len(data):
            candidate = ":".join(f"{b:02x}" for b in data[offset:offset + 6])
            if candidate != "00:00:00:00:00:00":
                mac = candidate
        if not names:
            return None
        return {"name": computer, "workgroup": workgroup, "names": names, "mac": mac}
    except (struct.error, IndexError, UnicodeDecodeError):
        return None


# --------------------------------------------------------------- SSDP / UPnP

SSDP_TARGETS = ["ssdp:all", "upnp:rootdevice"]


def ssdp_discover(duration: float = 3.0, source_ip: Optional[str] = None) -> Dict[str, dict]:
    """M-SEARCH the LAN for UPnP devices; returns {ip: headers}."""
    results: Dict[str, dict] = {}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        if source_ip:
            try:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(source_ip))
            except OSError:
                pass
        sock.bind(("", 0))
        sock.setblocking(False)
    except OSError:
        return results

    with sock:
        for target in SSDP_TARGETS:
            message = (
                "M-SEARCH * HTTP/1.1\r\n"
                f"HOST: {SSDP_ADDR}:{SSDP_PORT}\r\n"
                'MAN: "ssdp:discover"\r\n'
                "MX: 2\r\n"
                f"ST: {target}\r\n"
                "USER-AGENT: macOS/14 UPnP/1.1 netscan/1.0\r\n\r\n"
            ).encode()
            for _ in range(2):
                try:
                    sock.sendto(message, (SSDP_ADDR, SSDP_PORT))
                except OSError:
                    pass

        deadline = time.perf_counter() + duration
        while time.perf_counter() < deadline:
            ready, _, _ = select.select([sock], [], [], max(0.0, min(0.3, deadline - time.perf_counter())))
            if not ready:
                continue
            try:
                data, addr = sock.recvfrom(8192)
            except OSError:
                continue
            headers = _parse_http_headers(data.decode("utf-8", "replace"))
            if not headers:
                continue
            existing = results.setdefault(addr[0], {})
            for key, value in headers.items():
                existing.setdefault(key, value)
            st = headers.get("st") or headers.get("nt")
            if st:
                types = existing.setdefault("_types", "")
                if st not in types:
                    existing["_types"] = f"{types},{st}".strip(",")
    return results


def _parse_http_headers(text: str) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    lines = text.split("\r\n")
    if not lines or not lines[0].upper().startswith(("HTTP/1.1", "NOTIFY", "M-SEARCH", "HTTP/1.0")):
        return headers
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        headers[key.strip().lower()] = value.strip()
    return headers


def fetch_upnp_description(location: str, timeout: float = 3.0) -> Dict[str, str]:
    """Fetch and parse a UPnP device description XML for friendly name / model."""
    import urllib.request

    info: Dict[str, str] = {}
    try:
        req = urllib.request.Request(location, headers={"User-Agent": "netscan/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(65536).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001 - remote device, any failure is fine
        return info
    for tag in ("friendlyName", "manufacturer", "modelName", "modelNumber",
                "modelDescription", "serialNumber", "presentationURL", "UDN"):
        m = re.search(rf"<{tag}>(.*?)</{tag}>", body, re.S | re.I)
        if m:
            value = re.sub(r"\s+", " ", m.group(1)).strip()
            if value:
                info[tag] = value[:200]
    return info


# --------------------------------------------------------------- reverse DNS

def reverse_dns(ip: str, timeout: float = 1.0) -> Optional[str]:
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, socket.herror):
        return None
    finally:
        socket.setdefaulttimeout(old)
