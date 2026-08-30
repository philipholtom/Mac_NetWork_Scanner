"""Asynchronous TCP connect scanning and UDP protocol probing."""
from __future__ import annotations

import asyncio
import errno
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Tuple


@dataclass
class PortResult:
    port: int
    proto: str = "tcp"
    state: str = "open"          # open | closed | filtered | open|filtered
    latency_ms: Optional[float] = None
    banner: Optional[str] = None
    error: Optional[str] = None


def raise_fd_limit(target: int = 8192) -> int:
    """Best-effort bump of the open-file limit so we can use high concurrency."""
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        if soft < target:
            new = min(target, hard if hard > 0 else target)
            resource.setrlimit(resource.RLIMIT_NOFILE, (new, hard))
            return new
        return soft
    except Exception:  # noqa: BLE001
        return 256


async def _probe_tcp(ip: str, port: int, timeout: float) -> PortResult:
    start = time.perf_counter()
    writer = None
    try:
        fut = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        latency = (time.perf_counter() - start) * 1000
        return PortResult(port=port, state="open", latency_ms=latency)
    except asyncio.TimeoutError:
        return PortResult(port=port, state="filtered")
    except ConnectionRefusedError:
        return PortResult(port=port, state="closed")
    except OSError as exc:
        if exc.errno in (errno.EHOSTUNREACH, errno.ENETUNREACH, errno.EHOSTDOWN):
            return PortResult(port=port, state="filtered", error="unreachable")
        if exc.errno in (errno.EMFILE, errno.ENFILE):
            return PortResult(port=port, state="error", error="out of file descriptors")
        return PortResult(port=port, state="closed", error=str(exc))
    finally:
        if writer is not None:
            try:
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), timeout=0.5)
            except (Exception, asyncio.TimeoutError):  # noqa: BLE001
                pass


async def scan_host_ports(
    ip: str,
    ports: Iterable[int],
    timeout: float = 1.2,
    concurrency: int = 400,
    progress: Optional[Callable[[int, int], None]] = None,
) -> List[PortResult]:
    """TCP connect scan one host. Returns only ports that are open."""
    port_list = list(ports)
    done = 0
    open_ports: List[PortResult] = []

    # A fixed pool of workers pulling from one iterator, rather than a task per
    # port. Creating 65,535 tasks per host (the `full` profile) costs about
    # 100 MB each and multiplies by the number of hosts scanned in parallel.
    pending = iter(port_list)

    async def worker() -> None:
        nonlocal done
        while True:
            try:
                port = next(pending)     # safe: the loop is single-threaded
            except StopIteration:
                return
            result = await _probe_tcp(ip, port, timeout)
            done += 1
            if result.state == "open":
                open_ports.append(result)
            if progress and done % 64 == 0:
                progress(done, len(port_list))

    worker_count = max(1, min(concurrency, len(port_list)))
    await asyncio.gather(*(worker() for _ in range(worker_count)))
    if progress:
        progress(len(port_list), len(port_list))
    open_ports.sort(key=lambda r: r.port)
    return open_ports


async def scan_many_hosts(
    hosts: List[str],
    ports: List[int],
    timeout: float = 1.2,
    host_concurrency: int = 24,
    port_concurrency: int = 300,
    on_host_done: Optional[Callable[[str, List[PortResult]], None]] = None,
    on_progress: Optional[Callable[[str, int, int], None]] = None,
) -> Dict[str, List[PortResult]]:
    """Scan many hosts, bounded by both host- and port-level concurrency."""
    results: Dict[str, List[PortResult]] = {}
    remaining = iter(hosts)

    async def run() -> None:
        while True:
            try:
                ip = next(remaining)
            except StopIteration:
                return
            found = await scan_host_ports(
                ip, ports, timeout=timeout, concurrency=port_concurrency,
                progress=(lambda d, t, _ip=ip: on_progress(_ip, d, t)) if on_progress else None,
            )
            results[ip] = found
            if on_host_done:
                on_host_done(ip, found)

    worker_count = max(1, min(host_concurrency, len(hosts)))
    await asyncio.gather(*(run() for _ in range(worker_count)))
    return results


# ------------------------------------------------------------------ UDP probes

def _dns_probe() -> bytes:
    # Standard query: version.bind CHAOS TXT  (also answers as a plain A query)
    return struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + \
        b"\x07version\x04bind\x00" + struct.pack("!HH", 16, 3)


def _ntp_probe() -> bytes:
    return b"\x1b" + b"\x00" * 47


def _snmp_probe(community: str = "public") -> bytes:
    """SNMPv2c GET for sysDescr.0 (1.3.6.1.2.1.1.1.0)."""
    def tlv(tag: int, payload: bytes) -> bytes:
        if len(payload) < 128:
            return bytes([tag, len(payload)]) + payload
        length = len(payload)
        raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
        return bytes([tag, 0x80 | len(raw)]) + raw + payload

    oid = bytes([0x2B, 6, 1, 2, 1, 1, 1, 0])          # 1.3.6.1.2.1.1.1.0
    varbind = tlv(0x30, tlv(0x06, oid) + tlv(0x05, b""))
    varbinds = tlv(0x30, varbind)
    pdu = tlv(0xA0, tlv(0x02, b"\x1c") + tlv(0x02, b"\x00") + tlv(0x02, b"\x00") + varbinds)
    return tlv(0x30, tlv(0x02, b"\x01") + tlv(0x04, community.encode()) + pdu)


def _netbios_probe() -> bytes:
    name = b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00"
    return struct.pack("!HHHHHH", 0x4E53, 0, 1, 0, 0, 0) + name + struct.pack("!HH", 0x21, 1)


def _ssdp_probe() -> bytes:
    return (
        "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n'
    ).encode()


def _mdns_probe() -> bytes:
    from . import dnsmsg
    return dnsmsg.build_query([("_services._dns-sd._udp.local", dnsmsg.TYPE_PTR)],
                              unicast_reply=True)


UDP_PROBES: Dict[int, Tuple[str, bytes]] = {
    53: ("dns", _dns_probe()),
    123: ("ntp", _ntp_probe()),
    137: ("netbios-ns", _netbios_probe()),
    161: ("snmp", _snmp_probe()),
    1900: ("ssdp", _ssdp_probe()),
    5353: ("mdns", _mdns_probe()),
    11211: ("memcached", b"stats\r\n"),
    69: ("tftp", b"\x00\x01" + b"netscan-probe\x00octet\x00"),
    500: ("isakmp", b"\x00" * 8 + b"\x00" * 8 + b"\x01\x10\x02\x00" + b"\x00" * 12),
}


def udp_scan(ip: str, ports: List[int], timeout: float = 1.5) -> List[PortResult]:
    """Probe UDP ports with protocol-specific payloads.

    A reply proves the port is open; silence is ambiguous (open|filtered), so
    only responsive ports are reported.
    """
    results: List[PortResult] = []
    for port in ports:
        name, payload = UDP_PROBES.get(port, ("", b"\x00"))
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
        except OSError:
            continue
        start = time.perf_counter()
        try:
            sock.sendto(payload, (ip, port))
            data, _ = sock.recvfrom(4096)
            latency = (time.perf_counter() - start) * 1000
            banner = _summarise_udp(port, data)
            results.append(PortResult(port=port, proto="udp", state="open",
                                      latency_ms=latency, banner=banner))
        except socket.timeout:
            pass
        except ConnectionRefusedError:
            results.append(PortResult(port=port, proto="udp", state="closed"))
        except OSError:
            pass
        finally:
            sock.close()
    return results


def _summarise_udp(port: int, data: bytes) -> Optional[str]:
    if not data:
        return None
    try:
        if port == 161:
            text = _extract_snmp_string(data)
            return f"sysDescr: {text}" if text else "SNMP response (community 'public' accepted)"
        if port == 123:
            if len(data) >= 48:
                stratum = data[1]
                return f"NTP stratum {stratum}"
        if port == 1900:
            for line in data.decode("utf-8", "replace").split("\r\n"):
                if line.lower().startswith("server:"):
                    return line.split(":", 1)[1].strip()
        if port == 11211:
            text = data.decode("utf-8", "replace")
            for line in text.split("\r\n"):
                if "version" in line.lower():
                    return line.strip()
            return "memcached stats returned (no auth)"
        if port == 53:
            return "DNS server responded"
        if port == 5353:
            return "mDNS responder"
        text = data.decode("utf-8", "replace").strip()
        printable = "".join(c for c in text if c.isprintable())
        return printable[:120] or f"{len(data)} bytes"
    except Exception:  # noqa: BLE001
        return f"{len(data)} bytes"


def _extract_snmp_string(data: bytes) -> Optional[str]:
    """Pull the longest printable OCTET STRING out of an SNMP response."""
    best = ""
    i = 0
    while i < len(data) - 2:
        if data[i] == 0x04:
            length = data[i + 1]
            start = i + 2
            if length & 0x80:
                count = length & 0x7F
                if count == 0 or count > 3:
                    i += 1
                    continue
                length = int.from_bytes(data[i + 2:i + 2 + count], "big")
                start = i + 2 + count
            chunk = data[start:start + length]
            try:
                text = chunk.decode("utf-8")
            except UnicodeDecodeError:
                i += 1
                continue
            if len(text) > len(best) and sum(c.isprintable() for c in text) > len(text) * 0.8:
                best = text
            i = start + length
            continue
        i += 1
    return " ".join(best.split())[:200] or None
