"""Service fingerprinting: banners, HTTP metadata, TLS certificates, device typing."""
from __future__ import annotations

import asyncio
import os
import re
import ssl
import tempfile
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# Ports where the server speaks first.
BANNER_FIRST = {21, 22, 23, 25, 79, 110, 119, 143, 194, 465, 587, 993, 995, 1433,
                2222, 3306, 5432, 5900, 5901, 6667, 9418, 11211, 27017}
HTTP_PORTS = {80, 81, 82, 88, 280, 591, 593, 631, 777, 800, 808, 981, 1010, 2082,
              2086, 2095, 3000, 3128, 5000, 5001, 5601, 5800, 7000, 7001, 8000, 8008,
              8009, 8080, 8081, 8083, 8086, 8088, 8090, 8123, 8180, 8181, 8200, 8888,
              9000, 9080, 9090, 9200, 10000, 32400, 49152}
TLS_PORTS = {443, 465, 563, 636, 989, 990, 993, 995, 1443, 2083, 2087, 2096, 3269,
             4443, 5061, 5986, 6443, 8443, 8834, 8883, 9443, 10443, 44443}


@dataclass
class ServiceFingerprint:
    port: int
    proto: str = "tcp"
    banner: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    http: Optional[dict] = None
    tls: Optional[dict] = None
    notes: List[str] = field(default_factory=list)
    findings: List[dict] = field(default_factory=list)   # {severity, message}

    def add_finding(self, severity: str, message: str) -> None:
        self.findings.append({"severity": severity, "message": message})


def _clean(text: str, limit: int = 300) -> str:
    text = "".join(ch for ch in text if ch.isprintable() or ch in "\n\t")
    return re.sub(r"\s+", " ", text).strip()[:limit]


async def _read_some(reader: asyncio.StreamReader, timeout: float, limit: int = 8192) -> bytes:
    try:
        return await asyncio.wait_for(reader.read(limit), timeout=timeout)
    except (asyncio.TimeoutError, ConnectionError, OSError):
        return b""


async def fingerprint_port(
    ip: str, port: int, timeout: float = 3.0, hostname_hint: Optional[str] = None
) -> ServiceFingerprint:
    """Probe one open TCP port and describe what is listening."""
    fp = ServiceFingerprint(port=port)

    if port in TLS_PORTS:
        await _probe_tls(ip, port, fp, timeout, hostname_hint)
        if fp.tls is not None:
            await _probe_http(ip, port, fp, timeout, use_tls=True, hostname_hint=hostname_hint)
            return fp

    reader = writer = None
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
    except (asyncio.TimeoutError, OSError):
        fp.notes.append("connection failed during fingerprinting")
        return fp

    try:
        if port in BANNER_FIRST:
            data = await _read_some(reader, min(timeout, 3.0))
            if data:
                fp.banner = _clean(data.decode("utf-8", "replace"))
                _classify_banner(fp, data)
                await _followup_probe(ip, port, fp, reader, writer, timeout)
                return fp

        # Nothing volunteered — try HTTP, then a passive read.
        if port in HTTP_PORTS or port not in BANNER_FIRST:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=0.5)
            except (Exception, asyncio.TimeoutError):  # noqa: BLE001
                pass
            writer = None
            await _probe_http(ip, port, fp, timeout, use_tls=False, hostname_hint=hostname_hint)
            if fp.http is None:
                await _probe_tls(ip, port, fp, timeout, hostname_hint)
                if fp.tls is not None:
                    await _probe_http(ip, port, fp, timeout, use_tls=True, hostname_hint=hostname_hint)
            if fp.http is None and fp.tls is None:
                await _passive_banner(ip, port, fp, timeout)
    finally:
        if writer is not None:
            try:
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), timeout=0.5)
            except (Exception, asyncio.TimeoutError):  # noqa: BLE001
                pass
    return fp


async def _passive_banner(ip: str, port: int, fp: ServiceFingerprint, timeout: float) -> None:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
    except (asyncio.TimeoutError, OSError):
        return
    try:
        data = await _read_some(reader, 2.0)
        if not data:
            writer.write(b"\r\n")
            try:
                await writer.drain()
            except (ConnectionError, OSError):
                return
            data = await _read_some(reader, 1.5)
        if data:
            fp.banner = _clean(data.decode("utf-8", "replace"))
            _classify_banner(fp, data)
    finally:
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=0.5)
        except (Exception, asyncio.TimeoutError):  # noqa: BLE001
            pass


async def _followup_probe(ip: str, port: int, fp: ServiceFingerprint,
                          reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                          timeout: float) -> None:
    """Protocol-specific second question for high-signal services."""
    try:
        if port == 11211:
            writer.write(b"version\r\n")
            await writer.drain()
            data = await _read_some(reader, 1.5)
            if data:
                fp.add_finding("high", "Memcached answers without authentication")
                fp.version = _clean(data.decode("utf-8", "replace"), 60)
        elif port == 27017:
            fp.notes.append("MongoDB wire protocol detected")
    except (ConnectionError, OSError):
        pass


async def probe_redis(ip: str, port: int = 6379, timeout: float = 3.0) -> Optional[dict]:
    """Redis INFO — an answer means no authentication is required."""
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
    except (asyncio.TimeoutError, OSError):
        return None
    try:
        writer.write(b"*1\r\n$4\r\nINFO\r\n")
        await writer.drain()
        data = await _read_some(reader, 2.0, 16384)
        text = data.decode("utf-8", "replace")
        if "redis_version" in text:
            version = re.search(r"redis_version:(\S+)", text)
            os_line = re.search(r"os:(.+)", text)
            return {
                "authenticated": False,
                "version": version.group(1) if version else None,
                "os": os_line.group(1).strip() if os_line else None,
            }
        if "NOAUTH" in text or "operation not permitted" in text.lower():
            return {"authenticated": True}
    except (ConnectionError, OSError):
        return None
    finally:
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=0.5)
        except (Exception, asyncio.TimeoutError):  # noqa: BLE001
            pass
    return None


def _classify_banner(fp: ServiceFingerprint, raw: bytes) -> None:
    text = raw.decode("utf-8", "replace")
    port = fp.port

    m = re.match(r"SSH-([\d.]+)-(\S+)", text)
    if m:
        fp.product, fp.version = "SSH", m.group(2)
        fp.notes.append(f"SSH protocol {m.group(1)}")
        if m.group(1).startswith("1."):
            fp.add_finding("high", "SSH protocol version 1 is cryptographically broken")
        return

    m = re.match(r"RFB (\d+)\.(\d+)", text)
    if m:
        fp.product, fp.version = "VNC", f"RFB {m.group(1)}.{m.group(2)}"
        fp.add_finding("medium", "VNC/Screen Sharing is reachable — verify it requires a password")
        return

    if port == 21 and text.startswith("220"):
        fp.product = "FTP"
        fp.version = _clean(text.split("\r\n")[0][4:], 80)
        fp.add_finding("high", "FTP transmits credentials in cleartext")
        return

    if port == 25 or port == 587:
        fp.product = "SMTP"
        fp.version = _clean(text.split("\r\n")[0][4:], 80)
        return

    if port == 23:
        fp.product = "Telnet"
        fp.add_finding("high", "Telnet sends credentials in cleartext — disable it")
        return

    if port == 3306 and len(raw) > 5:
        try:
            end = raw.index(b"\x00", 5)
            fp.product, fp.version = "MySQL/MariaDB", raw[5:end].decode("utf-8", "replace")
            fp.add_finding("medium", "MySQL is reachable from the network")
        except ValueError:
            fp.product = "MySQL/MariaDB"
        return

    if port == 11211:
        fp.product = "Memcached"
        return

    if "redis" in text.lower():
        fp.product = "Redis"
        return

    if port in (110, 143) and text.startswith(("+OK", "* OK")):
        fp.product = "POP3" if port == 110 else "IMAP"
        fp.version = _clean(text.split("\r\n")[0], 80)
        return

    if text.strip():
        fp.product = _clean(text.split("\r\n")[0], 80) or None


# ------------------------------------------------------------------------ HTTP

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


async def _probe_http(ip: str, port: int, fp: ServiceFingerprint, timeout: float,
                      use_tls: bool, hostname_hint: Optional[str] = None) -> None:
    host_header = hostname_hint or ip
    context = None
    if use_tls:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            context.set_ciphers("DEFAULT:@SECLEVEL=0")
        except ssl.SSLError:
            pass

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=context,
                                    server_hostname=host_header if use_tls else None),
            timeout=timeout,
        )
    except (asyncio.TimeoutError, OSError, ssl.SSLError):
        return

    try:
        request = (
            f"GET / HTTP/1.1\r\nHost: {host_header}\r\n"
            "User-Agent: netscan/1.0 (network inventory)\r\n"
            "Accept: */*\r\nConnection: close\r\n\r\n"
        )
        writer.write(request.encode())
        await writer.drain()

        chunks, total = [], 0
        deadline = time.perf_counter() + timeout
        while total < 65536 and time.perf_counter() < deadline:
            chunk = await _read_some(reader, max(0.3, deadline - time.perf_counter()))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        raw = b"".join(chunks)
        if not raw:
            return

        head, _, body = raw.partition(b"\r\n\r\n")
        head_text = head.decode("utf-8", "replace")
        lines = head_text.split("\r\n")
        if not lines or not lines[0].startswith("HTTP/"):
            return

        status = lines[0]
        headers: Dict[str, str] = {}
        for line in lines[1:]:
            key, sep, value = line.partition(":")
            if sep:
                headers[key.strip().lower()] = value.strip()

        info: Dict[str, object] = {
            "scheme": "https" if use_tls else "http",
            "status": status,
            "server": headers.get("server"),
            "powered_by": headers.get("x-powered-by"),
            "location": headers.get("location"),
            "content_type": headers.get("content-type"),
            "url": f"{'https' if use_tls else 'http'}://{ip}:{port}/",
        }

        body_text = body.decode("utf-8", "replace")
        m = _TITLE_RE.search(body_text)
        if m:
            info["title"] = _clean(m.group(1), 120)

        auth = headers.get("www-authenticate")
        if auth:
            info["auth"] = auth
            realm = re.search(r'realm="?([^",]+)', auth)
            if realm:
                info["auth_realm"] = realm.group(1)

        code = status.split()[1] if len(status.split()) > 1 else ""
        if code == "401":
            fp.notes.append("HTTP authentication required")
        elif code in ("200", "302", "301") and not auth:
            fp.notes.append("HTTP responds without authentication")

        missing = [h for h in ("strict-transport-security", "content-security-policy",
                               "x-frame-options") if h not in headers]
        if use_tls and "strict-transport-security" in missing:
            info["missing_security_headers"] = missing

        fp.http = info
        fp.product = fp.product or headers.get("server") or "HTTP service"

        title = str(info.get("title", ""))
        blob = f"{headers.get('server','')} {title}".lower()
        for keyword, message, severity in (
            ("jupyter", "Jupyter notebook exposed — may allow code execution", "high"),
            ("phpmyadmin", "phpMyAdmin exposed", "high"),
            ("grafana", "Grafana dashboard exposed", "medium"),
            ("kibana", "Kibana exposed", "high"),
            ("portainer", "Portainer (Docker UI) exposed", "high"),
            ("webmin", "Webmin exposed — root-level administration", "high"),
            ("router", "Router administration page", "medium"),
            ("camera", "Camera web interface", "medium"),
            ("printer", "Printer web interface", "low"),
        ):
            if keyword in blob:
                fp.add_finding(severity, message)
    except (ConnectionError, OSError, ssl.SSLError):
        return
    finally:
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=0.5)
        except (Exception, asyncio.TimeoutError):  # noqa: BLE001
            pass


# ------------------------------------------------------------------------- TLS

def _decode_cert(der: bytes) -> Optional[dict]:
    """Turn a DER certificate into the dict shape ssl.getpeercert() returns."""
    pem = ssl.DER_cert_to_PEM_cert(der)
    try:
        import _ssl  # type: ignore
        handle, path = tempfile.mkstemp(suffix=".pem")
        try:
            with os.fdopen(handle, "w") as fh:
                fh.write(pem)
            return _ssl._test_decode_cert(path)   # noqa: SLF001 - stdlib parser
        finally:
            os.unlink(path)
    except Exception:  # noqa: BLE001
        return None


def _flatten_name(name) -> str:
    if not name:
        return ""
    parts = []
    for rdn in name:
        for key, value in rdn:
            parts.append(f"{key}={value}")
    return ", ".join(parts)


async def _probe_tls(ip: str, port: int, fp: ServiceFingerprint, timeout: float,
                     hostname_hint: Optional[str] = None) -> None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        context.set_ciphers("DEFAULT:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    context.minimum_version = ssl.TLSVersion.TLSv1 if hasattr(ssl, "TLSVersion") else context.minimum_version

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=context, server_hostname=hostname_hint or None),
            timeout=timeout,
        )
    except (asyncio.TimeoutError, OSError, ssl.SSLError, ValueError):
        return

    try:
        sslobj = writer.get_extra_info("ssl_object")
        if sslobj is None:
            return
        info: Dict[str, object] = {
            "version": sslobj.version(),
            "cipher": (sslobj.cipher() or [None])[0],
        }
        der = sslobj.getpeercert(binary_form=True)
        if der:
            info["fingerprint_sha256"] = _sha256_hex(der)
            cert = _decode_cert(der)
            if cert:
                info["subject"] = _flatten_name(cert.get("subject"))
                info["issuer"] = _flatten_name(cert.get("issuer"))
                info["not_before"] = cert.get("notBefore")
                info["not_after"] = cert.get("notAfter")
                info["serial"] = cert.get("serialNumber")
                sans = [v for k, v in cert.get("subjectAltName", ()) if k in ("DNS", "IP Address")]
                if sans:
                    info["san"] = sans[:12]
                _assess_certificate(fp, info)
        version = str(info.get("version") or "")
        if version in ("SSLv3", "TLSv1", "TLSv1.1"):
            fp.add_finding("medium", f"Obsolete TLS version supported ({version})")
        fp.tls = info
    finally:
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=0.5)
        except (Exception, asyncio.TimeoutError):  # noqa: BLE001
            pass


def _sha256_hex(data: bytes) -> str:
    import hashlib
    digest = hashlib.sha256(data).hexdigest().upper()
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))


def _assess_certificate(fp: ServiceFingerprint, info: Dict[str, object]) -> None:
    not_after = info.get("not_after")
    if isinstance(not_after, str):
        try:
            import datetime
            expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
            days = (expiry - now).days
            info["days_until_expiry"] = days
            if days < 0:
                fp.add_finding("medium", f"TLS certificate expired {abs(days)} days ago")
            elif days < 30:
                fp.add_finding("low", f"TLS certificate expires in {days} days")
        except ValueError:
            pass
    subject, issuer = info.get("subject"), info.get("issuer")
    if subject and subject == issuer:
        info["self_signed"] = True
        fp.notes.append("Self-signed certificate")


# ------------------------------------------------------- device classification

DEVICE_RULES: List[Tuple[str, str]] = [
    (r"appletv|apple tv", "Apple TV"),
    (r"macbook|imac|mac mini|macstudio|mac studio|macpro", "Mac"),
    (r"iphone", "iPhone"),
    (r"ipad", "iPad"),
    (r"watch", "Apple Watch"),
    (r"homepod", "HomePod"),
    (r"airport|time capsule", "AirPort base station"),
    (r"synology|diskstation|filestation|qnap|truenas|freenas|unraid", "NAS"),
    (r"printer|epson|brother|canon|hp ?laser|officejet|deskjet|pixma", "Printer"),
    (r"camera|ipcam|hikvision|dahua|reolink|wyze|nest ?cam|unifi ?video", "IP camera"),
    (r"router|gateway|openwrt|dd-wrt|mikrotik|edgerouter|unifi|udm|fritz", "Router / gateway"),
    (r"switch|poe", "Network switch"),
    (r"chromecast|google ?home|nest ?(hub|mini|audio)", "Google / Nest device"),
    (r"echo|alexa|amazon", "Amazon Echo"),
    (r"sonos", "Sonos speaker"),
    (r"roku|firetv|fire tv|shield", "Streaming device"),
    (r"xbox", "Xbox"),
    (r"playstation|ps4|ps5", "PlayStation"),
    (r"nintendo|switch", "Nintendo"),
    (r"raspberry|raspbian", "Raspberry Pi"),
    (r"esp(home|32|8266)|tasmota|shelly|sonoff|tuya", "IoT / smart-home device"),
    (r"lifx|hue|philips|nanoleaf", "Smart lighting"),
    (r"thermostat|ecobee|heatmiser|nest", "Thermostat"),
    (r"samsung|lg |sony bravia|tcl|hisense|vizio", "Smart TV"),
    (r"tesla|wallbox|zappi|easee", "EV charger / vehicle"),
    (r"windows|microsoft", "Windows PC"),
    (r"ubuntu|debian|centos|linux", "Linux host"),
    (r"vmware|proxmox|esxi|parallels|virtualbox", "Virtual machine / hypervisor"),
    (r"docker|kubernetes", "Container host"),
]


def classify_device(
    vendor: Optional[str],
    hostname: Optional[str],
    mdns_model: Optional[str],
    services: Dict[str, dict],
    open_ports: List[int],
    http_titles: List[str],
    ssdp: Optional[dict] = None,
) -> Tuple[Optional[str], float]:
    """Guess what a device is. Returns (label, confidence 0-1)."""
    blob_parts = [vendor or "", hostname or "", mdns_model or ""]
    blob_parts.extend(http_titles)
    blob_parts.extend(services.keys())
    for svc in services.values():
        blob_parts.append(str(svc.get("instance", "")))
        blob_parts.append(str(svc.get("txt", {}).get("model", "")))
    if ssdp:
        blob_parts.extend([str(ssdp.get("modelName", "")), str(ssdp.get("friendlyName", "")),
                           str(ssdp.get("manufacturer", "")), str(ssdp.get("server", ""))])
    blob = " ".join(blob_parts).lower()

    for pattern, label in DEVICE_RULES:
        if re.search(pattern, blob):
            confidence = 0.9 if (mdns_model or vendor) else 0.7
            return label, confidence

    # Fall back to port-shape heuristics.
    ports = set(open_ports)
    if {515, 631, 9100} & ports:
        return "Printer", 0.75
    if {548, 445, 5000, 5001} <= ports or {2049, 445} <= ports:
        return "NAS / file server", 0.6
    if 62078 in ports:
        return "iOS device", 0.85
    if {3389} & ports:
        return "Windows PC", 0.7
    if {22, 80} <= ports and 443 in ports:
        return "Server", 0.5
    if 554 in ports or 8554 in ports:
        return "IP camera", 0.6
    if {80, 443} & ports and len(ports) <= 3:
        return "Embedded / web device", 0.4
    return None, 0.0
