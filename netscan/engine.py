"""Scan orchestration: discovery -> port scan -> fingerprint -> classification."""
from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Set, Tuple

from . import bonjour, discovery, fingerprint, interfaces, localhost, oui, portscan, services

SCHEMA_VERSION = 1


@dataclass
class ScanOptions:
    targets: List[str] = field(default_factory=list)      # explicit CIDRs/IPs
    all_networks: bool = True          # every local interface subnet
    discover_networks: bool = True     # infer extra subnets (Bonjour, ARP, gateways)
    probe_adjacent: bool = False       # ping-sweep neighbouring /24s in the same /16
    profile: str = "common"            # fast | common | full
    ports: Optional[str] = None        # explicit port spec, overrides profile
    udp: bool = True
    timeout: float = 1.2
    host_concurrency: int = 32
    port_concurrency: int = 300
    ping_timeout: float = 1.0
    ping_retries: int = 1
    bonjour_seconds: float = 3.0
    fingerprint_enabled: bool = True
    fingerprint_concurrency: int = 40
    max_hosts: int = 8192
    include_offline: bool = False
    scan_self: bool = True

    def port_list(self) -> List[int]:
        if self.ports:
            return services.parse_port_spec(self.ports)
        return services.profile_ports(self.profile)


@dataclass
class Host:
    ip: str
    network: Optional[str] = None
    interface: Optional[str] = None
    alive: bool = False
    mac: Optional[str] = None
    vendor: Optional[str] = None
    rtt_ms: Optional[float] = None
    hostname: Optional[str] = None
    names: List[str] = field(default_factory=list)
    netbios_name: Optional[str] = None
    workgroup: Optional[str] = None
    model: Optional[str] = None
    device_type: Optional[str] = None
    confidence: float = 0.0
    discovery: List[str] = field(default_factory=list)
    bonjour: Dict[str, dict] = field(default_factory=dict)
    ssdp: Dict[str, str] = field(default_factory=dict)
    tcp_ports: List[dict] = field(default_factory=list)
    udp_ports: List[dict] = field(default_factory=list)
    findings: List[dict] = field(default_factory=list)
    is_self: bool = False
    is_gateway: bool = False
    scanned: bool = False

    def label(self) -> str:
        return self.hostname or self.netbios_name or (self.names[0] if self.names else self.ip)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["label"] = self.label()
        data["open_port_count"] = len(self.tcp_ports) + len(self.udp_ports)
        data["risk"] = max((f.get("severity", "info") for f in self.findings),
                           key=lambda s: -services.SEVERITY_ORDER.get(s, 3), default="info") \
            if self.findings else "info"
        return data


class Scanner:
    """Runs a full scan, emitting structured events as it goes."""

    def __init__(self, options: ScanOptions, emit: Optional[Callable[[dict], None]] = None):
        self.options = options
        self.emit = emit or (lambda event: None)
        self.hosts: Dict[str, Host] = {}
        self.networks: List[dict] = []
        self.local_ips: Set[str] = set()
        self.gateways: Set[str] = set()
        self.started = 0.0
        self.cancelled = False

    # ------------------------------------------------------------- utilities

    def _event(self, kind: str, **payload) -> None:
        payload["event"] = kind
        payload["t"] = round(time.time() - self.started, 3) if self.started else 0.0
        self.emit(payload)

    def _host(self, ip: str) -> Host:
        host = self.hosts.get(ip)
        if host is None:
            host = Host(ip=ip)
            self.hosts[ip] = host
        return host

    # ------------------------------------------------------------ target set

    def plan_targets(self) -> List[dict]:
        """Work out every network to scan, and why."""
        plan: List[dict] = []
        seen: Set[str] = set()

        def add(cidr: str, source: str, iface: Optional[str] = None,
                gateway: Optional[str] = None) -> None:
            if cidr in seen:
                return
            seen.add(cidr)
            try:
                net = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                return
            plan.append({
                "cidr": str(net),
                "source": source,
                "interface": iface,
                "gateway": gateway,
                "hosts": net.num_addresses if net.prefixlen == 32 else max(0, net.num_addresses - 2),
            })

        ifaces = interfaces.enumerate_interfaces()
        self.local_ips = {i.ipv4 for i in ifaces if i.ipv4}
        gws = interfaces.default_gateways()
        self.gateways = set(gws.values())

        if self.options.all_networks:
            for net, iface in interfaces.scannable_networks(ifaces):
                add(str(net), "local interface", iface.name, iface.gateway)

        for target in self.options.targets:
            target = target.strip()
            if not target:
                continue
            if "/" not in target:
                try:
                    ipaddress.ip_address(target)
                    add(f"{target}/32", "user specified")
                    continue
                except ValueError:
                    resolved = _resolve(target)
                    if resolved:
                        add(f"{resolved}/32", f"user specified ({target})")
                    continue
            add(target, "user specified")

        self.networks = plan
        return plan

    def discover_extra_networks(self, extra_ips: Iterable[str]) -> List[dict]:
        """Fold in subnets learned from Bonjour/ARP that we cannot see directly."""
        known = [ipaddress.ip_network(n["cidr"]) for n in self.networks]
        added: List[dict] = []
        seen: Set[str] = set()
        for ip in extra_ips:
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if not addr.is_private or addr.is_loopback or addr.is_link_local:
                continue
            if any(addr in net for net in known):
                continue
            candidate = ipaddress.ip_network(f"{ip}/24", strict=False)
            if str(candidate) in seen:
                continue
            seen.add(str(candidate))
            entry = {
                "cidr": str(candidate),
                "source": "discovered (Bonjour/ARP)",
                "interface": None,
                "gateway": None,
                "hosts": candidate.num_addresses - 2,
            }
            self.networks.append(entry)
            known.append(candidate)
            added.append(entry)
        return added

    def probe_adjacent_networks(self) -> List[dict]:
        """Ping the .1 of every /24 in the same /16 to find neighbouring subnets."""
        candidates: List[str] = []
        bases: Set[str] = set()
        for entry in list(self.networks):
            net = ipaddress.ip_network(entry["cidr"])
            if net.prefixlen < 16 or not net.network_address.is_private:
                continue
            octets = str(net.network_address).split(".")
            bases.add(".".join(octets[:2]))
        for base in bases:
            for third in range(256):
                candidates.append(f"{base}.{third}.1")
        known = [ipaddress.ip_network(n["cidr"]) for n in self.networks]
        candidates = [c for c in candidates
                      if not any(ipaddress.ip_address(c) in net for net in known)]
        if not candidates:
            return []
        self._event("phase", phase="adjacent", message=
                    f"Probing {len(candidates)} candidate gateways for other subnets")
        alive = discovery.icmp_sweep(candidates, timeout=1.0, retries=0)
        added: List[dict] = []
        for ip in alive:
            net = ipaddress.ip_network(f"{ip}/24", strict=False)
            entry = {"cidr": str(net), "source": "adjacent subnet (gateway responded)",
                     "interface": None, "gateway": ip, "hosts": net.num_addresses - 2}
            self.networks.append(entry)
            added.append(entry)
        return added

    # ---------------------------------------------------------------- phases

    async def run(self) -> dict:
        self.started = time.time()
        options = self.options
        portscan.raise_fd_limit(16384)

        ifaces = interfaces.enumerate_interfaces()
        self._event("interfaces", interfaces=[i.to_dict() for i in ifaces],
                    dns=interfaces.dns_servers(), search=interfaces.search_domains(),
                    system=localhost.system_info())

        self.plan_targets()

        # Bonjour first: it is fast, passive, and often reveals extra subnets.
        bonjour_data: Dict[str, dict] = {}
        if bonjour.available():
            self._event("phase", phase="bonjour", message="Asking Bonjour what is on the network")
            bonjour_data = await asyncio.to_thread(
                bonjour.discover, options.bonjour_seconds, 2.0
            )
            self._event("bonjour", count=len(bonjour_data))

        arp_before = discovery.arp_table()
        if options.discover_networks:
            extra = self.discover_extra_networks(list(bonjour_data) + list(arp_before))
            if extra:
                self._event("networks_discovered", networks=extra)

        if options.probe_adjacent:
            found = self.probe_adjacent_networks()
            if found:
                self._event("networks_discovered", networks=found)

        total_hosts = sum(n["hosts"] for n in self.networks)
        self._event("plan", networks=self.networks, total_addresses=total_hosts,
                    port_count=len(options.port_list()), profile=options.profile)

        if total_hosts > options.max_hosts:
            self._event("warning", message=(
                f"{total_hosts:,} addresses exceeds the limit of {options.max_hosts:,}; "
                "scanning the first networks only"))

        # ---- discovery
        targets = self._expand_targets(options.max_hosts)
        self._event("phase", phase="discovery",
                    message=f"Sweeping {len(targets):,} addresses across {len(self.networks)} networks")

        alive = await self._discover_hosts(targets, bonjour_data)
        self._event("phase", phase="discovery_done", alive=len(alive))

        # ---- port scanning
        scan_list = sorted(alive, key=_ip_sort_key)
        ports = options.port_list()
        self._event("phase", phase="ports",
                    message=f"Scanning {len(ports):,} TCP ports on {len(scan_list)} hosts")

        completed = 0

        def host_done(ip: str, results: List[portscan.PortResult]) -> None:
            nonlocal completed
            completed += 1
            host = self._host(ip)
            host.tcp_ports = [_port_dict(r) for r in results]
            host.scanned = True
            self._event("host_ports", ip=ip, ports=host.tcp_ports,
                        done=completed, total=len(scan_list))

        await portscan.scan_many_hosts(
            scan_list, ports,
            timeout=options.timeout,
            host_concurrency=options.host_concurrency,
            port_concurrency=options.port_concurrency,
            on_host_done=host_done,
        )

        # ---- UDP
        if options.udp:
            self._event("phase", phase="udp", message="Probing UDP services")
            await self._udp_phase(scan_list)

        # ---- fingerprinting
        if options.fingerprint_enabled:
            open_total = sum(len(self._host(ip).tcp_ports) for ip in scan_list)
            self._event("phase", phase="fingerprint",
                        message=f"Identifying {open_total} open services")
            await self._fingerprint_phase(scan_list)

        # ---- enrichment + classification
        self._event("phase", phase="enrich", message="Resolving names and identifying devices")
        await self._enrich_phase(scan_list, bonjour_data)

        for ip in scan_list:
            self._event("host_complete", host=self._host(ip).to_dict())

        summary = self.summary()
        self._event("complete", summary=summary,
                    duration=round(time.time() - self.started, 2))
        return summary

    def _expand_targets(self, cap: int) -> List[str]:
        targets: List[str] = []
        for entry in self.networks:
            net = ipaddress.ip_network(entry["cidr"])
            if net.prefixlen == 32:
                candidates = [str(net.network_address)]
            else:
                candidates = [str(h) for h in net.hosts()]
            for ip in candidates:
                if len(targets) >= cap:
                    return targets
                targets.append(ip)
        return targets

    async def _discover_hosts(self, targets: List[str],
                              bonjour_data: Dict[str, dict]) -> Set[str]:
        options = self.options
        alive: Set[str] = set()

        # 1. ICMP
        ping_results = await asyncio.to_thread(
            discovery.icmp_sweep, targets, options.ping_timeout, options.ping_retries
        )
        for ip, rtt in ping_results.items():
            host = self._host(ip)
            host.alive = True
            host.rtt_ms = round(rtt, 2)
            if "icmp" not in host.discovery:
                host.discovery.append("icmp")
            alive.add(ip)
        self._event("discovery_progress", method="icmp", found=len(ping_results))

        # 2. TCP probes on ports that almost everything answers
        remaining = [ip for ip in targets if ip not in alive]
        if remaining:
            probe_results = await portscan.scan_many_hosts(
                remaining, services.DISCOVERY_PORTS,
                timeout=min(1.0, options.timeout),
                host_concurrency=max(64, options.host_concurrency * 2),
                port_concurrency=len(services.DISCOVERY_PORTS),
            )
            for ip, results in probe_results.items():
                if results:
                    host = self._host(ip)
                    host.alive = True
                    if "tcp" not in host.discovery:
                        host.discovery.append("tcp")
                    if host.rtt_ms is None and results[0].latency_ms:
                        host.rtt_ms = round(results[0].latency_ms, 2)
                    alive.add(ip)
            self._event("discovery_progress", method="tcp",
                        found=sum(1 for r in probe_results.values() if r))

        # 3. Bonjour-sourced hosts inside our networks
        for ip in bonjour_data:
            if ip in targets or self._in_scope(ip):
                host = self._host(ip)
                host.alive = True
                if "bonjour" not in host.discovery:
                    host.discovery.append("bonjour")
                alive.add(ip)

        # 4. ARP cache (populated by the sweeps above)
        await asyncio.to_thread(discovery.prime_arp, [ip for ip in targets if ip not in alive][:2048])
        await asyncio.sleep(0.4)
        for ip, mac in (await asyncio.to_thread(discovery.arp_table)).items():
            if not self._in_scope(ip):
                continue
            host = self._host(ip)
            host.mac = mac
            host.vendor = oui.describe(mac)
            if not host.alive:
                host.alive = True
                if "arp" not in host.discovery:
                    host.discovery.append("arp")
            alive.add(ip)
        self._event("discovery_progress", method="arp", found=len(alive))

        for ip in alive:
            host = self._host(ip)
            host.network = self._network_for(ip)
            host.is_self = ip in self.local_ips
            host.is_gateway = ip in self.gateways
            # Fold in what Bonjour already told us so names appear immediately
            # rather than only after the enrichment phase.
            info = bonjour_data.get(ip)
            if info:
                host.bonjour = info.get("services", {})
                host.model = host.model or info.get("model")
                for name in info.get("names", []):
                    if name not in host.names:
                        host.names.append(name)
                host.hostname = _best_name(host)
            if host.is_gateway:
                host.device_type = "Router / gateway"
            self._event("host_found", host=host.to_dict())
        return alive

    def _in_scope(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in ipaddress.ip_network(n["cidr"]) for n in self.networks)

    def _network_for(self, ip: str) -> Optional[str]:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for entry in self.networks:
            if addr in ipaddress.ip_network(entry["cidr"]):
                return entry["cidr"]
        return None

    async def _udp_phase(self, hosts: List[str]) -> None:
        ports = services.UDP_PROBE_PORTS
        semaphore = asyncio.Semaphore(16)

        async def probe(ip: str) -> None:
            async with semaphore:
                results = await asyncio.to_thread(portscan.udp_scan, ip, ports, 1.2)
            if results:
                host = self._host(ip)
                host.udp_ports = [_port_dict(r) for r in results]
                self._event("host_udp", ip=ip, ports=host.udp_ports)

        await asyncio.gather(*(probe(ip) for ip in hosts))

    async def _fingerprint_phase(self, hosts: List[str]) -> None:
        semaphore = asyncio.Semaphore(self.options.fingerprint_concurrency)
        jobs: List[Tuple[str, int]] = []
        for ip in hosts:
            host = self._host(ip)
            for entry in host.tcp_ports:
                jobs.append((ip, entry["port"]))

        done = 0
        total = len(jobs)

        async def run(ip: str, port: int) -> None:
            nonlocal done
            host = self._host(ip)
            hint = host.hostname or (host.names[0] if host.names else None)
            async with semaphore:
                fp = await fingerprint.fingerprint_port(ip, port, timeout=3.0, hostname_hint=hint)
                if port == 6379:
                    redis = await fingerprint.probe_redis(ip, port)
                    if redis and not redis.get("authenticated"):
                        fp.add_finding("high", "Redis accepts commands without authentication")
                        fp.version = redis.get("version")
            for entry in host.tcp_ports:
                if entry["port"] == port:
                    entry.update(_fingerprint_dict(fp))
                    break
            done += 1
            if fp.findings:
                self._event("host_finding", ip=ip, port=port, findings=fp.findings)
            if done % 5 == 0 or done == total:
                self._event("fingerprint_progress", done=done, total=total)

        await asyncio.gather(*(run(ip, port) for ip, port in jobs))

    async def _enrich_phase(self, hosts: List[str], bonjour_data: Dict[str, dict]) -> None:
        # Reverse DNS in parallel threads
        def resolve_all(ips: List[str]) -> Dict[str, Optional[str]]:
            with ThreadPoolExecutor(max_workers=24) as pool:
                return dict(zip(ips, pool.map(lambda i: discovery.reverse_dns(i, 1.0), ips)))

        ptr = await asyncio.to_thread(resolve_all, hosts)
        netbios = await asyncio.to_thread(discovery.netbios_query, hosts, 2.0)
        ssdp = await asyncio.to_thread(self._unicast_ssdp, hosts)
        mdns_names = await asyncio.to_thread(discovery.mdns_reverse, hosts, 2.0)
        arp = await asyncio.to_thread(discovery.arp_table)

        for ip in hosts:
            host = self._host(ip)
            if arp.get(ip) and not host.mac:
                host.mac = arp[ip]
            if host.mac and not host.vendor:
                host.vendor = oui.describe(host.mac)

            info = bonjour_data.get(ip)
            if info:
                host.bonjour = info.get("services", {})
                host.model = host.model or info.get("model")
                for name in info.get("names", []):
                    if name not in host.names:
                        host.names.append(name)

            local_name = mdns_names.get(ip)
            if local_name and local_name not in host.names:
                host.names.append(local_name)

            if ptr.get(ip):
                name = ptr[ip]
                if name not in host.names:
                    host.names.append(name)

            nb = netbios.get(ip)
            if nb:
                host.netbios_name = nb.get("name")
                host.workgroup = nb.get("workgroup")
                if nb.get("mac") and not host.mac:
                    host.mac = nb["mac"]
                    host.vendor = oui.describe(host.mac)
                if "netbios" not in host.discovery:
                    host.discovery.append("netbios")

            if ssdp.get(ip):
                host.ssdp = ssdp[ip]
                host.model = host.model or ssdp[ip].get("modelName")
                if "ssdp" not in host.discovery:
                    host.discovery.append("ssdp")

            host.hostname = _best_name(host)
            titles = [str(p.get("http", {}).get("title", "")) for p in host.tcp_ports
                      if isinstance(p.get("http"), dict)]
            titles += [str(p.get("http", {}).get("server", "")) for p in host.tcp_ports
                       if isinstance(p.get("http"), dict)]
            label, confidence = fingerprint.classify_device(
                host.vendor, host.hostname, host.model, host.bonjour,
                [p["port"] for p in host.tcp_ports], titles, host.ssdp,
            )
            if host.is_gateway:
                label, confidence = "Router / gateway", 0.95
            host.device_type = label
            host.confidence = confidence
            host.findings = self._collect_findings(host)

    def _unicast_ssdp(self, hosts: List[str]) -> Dict[str, dict]:
        """Ask each host directly for its UPnP description (works without multicast)."""
        results: Dict[str, dict] = {}
        import select
        import socket as sk

        message = (
            "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
            'MAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n'
        ).encode()
        try:
            sock = sk.socket(sk.AF_INET, sk.SOCK_DGRAM)
            sock.setblocking(False)
        except OSError:
            return results
        with sock:
            for ip in hosts:
                try:
                    sock.sendto(message, (ip, 1900))
                except OSError:
                    continue
            deadline = time.perf_counter() + 2.5
            while time.perf_counter() < deadline:
                ready, _, _ = select.select([sock], [], [], 0.25)
                if not ready:
                    continue
                try:
                    data, addr = sock.recvfrom(8192)
                except OSError:
                    continue
                headers = discovery._parse_http_headers(data.decode("utf-8", "replace"))
                if headers:
                    results.setdefault(addr[0], {}).update(headers)

        # Fetch device description XML for anything that advertised one.
        def fetch(item: Tuple[str, dict]) -> Tuple[str, dict]:
            ip, headers = item
            location = headers.get("location")
            if location:
                headers.update(discovery.fetch_upnp_description(location, 3.0,
                                                                expected_host=ip))
            return ip, headers

        if results:
            with ThreadPoolExecutor(max_workers=12) as pool:
                for ip, headers in pool.map(fetch, list(results.items())):
                    results[ip] = headers
        return results

    @staticmethod
    def _has_evidence(entry: dict) -> bool:
        """Did fingerprinting actually learn what is listening on this port?"""
        return bool(entry.get("banner") or entry.get("product") or
                    entry.get("http") or entry.get("tls") or entry.get("version"))

    @staticmethod
    def _downgrade(severity: str) -> str:
        return {"high": "medium", "medium": "low", "low": "info"}.get(severity, "info")

    def _collect_findings(self, host: Host) -> List[dict]:
        """Build the findings list.

        Findings proven by fingerprinting (a banner, certificate or HTTP reply)
        are reported as-is. Anything inferred only from a port number is marked
        unverified and downgraded, because plenty of devices listen on ports
        that merely happen to be well known for something else.
        """
        findings: List[dict] = []

        for entry in host.tcp_ports:
            port = entry["port"]
            info = services.service_for(port, "tcp")
            verified = self._has_evidence(entry)

            for item in entry.get("findings", []):
                findings.append({**item, "port": port, "service": info.name,
                                 "verified": True, "proto": "tcp"})

            if info.risk and info.severity in ("high", "medium"):
                if verified:
                    findings.append({
                        "severity": info.severity,
                        "message": info.risk,
                        "port": port,
                        "service": info.name,
                        "verified": True,
                        "proto": "tcp",
                    })
                else:
                    findings.append({
                        "severity": self._downgrade(info.severity),
                        "message": (f"Port {port} is open but did not identify itself. "
                                    f"If this is {info.name}: {info.risk}"),
                        "port": port,
                        "service": info.name,
                        "verified": False,
                        "proto": "tcp",
                    })

        for entry in host.udp_ports:
            info = services.service_for(entry["port"], "udp")
            if info.risk and info.severity in ("high", "medium"):
                verified = bool(entry.get("banner"))
                findings.append({
                    "severity": info.severity if verified else self._downgrade(info.severity),
                    "message": info.risk if verified else
                               (f"UDP {entry['port']} responded. If this is {info.name}: {info.risk}"),
                    "port": entry["port"],
                    "service": info.name,
                    "verified": verified,
                    "proto": "udp",
                })

        findings.sort(key=lambda f: (services.SEVERITY_ORDER.get(f.get("severity", "info"), 3),
                                     not f.get("verified", False)))
        return findings

    # --------------------------------------------------------------- summary

    def summary(self) -> dict:
        hosts = [h for h in self.hosts.values() if h.alive]
        open_ports = sum(len(h.tcp_ports) for h in hosts)
        findings = [f for h in hosts for f in h.findings]
        by_severity: Dict[str, int] = {}
        for f in findings:
            by_severity[f.get("severity", "info")] = by_severity.get(f.get("severity", "info"), 0) + 1
        device_types: Dict[str, int] = {}
        for h in hosts:
            key = h.device_type or "Unidentified"
            device_types[key] = device_types.get(key, 0) + 1
        return {
            "schema": SCHEMA_VERSION,
            "networks": self.networks,
            "hosts_alive": len(hosts),
            "open_tcp_ports": open_ports,
            "open_udp_ports": sum(len(h.udp_ports) for h in hosts),
            "findings": len(findings),
            "findings_by_severity": by_severity,
            "device_types": device_types,
            "duration": round(time.time() - self.started, 2) if self.started else 0,
        }

    def result_document(self) -> dict:
        return {
            "schema": SCHEMA_VERSION,
            "generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "summary": self.summary(),
            "networks": self.networks,
            "hosts": [h.to_dict() for h in
                      sorted((h for h in self.hosts.values() if h.alive or self.options.include_offline),
                             key=lambda h: _ip_sort_key(h.ip))],
        }


# ------------------------------------------------------------------- helpers

def _port_dict(result: portscan.PortResult) -> dict:
    info = services.service_for(result.port, result.proto)
    return {
        "service_guess": info.name,
        "port": result.port,
        "proto": result.proto,
        "state": result.state,
        "latency_ms": round(result.latency_ms, 1) if result.latency_ms else None,
        "service": info.name,
        "description": info.description,
        "severity": info.severity,
        "risk": info.risk,
        "banner": result.banner,
    }


def _fingerprint_dict(fp: fingerprint.ServiceFingerprint) -> dict:
    data: Dict[str, object] = {}
    if fp.banner:
        data["banner"] = fp.banner
    if fp.product:
        data["product"] = fp.product
    if fp.version:
        data["version"] = fp.version
    if fp.http:
        data["http"] = fp.http
    if fp.tls:
        data["tls"] = fp.tls
    if fp.notes:
        data["notes"] = fp.notes
    if fp.findings:
        data["findings"] = fp.findings
    return data


def _best_name(host: Host) -> Optional[str]:
    candidates = list(host.names)
    if host.netbios_name:
        candidates.append(host.netbios_name)
    if host.ssdp.get("friendlyName"):
        candidates.append(host.ssdp["friendlyName"])
    scored = []
    for name in candidates:
        if not name:
            continue
        score = 0
        if name.endswith(".local"):
            score += 2
        if not re.match(r"^[0-9a-fA-F]{8,}$", name.split(".")[0]):
            score += 1
        if "." in name:
            score += 1
        scored.append((score, name))
    if not scored:
        return None
    scored.sort(key=lambda item: (-item[0], len(item[1])))
    return scored[0][1]


def _ip_sort_key(ip: str) -> Tuple:
    try:
        return tuple(int(part) for part in ip.split("."))
    except ValueError:
        return (999, 999, 999, 999)


def _resolve(name: str) -> Optional[str]:
    try:
        return socket.gethostbyname(name)
    except OSError:
        return None
