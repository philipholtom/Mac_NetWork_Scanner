"""Enumerate local network interfaces, routes, gateways and DNS config (macOS)."""
from __future__ import annotations

import ipaddress
import re
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# Interfaces that are never worth scanning as a subnet.
SKIP_PREFIXES = ("lo", "gif", "stf", "awdl", "llw", "ap", "anpi", "pktap", "vmenet")


def _run(cmd: List[str], timeout: float = 8.0) -> str:
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
        return out.stdout
    except (OSError, subprocess.SubprocessError):
        return ""


@dataclass
class Interface:
    name: str
    mac: Optional[str] = None
    ipv4: Optional[str] = None
    netmask: Optional[str] = None
    broadcast: Optional[str] = None
    peer: Optional[str] = None          # point-to-point remote address
    ipv6: List[str] = field(default_factory=list)
    flags: List[str] = field(default_factory=list)
    mtu: Optional[int] = None
    status: Optional[str] = None
    media: Optional[str] = None
    hardware_port: Optional[str] = None
    kind: str = "unknown"               # wifi / ethernet / vpn / bridge / virtual
    gateway: Optional[str] = None
    dhcp_server: Optional[str] = None
    dhcp_lease: Optional[str] = None
    ssid: Optional[str] = None
    network: Optional[ipaddress.IPv4Network] = None

    @property
    def is_up(self) -> bool:
        return "UP" in self.flags and "RUNNING" in self.flags

    @property
    def is_point_to_point(self) -> bool:
        return "POINTOPOINT" in self.flags

    @property
    def cidr(self) -> Optional[str]:
        return str(self.network) if self.network else None

    def to_dict(self) -> dict:
        d = {k: v for k, v in self.__dict__.items() if k != "network"}
        d["cidr"] = self.cidr
        d["is_up"] = self.is_up
        return d


def _mask_to_prefix(hexmask: str) -> int:
    value = int(hexmask, 16) if hexmask.startswith("0x") else int(hexmask)
    return bin(value).count("1")


def _hex_to_dotted(hexmask: str) -> str:
    value = int(hexmask, 16) if hexmask.startswith("0x") else int(hexmask)
    return str(ipaddress.IPv4Address(value))


def parse_ifconfig(text: str) -> Dict[str, Interface]:
    """Parse `ifconfig -a` output into Interface objects."""
    interfaces: Dict[str, Interface] = {}
    current: Optional[Interface] = None

    for line in text.splitlines():
        header = re.match(r"^(\w+):\s+flags=[0-9a-fA-F]+<([^>]*)>\s+mtu\s+(\d+)", line)
        if header:
            name, flags, mtu = header.groups()
            current = Interface(
                name=name,
                flags=[f for f in flags.split(",") if f],
                mtu=int(mtu),
            )
            interfaces[name] = current
            continue
        if current is None:
            continue

        stripped = line.strip()
        if stripped.startswith("ether "):
            current.mac = stripped.split()[1].lower()
        elif stripped.startswith("inet6 "):
            current.ipv6.append(stripped.split()[1])
        elif stripped.startswith("inet "):
            parts = stripped.split()
            current.ipv4 = parts[1]
            if "-->" in stripped:
                current.peer = parts[3]
            if "netmask" in parts:
                raw = parts[parts.index("netmask") + 1]
                try:
                    current.netmask = _hex_to_dotted(raw)
                    prefix = _mask_to_prefix(raw)
                    current.network = ipaddress.ip_network(
                        f"{current.ipv4}/{prefix}", strict=False
                    )
                except (ValueError, IndexError):
                    pass
            if "broadcast" in parts:
                current.broadcast = parts[parts.index("broadcast") + 1]
        elif stripped.startswith("status:"):
            current.status = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("media:"):
            current.media = stripped.split(":", 1)[1].strip()

    return interfaces


def _hardware_ports() -> Dict[str, str]:
    """Map BSD device name -> human hardware port name (Wi-Fi, Thunderbolt, ...)."""
    mapping: Dict[str, str] = {}
    text = _run(["/usr/sbin/networksetup", "-listallhardwareports"])
    port = None
    for line in text.splitlines():
        if line.startswith("Hardware Port:"):
            port = line.split(":", 1)[1].strip()
        elif line.startswith("Device:") and port:
            mapping[line.split(":", 1)[1].strip()] = port
    return mapping


def _classify(iface: Interface) -> str:
    name, hw = iface.name, (iface.hardware_port or "").lower()
    if name.startswith("utun") or name.startswith("ipsec") or name.startswith("ppp"):
        return "vpn"
    if name.startswith("bridge"):
        return "bridge"
    if "wi-fi" in hw or "airport" in hw or "wireless" in hw:
        return "wifi"
    if "thunderbolt" in hw or "ethernet" in hw or "lan" in hw:
        return "ethernet"
    if name.startswith("en"):
        return "ethernet"
    return "virtual"


def default_gateways() -> Dict[str, str]:
    """Map interface name -> default gateway address."""
    gateways: Dict[str, str] = {}
    for line in _run(["/usr/sbin/netstat", "-rn", "-f", "inet"]).splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[0] == "default":
            gw, netif = parts[1], parts[3]
            if not gw.startswith("link#"):
                gateways.setdefault(netif, gw)
    return gateways


def routed_networks() -> Dict[str, str]:
    """Map interface -> directly connected network from the routing table.

    Catches subnets reachable through an interface that has no address of its
    own on that subnet (e.g. some VPN and virtualisation setups).
    """
    nets: Dict[str, str] = {}
    for line in _run(["/usr/sbin/netstat", "-rn", "-f", "inet"]).splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[0] in ("default", "Destination", "Internet:"):
            continue
        dest, gw, flags, netif = parts[0], parts[1], parts[2], parts[3]
        if "C" not in flags or not gw.startswith("link#"):
            continue
        try:
            if "/" in dest:
                net = ipaddress.ip_network(dest, strict=False)
            else:
                # netstat abbreviates: "192.168.0" means 192.168.0.0/24
                octets = dest.split(".")
                if not all(o.isdigit() for o in octets):
                    continue
                prefix = len(octets) * 8
                dest_full = ".".join(octets + ["0"] * (4 - len(octets)))
                net = ipaddress.ip_network(f"{dest_full}/{prefix}", strict=False)
        except ValueError:
            continue
        if net.is_loopback or net.is_link_local or net.is_multicast:
            continue
        nets.setdefault(netif, str(net))
    return nets


def dns_servers() -> List[str]:
    servers, seen = [], set()
    for line in _run(["/usr/sbin/scutil", "--dns"]).splitlines():
        m = re.match(r"\s*nameserver\[\d+\]\s*:\s*(\S+)", line)
        if m and m.group(1) not in seen:
            seen.add(m.group(1))
            servers.append(m.group(1))
    return servers


def search_domains() -> List[str]:
    domains, seen = [], set()
    for line in _run(["/usr/sbin/scutil", "--dns"]).splitlines():
        m = re.match(r"\s*(?:search domain\[\d+\]|domain)\s*:\s*(\S+)", line)
        if m and m.group(1) not in seen:
            seen.add(m.group(1))
            domains.append(m.group(1))
    return domains


def _dhcp_info(iface: Interface) -> None:
    text = _run(["/usr/sbin/ipconfig", "getpacket", iface.name], timeout=4)
    m = re.search(r"server_identifier \(ip\): (\S+)", text)
    if m:
        iface.dhcp_server = m.group(1)
    m = re.search(r"lease_time \(uint32\): (\S+)", text)
    if m:
        iface.dhcp_lease = m.group(1)


def _wifi_ssid(iface: Interface) -> None:
    text = _run(["/usr/sbin/networksetup", "-getairportnetwork", iface.name], timeout=4)
    m = re.search(r"Current Wi-Fi Network:\s*(.+)", text)
    if m:
        iface.ssid = m.group(1).strip()


def enumerate_interfaces(include_all: bool = False) -> List[Interface]:
    """Return every interface, annotated with gateway/DHCP/SSID details."""
    interfaces = parse_ifconfig(_run(["/sbin/ifconfig", "-a"]))
    hw_ports = _hardware_ports()
    gateways = default_gateways()

    result = []
    for name, iface in interfaces.items():
        iface.hardware_port = hw_ports.get(name)
        iface.kind = _classify(iface)
        iface.gateway = gateways.get(name)
        if not include_all and name.startswith(SKIP_PREFIXES):
            continue
        if iface.ipv4 and iface.is_up:
            _dhcp_info(iface)
            if iface.kind == "wifi":
                _wifi_ssid(iface)
        result.append(iface)
    return result


def scannable_networks(
    interfaces: List[Interface],
) -> List[tuple]:
    """Return [(network, interface), ...] — every distinct IPv4 subnet we can reach.

    Deduplicates subnets shared by several interfaces (e.g. Wi-Fi + Ethernet on
    the same LAN) and folds in link-scoped routes that have no local address.
    """
    seen: Dict[str, Interface] = {}
    by_name = {i.name: i for i in interfaces}

    for iface in interfaces:
        if not (iface.is_up and iface.ipv4 and iface.network):
            continue
        net = iface.network
        if net.is_loopback or net.is_multicast:
            continue
        if net.prefixlen == 32:
            # Point-to-point link: scan the peer only.
            if iface.peer:
                seen.setdefault(f"{iface.peer}/32", iface)
            continue
        if str(net.network_address).startswith("169.254."):
            continue
        seen.setdefault(str(net), iface)

    for netif, cidr in routed_networks().items():
        iface = by_name.get(netif)
        if iface is None or not iface.is_up:
            continue
        seen.setdefault(cidr, iface)

    return [(ipaddress.ip_network(c), i) for c, i in seen.items()]
