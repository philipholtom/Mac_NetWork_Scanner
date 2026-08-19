"""What this Mac itself is exposing: listening sockets, owning processes, sharing."""
from __future__ import annotations

import re
import subprocess
from typing import Dict, List, Optional


def _run(cmd: List[str], timeout: float = 12.0) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout, check=False).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def listening_sockets() -> List[dict]:
    """Every listening TCP/UDP socket on this Mac, with the process behind it."""
    out = _run(["/usr/sbin/lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "+c", "0"])
    out += _run(["/usr/sbin/lsof", "-nP", "-iUDP", "+c", "0"])

    seen = set()
    results: List[dict] = []
    for line in out.splitlines():
        if line.startswith("COMMAND") or not line.strip():
            continue
        parts = line.split()
        if len(parts) < 9:
            continue
        command, pid, user = parts[0], parts[1], parts[2]
        node = parts[7]
        name = parts[8]
        if node not in ("TCP", "UDP"):
            continue
        m = re.match(r"^(.*):(\d+|\*)$", name.split("->")[0])
        if not m:
            continue
        address, port = m.group(1), m.group(2)
        if port == "*":
            continue
        state = "LISTEN" if node == "TCP" else "open"
        key = (node, port, address, pid)
        if key in seen:
            continue
        seen.add(key)
        scope = "all interfaces" if address in ("*", "0.0.0.0", "[::]", "::") else (
            "loopback only" if address in ("127.0.0.1", "[::1]") else address)
        results.append({
            "proto": node.lower(),
            "port": int(port),
            "address": address,
            "scope": scope,
            "process": command,
            "pid": int(pid) if pid.isdigit() else None,
            "user": user,
            "state": state,
            "exposed": scope not in ("loopback only",),
        })
    results.sort(key=lambda r: (r["proto"], r["port"]))
    return results


def sharing_services() -> Dict[str, bool]:
    """macOS sharing services that expose this Mac to the network."""
    checks = {
        "Screen Sharing": ["/bin/launchctl", "print", "system/com.apple.screensharing"],
        "Remote Login (SSH)": ["/usr/sbin/systemsetup", "-getremotelogin"],
        "File Sharing (SMB)": ["/bin/launchctl", "print", "system/com.apple.smbd"],
        "Remote Management": ["/bin/launchctl", "print", "system/com.apple.RemoteDesktop.agent"],
        "Printer Sharing": ["/bin/launchctl", "print", "system/org.cups.cupsd"],
    }
    status: Dict[str, bool] = {}
    for label, cmd in checks.items():
        out = _run(cmd, timeout=6)
        if label == "Remote Login (SSH)":
            status[label] = "On" in out
        else:
            status[label] = bool(out.strip()) and "could not find" not in out.lower()
    return status


def firewall_status() -> Dict[str, object]:
    fw = "/usr/libexec/ApplicationFirewall/socketfilterfw"
    state = _run([fw, "--getglobalstate"], timeout=6)
    stealth = _run([fw, "--getstealthmode"], timeout=6)
    blockall = _run([fw, "--getblockall"], timeout=6)
    return {
        "enabled": "enabled" in state.lower() and "disabled" not in state.lower().split("state")[0],
        "raw_state": state.strip(),
        "stealth_mode": "enabled" in stealth.lower(),
        "block_all": "enabled" in blockall.lower() and "disabled" not in blockall.lower(),
    }


def system_info() -> Dict[str, str]:
    info: Dict[str, str] = {}
    for key, cmd in (("hostname", ["/bin/hostname"]),
                     ("model", ["/usr/sbin/sysctl", "-n", "hw.model"]),
                     ("os", ["/usr/bin/sw_vers", "-productVersion"]),
                     ("build", ["/usr/bin/sw_vers", "-buildVersion"])):
        value = _run(cmd, timeout=6).strip()
        if value:
            info[key] = value
    scutil = _run(["/usr/sbin/scutil", "--get", "ComputerName"], timeout=6).strip()
    if scutil:
        info["computer_name"] = scutil
    local = _run(["/usr/sbin/scutil", "--get", "LocalHostName"], timeout=6).strip()
    if local:
        info["local_hostname"] = f"{local}.local"
    return info


def wifi_details() -> Dict[str, str]:
    """Current Wi-Fi network details, where available."""
    details: Dict[str, str] = {}
    out = _run(["/usr/sbin/networksetup", "-listallhardwareports"])
    wifi_device = None
    port = None
    for line in out.splitlines():
        if line.startswith("Hardware Port:"):
            port = line.split(":", 1)[1].strip()
        elif line.startswith("Device:") and port and "Wi-Fi" in port:
            wifi_device = line.split(":", 1)[1].strip()
            break
    if not wifi_device:
        return details
    details["device"] = wifi_device
    ssid = _run(["/usr/sbin/networksetup", "-getairportnetwork", wifi_device], timeout=6)
    m = re.search(r"Current Wi-Fi Network:\s*(.+)", ssid)
    if m:
        details["ssid"] = m.group(1).strip()
    return details
