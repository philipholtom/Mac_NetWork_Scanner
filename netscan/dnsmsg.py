"""Minimal DNS/mDNS message encoder and decoder (enough for discovery)."""
from __future__ import annotations

import struct
from typing import Dict, List, NamedTuple, Optional, Tuple

TYPE_A = 1
TYPE_PTR = 12
TYPE_TXT = 16
TYPE_AAAA = 28
TYPE_SRV = 33
TYPE_ANY = 255
CLASS_IN = 1


class Record(NamedTuple):
    name: str
    rtype: int
    data: object


def encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("utf-8")[:63]
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def build_query(questions: List[Tuple[str, int]], qid: int = 0, unicast_reply: bool = False) -> bytes:
    header = struct.pack("!HHHHHH", qid, 0, len(questions), 0, 0, 0)
    body = b""
    for name, qtype in questions:
        qclass = CLASS_IN | (0x8000 if unicast_reply else 0)
        body += encode_name(name) + struct.pack("!HH", qtype, qclass)
    return header + body


def _read_name(data: bytes, offset: int, depth: int = 0) -> Tuple[str, int]:
    labels: List[str] = []
    jumped = False
    end = offset
    while depth < 20:
        if offset >= len(data):
            break
        length = data[offset]
        if length == 0:
            offset += 1
            if not jumped:
                end = offset
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                end = offset + 2
            jumped = True
            if pointer >= offset:      # guard against pointer loops
                break
            offset = pointer
            depth += 1
            continue
        offset += 1
        labels.append(data[offset:offset + length].decode("utf-8", "replace"))
        offset += length
        if not jumped:
            end = offset
    return ".".join(labels), end


def parse_txt(blob: bytes) -> Dict[str, str]:
    result: Dict[str, str] = {}
    i = 0
    while i < len(blob):
        length = blob[i]
        i += 1
        item = blob[i:i + length].decode("utf-8", "replace")
        i += length
        if not item:
            continue
        key, sep, value = item.partition("=")
        result[key.strip()] = value.strip() if sep else ""
    return result


def parse_message(data: bytes) -> List[Record]:
    """Return every answer/authority/additional record in a DNS message."""
    records: List[Record] = []
    if len(data) < 12:
        return records
    try:
        _, _, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
        offset = 12
        for _ in range(qd):
            _, offset = _read_name(data, offset)
            offset += 4
        for _ in range(an + ns + ar):
            name, offset = _read_name(data, offset)
            if offset + 10 > len(data):
                break
            rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", data[offset:offset + 10])
            offset += 10
            rdata = data[offset:offset + rdlen]
            value: object = rdata
            if rtype == TYPE_A and rdlen == 4:
                value = ".".join(str(b) for b in rdata)
            elif rtype == TYPE_AAAA and rdlen == 16:
                value = ":".join(f"{rdata[i]<<8 | rdata[i+1]:x}" for i in range(0, 16, 2))
            elif rtype == TYPE_PTR:
                value, _ = _read_name(data, offset)
            elif rtype == TYPE_TXT:
                value = parse_txt(rdata)
            elif rtype == TYPE_SRV and rdlen >= 6:
                priority, weight, port = struct.unpack("!HHH", rdata[:6])
                target, _ = _read_name(data, offset + 6)
                value = {"port": port, "target": target, "priority": priority, "weight": weight}
            records.append(Record(name, rtype, value))
            offset += rdlen
    except (struct.error, IndexError):
        pass
    return records


def reverse_name(ip: str) -> str:
    return ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
