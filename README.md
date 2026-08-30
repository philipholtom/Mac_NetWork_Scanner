# Network Scanner for macOS

A native Mac app plus a command-line tool that sweeps **every network your Mac can
reach**, finds the devices on them, and reports open ports with as much detail as
can be gathered without installing anything.

No dependencies: the engine is pure Python 3 standard library, the app is SwiftUI.
Nothing needs `sudo`.

## Quick start

```bash
./build.sh && open build/NetScan.app
```

`build.sh` compiles the app, bundles the engine inside it, attaches the icon and
ad-hoc signs the result. The icon is drawn programmatically — run
`icon/GenerateIcon.swift` to regenerate it, or delete `icon/AppIcon.icns` and the
build will rebuild it for you.

The command line works on its own too:

```bash
python3 -m netscan
```

## What "all networks" means

The scanner does not just scan the subnet you are sitting on. It assembles the
target list from four sources:

| Source | Example |
|---|---|
| Every active interface (Ethernet, Wi-Fi, bridges, VPN tunnels) | `192.168.0.0/24` |
| Directly-routed subnets from the routing table | Parallels/VMware bridges |
| Subnets inferred from Bonjour and ARP replies | a second LAN behind your router |
| Neighbouring subnets found by probing gateways (optional) | `192.168.1-255.0/24` |

That third row matters. It is common for a router to serve a second subnet — a
guest network, an IoT VLAN, a mesh backhaul — that your Mac has no interface on and
no route to in `netstat -rn`, yet can reach perfectly well through the gateway.
Bonjour gives it away, so those devices get scanned too.

## What it reports

**Per device** — IPv4 address, MAC address, hardware vendor (1,300 built-in OUI
prefixes, or the full IEEE registry via `--update-oui`), reverse-DNS name, Bonjour
`.local` name, NetBIOS name and workgroup, UPnP friendly name and model, hardware
model from Bonjour TXT records, round-trip latency, how it was discovered, and a
device-type guess (router, NAS, printer, camera, iPhone, smart TV, IoT…).

**Per open port** — service name, connect latency, and a real fingerprint where one
can be obtained:

- **Banners** for SSH, FTP, SMTP, IMAP/POP3, MySQL, VNC, Telnet, memcached
- **HTTP** status, `Server`, page title, redirect target, auth realm, missing
  security headers
- **TLS** protocol version, cipher, certificate subject/issuer/SAN, expiry
  (with days remaining), self-signed detection, SHA-256 fingerprint
- **UDP** probes with real protocol payloads for DNS, NTP, SNMP (`sysDescr` via
  SNMPv2c), NetBIOS, SSDP, mDNS, memcached, TFTP, IKE

**Per network** — interface, gateway, DHCP server, DNS servers, search domains.

## Clicking through to a device

Ports in the detail pane are actionable. Double-click a port (or use the button on
the row, or right-click for the full list) and it opens in whatever macOS uses for
that protocol:

| Port | Opens in |
|---|---|
| HTTP/HTTPS, and any unrecognised port | your browser |
| SSH (22, 2222), Telnet (23) | Terminal |
| VNC / Screen Sharing (5900+) | Screen Sharing |
| SMB (445), AFP (548), FTP (21) | Finder |
| RTSP (554) | your video player |
| RDP (3389) | your remote desktop client |
| Printers (631, 9100, 515) | the printer's web admin |

Databases and caches (MySQL, PostgreSQL, Redis, MongoDB, SQL Server, memcached,
Elasticsearch) copy a ready-to-paste client command instead, since there is no
sensible URL to open. Every port also offers "Copy address" and a `nc` probe.

**This Mac** — every listening socket with the owning process, PID and user;
whether each is loopback-only or reachable from the network; firewall and stealth
mode state; sharing services; interface details.

## Ports it will not talk to

Some ports treat whatever arrives as payload rather than as a request. A raw print
port (9100 and friends, plus LPD on 515) hands anything it receives straight to the
print engine, so a probe comes out as a printed page of protocol text — and because
the job is never terminated, the queue can jam behind it. Industrial controllers
(Modbus, S7, DNP3, EtherNet/IP, BACnet) are on the same list in spirit: a scanner
has no business writing arbitrary bytes at a PLC.

Those ports are still discovered and reported as open. The scanner connects and
listens, but sends nothing at all, and the port is annotated to say so. Printer web
interfaces (631/IPP, 80) are ordinary HTTP servers and are probed normally.

## Honest findings

Findings are split into two classes, because a port number alone proves nothing:

- **Confirmed** — backed by evidence the scanner actually collected (a Telnet
  banner, an expired certificate, memcached answering without auth, Redis
  accepting `INFO`).
- **Unconfirmed** — inferred only from the port number. These are downgraded a
  severity level and labelled, because plenty of devices listen on ports that
  merely happen to be well known for something else. A smart speaker answering on
  8888 is not a Jupyter notebook.

## Command line

```
netscan                          scan every reachable network
netscan --profile full           all 65,535 TCP ports
netscan 192.168.1.0/24 10.0.0.5  specific targets only
netscan --probe-adjacent         hunt for neighbouring subnets
netscan --self                   audit what this Mac exposes
netscan --list-networks          show the scan plan, then exit
netscan --html report.html       write an HTML report
netscan --json out.json          machine-readable output
netscan --csv out.csv            spreadsheet output
netscan --update-oui             download the full IEEE vendor database
```

Port profiles: `fast` (76 ports), `common` (920 ports, default), `full` (all 65,535).

Useful flags: `--no-udp`, `--no-fingerprint`, `--timeout`, `--concurrency`,
`--hosts-parallel`, `--max-hosts`, `-v` for every port.

## How it works around macOS

- **No root needed.** macOS allows unprivileged ICMP through `SOCK_DGRAM`, so the
  ping sweep works as a normal user.
- **Host discovery uses four methods**, because plenty of devices ignore pings:
  ICMP, TCP connect probes on 20 always-answering ports, the ARP cache (primed by
  sending stray UDP datagrams), and Bonjour.
- **Bonjour goes through `dns-sd`**, i.e. the system's own mDNSResponder. macOS's
  Local Network privacy layer blocks direct multicast from unsigned processes —
  sends fail with `EHOSTUNREACH` — so asking the system daemon is both more
  reliable and faster, and it reuses the cache mDNSResponder already holds.
- **UPnP discovery is unicast**, sent straight to each host on port 1900 rather
  than to the multicast group, for the same reason.
- The app is ad-hoc signed and declares `NSLocalNetworkUsageDescription`, so macOS
  can remember its Local Network permission grant.

## Layout

```
icon/               app icon generator (GenerateIcon.swift) and AppIcon.icns
netscan/            Python engine
  interfaces.py       interface, route, gateway, DHCP and DNS enumeration
  discovery.py        ICMP, ARP, NetBIOS, SSDP, reverse DNS
  bonjour.py          Bonjour/mDNS via dns-sd
  dnsmsg.py           minimal DNS/mDNS codec
  portscan.py         asyncio TCP connect scanning, UDP protocol probes
  fingerprint.py      banners, HTTP, TLS certificates, device classification
  services.py         port/service knowledge and scan profiles
  oui.py              MAC vendor lookup
  localhost.py        this Mac's listening sockets, firewall, sharing
  engine.py           orchestration, emits NDJSON events
  report.py           terminal, HTML and CSV rendering
  cli.py              argument parsing
NetScanApp/Sources/ SwiftUI app driving the engine
build.sh            builds and signs NetScan.app
```

The app runs the engine as a subprocess with `--ndjson` and renders the event
stream live, so results appear as they are found.

## Handling untrusted input

Everything a scan learns comes from devices on the network, which are not trusted:

- A UPnP device supplies the URL of its own description document. Only `http(s)`
  is fetched (urllib will otherwise happily open a `file://` URL and read a local
  file into the report), and the host must match the address that answered.
- Device names are escaped in HTML output and prefixed in CSV output, so a host
  calling itself `=1+1` cannot become a live formula when the report is opened.

## Tests

```bash
python3 tests/test_probe_safety.py
```

Regression tests for the ways a scanner can misbehave: that raw print ports and
industrial controllers receive zero bytes while ordinary ports are still probed,
that device-supplied UPnP URLs and device names cannot reach a local file or a
spreadsheet formula, that port scanning uses a bounded worker pool, and that an
abbreviated route is not expanded into millions of addresses. No network access
or privileges required.

## Notes and limits

- TCP scanning is *connect*-based, so scans are logged by anything watching. There
  is no raw-socket SYN scan (that would need root).
- UDP results are best-effort: a reply proves a port is open, silence proves
  nothing, so only responsive ports are reported.
- The `full` profile against a large subnet is slow — start with `fast`.
- Only scan networks you are responsible for.
