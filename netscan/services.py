"""Port -> service knowledge: names, descriptions, risk notes and scan profiles."""
from __future__ import annotations

from typing import Dict, List, NamedTuple, Optional, Set


class ServiceInfo(NamedTuple):
    name: str
    description: str
    risk: Optional[str] = None      # note shown when the port is found open
    severity: str = "info"          # info | low | medium | high


_S = ServiceInfo

# Curated map of the ports that actually matter on a real network.
TCP_SERVICES: Dict[int, ServiceInfo] = {
    7: _S("echo", "Echo service", "Legacy service, can be abused for traffic amplification", "low"),
    13: _S("daytime", "Daytime service", "Legacy diagnostic service", "low"),
    19: _S("chargen", "Character generator", "Amplification DDoS vector — should be disabled", "high"),
    21: _S("ftp", "File Transfer Protocol", "Credentials and data sent in cleartext; check for anonymous login", "high"),
    22: _S("ssh", "Secure Shell", "Remote shell access — ensure key-only auth and no default passwords", "medium"),
    23: _S("telnet", "Telnet", "Cleartext remote login — should never be exposed; disable it", "high"),
    25: _S("smtp", "Mail transfer", "Check it is not an open relay", "medium"),
    37: _S("time", "Time protocol", None, "info"),
    43: _S("whois", "WHOIS directory", None, "info"),
    53: _S("dns", "Domain Name System", "Check recursion is not open to the internet", "medium"),
    67: _S("dhcps", "DHCP server", None, "info"),
    69: _S("tftp", "Trivial FTP", "No authentication by design — often used to pull device configs", "high"),
    79: _S("finger", "Finger user info", "Leaks user account names", "medium"),
    80: _S("http", "Web server", "Unencrypted web traffic", "low"),
    81: _S("http-alt", "Web server (alt)", "Common on IP cameras and routers", "low"),
    88: _S("kerberos", "Kerberos auth", None, "info"),
    102: _S("iso-tsap", "Siemens S7 / ICS", "Industrial control protocol exposed", "high"),
    106: _S("pop3pw", "Password server", None, "info"),
    110: _S("pop3", "POP3 mail", "Cleartext mail retrieval unless TLS enforced", "medium"),
    111: _S("rpcbind", "ONC RPC portmapper", "Enumerable RPC services; used in reflection attacks", "medium"),
    119: _S("nntp", "Usenet news", None, "info"),
    123: _S("ntp", "Network Time Protocol", None, "info"),
    135: _S("msrpc", "Microsoft RPC", "Windows RPC endpoint mapper — should not be internet facing", "medium"),
    137: _S("netbios-ns", "NetBIOS name service", "Leaks hostnames and workgroup info", "medium"),
    138: _S("netbios-dgm", "NetBIOS datagram", None, "low"),
    139: _S("netbios-ssn", "NetBIOS session", "Legacy SMB — disable in favour of 445", "medium"),
    143: _S("imap", "IMAP mail", "Cleartext mail access unless TLS enforced", "medium"),
    161: _S("snmp", "SNMP agent", "Often left on public/private community strings", "high"),
    179: _S("bgp", "Border Gateway Protocol", None, "medium"),
    194: _S("irc", "IRC", None, "info"),
    389: _S("ldap", "Directory service", "Check anonymous bind is disabled", "medium"),
    427: _S("svrloc", "Service Location Protocol", "Amplification vector; common on NAS and printers", "medium"),
    443: _S("https", "Web server (TLS)", None, "info"),
    445: _S("smb", "SMB file sharing", "Check for guest access and unpatched SMB versions", "high"),
    465: _S("smtps", "SMTP over TLS", None, "info"),
    500: _S("isakmp", "IPsec key exchange", None, "info"),
    502: _S("modbus", "Modbus TCP / ICS", "Industrial protocol with no authentication", "high"),
    515: _S("printer", "LPD print service", None, "low"),
    520: _S("rip", "Routing Information Protocol", None, "low"),
    523: _S("ibm-db2", "IBM DB2", None, "medium"),
    548: _S("afp", "Apple Filing Protocol", "Legacy macOS file sharing", "medium"),
    554: _S("rtsp", "Streaming media", "Cameras often expose unauthenticated RTSP streams", "high"),
    587: _S("submission", "Mail submission", None, "info"),
    623: _S("ipmi", "IPMI / BMC", "Out-of-band server management — critical if exposed", "high"),
    631: _S("ipp", "Internet Printing (CUPS)", None, "low"),
    636: _S("ldaps", "Directory service (TLS)", None, "info"),
    771: _S("realm-rusd", "Terminal server", None, "info"),
    777: _S("multiling-http", "Web (alt)", None, "info"),
    789: _S("redlion", "Red Lion / ICS", "Industrial device", "high"),
    873: _S("rsync", "Rsync daemon", "Often allows anonymous module listing and file access", "high"),
    902: _S("vmware-auth", "VMware authentication", None, "medium"),
    993: _S("imaps", "IMAP over TLS", None, "info"),
    995: _S("pop3s", "POP3 over TLS", None, "info"),
    1080: _S("socks", "SOCKS proxy", "Open proxies get abused for relaying traffic", "high"),
    1099: _S("java-rmi", "Java RMI registry", "Historically a remote code execution vector", "high"),
    1194: _S("openvpn", "OpenVPN", None, "info"),
    1234: _S("vlc/other", "Streaming or misc service", None, "low"),
    1433: _S("mssql", "Microsoft SQL Server", "Database exposed on the network", "high"),
    1434: _S("mssql-m", "MSSQL monitor", "UDP browser service used for amplification", "medium"),
    1521: _S("oracle", "Oracle database", "Database exposed on the network", "high"),
    1723: _S("pptp", "PPTP VPN", "Cryptographically broken VPN protocol", "high"),
    1883: _S("mqtt", "MQTT broker", "IoT message broker, frequently unauthenticated", "high"),
    1900: _S("upnp", "UPnP / SSDP", "Auto port-forwarding; a classic home-network weakness", "medium"),
    2000: _S("cisco-sccp", "Cisco SCCP / misc", None, "low"),
    2049: _S("nfs", "Network File System", "Check exports are not world readable", "high"),
    2082: _S("cpanel", "cPanel", None, "medium"),
    2083: _S("cpanel-ssl", "cPanel (TLS)", None, "low"),
    2086: _S("whm", "WHM", None, "medium"),
    2087: _S("whm-ssl", "WHM (TLS)", None, "low"),
    2181: _S("zookeeper", "Apache ZooKeeper", "Usually unauthenticated — leaks cluster config", "high"),
    2222: _S("ssh-alt", "SSH (alternate)", None, "medium"),
    2375: _S("docker", "Docker API (plain)", "Unauthenticated Docker API = full host takeover", "high"),
    2376: _S("docker-tls", "Docker API (TLS)", "Verify client certificate auth is required", "medium"),
    2377: _S("docker-swarm", "Docker Swarm", None, "medium"),
    2483: _S("oracle-db", "Oracle DB", None, "high"),
    3000: _S("http-dev", "Dev server / Grafana", "Development servers often ship with no auth", "medium"),
    3128: _S("squid", "Squid proxy", "Check it is not an open proxy", "medium"),
    3260: _S("iscsi", "iSCSI target", "Raw block storage access", "high"),
    3283: _S("ard", "Apple Remote Desktop", "Remote control of this Mac", "medium"),
    3306: _S("mysql", "MySQL / MariaDB", "Database exposed on the network", "high"),
    3389: _S("rdp", "Remote Desktop", "Prime target for brute force — restrict access", "high"),
    3478: _S("stun", "STUN/TURN", None, "info"),
    3689: _S("daap", "iTunes / AirPlay sharing", None, "info"),
    3690: _S("svn", "Subversion", None, "medium"),
    4444: _S("metasploit?", "Common backdoor/listener port", "Frequently used by malware and reverse shells", "high"),
    4500: _S("ipsec-nat", "IPsec NAT traversal", None, "info"),
    4567: _S("galera/http", "Galera or web service", None, "medium"),
    4786: _S("cisco-smi", "Cisco Smart Install", "Remotely abusable to rewrite switch config", "high"),
    5000: _S("upnp/http", "UPnP, Flask or AirPlay", None, "low"),
    5001: _S("http-alt", "Alt web / synology", None, "low"),
    5009: _S("airport-admin", "AirPort admin", None, "medium"),
    5060: _S("sip", "SIP telephony", "VoIP scanning and toll fraud target", "medium"),
    5061: _S("sips", "SIP over TLS", None, "info"),
    5222: _S("xmpp", "XMPP client", None, "info"),
    5353: _S("mdns", "Bonjour / mDNS", "Broadcasts device and service names on the LAN", "low"),
    5357: _S("wsdapi", "Windows web services", None, "low"),
    5432: _S("postgresql", "PostgreSQL", "Database exposed on the network", "high"),
    5555: _S("adb/http", "Android Debug Bridge or web", "Open ADB allows full device control", "high"),
    5601: _S("kibana", "Kibana", "Often deployed with no authentication", "high"),
    5672: _S("amqp", "RabbitMQ / AMQP", "Check default guest:guest credentials", "high"),
    5800: _S("vnc-http", "VNC over HTTP", None, "medium"),
    5900: _S("vnc", "VNC / Screen Sharing", "VNC often has weak or no authentication", "high"),
    5938: _S("teamviewer", "TeamViewer", "Third-party remote access", "medium"),
    5984: _S("couchdb", "CouchDB", "Historically exposed without auth", "high"),
    6000: _S("x11", "X11 display", "Open X11 allows keylogging and screen capture", "high"),
    6379: _S("redis", "Redis", "Unauthenticated Redis is trivially exploitable", "high"),
    6443: _S("kubernetes", "Kubernetes API", "Cluster control plane", "high"),
    6667: _S("irc", "IRC", "Also used by botnet C2", "medium"),
    7000: _S("airplay", "AirPlay / misc", None, "info"),
    7001: _S("weblogic", "WebLogic / AirPlay", "WebLogic has a long history of RCE bugs", "high"),
    7070: _S("realserver", "Streaming / web", None, "low"),
    8000: _S("http-alt", "Web server (alt)", "Very common for cameras, NAS and dev servers", "low"),
    8008: _S("http-alt", "Web / Chromecast", None, "low"),
    8009: _S("ajp13", "Apache JServ", "Ghostcat file-read vulnerability", "high"),
    8080: _S("http-proxy", "Web server / proxy", "Admin panels and proxies commonly live here", "low"),
    8081: _S("http-alt", "Web server (alt)", None, "low"),
    8086: _S("influxdb", "InfluxDB", None, "medium"),
    8088: _S("http-alt", "Web / Hadoop", None, "medium"),
    8123: _S("home-assistant", "Home Assistant", None, "low"),
    8140: _S("puppet", "Puppet master", None, "medium"),
    8181: _S("http-alt", "Web server (alt)", None, "low"),
    8200: _S("vault/gopro", "HashiCorp Vault or media", None, "medium"),
    8443: _S("https-alt", "Web server (TLS, alt)", "Common for admin consoles and firewalls", "low"),
    8888: _S("http-alt", "Web / Jupyter", "Jupyter notebooks can allow code execution", "medium"),
    9000: _S("php-fpm/sonar", "PHP-FPM, Portainer or SonarQube", "Exposed PHP-FPM can lead to code execution", "high"),
    9001: _S("tor/supervisor", "Tor or Supervisor", None, "medium"),
    9090: _S("prometheus/cockpit", "Prometheus or Cockpit", "Metrics endpoints leak infrastructure detail", "medium"),
    9100: _S("jetdirect", "Raw printing (JetDirect)", "Printers accept raw jobs and config changes", "medium"),
    9200: _S("elasticsearch", "Elasticsearch", "Classic source of unauthenticated data leaks", "high"),
    9300: _S("elastic-node", "Elasticsearch transport", None, "high"),
    9418: _S("git", "Git daemon", "Anonymous repository access", "medium"),
    9999: _S("http-alt/abyss", "Web or admin service", None, "low"),
    10000: _S("webmin", "Webmin", "Root-level web administration", "high"),
    11211: _S("memcached", "Memcached", "Unauthenticated cache and DDoS amplifier", "high"),
    27017: _S("mongodb", "MongoDB", "Historically exposed without authentication", "high"),
    27018: _S("mongodb-shard", "MongoDB shard", None, "high"),
    32400: _S("plex", "Plex Media Server", None, "low"),
    49152: _S("upnp-dyn", "Dynamic / UPnP", None, "info"),
    50000: _S("sap/db2", "SAP or DB2", None, "medium"),
    51413: _S("transmission", "Transmission BitTorrent", None, "low"),
    62078: _S("iphone-sync", "iPhone/iPad sync (lockdownd)", "Indicates an iOS device", "info"),
}

UDP_SERVICES: Dict[int, ServiceInfo] = {
    53: _S("dns", "Domain Name System", "Check recursion is not open", "medium"),
    67: _S("dhcp", "DHCP server", None, "info"),
    68: _S("dhcp-client", "DHCP client", None, "info"),
    69: _S("tftp", "Trivial FTP", "No authentication by design", "high"),
    123: _S("ntp", "Network Time Protocol", "Check monlist is disabled (amplification)", "medium"),
    137: _S("netbios-ns", "NetBIOS name service", "Leaks hostname and workgroup", "medium"),
    161: _S("snmp", "SNMP agent", "Default community strings expose full device config", "high"),
    500: _S("isakmp", "IPsec key exchange", None, "info"),
    1900: _S("ssdp", "UPnP discovery", "Exposes device model and services; DDoS amplifier", "medium"),
    5353: _S("mdns", "Bonjour / mDNS", "Broadcasts device names and services", "low"),
    11211: _S("memcached", "Memcached", "Major DDoS amplification vector over UDP", "high"),
}

# Ports probed during host discovery — chosen because something answers on
# almost any live device.
DISCOVERY_PORTS: List[int] = [80, 443, 22, 445, 139, 135, 3389, 5900, 62078, 8080, 631, 548, 5000, 7000, 9100, 53, 23, 21, 111, 32400]

FAST_PORTS: List[int] = [
    20, 21, 22, 23, 25, 53, 80, 81, 110, 111, 123, 135, 137, 139, 143, 161, 389,
    443, 445, 465, 500, 515, 548, 554, 587, 631, 636, 993, 995, 1080, 1194, 1433,
    1521, 1723, 1883, 1900, 2049, 2181, 2222, 2375, 3000, 3128, 3283, 3306, 3389,
    3689, 5000, 5001, 5060, 5222, 5353, 5432, 5555, 5900, 5984, 6000, 6379, 6443,
    7000, 8000, 8008, 8080, 8081, 8086, 8123, 8443, 8888, 9000, 9090, 9100, 9200,
    10000, 11211, 27017, 32400, 62078,
]

COMMON_PORTS: List[int] = sorted(set(
    list(TCP_SERVICES.keys()) + FAST_PORTS + [
        1, 3, 17, 19, 20, 24, 26, 42, 49, 70, 113, 125, 129, 146, 163, 199, 211,
        222, 254, 255, 256, 259, 264, 280, 301, 306, 311, 340, 366, 406, 407, 416,
        417, 425, 444, 458, 464, 481, 497, 512, 513, 514, 524, 541, 543, 544, 545,
        555, 563, 593, 616, 617, 625, 646, 648, 666, 667, 668, 683, 687, 691, 700,
        705, 711, 714, 720, 722, 726, 749, 765, 783, 787, 800, 801, 808, 843, 880,
        888, 898, 900, 901, 903, 911, 912, 981, 987, 990, 992, 999, 1000, 1001,
        1002, 1007, 1009, 1010, 1011, 1021, 1022, 1023, 1024, 1025, 1026, 1027,
        1028, 1029, 1030, 1035, 1039, 1040, 1041, 1044, 1048, 1049, 1050, 1053,
        1054, 1056, 1058, 1059, 1064, 1065, 1066, 1069, 1071, 1074, 1081, 1085,
        1100, 1102, 1105, 1110, 1111, 1112, 1117, 1119, 1122, 1126, 1155, 1161,
        1183, 1200, 1214, 1216, 1221, 1248, 1259, 1300, 1301, 1309, 1310, 1311,
        1322, 1328, 1352, 1417, 1443, 1455, 1461, 1494, 1500, 1501, 1503, 1524,
        1533, 1556, 1580, 1583, 1594, 1600, 1641, 1658, 1666, 1687, 1688, 1700,
        1717, 1755, 1761, 1782, 1801, 1805, 1812, 1839, 1900, 1935, 1947, 1971,
        1972, 1974, 1984, 1998, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008,
        2009, 2010, 2013, 2020, 2021, 2022, 2030, 2033, 2034, 2038, 2040, 2041,
        2042, 2045, 2046, 2047, 2065, 2068, 2099, 2100, 2103, 2105, 2106, 2107,
        2111, 2119, 2121, 2126, 2135, 2144, 2160, 2161, 2170, 2179, 2190, 2191,
        2196, 2200, 2260, 2288, 2301, 2323, 2366, 2381, 2382, 2383, 2393, 2394,
        2399, 2401, 2492, 2500, 2522, 2557, 2601, 2602, 2604, 2605, 2607, 2608,
        2638, 2701, 2702, 2710, 2717, 2718, 2725, 2800, 2809, 2811, 2869, 2875,
        2909, 2910, 2920, 2967, 2968, 2998, 3001, 3003, 3005, 3006, 3007, 3011,
        3013, 3017, 3030, 3031, 3052, 3071, 3077, 3168, 3211, 3221, 3261, 3268,
        3269, 3300, 3301, 3323, 3324, 3325, 3333, 3351, 3367, 3369, 3370, 3371,
        3372, 3390, 3404, 3476, 3493, 3517, 3527, 3546, 3551, 3580, 3659, 3703,
        3737, 3766, 3784, 3800, 3801, 3809, 3814, 3826, 3827, 3828, 3851, 3869,
        3871, 3878, 3880, 3889, 3905, 3914, 3918, 3920, 3945, 3971, 3986, 3995,
        3998, 4000, 4001, 4002, 4003, 4004, 4005, 4006, 4045, 4111, 4125, 4126,
        4129, 4224, 4242, 4279, 4321, 4343, 4443, 4445, 4446, 4449, 4550, 4555,
        4559, 4567, 4662, 4848, 4899, 4900, 4998, 5002, 5003, 5004, 5009, 5030,
        5033, 5050, 5051, 5054, 5080, 5087, 5100, 5101, 5102, 5120, 5190, 5200,
        5214, 5221, 5225, 5226, 5269, 5280, 5298, 5357, 5405, 5414, 5431, 5440,
        5500, 5510, 5544, 5550, 5566, 5631, 5633, 5666, 5678, 5679, 5718, 5730,
        5801, 5802, 5810, 5811, 5815, 5822, 5825, 5850, 5859, 5862, 5877, 5901,
        5902, 5903, 5904, 5906, 5907, 5910, 5911, 5915, 5922, 5925, 5950, 5952,
        5959, 5960, 5961, 5962, 5963, 5987, 5988, 5989, 5998, 5999, 6001, 6002,
        6003, 6004, 6005, 6006, 6007, 6009, 6025, 6059, 6100, 6101, 6106, 6112,
        6123, 6129, 6156, 6346, 6389, 6502, 6510, 6543, 6547, 6565, 6566, 6567,
        6580, 6646, 6666, 6668, 6669, 6689, 6692, 6699, 6779, 6788, 6789, 6792,
        6839, 6881, 6901, 6969, 7002, 7004, 7007, 7019, 7025, 7100, 7103, 7106,
        7200, 7201, 7402, 7435, 7443, 7496, 7512, 7625, 7627, 7676, 7741, 7777,
        7778, 7800, 7911, 7920, 7921, 7937, 7938, 7999, 8001, 8002, 8003, 8004,
        8005, 8006, 8007, 8010, 8011, 8021, 8022, 8031, 8042, 8045, 8082, 8083,
        8084, 8085, 8087, 8088, 8089, 8090, 8093, 8099, 8100, 8180, 8192, 8193,
        8194, 8200, 8222, 8254, 8290, 8291, 8292, 8300, 8333, 8383, 8400, 8402,
        8500, 8600, 8649, 8651, 8652, 8654, 8701, 8800, 8873, 8880, 8881, 8899,
        8994, 9002, 9003, 9009, 9010, 9011, 9040, 9050, 9071, 9080, 9081, 9091,
        9099, 9101, 9102, 9103, 9110, 9111, 9200, 9207, 9220, 9290, 9415, 9485,
        9500, 9502, 9503, 9535, 9575, 9593, 9594, 9595, 9618, 9666, 9876, 9877,
        9878, 9898, 9900, 9917, 9929, 9943, 9944, 10001, 10002, 10003, 10004,
        10009, 10010, 10012, 10024, 10025, 10082, 10180, 10215, 10243, 10566,
        10616, 10617, 10621, 10626, 10628, 10629, 10778, 11110, 11111, 11967,
        12000, 12174, 12265, 12345, 13456, 13722, 13782, 13783, 14000, 14238,
        14441, 14442, 15000, 15002, 15003, 15004, 15660, 15742, 16000, 16001,
        16012, 16016, 16018, 16080, 16113, 16992, 16993, 17877, 17988, 18040,
        18101, 18988, 19101, 19283, 19315, 19350, 19780, 19801, 19842, 20000,
        20005, 20031, 20221, 20222, 20828, 21571, 22939, 23502, 24444, 24800,
        25734, 25735, 26214, 27000, 27352, 27353, 27355, 27356, 27715, 28201,
        30000, 30718, 30951, 31038, 31337, 32768, 32769, 32770, 32771, 32772,
        32773, 32774, 32775, 32776, 32777, 32778, 32779, 32780, 32781, 32782,
        33354, 33899, 34571, 34572, 34573, 35500, 38292, 40193, 40911, 41511,
        42510, 44176, 44442, 44443, 44501, 45100, 48080, 49153, 49154, 49155,
        49156, 49157, 49158, 49159, 49160, 49161, 49163, 49165, 49167, 49175,
        49176, 49400, 49999, 50001, 50002, 50003, 50006, 50300, 50389, 50500,
        50636, 50800, 51103, 51493, 52673, 52822, 52848, 52869, 54045, 54328,
        55055, 55056, 55555, 55600, 56737, 56738, 57294, 57797, 58080, 60020,
        60443, 61532, 61900, 62078, 63331, 64623, 64680, 65000, 65129, 65389,
    ]
))

UDP_PROBE_PORTS: List[int] = [53, 67, 69, 123, 137, 161, 500, 1900, 5353, 11211]

PROFILES: Dict[str, str] = {
    "fast": "~75 highest-value ports — a few seconds per host",
    "common": f"{len(COMMON_PORTS)} well-known ports — recommended default",
    "full": "All 65,535 TCP ports — thorough, slower",
}


def profile_ports(profile: str) -> List[int]:
    if profile == "fast":
        return sorted(set(FAST_PORTS))
    if profile == "full":
        return list(range(1, 65536))
    return COMMON_PORTS


def parse_port_spec(spec: str) -> List[int]:
    """Parse '22,80,8000-8100' into a sorted list of ports."""
    ports: Set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            lo, _, hi = chunk.partition("-")
            lo_i, hi_i = int(lo), int(hi)
            if lo_i > hi_i:
                lo_i, hi_i = hi_i, lo_i
            ports.update(range(max(1, lo_i), min(65535, hi_i) + 1))
        else:
            port = int(chunk)
            if 1 <= port <= 65535:
                ports.add(port)
    return sorted(ports)


def service_for(port: int, proto: str = "tcp") -> ServiceInfo:
    table = TCP_SERVICES if proto == "tcp" else UDP_SERVICES
    return table.get(port, _S("unknown", f"Unregistered {proto.upper()} port {port}"))


SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
