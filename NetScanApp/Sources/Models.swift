import Foundation

// MARK: - Wire format
// These mirror the JSON emitted by the Python engine (`netscan --ndjson`).
// Keys arrive in snake_case and are converted automatically.

struct HTTPInfo: Codable, Hashable {
    var scheme: String?
    var status: String?
    var server: String?
    var poweredBy: String?
    var location: String?
    var contentType: String?
    var url: String?
    var title: String?
    var auth: String?
    var authRealm: String?
    var missingSecurityHeaders: [String]?
}

struct TLSInfo: Codable, Hashable {
    var version: String?
    var cipher: String?
    var subject: String?
    var issuer: String?
    var notBefore: String?
    var notAfter: String?
    var serial: String?
    var fingerprintSha256: String?
    var san: [String]?
    var daysUntilExpiry: Int?
    var selfSigned: Bool?
}

struct Finding: Codable, Hashable, Identifiable {
    var severity: String
    var message: String
    var port: Int?
    var service: String?
    var proto: String?
    var verified: Bool?

    var id: String { "\(severity)-\(port ?? 0)-\(message)" }
    var isVerified: Bool { verified ?? true }
    var rank: Int { Severity(rawValue: severity)?.rank ?? 4 }
}

struct Port: Codable, Hashable, Identifiable {
    var port: Int
    var proto: String
    var state: String?
    var latencyMs: Double?
    var service: String?
    var serviceGuess: String?
    var description: String?
    var severity: String?
    var risk: String?
    var banner: String?
    var product: String?
    var version: String?
    var notes: [String]?
    var findings: [Finding]?
    var http: HTTPInfo?
    var tls: TLSInfo?

    var id: String { "\(proto)/\(port)" }

    /// True when fingerprinting actually learned what is listening here.
    var identified: Bool {
        banner != nil || product != nil || http != nil || tls != nil || version != nil
    }

    var displayName: String {
        if let product = product, !product.isEmpty { return product }
        if let title = http?.title, !title.isEmpty { return title }
        if let server = http?.server, !server.isEmpty { return server }
        if let service = service, !service.isEmpty {
            return identified ? service : "\(service)?"
        }
        return "unknown"
    }

    var detail: String {
        var parts: [String] = []
        if let version = version, !version.isEmpty { parts.append(version) }
        if let title = http?.title, !title.isEmpty, title != product { parts.append("\u{201C}\(title)\u{201D}") }
        if let server = http?.server, !server.isEmpty, server != product { parts.append(server) }
        if let location = http?.location, !location.isEmpty { parts.append("→ \(location)") }
        if let tls = tls {
            var bits: [String] = []
            if let v = tls.version { bits.append(v) }
            if let s = tls.subject { bits.append(s) }
            if let d = tls.daysUntilExpiry { bits.append(d < 0 ? "expired" : "expires in \(d)d") }
            if !bits.isEmpty { parts.append("TLS " + bits.joined(separator: " · ")) }
        }
        if parts.isEmpty, let banner = banner { parts.append(banner) }
        if parts.isEmpty, let description = description { parts.append(description) }
        return parts.joined(separator: " · ")
    }
}

struct BonjourService: Codable, Hashable {
    var label: String?
    var instance: String?
    var port: Int?
    var txt: [String: String]?
}

struct Host: Codable, Hashable, Identifiable {
    var ip: String
    var network: String?
    var interface: String?
    var alive: Bool
    var mac: String?
    var vendor: String?
    var rttMs: Double?
    var hostname: String?
    var names: [String]
    var netbiosName: String?
    var workgroup: String?
    var model: String?
    var deviceType: String?
    var confidence: Double
    var discovery: [String]
    var bonjour: [String: BonjourService]
    var ssdp: [String: String]
    var tcpPorts: [Port]
    var udpPorts: [Port]
    var findings: [Finding]
    var isSelf: Bool
    var isGateway: Bool
    var scanned: Bool
    var label: String?
    var openPortCount: Int?
    var risk: String?

    var id: String { ip }

    var displayName: String {
        if let label = label, !label.isEmpty, label != ip { return label }
        if let hostname = hostname, !hostname.isEmpty { return hostname }
        return ip
    }

    var shortName: String {
        let name = displayName
        if name.hasSuffix(".local") { return String(name.dropLast(6)) }
        return name
    }

    var allPorts: [Port] { tcpPorts + udpPorts }

    var highestSeverity: Severity {
        findings.map { Severity(rawValue: $0.severity) ?? .info }.min(by: { $0.rank < $1.rank }) ?? .info
    }

    var sortKey: [Int] {
        ip.split(separator: ".").map { Int($0) ?? 0 }
    }

    static func placeholder(ip: String) -> Host {
        Host(ip: ip, network: nil, interface: nil, alive: true, mac: nil, vendor: nil,
             rttMs: nil, hostname: nil, names: [], netbiosName: nil, workgroup: nil,
             model: nil, deviceType: nil, confidence: 0, discovery: [], bonjour: [:],
             ssdp: [:], tcpPorts: [], udpPorts: [], findings: [], isSelf: false,
             isGateway: false, scanned: false, label: nil, openPortCount: 0, risk: nil)
    }
}

struct NetworkPlan: Codable, Hashable, Identifiable {
    var cidr: String
    var source: String?
    var interface: String?
    var gateway: String?
    var hosts: Int?

    var id: String { cidr }
}

struct InterfaceInfo: Codable, Hashable, Identifiable {
    var name: String
    var mac: String?
    var ipv4: String?
    var netmask: String?
    var broadcast: String?
    var kind: String?
    var hardwarePort: String?
    var gateway: String?
    var ssid: String?
    var status: String?
    var cidr: String?
    var isUp: Bool?
    var mtu: Int?
    var dhcpServer: String?

    var id: String { name }
}

struct Summary: Codable, Hashable {
    var hostsAlive: Int?
    var openTcpPorts: Int?
    var openUdpPorts: Int?
    var findings: Int?
    var findingsBySeverity: [String: Int]?
    var deviceTypes: [String: Int]?
    var duration: Double?
}

/// One line of the engine's NDJSON stream. Every field is optional because a
/// single struct covers every event type.
struct ScanEvent: Decodable {
    var event: String
    var t: Double?
    var message: String?
    var phase: String?
    var host: Host?
    var ip: String?
    var ports: [Port]?
    var networks: [NetworkPlan]?
    var interfaces: [InterfaceInfo]?
    var summary: Summary?
    var done: Int?
    var total: Int?
    var found: Int?
    var method: String?
    var count: Int?
    var alive: Int?
    var duration: Double?
    var totalAddresses: Int?
    var portCount: Int?
    var profile: String?
    var system: [String: String]?
    var dns: [String]?
    var findings: [Finding]?
    var port: Int?
}

// MARK: - Self audit

struct ListeningSocket: Codable, Hashable, Identifiable {
    var proto: String
    var port: Int
    var address: String
    var scope: String
    var process: String
    var pid: Int?
    var user: String?
    var state: String?
    var exposed: Bool

    var id: String { "\(proto)-\(port)-\(address)-\(pid ?? 0)" }
    var cleanProcess: String { process.replacingOccurrences(of: "\\x20", with: " ") }
}

struct FirewallStatus: Codable, Hashable {
    var enabled: Bool?
    var rawState: String?
    var stealthMode: Bool?
    var blockAll: Bool?
}

struct SelfAudit: Codable {
    var system: [String: String]?
    var interfaces: [InterfaceInfo]?
    var firewall: FirewallStatus?
    var sharing: [String: Bool]?
    var sockets: [ListeningSocket]?
    var dns: [String]?
    var wifi: [String: String]?
}

// MARK: - Severity

enum Severity: String, CaseIterable {
    case high, medium, low, info

    var rank: Int {
        switch self {
        case .high: return 0
        case .medium: return 1
        case .low: return 2
        case .info: return 3
        }
    }

    var title: String {
        switch self {
        case .high: return "High"
        case .medium: return "Medium"
        case .low: return "Low"
        case .info: return "Info"
        }
    }
}
