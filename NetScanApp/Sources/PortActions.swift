import AppKit
import SwiftUI

/// Something you can do with an open port: open it in the right app, or copy
/// a command to the clipboard.
struct PortAction: Identifiable {
    let id = UUID()
    let title: String
    let systemImage: String
    let kind: Kind

    enum Kind {
        case open(URL)
        case copy(String)
    }

    /// The app macOS would use, so the menu can say "Open in Terminal".
    var handlerName: String? {
        guard case .open(let url) = kind else { return nil }
        return NSWorkspace.shared.urlForApplication(toOpen: url)?
            .deletingPathExtension().lastPathComponent
    }

    var isOpenable: Bool {
        guard case .open(let url) = kind else { return true }
        return NSWorkspace.shared.urlForApplication(toOpen: url) != nil
    }

    var menuTitle: String {
        if let handler = handlerName { return "\(title) — \(handler)" }
        return title
    }

    func perform() {
        switch kind {
        case .open(let url):
            NSWorkspace.shared.open(url)
        case .copy(let text):
            let pasteboard = NSPasteboard.general
            pasteboard.clearContents()
            pasteboard.setString(text, forType: .string)
        }
    }
}

enum PortActions {

    private static let webPorts: Set<Int> = [
        80, 81, 82, 88, 280, 591, 593, 631, 777, 800, 808, 981, 1010, 2082, 2083,
        2086, 2087, 2095, 2096, 3000, 3128, 5000, 5001, 5601, 5800, 7001, 8000,
        8008, 8080, 8081, 8083, 8086, 8088, 8090, 8123, 8180, 8181, 8200, 8443,
        8888, 9000, 9080, 9090, 9200, 10000, 32400, 49152,
    ]

    /// Everything you can do with this port, most useful first.
    static func actions(for port: Port, ip: String) -> [PortAction] {
        var actions: [PortAction] = []
        let number = port.port
        let product = (port.product ?? "").lowercased()
        let service = (port.service ?? "").lowercased()

        if port.proto == "tcp" {
            // --- Web
            if isWeb(port) {
                let scheme = port.http?.scheme ?? (port.tls != nil ? "https" : "http")
                let isDefaultPort = (scheme == "http" && number == 80) || (scheme == "https" && number == 443)
                let authority = isDefaultPort ? ip : "\(ip):\(number)"
                if let url = URL(string: "\(scheme)://\(authority)/") {
                    actions.append(PortAction(title: "Open in browser",
                                              systemImage: "safari", kind: .open(url)))
                }
            }

            // --- Remote shells
            if number == 22 || number == 2222 || product.contains("ssh") || service.contains("ssh") {
                if let url = URL(string: "ssh://\(ip):\(number)") {
                    actions.append(PortAction(title: "Open SSH session",
                                              systemImage: "terminal", kind: .open(url)))
                }
                actions.append(PortAction(title: "Copy ssh command", systemImage: "doc.on.doc",
                                          kind: .copy("ssh -p \(number) \(ip)")))
            }

            if number == 23 || product.contains("telnet") || service.contains("telnet") {
                if let url = URL(string: "telnet://\(ip):\(number)") {
                    actions.append(PortAction(title: "Open Telnet session",
                                              systemImage: "terminal", kind: .open(url)))
                }
                actions.append(PortAction(title: "Copy telnet command", systemImage: "doc.on.doc",
                                          kind: .copy("telnet \(ip) \(number)")))
            }

            // --- Screen sharing / remote desktop
            if (5900...5910).contains(number) || product.contains("vnc") || product.contains("rfb") {
                if let url = URL(string: "vnc://\(ip):\(number)") {
                    actions.append(PortAction(title: "Open screen sharing",
                                              systemImage: "display", kind: .open(url)))
                }
            }

            if number == 3389 {
                // The documented "rdp://full%20address=s:host:port" form is not a
                // parseable URL, so use the plain host form, which still hands off
                // to the RDP client.
                if let url = URL(string: "rdp://\(ip):\(number)") {
                    actions.append(PortAction(title: "Open remote desktop",
                                              systemImage: "display", kind: .open(url)))
                }
                actions.append(PortAction(title: "Copy RDP address", systemImage: "doc.on.doc",
                                          kind: .copy("\(ip):\(number)")))
            }

            // --- File sharing
            if number == 445 || number == 139 {
                if let url = URL(string: "smb://\(ip)") {
                    actions.append(PortAction(title: "Open file share",
                                              systemImage: "folder", kind: .open(url)))
                }
            }
            if number == 548 {
                if let url = URL(string: "afp://\(ip)") {
                    actions.append(PortAction(title: "Open file share (AFP)",
                                              systemImage: "folder", kind: .open(url)))
                }
            }
            if number == 21 {
                if let url = URL(string: "ftp://\(ip)") {
                    actions.append(PortAction(title: "Open FTP", systemImage: "folder",
                                              kind: .open(url)))
                }
                actions.append(PortAction(title: "Copy ftp command", systemImage: "doc.on.doc",
                                          kind: .copy("ftp \(ip)")))
            }
            if number == 2049 {
                actions.append(PortAction(title: "Copy NFS mount command", systemImage: "doc.on.doc",
                                          kind: .copy("mount -t nfs \(ip):/export /mnt")))
            }

            // --- Media
            if number == 554 || number == 8554 {
                if let url = URL(string: "rtsp://\(ip):\(number)/") {
                    actions.append(PortAction(title: "Open video stream",
                                              systemImage: "play.rectangle", kind: .open(url)))
                }
            }

            // --- Printing
            if number == 631 || number == 9100 || number == 515 {
                if let url = URL(string: "http://\(ip):631/") {
                    actions.append(PortAction(title: "Open printer admin",
                                              systemImage: "printer", kind: .open(url)))
                }
            }

            // --- Databases and caches: a ready-to-paste client command
            let clients: [Int: String] = [
                3306: "mysql -h \(ip) -P \(number) -u root -p",
                5432: "psql -h \(ip) -p \(number) -U postgres",
                6379: "redis-cli -h \(ip) -p \(number)",
                27017: "mongosh mongodb://\(ip):\(number)",
                1433: "sqlcmd -S \(ip),\(number) -U sa",
                11211: "nc \(ip) \(number)   # then: stats",
                9200: "curl http://\(ip):\(number)/_cluster/health?pretty",
                5672: "amqp://\(ip):\(number)",
            ]
            if let command = clients[number] {
                actions.append(PortAction(title: "Copy client command",
                                          systemImage: "doc.on.doc", kind: .copy(command)))
            }
        }

        // --- Always available
        actions.append(PortAction(title: "Copy address", systemImage: "doc.on.doc",
                                  kind: .copy("\(ip):\(number)")))
        if isWeb(port) {
            let scheme = port.http?.scheme ?? (port.tls != nil ? "https" : "http")
            actions.append(PortAction(title: "Copy URL", systemImage: "link",
                                      kind: .copy("\(scheme)://\(ip):\(number)/")))
        }
        actions.append(PortAction(title: "Copy netcat probe", systemImage: "doc.on.doc",
                                  kind: .copy("nc -v \(ip) \(number)")))

        var result = actions.filter { $0.isOpenable }

        // Nothing openable and no protocol we recognise: plenty of unknown ports
        // turn out to speak HTTP, so offer that rather than leaving a dead row.
        let notWebProtocols: Set<Int> = [53, 111, 123, 135, 161, 1433, 2049, 3306,
                                         5432, 5672, 6379, 11211, 27017]
        if port.proto == "tcp", !notWebProtocols.contains(number),
           !result.contains(where: { if case .open = $0.kind { return true } else { return false } }),
           let url = URL(string: "http://\(ip):\(number)/") {
            result.insert(PortAction(title: "Try in browser",
                                     systemImage: "safari", kind: .open(url)), at: 0)
        }

        return result
    }

    /// The single action a click should perform, if there is an obvious one.
    static func primary(for port: Port, ip: String) -> PortAction? {
        let all = actions(for: port, ip: ip)
        return all.first { if case .open = $0.kind { return true } else { return false } }
    }

    static func isWeb(_ port: Port) -> Bool {
        if port.proto != "tcp" { return false }
        if port.http != nil { return true }
        if port.tls != nil { return true }
        return webPorts.contains(port.port)
    }

    /// Best "open this device" action for a host — used by the detail header.
    static func primaryForHost(_ host: Host) -> PortAction? {
        let preferred = [443, 80, 8443, 8080, 8000, 5000, 8123, 631, 9090, 3000]
        for candidate in preferred {
            if let port = host.tcpPorts.first(where: { $0.port == candidate }),
               let action = primary(for: port, ip: host.ip) {
                return action
            }
        }
        for port in host.tcpPorts where isWeb(port) {
            if let action = primary(for: port, ip: host.ip) { return action }
        }
        for port in host.tcpPorts {
            if let action = primary(for: port, ip: host.ip) { return action }
        }
        return nil
    }
}
