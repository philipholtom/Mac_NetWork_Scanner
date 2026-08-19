import Foundation
import SwiftUI

/// Drives the Python scanning engine and turns its NDJSON stream into
/// observable state for the UI.
@MainActor
final class ScanController: ObservableObject {

    // Live scan state
    @Published var hosts: [Host] = []
    @Published var networks: [NetworkPlan] = []
    @Published var interfaces: [InterfaceInfo] = []
    @Published var systemInfo: [String: String] = [:]
    @Published var dnsServers: [String] = []
    @Published var summary: Summary?
    @Published var isScanning = false
    @Published var phaseMessage = "Ready"
    @Published var progress: Double = 0
    @Published var progressLabel = ""
    @Published var log: [LogLine] = []
    @Published var lastError: String?
    @Published var lastScanDate: Date?

    // Self audit
    @Published var selfAudit: SelfAudit?
    @Published var isAuditing = false

    // Options
    @AppStorage("profile") var profile: String = "common"
    @AppStorage("scanUDP") var scanUDP: Bool = true
    @AppStorage("fingerprint") var fingerprint: Bool = true
    @AppStorage("probeAdjacent") var probeAdjacent: Bool = false
    @AppStorage("customTargets") var customTargets: String = ""

    struct LogLine: Identifiable {
        let id = UUID()
        let time: Date
        let text: String
        let kind: Kind
        enum Kind { case info, good, warn, bad }
    }

    private var process: Process?
    private var buffer = Data()
    private var hostIndex: [String: Int] = [:]

    // MARK: - Engine location

    /// Python interpreter to run the engine with.
    private var pythonPath: String {
        let candidates = ["/usr/bin/python3", "/opt/homebrew/bin/python3", "/usr/local/bin/python3"]
        for path in candidates where FileManager.default.isExecutableFile(atPath: path) {
            return path
        }
        return "/usr/bin/python3"
    }

    /// Directory containing the `netscan` package.
    private var enginePath: String? {
        // Inside the app bundle first.
        if let resources = Bundle.main.resourceURL {
            let bundled = resources.appendingPathComponent("engine")
            if FileManager.default.fileExists(atPath: bundled.appendingPathComponent("netscan").path) {
                return bundled.path
            }
        }
        // Development fallback: alongside the built binary or in the source tree.
        let dev = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()   // Sources
            .deletingLastPathComponent()   // NetScanApp
            .deletingLastPathComponent()   // project root
        if FileManager.default.fileExists(atPath: dev.appendingPathComponent("netscan").path) {
            return dev.path
        }
        return nil
    }

    var engineAvailable: Bool { enginePath != nil }

    // MARK: - Scanning

    func startScan() {
        guard !isScanning else { return }
        guard let engine = enginePath else {
            lastError = "Could not find the scanning engine (netscan package)."
            return
        }

        hosts.removeAll()
        hostIndex.removeAll()
        networks.removeAll()
        summary = nil
        log.removeAll()
        progress = 0
        progressLabel = ""
        lastError = nil
        isScanning = true
        phaseMessage = "Starting…"

        var arguments = ["-u", "-m", "netscan", "--ndjson", "--profile", profile]
        if !scanUDP { arguments.append("--no-udp") }
        if !fingerprint { arguments.append("--no-fingerprint") }
        if probeAdjacent { arguments.append("--probe-adjacent") }

        let targets = customTargets
            .split(whereSeparator: { ", \n\t".contains($0) })
            .map(String.init)
            .filter { !$0.isEmpty }
        arguments.append(contentsOf: targets)

        let task = Process()
        task.executableURL = URL(fileURLWithPath: pythonPath)
        task.arguments = arguments
        task.currentDirectoryURL = URL(fileURLWithPath: engine)
        var environment = ProcessInfo.processInfo.environment
        environment["PYTHONPATH"] = engine
        environment["PYTHONUNBUFFERED"] = "1"
        task.environment = environment

        let outPipe = Pipe()
        let errPipe = Pipe()
        task.standardOutput = outPipe
        task.standardError = errPipe

        outPipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty else { return }
            Task { @MainActor in self?.consume(data) }
        }
        errPipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty,
                  let text = String(data: data, encoding: .utf8) else { return }
            Task { @MainActor in
                for line in text.split(separator: "\n") where !line.isEmpty {
                    self?.append(String(line), kind: .warn)
                }
            }
        }

        task.terminationHandler = { [weak self] proc in
            Task { @MainActor in
                self?.finish(status: proc.terminationStatus)
            }
        }

        do {
            try task.run()
            process = task
            append("Scanning with the \(profile) port profile", kind: .info)
        } catch {
            isScanning = false
            lastError = "Could not start the engine: \(error.localizedDescription)"
        }
    }

    func stopScan() {
        process?.terminate()
        process = nil
        isScanning = false
        phaseMessage = "Stopped"
    }

    private func finish(status: Int32) {
        isScanning = false
        process = nil
        lastScanDate = Date()
        progress = 1
        if status != 0 && status != 15 && status != -15 {
            phaseMessage = "Engine exited with code \(status)"
            append(phaseMessage, kind: .bad)
        } else {
            phaseMessage = summary.map {
                "Done — \($0.hostsAlive ?? 0) hosts, \($0.openTcpPorts ?? 0) open ports in \(String(format: "%.0f", $0.duration ?? 0))s"
            } ?? "Finished"
        }
    }

    // MARK: - Stream parsing

    private func consume(_ data: Data) {
        buffer.append(data)
        while let range = buffer.firstRange(of: Data([0x0A])) {
            let lineData = buffer.subdata(in: buffer.startIndex..<range.lowerBound)
            buffer.removeSubrange(buffer.startIndex..<range.upperBound)
            guard !lineData.isEmpty else { continue }
            handle(lineData)
        }
    }

    private static let decoder: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return decoder
    }()

    private func handle(_ lineData: Data) {
        guard let event = try? Self.decoder.decode(ScanEvent.self, from: lineData) else { return }

        switch event.event {
        case "interfaces":
            interfaces = event.interfaces ?? []
            systemInfo = event.system ?? [:]
            dnsServers = event.dns ?? []

        case "plan":
            networks = event.networks ?? []
            let addresses = event.totalAddresses ?? 0
            append("Scanning \(networks.count) networks · \(addresses) addresses", kind: .info)

        case "networks_discovered":
            for network in event.networks ?? [] {
                networks.append(network)
                append("Found another network: \(network.cidr) — \(network.source ?? "")", kind: .good)
            }

        case "phase":
            if let message = event.message {
                phaseMessage = message
                append(message, kind: .info)
            }

        case "discovery_progress":
            if let method = event.method, let found = event.found {
                progressLabel = "\(method): \(found) hosts"
            }

        case "host_found":
            if let host = event.host { upsert(host) }

        case "host_ports":
            if let ip = event.ip, let ports = event.ports {
                update(ip: ip) { $0.tcpPorts = ports; $0.scanned = true }
            }
            if let done = event.done, let total = event.total, total > 0 {
                progress = Double(done) / Double(total)
                progressLabel = "Scanned \(done) of \(total) hosts"
            }

        case "host_udp":
            if let ip = event.ip, let ports = event.ports {
                update(ip: ip) { $0.udpPorts = ports }
            }

        case "fingerprint_progress":
            if let done = event.done, let total = event.total, total > 0 {
                progress = Double(done) / Double(total)
                progressLabel = "Identified \(done) of \(total) services"
            }

        case "host_finding":
            if let ip = event.ip, let findings = event.findings {
                let worst = findings.min(by: { ($0.rank) < ($1.rank) })
                if let worst = worst, worst.rank <= 1 {
                    append("\(ip):\(event.port ?? 0) — \(worst.message)", kind: .bad)
                }
            }

        case "host_complete":
            if let host = event.host { upsert(host) }

        case "warning":
            if let message = event.message { append(message, kind: .warn) }

        case "complete":
            summary = event.summary
            progress = 1

        default:
            break
        }
    }

    private func upsert(_ host: Host) {
        if let index = hostIndex[host.ip] {
            let existing = hosts[index]
            var merged = host
            // Keep data the newer event does not carry.
            if merged.tcpPorts.isEmpty { merged.tcpPorts = existing.tcpPorts }
            if merged.udpPorts.isEmpty { merged.udpPorts = existing.udpPorts }
            if merged.mac == nil { merged.mac = existing.mac }
            if merged.vendor == nil { merged.vendor = existing.vendor }
            hosts[index] = merged
        } else {
            hosts.append(host)
            hosts.sort { $0.sortKey.lexicographicallyPrecedes($1.sortKey) }
            reindex()
        }
    }

    private func update(ip: String, _ mutate: (inout Host) -> Void) {
        if let index = hostIndex[ip] {
            mutate(&hosts[index])
        } else {
            var host = Host.placeholder(ip: ip)
            mutate(&host)
            hosts.append(host)
            hosts.sort { $0.sortKey.lexicographicallyPrecedes($1.sortKey) }
            reindex()
        }
    }

    private func reindex() {
        hostIndex = Dictionary(uniqueKeysWithValues: hosts.enumerated().map { ($1.ip, $0) })
    }

    private func append(_ text: String, kind: LogLine.Kind) {
        log.append(LogLine(time: Date(), text: text, kind: kind))
        if log.count > 500 { log.removeFirst(log.count - 500) }
    }

    // MARK: - Self audit

    func runSelfAudit() {
        guard !isAuditing, let engine = enginePath else { return }
        isAuditing = true
        let python = pythonPath

        Task.detached { [weak self] in
            let task = Process()
            task.executableURL = URL(fileURLWithPath: python)
            task.arguments = ["-u", "-m", "netscan", "--self", "--json", "-"]
            task.currentDirectoryURL = URL(fileURLWithPath: engine)
            var environment = ProcessInfo.processInfo.environment
            environment["PYTHONPATH"] = engine
            task.environment = environment
            let pipe = Pipe()
            task.standardOutput = pipe
            task.standardError = FileHandle.nullDevice

            do {
                try task.run()
                let data = pipe.fileHandleForReading.readDataToEndOfFile()
                task.waitUntilExit()
                let decoder = JSONDecoder()
                decoder.keyDecodingStrategy = .convertFromSnakeCase
                let audit = try decoder.decode(SelfAudit.self, from: data)
                await MainActor.run { [weak self] in
                    self?.selfAudit = audit
                    self?.isAuditing = false
                }
            } catch {
                let message = error.localizedDescription
                await MainActor.run { [weak self] in
                    self?.isAuditing = false
                    self?.lastError = "Self audit failed: \(message)"
                }
            }
        }
    }

    // MARK: - Export

    func exportDocument() -> [String: Any] {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        var document: [String: Any] = [:]
        document["generated"] = ISO8601DateFormatter().string(from: Date())
        if let data = try? encoder.encode(hosts),
           let array = try? JSONSerialization.jsonObject(with: data) {
            document["hosts"] = array
        }
        if let data = try? encoder.encode(networks),
           let array = try? JSONSerialization.jsonObject(with: data) {
            document["networks"] = array
        }
        if let summary = summary, let data = try? encoder.encode(summary),
           let object = try? JSONSerialization.jsonObject(with: data) {
            document["summary"] = object
        }
        return document
    }

    func exportJSON(to url: URL) throws {
        let data = try JSONSerialization.data(withJSONObject: exportDocument(),
                                              options: [.prettyPrinted, .sortedKeys])
        try data.write(to: url)
    }

    func exportCSV(to url: URL) throws {
        var lines = ["ip,name,device,vendor,mac,network,rtt_ms,proto,port,service,product,detail,severity"]
        for host in hosts {
            let base = [host.ip, host.displayName, host.deviceType ?? "", host.vendor ?? "",
                        host.mac ?? "", host.network ?? "",
                        host.rttMs.map { String(format: "%.1f", $0) } ?? ""]
            if host.allPorts.isEmpty {
                lines.append((base + ["", "", "", "", "", ""]).map(csvEscape).joined(separator: ","))
            }
            for port in host.allPorts {
                let row = base + [port.proto, String(port.port), port.service ?? "",
                                  port.product ?? "", port.detail, port.severity ?? ""]
                lines.append(row.map(csvEscape).joined(separator: ","))
            }
        }
        try lines.joined(separator: "\n").write(to: url, atomically: true, encoding: .utf8)
    }

    private func csvEscape(_ value: String) -> String {
        if value.contains(",") || value.contains("\"") || value.contains("\n") {
            return "\"" + value.replacingOccurrences(of: "\"", with: "\"\"") + "\""
        }
        return value
    }
}
