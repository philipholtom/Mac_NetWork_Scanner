import SwiftUI
import UniformTypeIdentifiers

enum SidebarItem: Hashable {
    case allHosts
    case network(String)
    case risks
    case thisMac
    case activity
}

/// View-local state. Held in an ObservableObject because the Command Line
/// Tools toolchain cannot expand SwiftUI's @State macro.
final class UIState: ObservableObject {
    @Published var selection: SidebarItem? = .allHosts
    @Published var selectedHost: Host.ID?
    @Published var search = ""
    @Published var showOnlyOpen = false
}

struct ContentView: View {
    @EnvironmentObject var controller: ScanController
    @StateObject private var ui = UIState()

    private var selection: SidebarItem? { ui.selection }
    private var selectedHost: Host.ID? { ui.selectedHost }
    private var search: String { ui.search }
    private var showOnlyOpen: Bool { ui.showOnlyOpen }

    var body: some View {
        NavigationSplitView {
            SidebarView(selection: $ui.selection)
                .navigationSplitViewColumnWidth(min: 230, ideal: 250, max: 320)
        } content: {
            Group {
                switch selection ?? .allHosts {
                case .thisMac:
                    SelfAuditView()
                case .activity:
                    ActivityView()
                default:
                    hostList
                }
            }
            .navigationSplitViewColumnWidth(min: 380, ideal: 460)
        } detail: {
            if case .thisMac = selection ?? .allHosts {
                EmptyDetail(text: "Local services are listed on the left.")
            } else if let host = currentHost {
                HostDetailView(host: host)
            } else {
                EmptyDetail(text: controller.hosts.isEmpty
                            ? "Press Scan to sweep every network this Mac can reach."
                            : "Select a device to see its open ports and details.")
            }
        }
        .toolbar { toolbarContent }
        .onAppear {
            if controller.selfAudit == nil { controller.runSelfAudit() }
        }
    }

    private var currentHost: Host? {
        guard let id = selectedHost else { return nil }
        return controller.hosts.first { $0.id == id }
    }

    // MARK: - Host list

    private var filteredHosts: [Host] {
        var result = controller.hosts

        switch selection ?? .allHosts {
        case .network(let cidr):
            result = result.filter { $0.network == cidr }
        case .risks:
            result = result.filter { host in
                host.findings.contains { ($0.verified ?? true) && (Severity(rawValue: $0.severity)?.rank ?? 3) <= 1 }
            }
        default:
            break
        }

        if showOnlyOpen {
            result = result.filter { !$0.allPorts.isEmpty }
        }

        if !search.isEmpty {
            let needle = search.lowercased()
            result = result.filter { host in
                host.ip.contains(needle)
                || host.displayName.lowercased().contains(needle)
                || (host.vendor ?? "").lowercased().contains(needle)
                || (host.deviceType ?? "").lowercased().contains(needle)
                || (host.mac ?? "").lowercased().contains(needle)
                || host.allPorts.contains { String($0.port).contains(needle) || ($0.service ?? "").contains(needle) }
            }
        }
        return result
    }

    private var hostList: some View {
        VStack(spacing: 0) {
            summaryBar

            List(selection: $ui.selectedHost) {
                ForEach(filteredHosts) { host in
                    HostRow(host: host)
                        .tag(host.id)
                        .contextMenu {
                            if let primary = PortActions.primaryForHost(host) {
                                Button(primary.menuTitle) { primary.perform() }
                                Divider()
                            }
                            ForEach(host.tcpPorts.compactMap { port -> PortAction? in
                                guard let action = PortActions.primary(for: port, ip: host.ip) else { return nil }
                                return PortAction(title: "\(port.port) — \(action.title)",
                                                  systemImage: action.systemImage,
                                                  kind: action.kind)
                            }) { action in
                                Button(action.title) { action.perform() }
                            }
                            Divider()
                            Button("Copy IP address") {
                                NSPasteboard.general.clearContents()
                                NSPasteboard.general.setString(host.ip, forType: .string)
                            }
                        }
                }
            }
            .listStyle(.inset)
            .searchable(text: $ui.search, placement: .toolbar, prompt: "Search address, name, vendor or port")
            .overlay {
                if filteredHosts.isEmpty {
                    ContentUnavailableFallback(
                        title: controller.isScanning ? "Scanning…" : "No devices yet",
                        message: controller.isScanning
                            ? controller.phaseMessage
                            : "Press Scan to sweep every network this Mac can reach.")
                }
            }
        }
    }

    private var summaryBar: some View {
        VStack(spacing: 8) {
            HStack(spacing: 8) {
                StatTile(value: "\(controller.hosts.count)", label: "devices")
                StatTile(value: "\(controller.hosts.reduce(0) { $0 + $1.tcpPorts.count })",
                         label: "open TCP", color: .orange)
                StatTile(value: "\(highRiskCount)", label: "high findings",
                         color: highRiskCount > 0 ? Severity.high.color : .primary)
                StatTile(value: "\(controller.networks.count)", label: "networks", color: .blue)
            }

            if controller.isScanning {
                VStack(alignment: .leading, spacing: 3) {
                    ProgressView(value: max(0.02, controller.progress))
                        .progressViewStyle(.linear)
                    HStack {
                        Text(controller.phaseMessage).font(.caption2).foregroundStyle(.secondary)
                        Spacer()
                        Text(controller.progressLabel).font(.caption2).foregroundStyle(.tertiary)
                    }
                }
            }

            Toggle("Only devices with open ports", isOn: $ui.showOnlyOpen)
                .toggleStyle(.checkbox)
                .font(.caption)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(10)
        .background(.background)
    }

    private var highRiskCount: Int {
        controller.hosts.reduce(0) { total, host in
            total + host.findings.filter {
                ($0.verified ?? true) && (Severity(rawValue: $0.severity)?.rank ?? 3) <= 1
            }.count
        }
    }

    // MARK: - Toolbar

    @ToolbarContentBuilder
    private var toolbarContent: some ToolbarContent {
        ToolbarItem(placement: .primaryAction) {
            Button {
                controller.isScanning ? controller.stopScan() : controller.startScan()
            } label: {
                Label(controller.isScanning ? "Stop" : "Scan",
                      systemImage: controller.isScanning ? "stop.fill" : "play.fill")
            }
            .keyboardShortcut("r", modifiers: .command)
            .disabled(!controller.engineAvailable)
        }

        ToolbarItem(placement: .automatic) {
            if controller.isScanning {
                ProgressView().controlSize(.small)
            }
        }

        ToolbarItem(placement: .automatic) {
            Menu {
                Button("Export JSON…") { export(.json) }
                Button("Export CSV…") { export(.commaSeparatedText) }
            } label: {
                Label("Export", systemImage: "square.and.arrow.up")
            }
            .disabled(controller.hosts.isEmpty)
        }
    }

    private func export(_ type: UTType) {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [type]
        panel.nameFieldStringValue = type == .json ? "network-scan.json" : "network-scan.csv"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            if type == .json {
                try controller.exportJSON(to: url)
            } else {
                try controller.exportCSV(to: url)
            }
        } catch {
            controller.lastError = error.localizedDescription
        }
    }
}

// MARK: - Sidebar

struct SidebarView: View {
    @EnvironmentObject var controller: ScanController
    @Binding var selection: SidebarItem?

    var body: some View {
        List(selection: $selection) {
            Section("Scan") {
                Picker("Ports", selection: $controller.profile) {
                    Text("Fast (76 ports)").tag("fast")
                    Text("Common (920 ports)").tag("common")
                    Text("Full (65,535 ports)").tag("full")
                }
                .pickerStyle(.menu)

                Toggle("Identify services", isOn: $controller.fingerprint)
                Toggle("Probe UDP", isOn: $controller.scanUDP)
                Toggle("Hunt for other subnets", isOn: $controller.probeAdjacent)

                TextField("Extra targets (optional)", text: $controller.customTargets)
                    .textFieldStyle(.roundedBorder)
                    .font(.caption)

                Button {
                    controller.isScanning ? controller.stopScan() : controller.startScan()
                } label: {
                    Label(controller.isScanning ? "Stop scan" : "Scan all networks",
                          systemImage: controller.isScanning ? "stop.circle" : "play.circle")
                        .frame(maxWidth: .infinity)
                }
                .controlSize(.large)
                .buttonStyle(.borderedProminent)
                .disabled(!controller.engineAvailable)
            }

            Section("Devices") {
                Label("All devices", systemImage: "list.bullet")
                    .badge(controller.hosts.count)
                    .tag(SidebarItem.allHosts)

                Label("Needs attention", systemImage: "exclamationmark.shield")
                    .badge(riskyCount)
                    .tag(SidebarItem.risks)
            }

            if !controller.networks.isEmpty {
                Section("Networks") {
                    ForEach(controller.networks) { network in
                        VStack(alignment: .leading, spacing: 1) {
                            Text(network.cidr).font(.system(size: 12, design: .monospaced))
                            Text(network.interface ?? network.source ?? "")
                                .font(.caption2).foregroundStyle(.secondary)
                        }
                        .badge(controller.hosts.filter { $0.network == network.cidr }.count)
                        .tag(SidebarItem.network(network.cidr))
                    }
                }
            }

            Section("This Mac") {
                Label("Local services", systemImage: "laptopcomputer")
                    .tag(SidebarItem.thisMac)
                Label("Activity", systemImage: "text.alignleft")
                    .tag(SidebarItem.activity)
            }
        }
        .listStyle(.sidebar)
        .safeAreaInset(edge: .bottom) {
            if let error = controller.lastError {
                Text(error)
                    .font(.caption2)
                    .foregroundStyle(Severity.high.color)
                    .padding(8)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }

    private var riskyCount: Int {
        controller.hosts.filter { host in
            host.findings.contains { ($0.verified ?? true) && (Severity(rawValue: $0.severity)?.rank ?? 3) <= 1 }
        }.count
    }
}

// MARK: - Rows

struct HostRow: View {
    let host: Host

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: deviceIcon(for: host))
                .font(.system(size: 15))
                .frame(width: 22)
                .foregroundStyle(host.isGateway ? Color.blue : Color.secondary)

            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(host.shortName)
                        .font(.system(size: 13, weight: .medium))
                        .lineLimit(1)
                    if host.isSelf { Badge(text: "this Mac") }
                    if host.isGateway { Badge(text: "gateway", color: .blue) }
                }
                HStack(spacing: 6) {
                    Text(host.ip)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(.secondary)
                    if let vendor = host.vendor {
                        Text("· \(vendor)")
                            .font(.system(size: 11))
                            .foregroundStyle(.tertiary)
                            .lineLimit(1)
                    }
                }
            }

            Spacer(minLength: 4)

            if worstSeverity.rank <= 1 {
                Image(systemName: worstSeverity.symbol)
                    .foregroundStyle(worstSeverity.color)
                    .font(.system(size: 11))
            }

            if !host.allPorts.isEmpty {
                Badge(text: "\(host.allPorts.count)", color: .orange)
            } else if host.scanned {
                Text("—").font(.caption2).foregroundStyle(.quaternary)
            } else {
                ProgressView().controlSize(.mini)
            }
        }
        .padding(.vertical, 3)
    }

    private var worstSeverity: Severity {
        host.findings
            .filter { $0.verified ?? true }
            .compactMap { Severity(rawValue: $0.severity) }
            .min(by: { $0.rank < $1.rank }) ?? .info
    }
}

// MARK: - Activity + helpers

struct ActivityView: View {
    @EnvironmentObject var controller: ScanController

    var body: some View {
        ScrollViewReader { proxy in
            List(controller.log) { line in
                HStack(alignment: .top, spacing: 8) {
                    Text(line.time, style: .time)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundStyle(.tertiary)
                    Text(line.text)
                        .font(.system(size: 11))
                        .foregroundStyle(color(for: line.kind))
                        .textSelection(.enabled)
                }
                .id(line.id)
            }
            .onChange(of: controller.log.count) { _ in
                if let last = controller.log.last { proxy.scrollTo(last.id) }
            }
        }
        .navigationTitle("Activity")
    }

    private func color(for kind: ScanController.LogLine.Kind) -> Color {
        switch kind {
        case .info: return .primary
        case .good: return .green
        case .warn: return Severity.medium.color
        case .bad: return Severity.high.color
        }
    }
}

struct EmptyDetail: View {
    let text: String
    var body: some View {
        VStack(spacing: 10) {
            Image(systemName: "network")
                .font(.system(size: 40))
                .foregroundStyle(.quaternary)
            Text(text)
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 300)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

struct ContentUnavailableFallback: View {
    let title: String
    let message: String
    var body: some View {
        VStack(spacing: 8) {
            Text(title).font(.headline)
            Text(message).font(.caption).foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .padding()
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(.background)
    }
}
