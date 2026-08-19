import SwiftUI

struct HostDetailView: View {
    let host: Host

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                header
                if !host.findings.isEmpty { findingsSection }
                identitySection
                if !host.allPorts.isEmpty { portsSection }
                if !host.bonjour.isEmpty { bonjourSection }
                if !host.ssdp.isEmpty { upnpSection }
            }
            .padding(18)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .navigationTitle(host.shortName)
    }

    private var header: some View {
        HStack(spacing: 14) {
            Image(systemName: deviceIcon(for: host))
                .font(.system(size: 30))
                .foregroundStyle(.tint)
                .frame(width: 44)

            VStack(alignment: .leading, spacing: 3) {
                Text(host.displayName).font(.title2).bold().textSelection(.enabled)
                HStack(spacing: 8) {
                    Text(host.ip)
                        .font(.system(size: 13, design: .monospaced))
                        .textSelection(.enabled)
                    if let type = host.deviceType {
                        Badge(text: type, color: .blue)
                    }
                    if host.isSelf { Badge(text: "this Mac") }
                    if host.isGateway { Badge(text: "gateway", color: .blue) }
                }
                if let rtt = host.rttMs {
                    Text(String(format: "responds in %.1f ms", rtt))
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            Spacer()

            if let primary = PortActions.primaryForHost(host) {
                Button {
                    primary.perform()
                } label: {
                    Label(primary.title, systemImage: primary.systemImage)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .help(primary.menuTitle)
            }
        }
    }

    private var findingsSection: some View {
        Section {
            VStack(alignment: .leading, spacing: 6) {
                ForEach(sortedFindings) { finding in
                    let severity = Severity(rawValue: finding.severity) ?? .info
                    HStack(alignment: .top, spacing: 8) {
                        Image(systemName: severity.symbol)
                            .foregroundStyle(severity.color)
                            .font(.system(size: 11))
                            .padding(.top, 2)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(finding.message)
                                .font(.system(size: 12))
                                .fixedSize(horizontal: false, vertical: true)
                            HStack(spacing: 6) {
                                if let port = finding.port {
                                    Text("port \(port)").font(.caption2).foregroundStyle(.secondary)
                                }
                                if !(finding.verified ?? true) {
                                    Badge(text: "unconfirmed")
                                }
                            }
                        }
                        Spacer()
                    }
                    .padding(8)
                    .background(severity.color.opacity(0.08), in: RoundedRectangle(cornerRadius: 6))
                }
            }
        } header: {
            sectionTitle("Security notes", count: host.findings.count)
        }
    }

    private var sortedFindings: [Finding] {
        host.findings.sorted {
            let a = (Severity(rawValue: $0.severity)?.rank ?? 3, $0.verified ?? true ? 0 : 1)
            let b = (Severity(rawValue: $1.severity)?.rank ?? 3, $1.verified ?? true ? 0 : 1)
            return a < b
        }
    }

    private var identitySection: some View {
        Section {
            VStack(alignment: .leading, spacing: 4) {
                if let mac = host.mac { DetailRow(label: "MAC", value: mac, mono: true) }
                if let vendor = host.vendor { DetailRow(label: "Vendor", value: vendor) }
                if let model = host.model { DetailRow(label: "Model", value: model) }
                if let network = host.network { DetailRow(label: "Network", value: network, mono: true) }
                if let workgroup = host.workgroup { DetailRow(label: "Workgroup", value: workgroup) }
                if let netbios = host.netbiosName { DetailRow(label: "NetBIOS", value: netbios) }
                if host.names.count > 0 {
                    DetailRow(label: "Names", value: host.names.joined(separator: ", "))
                }
                if !host.discovery.isEmpty {
                    DetailRow(label: "Seen via", value: host.discovery.joined(separator: ", "))
                }
            }
        } header: {
            sectionTitle("Identity")
        }
    }

    private var portsSection: some View {
        Section {
            VStack(spacing: 0) {
                ForEach(host.allPorts) { port in
                    PortRowView(port: port, ip: host.ip)
                    if port.id != host.allPorts.last?.id { Divider() }
                }
            }
            .background(.quaternary.opacity(0.25), in: RoundedRectangle(cornerRadius: 8))
        } header: {
            HStack(spacing: 6) {
                sectionTitle("Open ports", count: host.allPorts.count)
                Text("double-click to open · right-click for more")
                    .font(.system(size: 9))
                    .foregroundStyle(.tertiary)
            }
        }
    }

    private var bonjourSection: some View {
        Section {
            VStack(alignment: .leading, spacing: 5) {
                ForEach(host.bonjour.sorted(by: { $0.key < $1.key }), id: \.key) { key, service in
                    HStack(alignment: .top, spacing: 8) {
                        Text(service.label ?? key)
                            .font(.system(size: 12, weight: .medium))
                            .frame(width: 150, alignment: .leading)
                        VStack(alignment: .leading, spacing: 1) {
                            if let instance = service.instance {
                                Text(instance).font(.system(size: 12)).textSelection(.enabled)
                            }
                            if let txt = service.txt, !txt.isEmpty {
                                Text(txt.sorted(by: { $0.key < $1.key })
                                        .prefix(6)
                                        .map { "\($0.key)=\($0.value)" }
                                        .joined(separator: "  "))
                                    .font(.system(size: 10, design: .monospaced))
                                    .foregroundStyle(.secondary)
                                    .lineLimit(3)
                            }
                        }
                        Spacer()
                        if let port = service.port, port > 0 {
                            Text(":\(port)").font(.system(size: 11, design: .monospaced))
                                .foregroundStyle(.tertiary)
                        }
                    }
                }
            }
        } header: {
            sectionTitle("Bonjour services", count: host.bonjour.count)
        }
    }

    private var upnpSection: some View {
        Section {
            VStack(alignment: .leading, spacing: 4) {
                ForEach(host.ssdp.sorted(by: { $0.key < $1.key }).filter { !$0.key.hasPrefix("_") },
                        id: \.key) { key, value in
                    DetailRow(label: key, value: value)
                }
            }
        } header: {
            sectionTitle("UPnP / SSDP")
        }
    }

    private func sectionTitle(_ text: String, count: Int? = nil) -> some View {
        HStack(spacing: 6) {
            Text(text.uppercased())
                .font(.system(size: 10, weight: .semibold))
                .foregroundStyle(.secondary)
            if let count = count { Badge(text: "\(count)") }
            Spacer()
        }
        .padding(.top, 4)
    }
}

struct PortRowView: View {
    let port: Port
    let ip: String

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Text("\(port.port)")
                .font(.system(size: 13, weight: .semibold, design: .monospaced))
                .frame(width: 52, alignment: .trailing)
                .foregroundStyle(severityColor)

            Text(port.proto.uppercased())
                .font(.system(size: 9, weight: .medium))
                .foregroundStyle(.tertiary)
                .frame(width: 26, alignment: .leading)
                .padding(.top, 3)

            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(port.displayName)
                        .font(.system(size: 12, weight: .medium))
                    if !port.identified {
                        Badge(text: "not identified")
                    }
                }
                if !port.detail.isEmpty {
                    Text(port.detail)
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                        .textSelection(.enabled)
                }
                if let description = port.description, port.detail != description {
                    Text(description)
                        .font(.system(size: 10))
                        .foregroundStyle(.tertiary)
                }
            }

            Spacer(minLength: 4)

            if let primary = primaryAction {
                Button {
                    primary.perform()
                } label: {
                    Image(systemName: primary.systemImage)
                }
                .buttonStyle(.plain)
                .foregroundStyle(.tint)
                .help(primary.menuTitle)
            }

            Menu {
                ForEach(allActions) { action in
                    Button(action.menuTitle) { action.perform() }
                }
            } label: {
                Image(systemName: "ellipsis.circle")
            }
            .menuStyle(.borderlessButton)
            .menuIndicator(.hidden)
            .frame(width: 20)
            .opacity(0.55)
            .help("More actions")
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 7)
        .contentShape(Rectangle())
        .onTapGesture(count: 2) { primaryAction?.perform() }
        .contextMenu {
            ForEach(allActions) { action in
                Button(action.menuTitle) { action.perform() }
            }
        }
    }

    private var allActions: [PortAction] { PortActions.actions(for: port, ip: ip) }
    private var primaryAction: PortAction? { PortActions.primary(for: port, ip: ip) }

    private var severityColor: Color {
        guard port.identified, let severity = port.severity,
              let level = Severity(rawValue: severity), level.rank <= 1 else {
            return .primary
        }
        return level.color
    }
}
