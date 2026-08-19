import SwiftUI

struct SelfAuditView: View {
    @EnvironmentObject var controller: ScanController

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                if let audit = controller.selfAudit {
                    systemCard(audit)
                    firewallCard(audit)
                    interfacesCard(audit)
                    socketsCard(audit)
                } else {
                    ProgressView("Inspecting this Mac…")
                        .frame(maxWidth: .infinity, minHeight: 200)
                }
            }
            .padding(16)
        }
        .navigationTitle("This Mac")
        .toolbar {
            Button {
                controller.runSelfAudit()
            } label: {
                Label("Refresh", systemImage: "arrow.clockwise")
            }
            .disabled(controller.isAuditing)
        }
    }

    private func systemCard(_ audit: SelfAudit) -> some View {
        card("System") {
            VStack(alignment: .leading, spacing: 3) {
                ForEach((audit.system ?? [:]).sorted(by: { $0.key < $1.key }), id: \.key) { key, value in
                    DetailRow(label: key.replacingOccurrences(of: "_", with: " ").capitalized,
                              value: value)
                }
                if let dns = audit.dns, !dns.isEmpty {
                    DetailRow(label: "DNS servers", value: dns.joined(separator: ", "), mono: true)
                }
                if let ssid = audit.wifi?["ssid"] {
                    DetailRow(label: "Wi-Fi", value: ssid)
                }
            }
        }
    }

    private func firewallCard(_ audit: SelfAudit) -> some View {
        card("Firewall & sharing") {
            VStack(alignment: .leading, spacing: 6) {
                HStack(spacing: 8) {
                    let on = audit.firewall?.enabled ?? false
                    Image(systemName: on ? "checkmark.shield.fill" : "xmark.shield.fill")
                        .foregroundStyle(on ? Color.green : Severity.high.color)
                    Text(on ? "Application firewall is on" : "Application firewall is OFF")
                        .font(.system(size: 12, weight: .medium))
                    if audit.firewall?.stealthMode == true { Badge(text: "stealth", color: .green) }
                }
                ForEach((audit.sharing ?? [:]).sorted(by: { $0.key < $1.key }), id: \.key) { name, enabled in
                    HStack(spacing: 8) {
                        Image(systemName: enabled ? "dot.radiowaves.left.and.right" : "minus.circle")
                            .foregroundStyle(enabled ? Severity.medium.color : Color.secondary)
                            .font(.system(size: 11))
                        Text(name).font(.system(size: 12))
                        Spacer()
                        Text(enabled ? "on" : "off")
                            .font(.caption)
                            .foregroundStyle(enabled ? Severity.medium.color : .secondary)
                    }
                }
            }
        }
    }

    private func interfacesCard(_ audit: SelfAudit) -> some View {
        card("Interfaces") {
            VStack(alignment: .leading, spacing: 8) {
                ForEach((audit.interfaces ?? []).filter { $0.ipv4 != nil }) { iface in
                    VStack(alignment: .leading, spacing: 2) {
                        HStack(spacing: 6) {
                            Text(iface.name).font(.system(size: 12, weight: .semibold, design: .monospaced))
                            Badge(text: iface.kind ?? "", color: .blue)
                            if let ssid = iface.ssid { Text(ssid).font(.caption) }
                            Spacer()
                            Text(iface.ipv4 ?? "").font(.system(size: 12, design: .monospaced))
                        }
                        HStack(spacing: 10) {
                            if let cidr = iface.cidr {
                                Text(cidr).font(.caption2).foregroundStyle(.secondary)
                            }
                            if let gw = iface.gateway {
                                Text("gateway \(gw)").font(.caption2).foregroundStyle(.secondary)
                            }
                            if let mac = iface.mac {
                                Text(mac).font(.system(size: 10, design: .monospaced))
                                    .foregroundStyle(.tertiary)
                            }
                        }
                    }
                }
            }
        }
    }

    private func socketsCard(_ audit: SelfAudit) -> some View {
        let sockets = audit.sockets ?? []
        let exposed = sockets.filter { $0.exposed }
        let local = sockets.filter { !$0.exposed }
        return card("Listening services (\(exposed.count) reachable from the network)") {
            VStack(alignment: .leading, spacing: 0) {
                ForEach(exposed) { socket in
                    socketRow(socket, exposed: true)
                    Divider()
                }
                if !local.isEmpty {
                    Text("\(local.count) more listen on loopback only (not reachable from the network)")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .padding(.top, 8)
                }
            }
        }
    }

    private func socketRow(_ socket: ListeningSocket, exposed: Bool) -> some View {
        HStack(spacing: 10) {
            Text("\(socket.port)")
                .font(.system(size: 12, weight: .semibold, design: .monospaced))
                .frame(width: 52, alignment: .trailing)
            Text(socket.proto.uppercased())
                .font(.system(size: 9))
                .foregroundStyle(.tertiary)
                .frame(width: 26, alignment: .leading)
            Text(socket.cleanProcess)
                .font(.system(size: 12))
                .lineLimit(1)
            Spacer()
            Text(socket.user ?? "")
                .font(.caption2).foregroundStyle(.secondary)
            Text(socket.scope)
                .font(.caption2)
                .foregroundStyle(exposed ? Severity.medium.color : .secondary)
        }
        .padding(.vertical, 5)
    }

    private func card<Content: View>(_ title: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title.uppercased())
                .font(.system(size: 10, weight: .semibold))
                .foregroundStyle(.secondary)
            content()
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.quaternary.opacity(0.25), in: RoundedRectangle(cornerRadius: 8))
    }
}
