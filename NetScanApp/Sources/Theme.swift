import SwiftUI

extension Severity {
    var color: Color {
        switch self {
        case .high: return Color(red: 0.85, green: 0.22, blue: 0.18)
        case .medium: return Color(red: 0.90, green: 0.58, blue: 0.10)
        case .low: return Color(red: 0.20, green: 0.50, blue: 0.85)
        case .info: return Color.secondary
        }
    }

    var symbol: String {
        switch self {
        case .high: return "exclamationmark.octagon.fill"
        case .medium: return "exclamationmark.triangle.fill"
        case .low: return "info.circle.fill"
        case .info: return "circle.fill"
        }
    }
}

/// Small coloured capsule used for risk and count badges.
struct Badge: View {
    let text: String
    var color: Color = .secondary
    var filled: Bool = false

    var body: some View {
        Text(text)
            .font(.system(size: 10, weight: .semibold))
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(filled ? color.opacity(0.9) : color.opacity(0.14), in: Capsule())
            .foregroundStyle(filled ? Color.white : color)
    }
}

/// Icon chosen from the device classification the engine produced.
func deviceIcon(for host: Host) -> String {
    let type = (host.deviceType ?? "").lowercased()
    let name = host.displayName.lowercased()
    let blob = type + " " + name

    if host.isGateway || blob.contains("router") || blob.contains("gateway") { return "wifi.router.fill" }
    if blob.contains("nas") || blob.contains("file server") { return "externaldrive.connected.to.line.below.fill" }
    if blob.contains("printer") { return "printer.fill" }
    if blob.contains("scanner") { return "scanner.fill" }
    if blob.contains("camera") { return "video.fill" }
    if blob.contains("apple tv") || blob.contains("streaming") { return "appletv.fill" }
    if blob.contains("iphone") { return "iphone" }
    if blob.contains("ipad") { return "ipad" }
    if blob.contains("watch") { return "applewatch" }
    if blob.contains("mac") { return "desktopcomputer" }
    if blob.contains("homepod") || blob.contains("speaker") || blob.contains("sonos") { return "hifispeaker.fill" }
    if blob.contains("tv") { return "tv.fill" }
    if blob.contains("echo") || blob.contains("alexa") { return "homepod.mini.fill" }
    if blob.contains("google") || blob.contains("nest") || blob.contains("chromecast") { return "homepodmini.fill" }
    if blob.contains("light") { return "lightbulb.fill" }
    if blob.contains("thermostat") { return "thermometer.medium" }
    if blob.contains("xbox") || blob.contains("playstation") || blob.contains("nintendo") { return "gamecontroller.fill" }
    if blob.contains("raspberry") || blob.contains("iot") || blob.contains("smart-home") { return "cpu.fill" }
    if blob.contains("windows") { return "pc" }
    if blob.contains("linux") || blob.contains("server") { return "server.rack" }
    if blob.contains("virtual") || blob.contains("hypervisor") { return "cube.transparent" }
    if blob.contains("switch") { return "point.3.connected.trianglepath.dotted" }
    if blob.contains("ev charger") || blob.contains("tesla") { return "bolt.car.fill" }
    return "network"
}

/// A pill showing a labelled statistic.
struct StatTile: View {
    let value: String
    let label: String
    var color: Color = .primary

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(value)
                .font(.system(size: 22, weight: .semibold, design: .rounded))
                .foregroundStyle(color)
                .contentTransition(.numericText())
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.vertical, 10)
        .padding(.horizontal, 12)
        .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 8))
    }
}

struct DetailRow: View {
    let label: String
    let value: String
    var mono: Bool = false
    var copyable: Bool = true

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
                .frame(width: 108, alignment: .trailing)
            Text(value)
                .font(mono ? .system(size: 12, design: .monospaced) : .system(size: 12))
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}
