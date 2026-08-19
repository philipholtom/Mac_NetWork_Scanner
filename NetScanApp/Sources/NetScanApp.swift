import SwiftUI

@main
struct NetScanApp: App {
    @StateObject private var controller = ScanController()

    var body: some Scene {
        WindowGroup("Network Scanner") {
            ContentView()
                .environmentObject(controller)
                .frame(minWidth: 1040, minHeight: 620)
        }
        .defaultSize(width: 1280, height: 800)
        .commands {
            CommandGroup(replacing: .newItem) { }
            CommandMenu("Scan") {
                Button(controller.isScanning ? "Stop Scan" : "Start Scan") {
                    controller.isScanning ? controller.stopScan() : controller.startScan()
                }
                .keyboardShortcut("r", modifiers: .command)

                Divider()

                Button("Refresh This Mac") { controller.runSelfAudit() }
                    .keyboardShortcut("i", modifiers: [.command, .shift])
            }
        }
    }
}
