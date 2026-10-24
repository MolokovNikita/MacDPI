import AppKit
import SwiftUI

@main
struct MacDPIApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var model = AppModel()

    var body: some Scene {
        WindowGroup("MacDPI") {
            ContentView(model: model)
                .onAppear {
                    AppDelegate.model = model
                    NSApp.setActivationPolicy(.regular)
                    NSApp.activate(ignoringOtherApps: true)
                }
        }
        .defaultSize(width: 420, height: 640)
        .windowStyle(.hiddenTitleBar)

        MenuBarExtra {
            Text(model.status)
            Button(model.active ? "Отключить" : "Подключить") {
                model.toggle()
            }
            .disabled(model.busy)
            Divider()
            Button("Завершить MacDPI") {
                NSApp.terminate(nil)
            }
        } label: {
            Image(nsImage: .menuBarIcon(active: model.active))
        }
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    static weak var model: AppModel?

    func applicationWillTerminate(_ notification: Notification) {
        MainActor.assumeIsolated {
            Self.model?.stopBeforeQuit()
        }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }
}

extension NSImage {
    /// The app icon's mark (an arrow passing through a gap in a wall) as a menu bar template.
    static func menuBarIcon(active: Bool) -> NSImage {
        let image = NSImage(size: NSSize(width: 18, height: 18), flipped: false) { _ in
            NSColor.black.withAlphaComponent(active ? 1 : 0.45).set()
            NSBezierPath(roundedRect: NSRect(x: 8, y: 12, width: 2.4, height: 5), xRadius: 1.2, yRadius: 1.2).fill()
            NSBezierPath(roundedRect: NSRect(x: 8, y: 1, width: 2.4, height: 5), xRadius: 1.2, yRadius: 1.2).fill()

            let arrow = NSBezierPath()
            arrow.move(to: NSPoint(x: 2, y: 9))
            arrow.line(to: NSPoint(x: 15.5, y: 9))
            arrow.move(to: NSPoint(x: 12, y: 12.5))
            arrow.line(to: NSPoint(x: 15.5, y: 9))
            arrow.line(to: NSPoint(x: 12, y: 5.5))
            arrow.lineWidth = 2
            arrow.lineCapStyle = .round
            arrow.lineJoinStyle = .round
            arrow.stroke()
            return true
        }
        image.isTemplate = true
        return image
    }
}
