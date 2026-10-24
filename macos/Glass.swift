import AppKit
import SwiftUI

// NSGlassEffectView ships with macOS 26. It is created by name so the app still builds
// against older SDKs; on macOS 13–15 a regular blur material is used instead.
private let glassViewClass = NSClassFromString("NSGlassEffectView") as? NSView.Type

private struct GlassView: NSViewRepresentable {
    var cornerRadius: CGFloat
    var tint: Color?
    var clear: Bool

    func makeNSView(context: Context) -> NSView {
        if let glassViewClass {
            return glassViewClass.init(frame: .zero)
        }
        let view = NSVisualEffectView()
        view.material = .popover
        view.blendingMode = .withinWindow
        view.state = .active
        view.wantsLayer = true
        view.layer?.masksToBounds = true
        view.layer?.cornerCurve = .continuous
        return view
    }

    func updateNSView(_ view: NSView, context: Context) {
        guard glassViewClass != nil else {
            view.layer?.cornerRadius = cornerRadius
            view.layer?.backgroundColor = tint.map { NSColor($0).cgColor }
            return
        }
        view.setValue(cornerRadius, forKey: "cornerRadius")
        view.setValue(tint.map { NSColor($0) }, forKey: "tintColor")
        view.setValue(clear ? 1 : 0, forKey: "style")
    }
}

extension View {
    func glass(cornerRadius: CGFloat, tint: Color? = nil, clear: Bool = false) -> some View {
        background(GlassView(cornerRadius: cornerRadius, tint: tint, clear: clear))
    }
}

/// Makes the window see-through and fills it with a blurred view of the desktop.
struct WindowBackground: NSViewRepresentable {
    final class BackdropView: NSVisualEffectView {
        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            window?.isOpaque = false
            window?.backgroundColor = .clear
        }
    }

    func makeNSView(context: Context) -> NSView {
        let view = BackdropView()
        view.material = .underWindowBackground
        view.blendingMode = .behindWindow
        view.state = .followsWindowActiveState
        return view
    }

    func updateNSView(_ view: NSView, context: Context) {}
}

extension Color {
    /// The app's own blue, matching the icon, so it does not turn grey with a Graphite accent.
    static let appTint = Color(nsColor: .systemBlue)

    /// Fill for grouped rows, like the cells of an inset grouped list on iOS.
    static let groupedRow = Color(nsColor: NSColor(name: nil) { appearance in
        appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
            ? NSColor(white: 1, alpha: 0.07)
            : NSColor(white: 1, alpha: 0.62)
    })
}
