// Draws the app icon and packs it into an .icns file.
// Usage: swift scripts/make_icon.swift macos/AppIcon.icns [preview.png]
import AppKit

let sRGB = CGColorSpace(name: CGColorSpace.sRGB)!

func color(_ r: CGFloat, _ g: CGFloat, _ b: CGFloat, _ a: CGFloat = 1) -> CGColor {
    CGColor(colorSpace: sRGB, components: [r, g, b, a])!
}

func gradient(_ colors: [CGColor]) -> CGGradient {
    CGGradient(colorsSpace: sRGB, colors: colors as CFArray, locations: nil)!
}

func stroke(_ path: CGPath, width: CGFloat) -> CGPath {
    path.copy(strokingWithWidth: width, lineCap: .round, lineJoin: .round, miterLimit: 10)
}

// Coordinates are on Apple's 1024 px icon grid: an 824 px body with 100 px margins.
func drawIcon(in ctx: CGContext) {
    let body = CGRect(x: 100, y: 100, width: 824, height: 824)
    let shape = CGPath(roundedRect: body, cornerWidth: 185, cornerHeight: 185, transform: nil)

    ctx.saveGState()
    ctx.setShadow(offset: CGSize(width: 0, height: -8), blur: 20, color: color(0, 0, 0, 0.3))
    ctx.addPath(shape)
    ctx.setFillColor(color(0.1, 0.4, 0.95))
    ctx.fillPath()
    ctx.restoreGState()

    ctx.saveGState()
    ctx.addPath(shape)
    ctx.clip()
    ctx.drawLinearGradient(gradient([color(0.29, 0.78, 1.0), color(0.1, 0.38, 0.96), color(0.2, 0.2, 0.78)]),
                           start: CGPoint(x: 300, y: 924), end: CGPoint(x: 724, y: 100),
                           options: [.drawsBeforeStartLocation, .drawsAfterEndLocation])
    ctx.drawRadialGradient(gradient([color(1, 1, 1, 0.28), color(1, 1, 1, 0)]),
                           startCenter: CGPoint(x: 330, y: 900), startRadius: 0,
                           endCenter: CGPoint(x: 330, y: 900), endRadius: 560, options: [])
    ctx.restoreGState()

    // The wall: two frosted segments with a gap in the middle.
    for segment in [CGRect(x: 462, y: 616, width: 84, height: 200), CGRect(x: 462, y: 208, width: 84, height: 200)] {
        let path = CGPath(roundedRect: segment, cornerWidth: 42, cornerHeight: 42, transform: nil)
        ctx.addPath(path)
        ctx.setFillColor(color(1, 1, 1, 0.4))
        ctx.fillPath()
        ctx.addPath(stroke(path, width: 4))
        ctx.setFillColor(color(1, 1, 1, 0.5))
        ctx.fillPath()
    }

    // The arrow passing through the gap.
    let arrow = CGMutablePath()
    arrow.move(to: CGPoint(x: 240, y: 512))
    arrow.addLine(to: CGPoint(x: 770, y: 512))
    arrow.move(to: CGPoint(x: 640, y: 642))
    arrow.addLine(to: CGPoint(x: 770, y: 512))
    arrow.addLine(to: CGPoint(x: 640, y: 382))

    ctx.saveGState()
    ctx.setShadow(offset: CGSize(width: 0, height: -14), blur: 34, color: color(0.02, 0.1, 0.4, 0.45))
    ctx.addPath(stroke(arrow, width: 96))
    ctx.setFillColor(.white)
    ctx.fillPath()
    ctx.restoreGState()

    ctx.saveGState()
    ctx.addPath(shape)
    ctx.clip()
    ctx.addPath(stroke(shape, width: 8))
    ctx.clip()
    ctx.drawLinearGradient(gradient([color(1, 1, 1, 0.6), color(1, 1, 1, 0.08)]),
                           start: CGPoint(x: 512, y: 924), end: CGPoint(x: 512, y: 100), options: [])
    ctx.restoreGState()
}

func png(size: Int) -> Data {
    let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: size, pixelsHigh: size, bitsPerSample: 8,
                               samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB,
                               bytesPerRow: 0, bitsPerPixel: 0)!
    let ctx = NSGraphicsContext(bitmapImageRep: rep)!.cgContext
    ctx.scaleBy(x: CGFloat(size) / 1024, y: CGFloat(size) / 1024)
    drawIcon(in: ctx)
    return rep.representation(using: .png, properties: [:])!
}

let arguments = CommandLine.arguments
guard arguments.count >= 2 else {
    print("usage: swift scripts/make_icon.swift <output.icns> [preview.png]")
    exit(2)
}

let iconset = FileManager.default.temporaryDirectory.appendingPathComponent("AppIcon.iconset")
try? FileManager.default.removeItem(at: iconset)
try FileManager.default.createDirectory(at: iconset, withIntermediateDirectories: true)
for size in [16, 32, 128, 256, 512] {
    try png(size: size).write(to: iconset.appendingPathComponent("icon_\(size)x\(size).png"))
    try png(size: size * 2).write(to: iconset.appendingPathComponent("icon_\(size)x\(size)@2x.png"))
}
if arguments.count >= 3 {
    try png(size: 1024).write(to: URL(fileURLWithPath: arguments[2]))
}

let iconutil = Process()
iconutil.executableURL = URL(fileURLWithPath: "/usr/bin/iconutil")
iconutil.arguments = ["-c", "icns", iconset.path, "-o", arguments[1]]
try iconutil.run()
iconutil.waitUntilExit()
try? FileManager.default.removeItem(at: iconset)
exit(iconutil.terminationStatus)
