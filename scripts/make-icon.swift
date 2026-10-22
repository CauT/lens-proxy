import AppKit
import Foundation

let directory = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
for obsolete in ["icon_64x64.png", "icon_64x64@2x.png"] {
    try? FileManager.default.removeItem(at: directory.appendingPathComponent(obsolete))
}
for size in [16, 32, 64, 128, 256, 512, 1024] {
    let image = NSImage(size: NSSize(width: size, height: size))
    image.lockFocus()
    let scale = CGFloat(size) / 1024
    let transform = NSAffineTransform(); transform.scale(by: scale); transform.concat()
    let rect = NSRect(x: 58, y: 58, width: 908, height: 908)
    let shape = NSBezierPath(roundedRect: rect, xRadius: 202, yRadius: 202)
    NSGradient(starting: NSColor(srgbRed: 0.13, green: 0.34, blue: 0.96, alpha: 1), ending: NSColor(srgbRed: 0.12, green: 0.08, blue: 0.39, alpha: 1))!.draw(in: shape, angle: -75)
    let ring = NSBezierPath(ovalIn: NSRect(x: 236, y: 280, width: 472, height: 472))
    NSColor.white.withAlphaComponent(0.95).setStroke(); ring.lineWidth = 66; ring.stroke()
    let handle = NSBezierPath(); handle.move(to: NSPoint(x: 666, y: 320)); handle.line(to: NSPoint(x: 806, y: 180)); handle.lineWidth = 72; handle.lineCapStyle = .round; handle.stroke()
    for (index, width) in [144.0, 230.0, 166.0].enumerated() {
        let bar = NSBezierPath(roundedRect: NSRect(x: 358, y: 600 - CGFloat(index) * 84, width: width, height: 30), xRadius: 15, yRadius: 15)
        NSColor.white.withAlphaComponent(0.92).setFill(); bar.fill()
    }
    NSColor(srgbRed: 0.35, green: 0.98, blue: 0.77, alpha: 1).setFill()
    NSBezierPath(ovalIn: NSRect(x: 720, y: 724, width: 102, height: 102)).fill()
    image.unlockFocus()
    let representation = NSBitmapImageRep(data: image.tiffRepresentation!)!
    let data = representation.representation(using: .png, properties: [:])!
    let filename: String
    if size == 1024 { filename = "icon_512x512@2x.png" }
    else { filename = "icon_\(size)x\(size).png" }
    if size != 64 { try data.write(to: directory.appendingPathComponent(filename)) }
    if size >= 32 && size <= 512 && size != 128 {
        try data.write(to: directory.appendingPathComponent("icon_\(size / 2)x\(size / 2)@2x.png"))
    }
}
