import AppKit
import Foundation

private struct LayoutFailure: Error { let message: String }

@main struct BodyTextLayoutSmoke {
    @MainActor static func main() throws {
        _ = NSApplication.shared
        let scroll = LensBodyScrollView(frame: NSRect(x: 0, y: 0, width: 440, height: 260))
        let text = NSTextView(frame: scroll.contentView.bounds)
        text.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
        text.isVerticallyResizable = true
        text.isHorizontallyResizable = false
        text.autoresizingMask = [.width]
        text.textContainerInset = NSSize(width: 0, height: 6)
        text.textContainer?.widthTracksTextView = true
        text.textContainer?.containerSize = NSSize(width: 440, height: CGFloat.greatestFiniteMagnitude)
        text.string = "{\n  \"message\": \"" + String(repeating: "Every visible character must fit. ", count: 30) + "\"\n}"
        scroll.documentView = text
        let ruler = NSRulerView(scrollView: scroll, orientation: .verticalRuler)
        ruler.ruleThickness = 48
        scroll.verticalRulerView = ruler
        scroll.hasVerticalRuler = true
        scroll.rulersVisible = true
        scroll.hasVerticalScroller = true
        for width in [440.0, 290.0, 570.0] {
            scroll.setFrameSize(NSSize(width: width, height: 260))
            scroll.tile()
            guard let layout = text.layoutManager, let container = text.textContainer else {
                throw LayoutFailure(message: "TextKit owner is missing")
            }
            layout.ensureLayout(for: container)
            let used = layout.usedRect(for: container)
            let viewport = scroll.contentView.bounds.width
            guard used.maxX <= viewport + 0.5, text.frame.width <= viewport + 0.5 else {
                throw LayoutFailure(message: "Wrapped text is clipped after ruler/viewport resize: \(used.maxX) > \(viewport)")
            }
            guard layout.numberOfGlyphs == (text.string as NSString).length else {
                throw LayoutFailure(message: "Layout omitted captured text")
            }
        }
        print("PASS: wrapped body glyphs fit the actual viewport with a ruler and after narrow/wide resize")
    }
}
