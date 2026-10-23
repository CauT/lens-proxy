import AppKit
import SwiftUI

// Rulers and scrollers change the clip viewport after representable updates.
// Own the wrapped document width here, after AppKit has tiled those controls.
final class LensBodyScrollView: NSScrollView {
    var wrapsLines = true
    override func tile() {
        super.tile()
        guard wrapsLines, let text = documentView as? NSTextView else { return }
        let width = max(contentView.bounds.width, 1)
        if abs(text.frame.width - width) > 0.5 {
            text.setFrameSize(NSSize(width: width, height: max(text.frame.height, contentView.bounds.height)))
        }
        let containerWidth = max(width - text.textContainerInset.width * 2, 1)
        if let container = text.textContainer, abs(container.containerSize.width - containerWidth) > 0.5 {
            container.containerSize = NSSize(width: containerWidth, height: CGFloat.greatestFiniteMagnitude)
        }
    }
}

// Keep large previews out of SwiftUI's whole-string intrinsic-size measurement.
// TextKit lays out the visible viewport and retains the full formatted preview
// for selection and copying; it does not change capture or formatter limits.
struct LensBodyTextView: NSViewRepresentable {
    let text: String
    let title: String
    var syntax: [JSONSyntaxSpan] = []
    var syntaxID: UUID? = nil
    var selectedRange: NSRange? = nil
    var wrapLines = true
    var lineNumbers = false

    final class Coordinator: NSObject {
        var displayed: String?
        var syntaxID: UUID?
        var selection: NSRange?
        var wrap = true
        var spans: [JSONSyntaxSpan] = []
        weak var view: NSTextView?
        weak var scroll: NSScrollView?
        var observer: NSObjectProtocol?
        var coloredRange = NSRange(location: 0, length: 0)
        func stop() { if let observer { NotificationCenter.default.removeObserver(observer) }; observer = nil }
        deinit { stop() }
        func highlight() {
            guard let view, let layout = view.layoutManager, let container = view.textContainer else { return }
            if coloredRange.length > 0 { layout.removeTemporaryAttribute(.foregroundColor, forCharacterRange: coloredRange) }
            guard !spans.isEmpty else { return }
            let origin = view.textContainerOrigin
            let glyphs = layout.glyphRange(forBoundingRect: view.visibleRect.offsetBy(dx: -origin.x, dy: -origin.y), in: container)
            let range = layout.characterRange(forGlyphRange: glyphs, actualGlyphRange: nil)
            coloredRange = range
            var low = 0, high = spans.count
            while low < high {
                let middle = (low + high) / 2
                if NSMaxRange(spans[middle].range) <= range.location { low = middle + 1 } else { high = middle }
            }
            while low < spans.count, spans[low].range.location < NSMaxRange(range) {
                let span = spans[low], visible = NSIntersectionRange(span.range, range)
                if visible.length > 0 { layout.addTemporaryAttribute(.foregroundColor, value: jsonSyntaxColor(span.kind), forCharacterRange: visible) }
                low += 1
            }
            scroll?.verticalRulerView?.needsDisplay = true
        }
    }

    func makeCoordinator() -> Coordinator { Coordinator() }

    func makeNSView(context: Context) -> NSScrollView {
        let scroll = LensBodyScrollView()
        scroll.hasVerticalScroller = true
        scroll.autohidesScrollers = true
        scroll.drawsBackground = false
        let view = NSTextView(frame: .zero)
        view.isEditable = false
        view.isSelectable = true
        view.isRichText = false
        view.drawsBackground = false
        view.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
        view.textColor = .labelColor
        view.textContainerInset = NSSize(width: 0, height: 6)
        view.isVerticallyResizable = true
        view.isHorizontallyResizable = false
        view.autoresizingMask = [.width]
        view.maxSize = NSSize(width: CGFloat.greatestFiniteMagnitude, height: CGFloat.greatestFiniteMagnitude)
        view.textContainer?.widthTracksTextView = true
        view.textContainer?.containerSize = NSSize(width: 0, height: CGFloat.greatestFiniteMagnitude)
        view.layoutManager?.allowsNonContiguousLayout = true
        scroll.documentView = view
        context.coordinator.view = view; context.coordinator.scroll = scroll
        scroll.contentView.postsBoundsChangedNotifications = true
        context.coordinator.observer = NotificationCenter.default.addObserver(forName: NSView.boundsDidChangeNotification,
            object: scroll.contentView, queue: .main) { [weak coordinator = context.coordinator] _ in coordinator?.highlight() }
        return scroll
    }

    func updateNSView(_ scroll: NSScrollView, context: Context) {
        guard let view = scroll.documentView as? NSTextView else { return }
        (scroll as? LensBodyScrollView)?.wrapsLines = wrapLines
        view.setAccessibilityLabel("\(title) body")
        let coordinator = context.coordinator
        if coordinator.displayed != text || coordinator.syntaxID != syntaxID || coordinator.wrap != wrapLines {
            if coordinator.coloredRange.length > 0, coordinator.coloredRange.location + coordinator.coloredRange.length <= view.string.utf16.count {
                view.layoutManager?.removeTemporaryAttribute(.foregroundColor, forCharacterRange: coordinator.coloredRange)
            }
            coordinator.coloredRange = NSRange(location: 0, length: 0)
            coordinator.displayed = text; coordinator.syntaxID = syntaxID; coordinator.wrap = wrapLines; coordinator.spans = syntax
            view.isHorizontallyResizable = !wrapLines; scroll.hasHorizontalScroller = !wrapLines
            view.textContainer?.widthTracksTextView = wrapLines
            view.textContainer?.containerSize = NSSize(width: wrapLines ? max(scroll.contentSize.width, 1) : CGFloat.greatestFiniteMagnitude, height: CGFloat.greatestFiniteMagnitude)
            view.string = text
            if lineNumbers {
                scroll.hasVerticalRuler = true
                scroll.verticalRulerView = JSONLineRuler(text: view, scroll: scroll, source: text)
                scroll.rulersVisible = true
            }
            view.scrollToBeginningOfDocument(nil)
        }
        if coordinator.selection != selectedRange {
            coordinator.selection = selectedRange
            if let selectedRange, NSMaxRange(selectedRange) <= text.utf16.count {
                view.setSelectedRange(selectedRange); view.scrollRangeToVisible(selectedRange)
            }
        }
        scroll.tile()
        coordinator.highlight()
    }
    static func dismantleNSView(_ scroll: NSScrollView, coordinator: Coordinator) { coordinator.stop() }
}

func jsonSyntaxColor(_ kind: JSONSyntaxKind) -> NSColor {
    switch kind {
    case .key: return .systemBlue
    case .string: return .systemGreen
    case .number: return .systemTeal
    case .boolean: return .systemPurple
    case .null: return .secondaryLabelColor
    case .punctuation: return .labelColor
    }
}

private final class JSONLineRuler: NSRulerView {
    weak var text: NSTextView?
    let starts: [Int]
    init(text: NSTextView, scroll: NSScrollView, source: String) {
        self.text = text
        var starts = [0]
        for (offset, value) in source.utf16.enumerated() where value == 10 { starts.append(offset + 1) }
        self.starts = starts
        super.init(scrollView: scroll, orientation: .verticalRuler)
        clientView = text; ruleThickness = 48
    }
    required init(coder: NSCoder) { fatalError("init(coder:) is unsupported") }
    override func drawHashMarksAndLabels(in rect: NSRect) {
        NSColor.windowBackgroundColor.setFill(); NSBezierPath(rect: bounds).fill()
        guard let text, let layout = text.layoutManager, let container = text.textContainer else { return }
        let origin = text.textContainerOrigin
        let glyphs = layout.glyphRange(forBoundingRect: text.visibleRect.offsetBy(dx: -origin.x, dy: -origin.y), in: container)
        let attributes: [NSAttributedString.Key: Any] = [.font: NSFont.monospacedDigitSystemFont(ofSize: 10, weight: .regular), .foregroundColor: NSColor.secondaryLabelColor]
        layout.enumerateLineFragments(forGlyphRange: glyphs) { _, used, _, range, _ in
            let offset = layout.characterIndexForGlyph(at: range.location)
            var low = 0, high = self.starts.count
            while low < high { let mid = (low + high) / 2; if self.starts[mid] <= offset { low = mid + 1 } else { high = mid } }
            let line = max(low - 1, 0)
            guard self.starts[line] == offset else { return }
            let label = String(line + 1) as NSString, size = label.size(withAttributes: attributes)
            let point = self.convert(NSPoint(x: 0, y: used.minY + origin.y), from: text)
            label.draw(at: NSPoint(x: self.ruleThickness - size.width - 8, y: point.y), withAttributes: attributes)
        }
    }
}
