import AppKit
import SwiftUI

// Keep large previews out of SwiftUI's whole-string intrinsic-size measurement.
// TextKit lays out the visible viewport and retains the full formatted preview
// for selection and copying; it does not change capture or formatter limits.
struct LensBodyTextView: NSViewRepresentable {
    let text: String
    let title: String

    final class Coordinator {
        var displayed: String?
    }

    func makeCoordinator() -> Coordinator { Coordinator() }

    func makeNSView(context: Context) -> NSScrollView {
        let scroll = NSScrollView()
        scroll.hasVerticalScroller = true
        scroll.autohidesScrollers = true
        scroll.drawsBackground = false
        let view = NSTextView(frame: .zero)
        view.isEditable = false
        view.isSelectable = true
        view.isRichText = false
        view.drawsBackground = false
        view.font = .monospacedSystemFont(ofSize: NSFont.smallSystemFontSize, weight: .regular)
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
        return scroll
    }

    func updateNSView(_ scroll: NSScrollView, context: Context) {
        guard let view = scroll.documentView as? NSTextView else { return }
        view.setAccessibilityLabel("\(title) body")
        guard context.coordinator.displayed != text else { return }
        context.coordinator.displayed = text
        view.string = text
        view.scrollToBeginningOfDocument(nil)
    }
}
