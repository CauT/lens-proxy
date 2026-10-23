import AppKit
import SwiftUI

private enum JSONReadingMode: String, CaseIterable { case tree = "Tree", pretty = "Pretty", source = "Source" }

struct LensJSONBodyView: View {
    let document: JSONDocument
    let title: String
    @State private var mode = JSONReadingMode.tree
    @State private var query = ""
    @State private var matches: [Int] = []
    @State private var matchIndex = 0
    @State private var selected: Int?
    @State private var expand = 0
    @State private var collapse = 0
    @State private var wrap = true
    @State private var copyStatus = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 9) {
            HStack {
                Picker("JSON view", selection: $mode) {
                    ForEach(JSONReadingMode.allCases, id: \.self) { Text($0.rawValue).tag($0) }
                }.pickerStyle(.segmented).frame(maxWidth: 230)
                Spacer(minLength: 4)
                if mode == .tree {
                    Button { expand += 1 } label: { Image(systemName: "plus.square.on.square") }.help("Expand all JSON containers").accessibilityLabel("Expand all JSON")
                    Button { collapse += 1 } label: { Image(systemName: "minus.square") }.help("Collapse JSON containers").accessibilityLabel("Collapse JSON")
                } else {
                    Toggle(isOn: $wrap) { Image(systemName: "text.word.spacing") }.toggleStyle(.button).help("Wrap JSON lines").accessibilityLabel("Wrap JSON lines")
                }
                Menu {
                    Button("Copy formatted JSON") { copy(document.formatted, "Copied formatted JSON") }
                    Button("Copy original JSON") { copy(document.source, "Copied original JSON") }
                    Divider()
                    Button("Copy selected value") { copyValue() }.disabled(selected == nil)
                    Button("Copy JSON Pointer") { copyPointer() }.disabled(selected == nil || selected.map(document.pointerIsAmbiguous) == true)
                } label: { Image(systemName: "doc.on.doc") }.menuStyle(.borderlessButton).fixedSize().help("Copy JSON").accessibilityLabel("Copy JSON")
            }.controlSize(.small)
            if mode != .source {
                HStack(spacing: 6) {
                    TextField("Find key or value", text: $query).textFieldStyle(.roundedBorder).accessibilityLabel("Search JSON keys and values")
                        .onChange(of: query) {
                            let bounded = String(String.UnicodeScalarView(query.unicodeScalars.prefix(256)))
                            if bounded.utf8.count != query.utf8.count { query = bounded }
                        }
                    Text(matches.isEmpty ? (query.isEmpty ? "" : "0 matches") : "\(matchIndex + 1)/\(matches.count)").font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                    Button { advance(-1) } label: { Image(systemName: "chevron.up") }.disabled(matches.isEmpty).accessibilityLabel("Previous JSON match")
                    Button { advance(1) } label: { Image(systemName: "chevron.down") }.disabled(matches.isEmpty).accessibilityLabel("Next JSON match")
                }.controlSize(.small)
            }
            HStack {
                Text("\(document.nodes[0].kind.rawValue.capitalized) · \(document.nodes.count) nodes").font(.caption).foregroundStyle(.secondary)
                Spacer()
                Text("Source order preserved").font(.caption).foregroundStyle(.secondary)
            }
            if document.duplicateCount > 0 {
                Label("\(document.duplicateCount) duplicate key occurrences preserved. Their JSON Pointers are ambiguous.", systemImage: "exclamationmark.triangle")
                    .font(.caption).foregroundStyle(.orange)
            }
            if document.hasBOM { Text("UTF-8 BOM retained in Source; omitted in Pretty.").font(.caption).foregroundStyle(.secondary) }
            Group {
                switch mode {
                case .tree:
                    LensJSONOutlineView(document: document, title: title, selected: selected, expand: expand, collapse: collapse,
                        matches: Set(matches), onSelect: { selected = $0; copyStatus = "" },
                        onCopyValue: { id in copy(document.originalValue(id), "Copied selected JSON value") },
                        onCopyPointer: { id in copy(document.pointer(id), "Copied JSON Pointer") })
                case .pretty:
                    LensBodyTextView(text: document.formatted, title: "\(title) formatted JSON", syntax: document.spans,
                        syntaxID: document.id, selectedRange: selected.map { document.formattedRanges[$0] }, wrapLines: wrap, lineNumbers: true)
                case .source:
                    LensBodyTextView(text: document.source, title: "\(title) JSON source", wrapLines: wrap, lineNumbers: true)
                }
            }.frame(height: 460).background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 6))
            if let selected {
                let path = document.pointer(selected)
                HStack(spacing: 6) {
                    Text(path.isEmpty ? "JSON Pointer: \"\" (root)" : "JSON Pointer: " + String(String.UnicodeScalarView(path.unicodeScalars.prefix(200))))
                        .font(.system(.caption, design: .monospaced)).lineLimit(2).textSelection(.enabled)
                    Spacer(minLength: 0)
                    Button("Copy value", action: copyValue).controlSize(.mini).help("Copy original JSON value, preserving number precision and escapes")
                    Button("Copy pointer", action: copyPointer).controlSize(.mini).disabled(document.pointerIsAmbiguous(selected))
                }
            } else { Text("Select a field to inspect its path or copy its original value.").font(.caption).foregroundStyle(.secondary) }
            if !copyStatus.isEmpty { Text(copyStatus).font(.caption).foregroundStyle(.secondary).accessibilityLabel(copyStatus) }
        }
        .task(id: query) {
            let captured = query
            guard !captured.isEmpty else { matches = []; matchIndex = 0; return }
            do { try await Task.sleep(nanoseconds: 150_000_000) } catch { return }
            guard let result = await BodyRenderWorker.shared.searchJSON(document, query: captured), !Task.isCancelled else { return }
            matches = result; matchIndex = 0
            if let first = result.first { selected = first }
        }
    }
    private func advance(_ amount: Int) {
        guard !matches.isEmpty else { return }
        matchIndex = (matchIndex + amount + matches.count) % matches.count; selected = matches[matchIndex]
    }
    private func copy(_ value: String, _ message: String) { lensCopy(value); copyStatus = message }
    private func copyValue() { if let selected { copy(document.originalValue(selected), "Copied selected JSON value") } }
    private func copyPointer() {
        if let selected, !document.pointerIsAmbiguous(selected) { copy(document.pointer(selected), "Copied JSON Pointer") }
    }
}

private final class JSONOutlineItem: NSObject {
    let id: Int
    init(_ id: Int) { self.id = id }
}

// NSOutlineView reuses visible row views instead of constructing a SwiftUI view
// for every captured member. Each occurrence has its own identity, even duplicates.
struct LensJSONOutlineView: NSViewRepresentable {
    let document: JSONDocument
    let title: String
    let selected: Int?
    let expand: Int
    let collapse: Int
    let matches: Set<Int>
    let onSelect: (Int?) -> Void
    let onCopyValue: (Int) -> Void
    let onCopyPointer: (Int) -> Void

    final class Coordinator: NSObject, NSOutlineViewDataSource, NSOutlineViewDelegate, NSMenuDelegate {
        var document: JSONDocument?
        fileprivate var items: [JSONOutlineItem] = []
        weak var outline: NSOutlineView?
        var parent: LensJSONOutlineView
        var expand = 0, collapse = 0
        var applying = false
        init(_ parent: LensJSONOutlineView) { self.parent = parent }
        func outlineView(_ outlineView: NSOutlineView, numberOfChildrenOfItem item: Any?) -> Int {
            guard let item = item as? JSONOutlineItem else { return items.isEmpty ? 0 : 1 }
            return document!.nodes[item.id].children.count
        }
        func outlineView(_ outlineView: NSOutlineView, child index: Int, ofItem item: Any?) -> Any {
            guard let item = item as? JSONOutlineItem else { return items[0] }
            return items[document!.nodes[item.id].children[index]]
        }
        func outlineView(_ outlineView: NSOutlineView, isItemExpandable item: Any) -> Bool {
            guard let item = item as? JSONOutlineItem else { return false }
            return !document!.nodes[item.id].children.isEmpty
        }
        func outlineView(_ outlineView: NSOutlineView, viewFor tableColumn: NSTableColumn?, item: Any) -> NSView? {
            guard let document, let item = item as? JSONOutlineItem, let column = tableColumn else { return nil }
            let key = column.identifier.rawValue == "key"
            let identifier = column.identifier
            let cell = outlineView.makeView(withIdentifier: identifier, owner: self) as? NSTableCellView ?? makeCell(identifier)
            let node = document.nodes[item.id]
            let label = key ? document.label(item.id) : document.preview(item.id)
            cell.textField?.stringValue = String(String.UnicodeScalarView(label.unicodeScalars.prefix(320)))
            let kind: JSONSyntaxKind
            switch node.kind {
            case .string: kind = .string; case .number: kind = .number; case .boolean: kind = .boolean
            case .null: kind = .null; default: kind = .punctuation
            }
            cell.textField?.textColor = key ? .systemBlue : jsonSyntaxColor(kind)
            cell.textField?.font = .monospacedSystemFont(ofSize: 12, weight: key ? .medium : .regular)
            cell.textField?.drawsBackground = parent.matches.contains(item.id)
            cell.textField?.backgroundColor = .systemYellow.withAlphaComponent(0.18)
            cell.setAccessibilityLabel("\(key ? "Field" : node.kind.rawValue): \(cell.textField?.stringValue ?? "")\(node.duplicateKey ? ", duplicate key" : "")")
            cell.toolTip = node.kind.rawValue + (node.duplicateKey ? " · duplicate object key" : "")
            return cell
        }
        private func makeCell(_ id: NSUserInterfaceItemIdentifier) -> NSTableCellView {
            let cell = NSTableCellView(); cell.identifier = id
            let text = NSTextField(labelWithString: "")
            text.usesSingleLineMode = true; text.lineBreakMode = .byTruncatingTail
            text.translatesAutoresizingMaskIntoConstraints = false; cell.addSubview(text); cell.textField = text
            NSLayoutConstraint.activate([text.leadingAnchor.constraint(equalTo: cell.leadingAnchor, constant: 4),
                text.trailingAnchor.constraint(equalTo: cell.trailingAnchor, constant: -4), text.centerYAnchor.constraint(equalTo: cell.centerYAnchor)])
            return cell
        }
        func outlineViewSelectionDidChange(_ notification: Notification) {
            guard !applying, let outline else { return }
            parent.onSelect((outline.item(atRow: outline.selectedRow) as? JSONOutlineItem)?.id)
        }
        func menuNeedsUpdate(_ menu: NSMenu) {
            guard let outline, let document else { return }
            if outline.clickedRow >= 0 { outline.selectRowIndexes(IndexSet(integer: outline.clickedRow), byExtendingSelection: false) }
            let item = outline.item(atRow: outline.selectedRow) as? JSONOutlineItem
            menu.removeAllItems()
            let value = menu.addItem(withTitle: "Copy JSON value", action: #selector(copyValue), keyEquivalent: ""); value.target = self; value.isEnabled = item != nil
            let pointer = menu.addItem(withTitle: "Copy JSON Pointer", action: #selector(copyPointer), keyEquivalent: ""); pointer.target = self
            pointer.isEnabled = item.map { !document.pointerIsAmbiguous($0.id) } ?? false
            if item.map({ document.pointerIsAmbiguous($0.id) }) == true { menu.addItem(withTitle: "Duplicate key: pointer is ambiguous", action: nil, keyEquivalent: "") }
        }
        @objc private func copyValue() { if let outline, let item = outline.item(atRow: outline.selectedRow) as? JSONOutlineItem { parent.onCopyValue(item.id) } }
        @objc private func copyPointer() {
            if let outline, let item = outline.item(atRow: outline.selectedRow) as? JSONOutlineItem, document?.pointerIsAmbiguous(item.id) == false { parent.onCopyPointer(item.id) }
        }
    }

    func makeCoordinator() -> Coordinator { Coordinator(self) }
    func makeNSView(context: Context) -> NSScrollView {
        let scroll = NSScrollView(); scroll.hasVerticalScroller = true; scroll.hasHorizontalScroller = true; scroll.autohidesScrollers = true
        let outline = NSOutlineView()
        let key = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("key")); key.title = "Key / index"; key.width = 155; key.minWidth = 95
        let value = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("value")); value.title = "Value"; value.width = 280; value.minWidth = 140
        outline.addTableColumn(key); outline.addTableColumn(value); outline.outlineTableColumn = key
        outline.columnAutoresizingStyle = .lastColumnOnlyAutoresizingStyle
        outline.autoresizingMask = [.width]; outline.rowHeight = 25; outline.indentationPerLevel = 14
        outline.usesAlternatingRowBackgroundColors = true; outline.selectionHighlightStyle = .regular
        outline.dataSource = context.coordinator; outline.delegate = context.coordinator
        outline.setAccessibilityLabel("\(title) JSON tree")
        let menu = NSMenu(); menu.autoenablesItems = false; menu.delegate = context.coordinator; outline.menu = menu
        scroll.documentView = outline; context.coordinator.outline = outline
        return scroll
    }
    func updateNSView(_ scroll: NSScrollView, context: Context) {
        guard let outline = scroll.documentView as? NSOutlineView else { return }
        let coordinator = context.coordinator
        coordinator.applying = true; defer { coordinator.applying = false }
        let previousMatches = coordinator.parent.matches
        coordinator.parent = self
        if coordinator.document?.id != document.id {
            coordinator.document = document; coordinator.items = document.nodes.map { JSONOutlineItem($0.id) }
            outline.reloadData(); outline.expandItem(coordinator.items[0])
            for id in document.nodes[0].children where document.nodes[id].children.count < 12 { outline.expandItem(coordinator.items[id]) }
        } else if previousMatches != matches {
            outline.reloadData()
        }
        if coordinator.expand != expand { coordinator.expand = expand; outline.expandItem(nil, expandChildren: true) }
        if coordinator.collapse != collapse { coordinator.collapse = collapse; outline.collapseItem(nil, collapseChildren: true); outline.expandItem(coordinator.items[0]) }
        if let selected, selected < coordinator.items.count {
            let item = coordinator.items[selected]
            if (outline.item(atRow: outline.selectedRow) as? JSONOutlineItem)?.id != selected {
                var ancestors: [Int] = [], current = document.nodes[selected].parent
                while let id = current { ancestors.append(id); current = document.nodes[id].parent }
                for id in ancestors.reversed() { outline.expandItem(coordinator.items[id]) }
                let row = outline.row(forItem: item)
                if row >= 0 { outline.selectRowIndexes(IndexSet(integer: row), byExtendingSelection: false); outline.scrollRowToVisible(row) }
            }
        }
    }
}
