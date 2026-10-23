import Foundation

// One lossless owner for JSON syntax, formatting, tree identity and pointers.
// Values are never converted to Double or a dictionary of unique keys.
enum JSONValueKind: String { case object, array, string, number, boolean, null }
enum JSONSyntaxKind { case key, string, number, boolean, null, punctuation }
struct JSONSyntaxSpan { let range: NSRange; let kind: JSONSyntaxKind }
struct JSONValueNode {
    let id: Int
    let parent: Int?
    let name: String?
    let arrayIndex: Int?
    let keyRange: Range<Int>?
    var range: Range<Int>
    var kind: JSONValueKind
    var stringValue: String?
    var children: [Int] = []
    var duplicateKey = false
}

enum JSONReadFailure { case syntax, limit, encoding, unicode }
struct JSONReadError: Error, CustomStringConvertible {
    let reason: String
    let offset: Int
    let line: Int
    let column: Int
    var kind: JSONReadFailure = .syntax
    var description: String { "\(reason) · line \(line), column \(column) (UTF-8 byte \(offset))" }
}

final class JSONDocument: @unchecked Sendable {
    static let maxInputBytes = 2 * 1024 * 1024
    static let maxOutputBytes = 4 * 1024 * 1024
    static let maxNodes = 50_000
    static let maxDepth = 32
    let id = UUID()
    let source: String
    let bytes: [UInt8]
    let nodes: [JSONValueNode]
    let formatted: String
    let spans: [JSONSyntaxSpan]
    let formattedRanges: [NSRange]
    let duplicateCount: Int
    let hasBOM: Bool

    init(data: Data) throws {
        guard data.count <= Self.maxInputBytes else { throw JSONReadError(reason: "JSON display limit: 2 MiB input; save the body for complete bytes", offset: 0, line: 1, column: 1, kind: .limit) }
        guard String(data: data, encoding: .utf8) != nil else { throw JSONReadError(reason: "JSON viewer requires UTF-8 source bytes; use Hex for this encoding", offset: 0, line: 1, column: 1, kind: .encoding) }
        // String(data:encoding:) strips an initial UTF-8 BOM. Decode only after
        // strict validation so Source and copying still retain those bytes.
        let source = String(decoding: data, as: UTF8.self)
        var parser = JSONSyntaxReader(bytes: Array(data))
        try parser.parse()
        var printer = JSONPrettyPrinter(bytes: parser.bytes, nodes: parser.nodes)
        try printer.printValue(0, depth: 0)
        self.source = source; bytes = parser.bytes; nodes = parser.nodes
        formatted = printer.text; spans = printer.spans; formattedRanges = printer.ranges
        duplicateCount = parser.duplicateCount; hasBOM = parser.hasBOM
    }

    func originalValue(_ id: Int) -> String { String(decoding: bytes[nodes[id].range], as: UTF8.self) }
    func pointer(_ id: Int) -> String {
        var segments: [String] = [], current = id
        while let parent = nodes[current].parent {
            let value = nodes[current].arrayIndex.map(String.init) ?? nodes[current].name ?? ""
            segments.append(value.replacingOccurrences(of: "~", with: "~0").replacingOccurrences(of: "/", with: "~1"))
            current = parent
        }
        return segments.reversed().map { "/" + $0 }.joined()
    }
    func pointerIsAmbiguous(_ id: Int) -> Bool {
        var current: Int? = id
        while let value = current {
            if nodes[value].duplicateKey { return true }
            current = nodes[value].parent
        }
        return false
    }
    func label(_ id: Int) -> String {
        let node = nodes[id]
        if let index = node.arrayIndex { return "[\(index)]" }
        if let name = node.name { return name.isEmpty ? "\"\"" : Self.readable(name, limit: 120) }
        return "$"
    }
    func preview(_ id: Int) -> String {
        let node = nodes[id]
        switch node.kind {
        case .object: return "{ \(node.children.count) members }"
        case .array: return "[ \(node.children.count) items ]"
        case .string:
            return "\"" + Self.readable(node.stringValue!, limit: 240) + "\""
        default:
            let range = node.range, end = min(range.upperBound, range.lowerBound + 240)
            return String(decoding: bytes[range.lowerBound..<end], as: UTF8.self) + (end < range.upperBound ? "…" : "")
        }
    }
    private static func readable(_ source: String, limit: Int) -> String {
        var iterator = source.unicodeScalars.makeIterator(), value = ""
        for _ in 0..<limit {
            guard let scalar = iterator.next() else { return value }
            switch scalar.value {
            case 0x22: value += "\\\""
            case 0x5c: value += "\\\\"
            case 8: value += "\\b"
            case 9: value += "\\t"
            case 10: value += "\\n"
            case 12: value += "\\f"
            case 13: value += "\\r"
            case 0..<32: value += String(format: "\\u%04x", scalar.value)
            default: value.unicodeScalars.append(scalar)
            }
        }
        if iterator.next() != nil { value += "…" }
        return value
    }
    func search(_ query: String) throws -> [Int] {
        guard !query.isEmpty else { return [] }
        var matches: [Int] = []
        for node in nodes {
            if node.id % 256 == 0 { try Task.checkCancellation() }
            let value = node.stringValue ?? (node.kind == .object || node.kind == .array ? "" : originalValue(node.id))
            if node.name?.localizedCaseInsensitiveContains(query) == true || value.localizedCaseInsensitiveContains(query) { matches.append(node.id) }
        }
        return matches
    }
}

struct JSONPresentation {
    let document: JSONDocument?
    let text: String
    let issue: String?
    static func make(text: String, base64: String?, truncated: Bool) throws -> JSONPresentation {
        let prefix = truncated ? "[Body preview is truncated; save the body for complete bytes.]\n\n" : ""
        let bytes: Data
        if let base64 {
            guard base64.utf8.count <= ((JSONDocument.maxInputBytes + 2) / 3) * 4,
                  let decoded = Data(base64Encoded: base64) else {
                return JSONPresentation(document: nil, text: prefix + "[Invalid or oversized base64 JSON preview; use Hex or save the body.]", issue: "Invalid body bytes")
            }
            bytes = decoded
        } else {
            guard text.utf8.count <= JSONDocument.maxInputBytes else {
                return JSONPresentation(document: nil, text: prefix + "[JSON display limit: 2 MiB input; save the body.]", issue: "Display limit")
            }
            bytes = Data(text.utf8)
        }
        return try make(data: bytes, truncated: truncated)
    }
    static func make(data bytes: Data, truncated: Bool) throws -> JSONPresentation {
        let prefix = truncated ? "[Body preview is truncated; save the body for complete bytes.]\n\n" : ""
        func source() -> String { String(data: bytes, encoding: .utf8) == nil ? "[Non-UTF-8 source; use Hex.]" : String(decoding: bytes, as: UTF8.self) }
        if truncated {
            return JSONPresentation(document: nil, text: prefix + "[Incomplete preview: structural JSON view is unavailable.]\n\n" + source(), issue: "Truncated JSON preview")
        }
        do {
            let document = try JSONDocument(data: bytes)
            return JSONPresentation(document: document, text: document.formatted, issue: nil)
        } catch is CancellationError { throw CancellationError()
        } catch let error as JSONReadError {
            let issue: String
            switch error.kind {
            case .syntax: issue = "Invalid or incomplete JSON"
            case .limit: issue = "JSON display limit reached"
            case .encoding: issue = "Unsupported JSON encoding"
            case .unicode: issue = "Unsupported JSON Unicode sequence"
            }
            return JSONPresentation(document: nil, text: "[\(issue): \(error)]\n\n" + source(), issue: issue)
        } catch {
            return JSONPresentation(document: nil, text: "[JSON rendering failed: \(error)]\n\n" + source(), issue: "JSON rendering failed")
        }
    }
}

private struct JSONSyntaxReader {
    let bytes: [UInt8]
    var cursor = 0
    var nodes: [JSONValueNode] = []
    var duplicateCount = 0
    var hasBOM: Bool { bytes.starts(with: [0xef, 0xbb, 0xbf]) }
    var peek: UInt8? { cursor < bytes.count ? bytes[cursor] : nil }
    func failure(_ reason: String, at position: Int? = nil, kind: JSONReadFailure = .syntax) -> JSONReadError {
        let offset = position ?? cursor
        var line = 1, column = 1
        for byte in bytes.prefix(offset) { if byte == 10 { line += 1; column = 1 } else if byte & 0xc0 != 0x80 { column += 1 } }
        return JSONReadError(reason: reason, offset: offset, line: line, column: column, kind: kind)
    }
    mutating func whitespace() { while let byte = peek, [9, 10, 13, 32].contains(byte) { cursor += 1 } }
    mutating func expect(_ byte: UInt8, _ reason: String) throws { guard peek == byte else { throw failure(reason) }; cursor += 1 }
    mutating func parse() throws {
        if hasBOM { cursor = 3 }
        whitespace(); _ = try value(parent: nil, name: nil, keyRange: nil, index: nil, depth: 0)
        whitespace(); guard cursor == bytes.count else { throw failure("Unexpected content after JSON value") }
    }
    mutating func value(parent: Int?, name: String?, keyRange: Range<Int>?, index: Int?, depth: Int) throws -> Int {
        try Task.checkCancellation()
        guard depth <= JSONDocument.maxDepth, nodes.count < JSONDocument.maxNodes else { throw failure("Pretty-print display budget exceeded: 32 levels or 50,000 nodes. Showing source text", kind: .limit) }
        whitespace(); let start = cursor, id = nodes.count
        nodes.append(JSONValueNode(id: id, parent: parent, name: name, arrayIndex: index, keyRange: keyRange, range: start..<start, kind: .null))
        guard let leading = peek else { throw failure("Expected a JSON value") }
        switch leading {
        case 0x7b, 0x5b:
            let object = peek == 0x7b; cursor += 1; nodes[id].kind = object ? .object : .array
            let end: UInt8 = object ? 0x7d : 0x5d
            var keys: [Data: Int] = [:]
            whitespace()
            if peek == end { cursor += 1 }
            else {
                while true {
                    whitespace()
                    var name: String?, range: Range<Int>?
                    if object {
                        let begin = cursor; name = try string(); range = begin..<cursor
                        whitespace(); try expect(0x3a, "Expected ':' after object key")
                    }
                    let child = try value(parent: id, name: name, keyRange: range, index: object ? nil : nodes[id].children.count, depth: depth + 1)
                    nodes[id].children.append(child)
                    if let name {
                        // Swift String equality normalizes Unicode. JSON member identity does not.
                        let identity = Data(name.utf8)
                        if let earlier = keys[identity] { nodes[earlier].duplicateKey = true; nodes[child].duplicateKey = true; duplicateCount += 1 }
                        else { keys[identity] = child }
                    }
                    whitespace()
                    if peek == end { cursor += 1; break }
                    try expect(0x2c, "Expected ',' or closing delimiter")
                }
            }
        case 0x22: nodes[id].kind = .string; nodes[id].stringValue = try string()
        case 0x74: try literal("true"); nodes[id].kind = .boolean
        case 0x66: try literal("false"); nodes[id].kind = .boolean
        case 0x6e: try literal("null")
        case 0x2d, 0x30...0x39: try number(); nodes[id].kind = .number
        default: throw failure("Expected a JSON value")
        }
        nodes[id].range = start..<cursor
        return id
    }
    mutating func literal(_ value: String) throws {
        for byte in value.utf8 { try expect(byte, "Invalid JSON literal") }
    }
    mutating func number() throws {
        if peek == 0x2d { cursor += 1 }
        if peek == 0x30 { cursor += 1 }
        else { try digits() }
        if peek == 0x2e { cursor += 1; try digits() }
        if peek == 0x65 || peek == 0x45 {
            cursor += 1
            if peek == 0x2b || peek == 0x2d { cursor += 1 }
            try digits()
        }
    }
    mutating func digits() throws {
        let start = cursor
        while let byte = peek, (0x30...0x39).contains(byte) { cursor += 1 }
        guard cursor > start else { throw failure("Expected a digit") }
    }
    mutating func hex4() throws -> UInt32 {
        var result: UInt32 = 0
        for _ in 0..<4 {
            guard let byte = peek else { throw failure("Incomplete Unicode escape") }
            let value: UInt8
            switch byte {
            case 48...57: value = byte - 48
            case 65...70: value = byte - 55
            case 97...102: value = byte - 87
            default: throw failure("Invalid Unicode escape")
            }
            result = result * 16 + UInt32(value); cursor += 1
        }
        return result
    }
    mutating func string() throws -> String {
        try expect(0x22, "Expected a quoted object key")
        var decoded: [UInt8] = []
        while let byte = peek {
            let position = cursor
            cursor += 1
            if byte == 0x22 { return String(decoding: decoded, as: UTF8.self) }
            guard byte >= 0x20 else { throw failure("Unescaped control character in string", at: position) }
            if byte != 0x5c { decoded.append(byte); continue }
            guard let escape = peek else { throw failure("Incomplete string escape") }
            let escapePosition = cursor
            cursor += 1
            switch escape {
            case 0x22, 0x5c, 0x2f: decoded.append(escape)
            case 0x62: decoded.append(8)
            case 0x66: decoded.append(12)
            case 0x6e: decoded.append(10)
            case 0x72: decoded.append(13)
            case 0x74: decoded.append(9)
            case 0x75:
                var scalar = try hex4()
                if (0xd800...0xdbff).contains(scalar) {
                    guard peek == 0x5c else { throw failure("Unpaired Unicode surrogate; source is retained", kind: .unicode) }; cursor += 1
                    guard peek == 0x75 else { throw failure("Unpaired Unicode surrogate; source is retained", kind: .unicode) }; cursor += 1
                    let low = try hex4()
                    guard (0xdc00...0xdfff).contains(low) else { throw failure("Unpaired Unicode surrogate; source is retained", kind: .unicode) }
                    scalar = 0x10000 + (scalar - 0xd800) * 1024 + low - 0xdc00
                }
                guard let value = UnicodeScalar(scalar) else { throw failure("Unpaired Unicode surrogate; source is retained", kind: .unicode) }
                decoded.append(contentsOf: String(value).utf8)
            default: throw failure("Invalid string escape", at: escapePosition)
            }
        }
        throw failure("Unterminated string")
    }
}

private struct JSONPrettyPrinter {
    let bytes: [UInt8]
    let nodes: [JSONValueNode]
    var text = ""
    var spans: [JSONSyntaxSpan] = []
    var utf16Count = 0
    var byteCount = 0
    var ranges: [NSRange]
    init(bytes: [UInt8], nodes: [JSONValueNode]) {
        self.bytes = bytes; self.nodes = nodes; ranges = Array(repeating: NSRange(location: 0, length: 0), count: nodes.count)
    }
    mutating func append(_ value: String, kind: JSONSyntaxKind? = nil) throws {
        let size = value.utf8.count
        guard size <= JSONDocument.maxOutputBytes - byteCount else {
            throw JSONReadError(reason: "Pretty-print display budget exceeded: 4 MiB output. Showing source text", offset: 0, line: 1, column: 1, kind: .limit)
        }
        let length = value.utf16.count
        if let kind { spans.append(JSONSyntaxSpan(range: NSRange(location: utf16Count, length: length), kind: kind)) }
        text += value; byteCount += size; utf16Count += length
    }
    mutating func printValue(_ id: Int, depth: Int) throws {
        if id % 256 == 0 { try Task.checkCancellation() }
        let node = nodes[id], start = utf16Count
        if node.kind == .object || node.kind == .array {
            let object = node.kind == .object
            try append(object ? "{" : "[", kind: .punctuation)
            for (ordinal, childID) in node.children.enumerated() {
                try append("\n" + String(repeating: "  ", count: depth + 1))
                if let range = nodes[childID].keyRange {
                    try append(String(decoding: bytes[range], as: UTF8.self), kind: .key)
                    try append(": ", kind: .punctuation)
                }
                try printValue(childID, depth: depth + 1)
                if ordinal + 1 < node.children.count { try append(",", kind: .punctuation) }
            }
            if !node.children.isEmpty { try append("\n" + String(repeating: "  ", count: depth)) }
            try append(object ? "}" : "]", kind: .punctuation)
        } else {
            let kind: JSONSyntaxKind
            switch node.kind { case .string: kind = .string; case .number: kind = .number; case .boolean: kind = .boolean; default: kind = .null }
            try append(String(decoding: bytes[node.range], as: UTF8.self), kind: kind)
        }
        ranges[id] = NSRange(location: start, length: utf16Count - start)
    }
}
