import Foundation

// MIME interpretation belongs here. Consumers receive byte ranges into the
// supplied decoded-body preview; no filenames are opened or bodies rewritten.
private struct MIMEValue {
    enum Kind { case mediaType, disposition }
    let token: String
    let parameters: [(String, Data)]

    static func isToken(_ byte: UInt8) -> Bool {
        switch byte {
        case 48...57, 65...90, 97...122, 33, 35...39, 42, 43, 45, 46, 94...96, 124, 126: return true
        default: return false
        }
    }

    init(_ data: Data, kind: Kind = .mediaType) throws {
        guard data.count <= 65536 else { throw MultipartFailure("MIME header limit (65536 bytes) reached", offset: 0) }
        let source = Array(data)
        var bytes: [UInt8] = []
        var sourceCursor = 0
        while sourceCursor < source.count {
            if source[sourceCursor] == 13, sourceCursor + 2 < source.count,
               source[sourceCursor + 1] == 10, [9, 32].contains(source[sourceCursor + 2]) {
                bytes.append(32); sourceCursor += 3
                while sourceCursor < source.count && [9, 32].contains(source[sourceCursor]) { sourceCursor += 1 }
            } else { bytes.append(source[sourceCursor]); sourceCursor += 1 }
        }
        var cursor = 0
        func whitespace() { while cursor < bytes.count && [9, 32].contains(bytes[cursor]) { cursor += 1 } }
        whitespace()
        let start = cursor
        while cursor < bytes.count && bytes[cursor] != 59 && bytes[cursor] != 9 && bytes[cursor] != 32 { cursor += 1 }
        let main = bytes[start..<cursor]
        let components = main.split(separator: 47, omittingEmptySubsequences: false)
        guard components.count == (kind == .mediaType ? 2 : 1), components.allSatisfy({ !$0.isEmpty && $0.allSatisfy(Self.isToken) }) else {
            throw MultipartFailure("Invalid MIME type/disposition token", offset: 0)
        }
        token = String(decoding: main, as: UTF8.self).lowercased()
        var fields: [(String, Data)] = []
        whitespace()
        while cursor < bytes.count {
            guard bytes[cursor] == 59 else { throw MultipartFailure("Invalid MIME parameter separator", offset: cursor) }
            cursor += 1; whitespace()
            let keyStart = cursor
            while cursor < bytes.count && Self.isToken(bytes[cursor]) { cursor += 1 }
            guard cursor > keyStart else { throw MultipartFailure("Missing MIME parameter name", offset: cursor) }
            let key = String(decoding: bytes[keyStart..<cursor], as: UTF8.self).lowercased()
            whitespace()
            guard cursor < bytes.count && bytes[cursor] == 61 else { throw MultipartFailure("Missing MIME parameter equals sign", offset: cursor) }
            cursor += 1; whitespace()
            var value: [UInt8] = []
            if cursor < bytes.count && bytes[cursor] == 34 {
                cursor += 1
                var closed = false
                while cursor < bytes.count {
                    var byte = bytes[cursor]; cursor += 1
                    if byte == 34 { closed = true; break }
                    if byte == 92 {
                        guard cursor < bytes.count else { throw MultipartFailure("Incomplete MIME quoted escape", offset: cursor) }
                        byte = bytes[cursor]; cursor += 1
                    }
                    guard byte == 9 || byte >= 32 && byte != 127 else { throw MultipartFailure("Control byte in MIME parameter", offset: cursor - 1) }
                    value.append(byte)
                }
                guard closed else { throw MultipartFailure("Incomplete MIME quoted parameter", offset: cursor) }
            } else {
                let valueStart = cursor
                while cursor < bytes.count && Self.isToken(bytes[cursor]) { cursor += 1 }
                guard cursor > valueStart else { throw MultipartFailure("Missing MIME parameter value", offset: cursor) }
                value = Array(bytes[valueStart..<cursor])
            }
            fields.append((key, Data(value))); whitespace()
        }
        parameters = fields
    }

    func values(_ name: String) -> [Data] { parameters.filter { $0.0 == name }.map(\.1) }
    func boundary() throws -> [UInt8] {
        let values = values("boundary")
        guard values.count == 1 else { throw MultipartFailure("Exactly one boundary parameter is required; missing or duplicate boundary", offset: 0) }
        let bytes = Array(values[0]), extra = Array("'()+_,-./:=? ".utf8)
        guard (1...70).contains(bytes.count), bytes.last != 32,
              bytes.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || extra.contains($0) }) else {
            throw MultipartFailure("Invalid boundary: use 1–70 MIME boundary characters, with no trailing space", offset: 0)
        }
        return bytes
    }
}

private struct MultipartFailure: Error, CustomStringConvertible {
    let description: String
    let offset: Int
    init(_ description: String, offset: Int) { self.description = description; self.offset = offset }
}

private struct MultipartHeader {
    let name: String
    var value: Data
}

private struct MultipartPart {
    let ordinal: String
    let headers: [MultipartHeader]
    let headerRange: Range<Int>
    let bodyRange: Range<Int>
    let complete: Bool
    var nested: MultipartDocument?
    var issue: String?
}

private struct MultipartDocument {
    var parts: [MultipartPart] = []
    var closingSeen = false
    var preambleBytes = 0
    var epilogueBytes = 0
    var issue: MultipartFailure?
}

private struct MultipartReader {
    let bytes: [UInt8]
    var partCount = 0

    private struct Delimiter {
        let prefixStart: Int
        let afterLine: Int
        let closing: Bool
    }

    // Search bytes once per level; boundary-shaped payload is only framing when
    // the complete delimiter suffix and CRLF/closing EOF have been observed.
    private func delimiter(from start: Int, through end: Int, boundary: [UInt8], completeInput: Bool) -> Delimiter? {
        let marker = [UInt8(45), 45] + boundary
        var line = start
        while line < end {
            if bytes[line] == 45, end - line >= marker.count,
               bytes[line..<(line + marker.count)].elementsEqual(marker) {
                var after = line + marker.count
                let closing = end - after >= 2 && bytes[after] == 45 && bytes[after + 1] == 45
                if closing { after += 2 }
                while after < end && [9, 32].contains(bytes[after]) { after += 1 }
                if (after == end && closing && completeInput) || (end - after >= 2 && bytes[after] == 13 && bytes[after + 1] == 10) {
                    let prefix = line >= 2 && bytes[line - 2] == 13 && bytes[line - 1] == 10 ? line - 2 : line
                    return Delimiter(prefixStart: max(start, prefix), afterLine: after == end ? end : after + 2, closing: closing)
                }
            }
            while line < end && !(bytes[line] == 13 && line + 1 < end && bytes[line + 1] == 10) { line += 1 }
            line += 2
        }
        return nil
    }

    private func headers(in range: Range<Int>) throws -> ([MultipartHeader], Range<Int>, Int) {
        var cursor = range.lowerBound
        var fields: [MultipartHeader] = []
        while cursor < range.upperBound {
            var end = cursor
            while end + 1 < range.upperBound && !(bytes[end] == 13 && bytes[end + 1] == 10) {
                if end - range.lowerBound >= 65536 { throw MultipartFailure("Multipart header limit (65536 bytes) reached", offset: range.lowerBound) }
                end += 1
            }
            guard end + 1 < range.upperBound else { throw MultipartFailure("Incomplete multipart headers; remaining bytes are not interpreted", offset: cursor) }
            guard end + 2 - range.lowerBound <= 65536 else { throw MultipartFailure("Multipart header limit (65536 bytes) reached", offset: range.lowerBound) }
            if end == cursor { return (fields, range.lowerBound..<cursor, end + 2) }
            let line = bytes[cursor..<end]
            guard line.allSatisfy({ $0 == 9 || $0 >= 32 && $0 != 127 }) else {
                throw MultipartFailure("Invalid control byte in multipart header field", offset: cursor)
            }
            if [9, 32].contains(bytes[cursor]) {
                guard !fields.isEmpty else { throw MultipartFailure("Header continuation without a preceding field", offset: cursor) }
                // Preserve folded source separately; only MIME interpretation
                // consumes this once-unfolded value.
                fields[fields.count - 1].value.append(32)
                fields[fields.count - 1].value.append(contentsOf: line.drop(while: { [9, 32].contains($0) }))
            } else {
                guard let colon = line.firstIndex(of: 58), colon > cursor,
                      bytes[cursor..<colon].allSatisfy(MIMEValue.isToken) else { throw MultipartFailure("Malformed multipart header field", offset: cursor) }
                let name = String(decoding: bytes[cursor..<colon], as: UTF8.self).lowercased()
                let value = line[(colon + 1)...].drop(while: { [9, 32].contains($0) })
                fields.append(MultipartHeader(name: name, value: Data(value)))
            }
            cursor = end + 2
        }
        throw MultipartFailure("Incomplete multipart headers; remaining bytes are not interpreted", offset: cursor)
    }

    mutating func read(_ range: Range<Int>, type: MIMEValue, completeInput: Bool, depth: Int = 0, parent: String = "") -> MultipartDocument {
        var document = MultipartDocument()
        do {
            guard depth < 8 else { throw MultipartFailure("Multipart nesting limit (8) reached", offset: range.lowerBound) }
            let boundary: [UInt8]
            do { boundary = try type.boundary() }
            catch let failure as MultipartFailure {
                // Parameter offsets address header syntax, not the body. This
                // reader stopped before interpreting this child body's range.
                throw MultipartFailure(failure.description, offset: range.lowerBound)
            }
            guard let first = delimiter(from: range.lowerBound, through: range.upperBound, boundary: boundary, completeInput: completeInput) else {
                throw MultipartFailure("No valid opening delimiter in supplied preview", offset: range.lowerBound)
            }
            document.preambleBytes = first.prefixStart - range.lowerBound
            var previous = first
            while !previous.closing {
                guard partCount < 256 else { throw MultipartFailure("Multipart part limit (256) reached", offset: previous.afterLine) }
                if Task.isCancelled { throw MultipartFailure("Multipart rendering cancelled", offset: previous.afterLine) }
                let next = delimiter(from: previous.afterLine, through: range.upperBound, boundary: boundary, completeInput: completeInput)
                let partEnd = next?.prefixStart ?? range.upperBound
                let (fields, headRange, bodyStart) = try headers(in: previous.afterLine..<partEnd)
                partCount += 1
                let ordinal = parent + String(document.parts.count + 1)
                var part = MultipartPart(ordinal: ordinal, headers: fields, headerRange: headRange, bodyRange: bodyStart..<partEnd, complete: next != nil)
                let types = fields.filter { $0.name == "content-type" }
                if types.count == 1 {
                    do {
                        let nestedType = try MIMEValue(types[0].value)
                        let coded = fields.contains { ["content-transfer-encoding", "content-encoding"].contains($0.name) }
                        if nestedType.token.hasPrefix("multipart/") && !coded { part.nested = read(part.bodyRange, type: nestedType, completeInput: part.complete, depth: depth + 1, parent: ordinal + ".") }
                    } catch { part.issue = "Invalid part Content-Type; raw bytes retained: \(error)" }
                } else if types.count > 1 { part.issue = "Multiple Content-Type fields; nested data is not interpreted" }
                document.parts.append(part)
                guard let next else { throw MultipartFailure("Missing closing delimiter; final part is partial in supplied preview", offset: range.upperBound) }
                previous = next
            }
            document.closingSeen = true
            document.epilogueBytes = range.upperBound - previous.afterLine
        } catch let failure as MultipartFailure { document.issue = failure }
        catch { document.issue = MultipartFailure(String(describing: error), offset: range.lowerBound) }
        return document
    }
}

private struct MultipartDisplay {
    private(set) var lines: [String] = []
    private var used = 0
    private(set) var stopped = false

    mutating func append(_ text: String) {
        guard !stopped else { return }
        // Reserve space for the coverage footer before joining the output.
        guard text.utf8.count + 1 <= 524288 - 256 - used else { stop(); return }
        lines.append(text); used += text.utf8.count + 1
    }
    mutating func stop() {
        guard !stopped else { return }
        lines.append("[Multipart display limit (524288 bytes) reached; remaining part details are omitted. Save the body for complete bytes.]")
        stopped = true
    }
    mutating func quoted(_ data: Data) -> String? {
        // Quoted UTF-8 can expand by six; Base64 by less. Admit before encoding.
        guard data.count <= (524288 - 256 - used - 2) / 6 else { stop(); return nil }
        guard let value = String(data: data, encoding: .utf8) else { return "Base64(" + data.base64EncodedString() + ")" }
        let encoded = try? JSONSerialization.data(withJSONObject: value, options: .fragmentsAllowed)
        return encoded.map { String(decoding: $0, as: UTF8.self) }
    }

    mutating func show(_ document: MultipartDocument, bytes: Data) {
        append("Preamble: \(document.preambleBytes) bytes; epilogue: \(document.epilogueBytes) bytes observed.")
        for part in document.parts {
            guard !stopped else { break }
            append("\nPart \(part.ordinal) · body offset \(part.bodyRange.lowerBound)..<\(part.bodyRange.upperBound) · \(part.bodyRange.count) bytes · \(part.complete ? "complete" : "partial")")
            guard let rawHeaders = quoted(bytes.subdata(in: part.headerRange)) else { break }
            append("Raw headers (UTF-8; CRLF escaped): " + rawHeaders)
            let dispositions = part.headers.filter { $0.name == "content-disposition" }
            if dispositions.count == 1 {
                do {
                    let value = try MIMEValue(dispositions[0].value, kind: .disposition)
                    for (key, label) in [("name", "Field name"), ("filename", "Filename")] {
                        let parameters = value.values(key)
                        if parameters.count == 1, let name = quoted(parameters[0]) { append(label + ": " + name) }
                        else if parameters.count > 1 { append("[Duplicate \(key) parameters; \(label.lowercased()) is ambiguous.]") }
                    }
                } catch { append("[Invalid Content-Disposition parameters; original header bytes retained: \(error)]") }
            } else if dispositions.count > 1 { append("[Multiple Content-Disposition fields; field name/filename are ambiguous.]") }
            if let issue = part.issue { append("[\(issue)]") }
            if let nested = part.nested { show(nested, bytes: bytes); continue }
            let sample = bytes.subdata(in: part.bodyRange.prefix(4096))
            let types = part.headers.filter { $0.name == "content-type" }
            let parsed = types.count == 1 ? try? MIMEValue(types[0].value) : nil
            let charsetValues = parsed?.values("charset") ?? []
            let charset = charsetValues.count == 1 ? String(data: charsetValues[0], encoding: .ascii)?.lowercased() : nil
            let coding = part.headers.filter { ["content-transfer-encoding", "content-encoding"].contains($0.name) }
            let canText = types.count <= 1 && (types.isEmpty || parsed != nil) && charsetValues.count <= 1
                && (charsetValues.isEmpty || ["utf-8", "us-ascii"].contains(charset ?? "")) && coding.isEmpty
                && (charset != "us-ascii" || sample.allSatisfy { $0 < 128 })
            if canText, let value = String(data: sample, encoding: .utf8), !value.unicodeScalars.contains(where: { $0.value < 32 && ![9, 10, 13].contains($0.value) }), let quoted = quoted(sample) {
                append("UTF-8 preview (\(sample.count) of \(part.bodyRange.count) bytes)\(charsetValues.isEmpty ? " · candidate; charset not supplied" : ""): " + quoted)
            } else {
                if !coding.isEmpty { append("[Part transfer/content coding is not decoded; raw bytes shown.]") }
                if !charsetValues.isEmpty && !["utf-8", "us-ascii"].contains(charset ?? "") { append("[Unsupported or ambiguous charset; raw bytes shown.]") }
                append("Raw hex preview (\(sample.count) of \(part.bodyRange.count) bytes):\n" + BodyFormatter.hex(sample))
            }
            if sample.count < part.bodyRange.count { append("[Part preview limited; save the body for complete bytes.]") }
        }
        if document.closingSeen { append("Closing delimiter observed · \(document.parts.count) immediate parts examined.") }
        if let issue = document.issue { append("[Incomplete multipart at body offset \(issue.offset): \(issue.description)]") }
    }
}

enum MultipartFormatter {
    static func matches(contentTypes: [Data]) -> Bool {
        contentTypes.contains { (try? MIMEValue($0).token.hasPrefix("multipart/")) == true }
    }

    static func render(bytes: Data, contentTypes: [Data], truncated: Bool) -> String {
        guard contentTypes.count == 1 else { return "[Multipart unavailable: exactly one Content-Type header is required (found \(contentTypes.count)). Use Text/Hex for original preview bytes.]" }
        do {
            let type = try MIMEValue(contentTypes[0])
            guard type.token.hasPrefix("multipart/") else { return "[Content-Type is not multipart. Use Form for URL-encoded fields, or Text/Hex.]" }
            _ = try type.boundary()
            let examined = Data(bytes.prefix(2 * 1024 * 1024))
            var reader = MultipartReader(bytes: Array(examined))
            let document = reader.read(0..<examined.count, type: type, completeInput: !truncated && examined.count == bytes.count)
            var display = MultipartDisplay()
            display.append("Multipart \(type.token) · supplied body preview: \(bytes.count) bytes. Offsets refer to these decoded-body bytes.")
            if examined.count < bytes.count { display.append("[Multipart scan limit (2097152 bytes); examining \(examined.count) of \(bytes.count) supplied bytes.]") }
            display.show(document, bytes: examined)
            return display.lines.joined(separator: "\n")
        } catch { return "[Multipart unavailable: \(error). Use Text/Hex for original preview bytes.]" }
    }
}
