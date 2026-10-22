import Foundation

enum BodyFormat: String, CaseIterable, Identifiable {
    case text, json, xml, form, multipart, hex, protobuf
    var id: String { rawValue }
    var label: String {
        switch self {
        case .text: return "Text"
        case .json: return "JSON"
        case .xml: return "XML"
        case .form: return "Form"
        case .multipart: return "Multipart"
        case .hex: return "Hex"
        case .protobuf: return "Protobuf wire"
        }
    }
}

enum BodyFormatter {
    static func preferredFormat(binary: Bool, contentTypes: [Data]) -> BodyFormat {
        if MultipartFormatter.matches(contentTypes: contentTypes) { return .multipart }
        return binary ? .hex : .json
    }

    private struct FormattingLimit: Error {}
    private final class DisplayBudget {
        var remaining = 4 * 1024 * 1024
        var nodes = 0
        func admit(_ size: Int, depth: Int) throws {
            nodes += 1
            guard depth <= 32, nodes <= 50_000, size <= remaining else { throw FormattingLimit() }
            remaining -= size
        }
        func json(_ value: Any, depth: Int = 0) throws {
            try admit(depth * 2 + 16, depth: depth)
            if let value = value as? String { try admit(value.utf8.count * 6, depth: depth) }
            else if let values = value as? [Any] { for value in values { try json(value, depth: depth + 1) } }
            else if let values = value as? [String: Any] {
                for (key, value) in values { try admit(key.utf8.count * 6 + 4, depth: depth); try json(value, depth: depth + 1) }
            }
        }
        func xml(_ node: XMLNode, depth: Int = 0) throws {
            try admit(depth * 4 + 32 + (node.name?.utf8.count ?? 0) * 2, depth: depth)
            if [.text, .comment, .attribute, .processingInstruction, .namespace].contains(node.kind) {
                try admit((node.stringValue?.utf8.count ?? 0) * 6, depth: depth)
            }
            if let element = node as? XMLElement {
                for attribute in element.attributes ?? [] { try xml(attribute, depth: depth + 1) }
                for namespace in element.namespaces ?? [] { try xml(namespace, depth: depth + 1) }
            }
            for child in node.children ?? [] { try xml(child, depth: depth + 1) }
        }
    }
    static func render(format: BodyFormat, text: String, base64: String?, truncated: Bool, contentTypes: [Data] = []) -> String {
        let bytes: Data
        if let base64 {
            guard let decoded = Data(base64Encoded: base64) else { return "[Invalid base64 body bytes; the binary representation cannot be interpreted.]" }
            bytes = decoded
        } else { bytes = Data(text.utf8) }
        let prefix = truncated ? "[Body preview is truncated; save the body for complete bytes.]\n\n" : ""
        switch format {
        case .text: return prefix + text
        case .json:
            do {
                let object = try JSONSerialization.jsonObject(with: bytes, options: .fragmentsAllowed)
                try DisplayBudget().json(object)
                let data = try JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys, .fragmentsAllowed])
                return prefix + String(decoding: data, as: UTF8.self)
            } catch is FormattingLimit { return prefix + "[Pretty-print display budget exceeded: 32 levels, 50,000 nodes or 4 MiB estimated output. Showing source text.]\n\n" + text
            } catch { return prefix + "[Invalid or incomplete JSON: \(error.localizedDescription)]\n\n" + text }
        case .xml:
            guard let text = String(data: bytes, encoding: .utf8) else { return prefix + "[XML viewer requires UTF-8 source bytes. Use Hex or save the complete body for other encodings.]" }
            // External entities never load. DTDs are deliberately outside this
            // viewer: internal entity expansion can amplify a small preview.
            guard !text.contains("<!DOCTYPE"), !text.contains("<!ENTITY") else {
                return prefix + "[XML with a DTD/entity declaration is displayed as text.]\n\n" + text
            }
            do {
                let document = try XMLDocument(xmlString: text, options: [.nodeLoadExternalEntitiesNever])
                try DisplayBudget().xml(document)
                return prefix + document.xmlString(options: .nodePrettyPrint)
            } catch is FormattingLimit { return prefix + "[Pretty-print display budget exceeded: 32 levels, 50,000 nodes or 4 MiB estimated output. Showing source text.]\n\n" + text
            } catch { return prefix + "[Invalid or incomplete XML: \(error.localizedDescription)]\n\n" + text }
        case .form:
            return prefix + form(bytes)
        case .multipart: return prefix + MultipartFormatter.render(bytes: bytes, contentTypes: contentTypes, truncated: truncated)
        case .hex: return prefix + hex(bytes)
        case .protobuf:
            var reader = ProtobufWireReader(bytes: Array(bytes))
            return prefix + reader.render()
        }
    }

    private static func form(_ data: Data) -> String {
        guard String(data: data, encoding: .utf8) != nil else { return "[Form viewer requires UTF-8 source bytes. Use Hex or save the body.]" }
        let bytes = Array(data)
        var start = 0, used = 0, lines: [String] = []
        while true {
            let end = bytes[start...].firstIndex(of: 0x26) ?? bytes.endIndex
            // Bound expansion before allocating decoded fields or quoted lines.
            let estimate = (end - start) * 6 + 96
            if lines.count >= 10_000 || used + estimate > 512 * 1024 {
                lines.append("[Form display limit reached; examined \(start) of \(bytes.count) source bytes. Save the body for complete data.]")
                break
            }
            let field = bytes[start..<end]
            let equals = field.firstIndex(of: 0x3d)
            func decoded(_ raw: ArraySlice<UInt8>) -> String {
                let value = String(decoding: raw, as: UTF8.self).replacingOccurrences(of: "+", with: " ")
                return value.removingPercentEncoding ?? "[Invalid percent encoding or non-UTF-8 sequence] " + String(decoding: raw, as: UTF8.self)
            }
            func quoted(_ value: String) -> String {
                let data = try? JSONSerialization.data(withJSONObject: value, options: .fragmentsAllowed)
                return data.map { String(decoding: $0, as: UTF8.self) } ?? value
            }
            let name = quoted(decoded(bytes[start..<(equals ?? end)]))
            lines.append("\(lines.count + 1). \(name)" + (equals.map { " = " + quoted(decoded(bytes[($0 + 1)..<end])) } ?? " [no equals sign]"))
            used += estimate
            if end == bytes.endIndex { break }
            start = end + 1
        }
        return lines.joined(separator: "\n")
    }

    static func hex(_ data: Data) -> String {
        let bytes = Array(data)
        // A hex dump expands each byte several times. Bound rendered output
        // independently of the engine's 2 MiB binary-preview bound.
        let count = min(bytes.count, 64 * 1024)
        let rows = stride(from: 0, to: count, by: 16).map { offset -> String in
            let row = bytes[offset..<min(offset + 16, count)]
            let digits = row.map { String(format: "%02x", $0) }.joined(separator: " ").padding(toLength: 47, withPad: " ", startingAt: 0)
            let ascii = String(row.map { (32...126).contains($0) ? Character(UnicodeScalar($0)) : "." })
            return String(format: "%08x  ", offset) + digits + "  " + ascii
        }
        return rows.joined(separator: "\n") + (count < bytes.count ? "\n[Hex display limited to \(count) of \(bytes.count) preview bytes.]" : "")
    }
}

struct BodyRenderInput: Hashable {
    let format: BodyFormat
    let text: String
    let base64: String?
    let truncated: Bool
    var contentTypes: [Data] = []
}

actor BodyRenderWorker {
    static let shared = BodyRenderWorker()
    // One renderer owns CPU work. A superseded view task skips queued parsing;
    // only the current caller publishes its result back to the interface.
    func render(_ input: BodyRenderInput) -> String? {
        guard !Task.isCancelled else { return nil }
        return BodyFormatter.render(format: input.format, text: input.text, base64: input.base64, truncated: input.truncated, contentTypes: input.contentTypes)
    }
}

private struct ProtobufWireReader {
    let bytes: [UInt8]
    var offset = 0
    private enum ParseError: Error { case invalid(String) }

    init(bytes: [UInt8]) { self.bytes = bytes }

    private mutating func varint() throws -> UInt64 {
        var result: UInt64 = 0
        for shift in stride(from: 0, through: 63, by: 7) {
            guard offset < bytes.count else { throw ParseError.invalid("truncated varint") }
            let byte = bytes[offset]; offset += 1
            guard shift != 63 || byte <= 1 else { throw ParseError.invalid("varint exceeds 64 bits") }
            result |= UInt64(byte & 0x7f) << shift
            if byte & 0x80 == 0 { return result }
        }
        throw ParseError.invalid("invalid varint")
    }

    private mutating func take(_ count: Int) throws -> ArraySlice<UInt8> {
        guard count >= 0, count <= bytes.count - offset else { throw ParseError.invalid("field extends past available bytes") }
        let result = bytes[offset..<offset + count]; offset += count; return result
    }

    mutating func render() -> String {
        var lines = ["Schema-free wire fields. Names, signedness, message types and meaning are unknown."]
        var rendered = lines[0].utf8.count
        var fields = 0
        while offset < bytes.count {
            let start = offset
            do {
                let key = try varint(), field = key >> 3, wire = key & 7
                guard field > 0, field <= 0x1fffffff else { throw ParseError.invalid("invalid field number") }
                let value: String
                switch wire {
                case 0: value = "varint \(try varint())"
                case 1, 5:
                    let data = try take(wire == 1 ? 8 : 4)
                    value = "fixed\(wire == 1 ? 64 : 32) little-endian bytes " + data.map { String(format: "%02x", $0) }.joined()
                case 2:
                    let length = try varint()
                    guard length <= UInt64(bytes.count - offset) else { throw ParseError.invalid("length-delimited field exceeds available bytes") }
                    let data = try take(Int(length)), preview = Data(data.prefix(256))
                    let suffix = data.count > preview.count ? " … [value preview limited to 256 bytes]" : ""
                    if let text = String(data: preview, encoding: .utf8), !text.unicodeScalars.contains(where: { $0.value < 32 && $0 != "\n" && $0 != "\r" && $0 != "\t" }) {
                        let quoted = try JSONSerialization.data(withJSONObject: text, options: .fragmentsAllowed)
                        value = "\(length) bytes; UTF-8 candidate " + String(decoding: quoted, as: UTF8.self) + suffix
                    } else { value = "\(length) bytes; hex " + preview.map { String(format: "%02x", $0) }.joined() + suffix }
                case 3, 4: throw ParseError.invalid("deprecated group wire types are unsupported")
                default: throw ParseError.invalid("invalid wire type \(wire)")
                }
                let line = "@\(start)  field \(field): \(value)"
                lines.append(line); fields += 1; rendered += line.utf8.count
                if rendered >= 512 * 1024 || fields >= 10_000 {
                    if offset < bytes.count { lines.append("[Display limit reached; examined \(offset) of \(bytes.count) preview bytes.]") }
                    break
                }
            } catch ParseError.invalid(let reason) {
                lines.append("[Stopped at byte \(start): \(reason). Remaining bytes are not interpreted.]"); break
            } catch { lines.append("[Stopped at byte \(start): \(error.localizedDescription)]"); break }
        }
        if bytes.isEmpty { lines.append("[Empty body]") }
        return lines.joined(separator: "\n")
    }
}
