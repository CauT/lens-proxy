// Compile with JSONDocument.swift, BodyFormatting.swift and MultipartFormatting.swift.
// Protobuf vectors follow https://protobuf.dev/programming-guides/encoding/
// This is a schema-free wire viewer: readable bytes must never imply field types.
import Foundation

private struct FormatFailure: Error, CustomStringConvertible {
    let description: String
}

private func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
    if !condition() { throw FormatFailure(description: message) }
}

private func wire(_ bytes: [UInt8]) -> String {
    BodyFormatter.render(format: .protobuf, text: "", base64: Data(bytes).base64EncodedString(), truncated: false)
}

@main
private struct BodyFormatSmoke {
    static func main() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("lens-body-smoke-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let secret = "EXTERNAL_ENTITY_CONTENT_\(UUID().uuidString)"
        let secretURL = directory.appendingPathComponent("private-fixture.txt")
        try secret.write(to: secretURL, atomically: true, encoding: .utf8)

        var cases: [(String, () throws -> Void)] = []
        cases.append(("XML external entity is not loaded", {
                let source = "<!DOCTYPE root [<!ENTITY ext SYSTEM \"\(secretURL.absoluteString)\">]><root>&ext;</root>"
                let result = BodyFormatter.render(format: .xml, text: source, base64: nil, truncated: false)
                try require(!result.contains(secret), "Viewer loaded external file contents")
                try require(result.contains("DTD/entity") && result.contains("&ext;"), "Entity limitation or original bytes were hidden")
        }))
        cases.append(("XML internal expansion remains unexpanded", {
                let source = "<!DOCTYPE root [<!ENTITY a \"amplified\"><!ENTITY b \"&a;&a;&a;\">]><root>&b;</root>"
                let result = BodyFormatter.render(format: .xml, text: source, base64: nil, truncated: false)
                try require(result.contains("DTD/entity") && result.contains("<root>&b;</root>"), "Internal DTD was expanded")
                try require(!result.contains("amplifiedamplified"), "Internal expansion amplifier was evaluated")
        }))
        cases.append(("XML ordinary and malformed input", {
                let valid = BodyFormatter.render(format: .xml, text: "<root><item a=\"1\">value</item></root>", base64: nil, truncated: false)
                try require(valid.contains("<item a=\"1\">value</item>"), "Valid XML lost content")
                let invalid = BodyFormatter.render(format: .xml, text: "<root><unfinished>", base64: nil, truncated: false)
                try require(invalid.contains("Invalid or incomplete XML") && invalid.contains("<root><unfinished>"), "Malformed XML was silently normalized")
        }))
        cases.append(("Form keeps duplicates, plus, equals and whitespace", {
                let source = "key=one&key=two+words&literal=%2B&embedded=a%3Db&line=%0A&empty=&flag"
                let result = BodyFormatter.render(format: .form, text: source, base64: nil, truncated: false)
                try require(result.contains("1. \"key\" = \"one\"") && result.contains("2. \"key\" = \"two words\""), "Repeated fields or plus decoding were lost")
                try require(result.contains("\"literal\" = \"+\"") && result.contains("\"embedded\" = \"a=b\""), "Escaped plus or equals decoding is incorrect")
                try require(result.contains("\"line\" = \"\\n\"") && result.contains("\"empty\" = \"\""), "Whitespace or empty value is not visible")
                try require(result.contains("\"flag\" [no equals sign]"), "Missing equals sign became an empty value")
        }))
        cases.append(("Form malformed percent stays visible", {
                let source = "bad=%GG&cut=%A&utf8=%FF"
                let result = BodyFormatter.render(format: .form, text: source, base64: nil, truncated: false)
                try require(result.contains("%GG") && result.contains("%A") && result.contains("%FF"), "Invalid source percent bytes were lost")
                try require(result.components(separatedBy: "Invalid percent encoding").count == 4, "Invalid encodings were silently accepted")
                _ = BodyFormatter.render(format: .form, text: "", base64: nil, truncated: false)
                let emptyFields = BodyFormatter.render(format: .form, text: "&&x=", base64: nil, truncated: false)
                try require(emptyFields.contains("3. \"x\" = \"\""), "Empty form fields were dropped or crashed")
        }))
        cases.append(("Protobuf documented varint and maximum uint64", {
                try require(wire([0x08, 0x96, 0x01]).contains("field 1: varint 150"), "Official 150 encoding was not decoded")
                let maximum = wire([0x08] + Array(repeating: 0xff, count: 9) + [0x01])
                try require(maximum.contains("18446744073709551615"), "Maximum UInt64 overflowed or changed signedness")
                try require(maximum.contains("signedness") && maximum.contains("unknown"), "Schema uncertainty was omitted")
        }))
        cases.append(("Protobuf rejects overflow and unterminated varints", {
                let overflow: [UInt8] = [0x08] + Array(repeating: 0xff, count: 9) + [0x02]
                let unterminated: [UInt8] = [0x08] + Array(repeating: 0x80, count: 10) + [0x00]
                for source in [overflow, unterminated] {
                    let result = wire(source)
                    try require(result.contains("Stopped") && result.contains("64 bits"), "Overflowing varint was accepted")
                    try require(result.contains("Remaining bytes are not interpreted"), "Unexamined coverage was hidden")
                }
                for source: [UInt8] in [[0x08, 0x80], [0x80]] {
                    try require(wire(source).contains("truncated varint"), "Truncated varint was accepted")
                }
        }))
        cases.append(("Protobuf validates tag numbers and wire kinds", {
                for source: [UInt8] in [[0x00], [0x01], [0x80, 0x80, 0x80, 0x80, 0x10, 0x00]] {
                    try require(wire(source).contains("invalid field number"), "Field zero or larger than 29 bits was accepted")
                }
                let lastField = wire([0xf8, 0xff, 0xff, 0xff, 0x0f, 0x00])
                try require(lastField.contains("field 536870911: varint 0"), "Largest valid field number was rejected")
                for source: [UInt8] in [[0x0e], [0x0f]] {
                    try require(wire(source).contains("invalid wire type"), "Reserved wire kind was accepted")
                }
        }))
        cases.append(("Protobuf fixed widths, length bounds and candidate semantics", {
                for source: [UInt8] in [[0x0d, 1, 2, 3], [0x09, 1, 2, 3]] {
                    try require(wire(source).contains("field extends past available bytes"), "Truncated fixed field was accepted")
                }
                let fixed = wire([0x09, 0, 0, 0, 0, 0, 0, 0xf0, 0x3f, 0x15, 0, 0, 0x80, 0x3f])
                try require(fixed.contains("fixed64 little-endian bytes") && fixed.contains("fixed32 little-endian bytes"), "Fixed width wire data was not preserved")
                let unavailableLength: [UInt8] = [0x0a] + Array(repeating: 0xff, count: 9) + [1]
                for source in [[UInt8(0x0a), 4, 0xc3, 0xa9], unavailableLength] {
                    try require(wire(source).contains("length-delimited field exceeds available bytes"), "Length overflow or truncated value was accepted")
                }
                try require(wire([0x0a, 2, 0xc3, 0xa9]).contains("UTF-8 candidate"), "Readable bytes were asserted to be a declared string")
                let nestedCandidate = wire([0x1a, 3, 0x08, 0x96, 0x01])
                try require(nestedCandidate.contains("field 3") && !nestedCandidate.contains("field 1:"), "Unschematized bytes were asserted to be a submessage")
                try require(wire([0x0a, 0x00]).contains("0 bytes"), "Empty LEN value was rejected")
        }))
        cases.append(("Protobuf groups stop with an explicit limitation", {
                let grouped = wire([0x0b, 0x10, 1, 0x0c, 0x18, 2])
                try require(grouped.contains("group wire types are unsupported"), "Deprecated group support was falsely implied")
                try require(grouped.contains("Remaining bytes are not interpreted") && !grouped.contains("field 3:"), "Viewer silently skipped an unsupported group")
        }))
        cases.append(("Protobuf preserves repeated occurrence order", {
                let result = wire([0x08, 1, 0x08, 2])
                guard let first = result.range(of: "field 1: varint 1"), let second = result.range(of: "field 1: varint 2") else {
                    throw FormatFailure(description: "Repeated wire occurrences were collapsed")
                }
                try require(first.lowerBound < second.lowerBound, "Wire order changed")
        }))
        cases.append(("Protobuf display limits disclose partial coverage", {
                let largeValue = wire([0x0a, 0xac, 0x02] + Array(repeating: 0x78, count: 300))
                try require(largeValue.contains("300 bytes") && largeValue.contains("preview limited to 256 bytes"), "Value clipping was undisclosed")
                try require(largeValue.utf8.count < 1024, "Single value display grew without its advertised bound")
                let many = wire(Array(repeating: [UInt8(0x08), 1], count: 10_001).flatMap { $0 })
                try require(many.contains("Display limit reached") && many.contains("20000 of 20002"), "Field-count cutoff omitted examined-byte coverage")
                try require(many.utf8.count < 600_000, "Wire rendering exceeded its bounded display budget")
        }))
        cases.append(("Binary hex uses actual bytes and bounds expansion", {
                let bytes = Data([0x00, 0xff, 0x20, 0x7e, 0x7f])
                let result = BodyFormatter.render(format: .hex, text: "replacement text", base64: bytes.base64EncodedString(), truncated: false)
                try require(result.contains("00000000") && result.contains("00 ff 20 7e 7f"), "Hex dump used replacement text instead of byte evidence")
                try require(result.contains(".. ~."), "Hex ASCII pane mishandled nonprintable bytes")
                let limited = BodyFormatter.hex(Data(repeating: 0x41, count: 65_537))
                try require(limited.contains("limited to 65536 of 65537"), "Hex expansion cap hid discarded bytes")
                try require(limited.utf8.count < 400_000, "Hex display allocation exceeded its advertised cap")
        }))
        cases.append(("Truncation remains explicit in every viewer", {
                for format in BodyFormat.allCases {
                    let result = BodyFormatter.render(format: format, text: "", base64: nil, truncated: true)
                    try require(result.hasPrefix("[Body preview is truncated;"), "\(format) omitted preview truncation")
                }
        }))
        cases.append(("JSON and XML formatting budgets preserve source evidence", {
                let nestedJSON = String(repeating: "[", count: 40) + "0" + String(repeating: "]", count: 40)
                let nestedXML = String(repeating: "<node>", count: 40) + "value" + String(repeating: "</node>", count: 40)
                for (format, source): (BodyFormat, String) in [(.json, nestedJSON), (.xml, nestedXML)] {
                    let result = BodyFormatter.render(format: format, text: source, base64: nil, truncated: false)
                    try require(result.contains("display budget exceeded") && result.contains("Showing source text"), "Deep \(format) did not disclose its formatting limit")
                    try require(result.hasSuffix(source), "Deep \(format) discarded or normalized the source fallback")
                }
                let manyNodes = "[" + Array(repeating: "0", count: 50_001).joined(separator: ",") + "]"
                let nodeResult = BodyFormatter.render(format: .json, text: manyNodes, base64: nil, truncated: false)
                try require(nodeResult.contains("display budget exceeded") && nodeResult.hasSuffix(manyNodes), "Wide JSON bypassed its node-count budget or lost source")
                let largeScalar = "\"" + String(repeating: "x", count: 710_000) + "\""
                try require(BodyFormatter.render(format: .json, text: largeScalar, base64: nil, truncated: false) == largeScalar,
                            "A large scalar fitting the actual display budget was rejected")
                let expansive = String(repeating: "[", count: 32) + String(repeating: "0,", count: 40_000)
                    + "\"" + String(repeating: "x", count: 1_800_000) + "\"" + String(repeating: "]", count: 32)
                let byteResult = BodyFormatter.render(format: .json, text: expansive, base64: nil, truncated: false)
                try require(byteResult.contains("display budget exceeded") && byteResult.hasSuffix(expansive), "Large actual output bypassed its display budget or lost source")
        }))
        cases.append(("Malformed base64 cannot silently become replacement byte evidence", {
                for format: BodyFormat in [.hex, .protobuf] {
                    let result = BodyFormatter.render(format: format, text: "fallback-text", base64: "%%%invalid%%", truncated: false)
                    try require(result.lowercased().contains("base64") &&
                                (result.lowercased().contains("invalid") || result.lowercased().contains("unavailable")),
                                "\(format) silently used text bytes after a malformed encoded byte payload")
                }
        }))
        cases.append(("Form expansion is bounded before splitting and UTF-8 evidence stays explicit", {
            let separators = String(repeating: "&", count: 200_000)
            let limited = BodyFormatter.render(format: .form, text: separators, base64: nil, truncated: false)
            try require(limited.contains("display limit reached") && limited.contains("200000 source bytes") && limited.utf8.count < 512 * 1024, "Form separators expanded without a disclosed rendering budget")
            let huge = "name=" + String(repeating: "x", count: 100_000)
            try require(BodyFormatter.render(format: .form, text: huge, base64: nil, truncated: false).contains("examined 0"), "Oversized field was allocated/quoted before budget admission")
            let unicode = BodyFormatter.render(format: .form, text: "a=1&\u{301}=2", base64: nil, truncated: false)
            try require(unicode.contains("2.") && unicode.contains("= \"2\""), "Form delimiter was parsed as a grapheme rather than an ASCII protocol byte")
            let invalid = Data([0xff]).base64EncodedString()
            try require(BodyFormatter.render(format: .xml, text: "replacement", base64: invalid, truncated: false).contains("UTF-8 source"), "XML silently parsed replacement text as original bytes")
            try require(BodyFormatter.render(format: .form, text: "replacement", base64: invalid, truncated: false).contains("UTF-8 source"), "Form silently parsed replacement text as original bytes")
            let json = Data("{\"actual\":1}".utf8).base64EncodedString()
            try require(BodyFormatter.render(format: .json, text: "replacement", base64: json, truncated: false).contains("actual"), "JSON parser ignored actual encoded byte evidence")
        }))
        var failures: [String] = []
        for (name, test) in cases {
            do {
                try test()
                print("PASS: \(name)")
            } catch {
                failures.append("\(name): \(error)")
                print("FAIL: \(name): \(error)")
            }
        }
        print("Body formatter smoke: \(cases.count - failures.count)/\(cases.count) passed")
        if !failures.isEmpty { throw FormatFailure(description: failures.joined(separator: "\n")) }
    }
}
