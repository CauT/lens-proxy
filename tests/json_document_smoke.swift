import Foundation

private struct JSONTestFailure: Error { let message: String }
private func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
    if !condition() { throw JSONTestFailure(message: message) }
}
private func document(_ text: String) throws -> JSONDocument { try JSONDocument(data: Data(text.utf8)) }

@main struct JSONDocumentSmoke {
    static func main() async throws {
        let source = #"{"z":9007199254740993,"ratio":1.2300e+99,"list":[null,true,false,"x\/y"],"z":18446744073709551616}"#
        let parsed = try document(source), children = parsed.nodes[0].children
        try require(children.map { parsed.nodes[$0].name! } == ["z", "ratio", "list", "z"], "Object order or duplicate occurrences lost")
        try require(parsed.originalValue(children[0]) == "9007199254740993" && parsed.originalValue(children[3]) == "18446744073709551616", "Big integer precision lost")
        try require(parsed.formatted.contains("1.2300e+99") && parsed.formatted.contains(#""x\/y""#), "Numeric or string spelling changed")
        try require(parsed.duplicateCount == 1 && parsed.pointerIsAmbiguous(children[0]) && parsed.pointerIsAmbiguous(children[3]), "Duplicate path ambiguity hidden")
        try require(!parsed.pointerIsAmbiguous(children[1]), "Unique member became ambiguous")
        print("PASS source order, duplicate occurrence identity and exact number/escape lexemes")

        let paths = try document(#"{"a/b":{"~key":[42]},"":{"child":true}}"#)
        let number = paths.nodes.first { $0.kind == .number }!.id
        let boolean = paths.nodes.first { $0.kind == .boolean }!.id
        try require(paths.pointer(number) == "/a~1b/~0key/0" && paths.pointer(boolean) == "//child" && paths.pointer(0).isEmpty, "RFC 6901 escaping or empty keys incorrect")
        let duplicates = try document(#"{"x":{"child":1},"x":{"child":2}}"#)
        try require(duplicates.nodes.filter { $0.kind == .number }.allSatisfy { duplicates.pointerIsAmbiguous($0.id) }, "Descendant pointer ambiguity was not inherited")
        print("PASS pointers, array indices, empty keys and ambiguous ancestors")

        let unicode = try document(#"{"é":1,"e\u0301":2,"\u00e9":3,"rocket":"\ud83d\ude80","control":"\u0000\n\"\\"}"#)
        let names = unicode.nodes[0].children
        try require(unicode.duplicateCount == 1 && !unicode.nodes[names[1]].duplicateKey, "Unicode normalization merged distinct keys")
        try require(unicode.nodes[names[3]].stringValue == "🚀", "Surrogate pair decoding failed")
        try require(unicode.preview(names[4]) == #""\u0000\n\"\\""#, "Escaped control characters disappeared in tree preview")
        for span in unicode.spans {
            try require(NSMaxRange(span.range) <= unicode.formatted.utf16.count && span.range.length > 0, "Syntax span escapes UTF-16 string bounds")
        }
        let unicodeKey = unicode.spans.first { if case .key = $0.kind { return true }; return false }!
        try require((unicode.formatted as NSString).substring(with: unicodeKey.range) == "\"é\"", "Highlight range is a UTF-8 offset instead of UTF-16")
        print("PASS Unicode scalar identity, surrogate pairs, control display and highlight ranges")

        for valid in ["null", "false", "true", "-0", "-12.300e+999", "[]", "{}", "\"hello\"", " \n [1,2] \t"] { _ = try document(valid) }
        let bom = try JSONDocument(data: Data([0xef, 0xbb, 0xbf]) + Data("{\"a\":1}".utf8))
        try require(bom.hasBOM && bom.formatted.hasPrefix("{") && bom.source.utf8.starts(with: [0xef,0xbb,0xbf]), "BOM ownership changed")
        let invalid = ["", "+1", "01", "-01", "1.", "1e", "NaN", "Infinity", "[1,]", "{\"a\":1,}", "{\"a\" 1}", "true false", "[}", "\"\n\"", #""\ud800""#, #""\udc00""#, #""\ud800\u0000""#, #""\x01""#, #""unterminated"#]
        for source in invalid {
            do { _ = try document(source); throw JSONTestFailure(message: "Malformed JSON accepted: \(source)") }
            catch is JSONReadError {}
        }
        do { _ = try document("{\n\"key\": ]}"); throw JSONTestFailure(message: "Invalid input accepted") }
        catch let failure as JSONReadError { try require(failure.line == 2 && failure.offset > 0, "Error source location missing") }
        do { _ = try document("\"a\n\""); throw JSONTestFailure(message: "Unescaped control accepted") }
        catch let failure as JSONReadError { try require(failure.offset == 2 && failure.line == 1 && failure.column == 3, "Invalid control location points after the error") }
        print("PASS JSON grammar, root scalars, BOM and actionable failure positions")

        let partial = try JSONPresentation.make(text: "{}", base64: nil, truncated: true)
        try require(partial.document == nil && partial.text.hasPrefix("[Body preview is truncated;"), "Truncated source counted as a complete tree")
        let binary = try JSONPresentation.make(text: "replacement", base64: Data([0xff]).base64EncodedString(), truncated: false)
        try require(binary.document == nil && binary.text.contains("UTF-8 source"), "Invalid UTF-8 became replacement text evidence")
        let actual = try JSONPresentation.make(text: "replacement", base64: Data("{\"actual\":1}".utf8).base64EncodedString(), truncated: false)
        try require(actual.document?.nodes[1].name == "actual", "Display string overrode canonical body bytes")
        let badBase64 = try JSONPresentation.make(text: "{}", base64: "%%%", truncated: false)
        try require(badBase64.document == nil && badBase64.text.contains("base64"), "Malformed byte carrier used fallback text")
        print("PASS authoritative bytes, truncation and non-UTF-8/malformed carriers")

        let deep = String(repeating: "[", count: 34) + "0" + String(repeating: "]", count: 34)
        let wide = "[" + String(repeating: "0,", count: 50_000) + "0]"
        for source in [deep, wide] {
            let result = try JSONPresentation.make(text: source, base64: nil, truncated: false)
            try require(result.document == nil && result.issue == "JSON display limit reached" && result.text.contains("display budget exceeded") && result.text.hasSuffix(source), "Unbounded structure or lost fallback")
        }
        let oversized = try JSONPresentation.make(text: String(repeating: " ", count: JSONDocument.maxInputBytes + 1), base64: nil, truncated: false)
        try require(oversized.document == nil && oversized.text.contains("display limit"), "Input budget bypassed")
        print("PASS node/depth/input admission before unbounded work")

        let matches = try parsed.search("X/Y")
        try require(matches.count == 1 && parsed.nodes[matches[0]].stringValue == "x/y", "Search ignored decoded value or case")
        let cancelled = Task {
            try? await Task.sleep(nanoseconds: 1_000_000)
            return await BodyRenderWorker.shared.renderJSON(BodyRenderInput(format: .json, text: source, base64: nil, truncated: false))
        }
        cancelled.cancel()
        let result = await cancelled.value
        try require(result == nil, "Cancelled parse published a document")
        print("PASS decoded key/value search and cancelled worker result suppression")
        print("JSON document smoke passed")
    }
}
