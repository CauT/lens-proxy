// Independent byte vectors for RFC 2046 §5.1.1 and RFC 7578 §§4–5.
// Compile with the production BodyFormatting.swift and MultipartFormatting.swift.
// No multipart serializer/parser is reused by these fixtures.
import Foundation

private struct MultipartFailure: Error, CustomStringConvertible {
    let description: String
}

private func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
    if !condition() { throw MultipartFailure(description: message) }
}

private func display(_ body: Data, types: [String] = ["multipart/form-data; boundary=unit-boundary"], truncated: Bool = false, replacement: String = "UNRELATED_REPLACEMENT_TEXT") -> String {
    BodyFormatter.render(format: .multipart, text: replacement, base64: body.base64EncodedString(), truncated: truncated, contentTypes: types.map { Data($0.utf8) })
}

private func bytes(_ text: String) -> Data { Data(text.utf8) }

private func envelope(_ headers: String, _ body: Data, boundary: String = "unit-boundary") -> Data {
    bytes("--\(boundary)\r\n\(headers)\r\n\r\n") + body + bytes("\r\n--\(boundary)--\r\n")
}

private func ordered(_ text: String, _ needles: [String]) -> Bool {
    var remaining = text.startIndex..<text.endIndex
    for needle in needles {
        guard let found = text.range(of: needle, range: remaining) else { return false }
        remaining = found.upperBound..<text.endIndex
    }
    return true
}

private func diagnostic(_ result: String, _ keywords: [String]) -> Bool {
    let lower = result.lowercased()
    return keywords.contains { lower.contains($0.lowercased()) }
}

@main
private struct MultipartFormatSmoke {
    static func main() throws {
        var cases: [(String, () throws -> Void)] = []
        cases.append(("Repeated fields and header occurrences keep wire order", {
            let source = "--unit-boundary\r\nContent-Disposition: form-data; name=repeat\r\nX-Order: first\r\nX-Order: second\r\n\r\nVALUE_ONE\r\n--unit-boundary\r\nContent-Disposition: form-data; name=repeat\r\n\r\nVALUE_TWO\r\n--unit-boundary--\r\n"
            let result = display(bytes(source))
            try require(ordered(result, ["X-Order: first", "X-Order: second", "VALUE_ONE", "VALUE_TWO"]), "Repeated fields or headers were dropped/reordered")
            try require(result.components(separatedBy: "Field name: \"repeat\"").count == 3, "Repeated field names were collapsed or hidden")
            try require(!result.contains("UNRELATED_REPLACEMENT_TEXT"), "Structured facts came from replacement text")
        }))
        cases.append(("Quoted parameters keep semicolons and escaped quotes", {
            let result = display(envelope("Content-Disposition: form-data; name=upload; filename=\"a;\\\"b.bin\"\r\nContent-Type: text/plain; charset=\"UTF-8\"", bytes("QUOTED_FILE_VALUE")), types: ["MULTIPART/Form-Data; ignored=\"a;b\"; BOUNDARY=\"unit-boundary\""])
            try require(result.contains("QUOTED_FILE_VALUE") && result.contains("Filename: \"a;\\\"b.bin\""), "Quoted parameter separator or escaped quote broke parsing")
            try require(!diagnostic(result, ["invalid boundary", "missing boundary"]), "Valid quoted boundary was rejected")
        }))
        cases.append(("Missing and ambiguous media types never guess body boundary", {
            let source = envelope("Content-Disposition: form-data; name=x", bytes("DO_NOT_GUESS_VALUE"))
            for types in [[], ["multipart/form-data"], ["text/plain"], ["multipart/form-data; boundary=unit-boundary", "multipart/form-data; boundary=unit-boundary"]] as [[String]] {
                let result = display(source, types: types)
                try require(diagnostic(result, ["content-type", "boundary", "multipart"]), "Missing/ambiguous type omitted diagnostic")
                try require(!result.contains("Part 1"), "Viewer guessed a boundary despite missing/ambiguous Content-Type")
            }
        }))
        cases.append(("Invalid and duplicate boundary parameters fail closed", {
            let source = envelope("Content-Disposition: form-data; name=x", bytes("VALUE"))
            for value in ["multipart/form-data; boundary=", "multipart/form-data; boundary=unit-boundary; boundary=unit-boundary", "multipart/form-data; boundary=\"unterminated", "multipart/form-data; boundary=\"bad \"", "multipart/form-data; boundary=\"bad\\\"quote\"", "multipart/form-data; boundary=\"" + String(repeating: "x", count: 71) + "\""] {
                let result = display(source, types: [value])
                try require(diagnostic(result, ["boundary", "content-type", "MIME"]), "Invalid boundary omitted reason for \(value): \(result)")
                try require(!result.contains("Part 1"), "Invalid boundary produced invented part facts")
            }
        }))
        cases.append(("Preamble and epilogue stay outside part bytes", {
            let prefix = bytes("é preamble\r\n")
            let header = "Content-Disposition: form-data; name=x"
            let source = prefix + envelope(header, bytes("ONLY_PART_VALUE")) + bytes("epilogue unrelated")
            let result = display(source)
            let offset = prefix.count + bytes("--unit-boundary\r\n\(header)\r\n\r\n").count
            try require(result.contains("ONLY_PART_VALUE") && result.contains("15 bytes"), "Preamble/epilogue leaked into part length")
            try require(result.contains("body offset \(offset)"), "Part offset counted decoded characters instead of source bytes")
            try require(diagnostic(result, ["preamble"]) && diagnostic(result, ["epilogue"]), "Envelope coverage was hidden")
        }))
        cases.append(("CRLF belongs to boundary while preceding body CRLF is retained", {
            let body = bytes("FIRST\r\nSECOND\r\n")
            let result = display(envelope("Content-Disposition: form-data; name=x", body))
            try require(result.contains("\(body.count) bytes"), "Parser stripped body-owned CRLF or counted delimiter CRLF")
            try require(result.contains("FIRST") && result.contains("SECOND"), "Line-oriented body was changed")
        }))
        cases.append(("False delimiter prefixes and non-line markers remain body bytes", {
            let body = bytes("A--unit-boundary\r\nB\r\n--unit-boundaryXYZ\r\nC\r\n--unit-boundary--XYZ\r\nD")
            let result = display(envelope("Content-Disposition: form-data; name=x", body))
            try require(result.contains("\(body.count) bytes") && result.contains("--unit-boundaryXYZ") && result.contains("--unit-boundary--XYZ"), "Boundary prefix was mistaken for a MIME delimiter")
        }))
        cases.append(("Transport padding and no final CRLF are accepted", {
            let source = bytes("--unit-boundary \t\r\nContent-Disposition: form-data; name=x\r\n\r\nPADDED_VALUE\r\n--unit-boundary-- \t")
            let result = display(source)
            try require(result.contains("PADDED_VALUE") && !diagnostic(result, ["missing closing", "incomplete closing"]), "RFC transport padding or EOF close delimiter was rejected")
        }))
        cases.append(("Empty part body and absent optional headers remain distinct", {
            let empty = display(envelope("Content-Disposition: form-data; name=empty", Data()))
            try require(empty.contains("0 bytes") && empty.contains("Part 1"), "Empty field body was dropped")
            let headerless = display(bytes("--unit-boundary\r\n\r\nHEADERLESS_VALUE\r\n--unit-boundary--\r\n"))
            try require(headerless.contains("HEADERLESS_VALUE") && headerless.contains("Part 1"), "Legal MIME part without headers was rejected")
            let colon = display(envelope("Content-Disposition: form-data; name=x", bytes("COLON_BOUNDARY"), boundary: "boundary:with:colon"), types: ["multipart/form-data; boundary=\"boundary:with:colon\""])
            try require(colon.contains("COLON_BOUNDARY"), "Quoted RFC boundary punctuation was rejected")
        }))
        cases.append(("Binary parts use original bytes and never replacement text", {
            let body = Data([0x00, 0xff, 0x0d, 0x0a, 0x80, 0x41])
            let result = display(envelope("Content-Disposition: form-data; name=file; filename=x.bin\r\nContent-Type: application/octet-stream", body))
            try require(result.contains("00 ff 0d 0a 80 41") && result.contains("6 bytes"), "Binary evidence was replaced or transcoded")
            try require(!result.contains("UNRELATED_REPLACEMENT_TEXT"), "Replacement text became binary evidence")
        }))
        cases.append(("Invalid text bytes and unsupported charset retain raw hex", {
            for (type, body) in [("text/plain; charset=UTF-8", Data([0xff, 0x41])), ("text/plain; charset=US-ASCII", Data([0xc3, 0xa9])), ("text/plain; charset=ISO-8859-1", Data([0xe9]))] {
                let result = display(envelope("Content-Disposition: form-data; name=x\r\nContent-Type: \(type)", body))
                try require(result.contains("Raw hex preview"), "Unsupported/invalid charset was silently decoded")
                try require(!result.contains("�"), "Lossy replacement character hid source bytes")
            }
            let undeclared = display(envelope("Content-Disposition: form-data; name=x", bytes("é")))
            try require(undeclared.contains("candidate") && undeclared.contains("charset not supplied") && !undeclared.contains("�"), "Undeclared strict UTF-8 was asserted to be a declared charset rather than an explicitly uncertain candidate")
        }))
        cases.append(("Declared UTF-8 text is readable without changing source offsets", {
            let body = bytes("é 中文")
            let result = display(envelope("Content-Disposition: form-data; name=x\r\nContent-Type: text/plain; charset=UTF-8", body))
            try require(result.contains("é 中文") && result.contains("\(body.count) bytes"), "Declared UTF-8 text or byte count changed")
        }))
        cases.append(("Transfer-encoded data stays raw with explicit limitation", {
            for coding in ["base64", "quoted-printable", "x-unknown"] {
                let result = display(envelope("Content-Disposition: form-data; name=x\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: \(coding)", bytes("SEVMTE8=")))
                try require(diagnostic(result, ["transfer", "encoding"]) && result.contains("Raw hex preview"), "Transfer coding was decoded without supported authority")
                try require(!result.contains("HELLO"), "Transfer coding silently changed evidence bytes")
            }
        }))
        cases.append(("Duplicate interpretation parameters remain ambiguous", {
            let duplicateName = display(envelope("Content-Disposition: form-data; name=one; name=two", bytes("VALUE")))
            try require(duplicateName.contains("ambiguous") && !duplicateName.contains("Field name:"), "Duplicate name parameters selected an arbitrary identity")
            let duplicateFilename = display(envelope("Content-Disposition: form-data; name=file; filename=one; filename=two", bytes("VALUE")))
            try require(duplicateFilename.contains("ambiguous") && !duplicateFilename.contains("Filename:"), "Duplicate filename parameters selected an arbitrary file identity")
            let duplicateDisposition = display(envelope("Content-Disposition: form-data; name=one\r\nContent-Disposition: form-data; name=two", bytes("VALUE")))
            try require(duplicateDisposition.contains("ambiguous") && !duplicateDisposition.contains("Field name:"), "Duplicate disposition fields selected an arbitrary identity")
            let duplicateCharset = display(envelope("Content-Type: text/plain; charset=UTF-8; charset=US-ASCII", bytes("VALUE")))
            try require(duplicateCharset.contains("ambiguous charset") && duplicateCharset.contains("Raw hex preview"), "Duplicate charset parameters selected an arbitrary decoder")
            let duplicateType = display(envelope("Content-Type: text/plain; charset=UTF-8\r\nContent-Type: application/octet-stream", bytes("VALUE")))
            try require(duplicateType.contains("Multiple Content-Type") && duplicateType.contains("Raw hex preview"), "Duplicate Content-Type fields selected an arbitrary decoder")
        }))
        cases.append(("Missing closing delimiter preserves established part facts", {
            let source = bytes("--unit-boundary\r\nContent-Disposition: form-data; name=first\r\n\r\nFIRST_VALID\r\n--unit-boundary\r\nContent-Disposition: form-data; name=last\r\n\r\nLAST_PARTIAL")
            let result = display(source)
            try require(result.contains("FIRST_VALID") && result.contains("LAST_PARTIAL"), "Incomplete envelope discarded prior facts or current partial bytes")
            try require(diagnostic(result, ["partial", "incomplete", "missing closing"]), "Missing final boundary appeared complete")
        }))
        cases.append(("Truncated source cannot advertise whole-body completeness", {
            let result = display(envelope("Content-Disposition: form-data; name=x", bytes("VALUE")), truncated: true)
            try require(result.hasPrefix("[Body preview is truncated;"), "Source truncation was hidden")
            try require(diagnostic(result, ["partial", "truncated"]), "Complete preview delimiter overruled capture truncation")
            let cut = bytes("--unit-boundary\r\nContent-Disposition: form-data; name=x\r\n\r\nVALUE\r\n--unit-boun")
            try require(diagnostic(display(cut, truncated: true), ["partial", "incomplete"]), "Boundary cut at preview edge was claimed complete")
        }))
        cases.append(("Malformed later headers keep earlier part facts", {
            let source = bytes("--unit-boundary\r\nContent-Disposition: form-data; name=first\r\n\r\nFIRST_RETAINED\r\n--unit-boundary\r\nnot a header\r\n\r\nUNKNOWN_BODY\r\n--unit-boundary--\r\n")
            let result = display(source)
            try require(result.contains("FIRST_RETAINED") && diagnostic(result, ["malformed", "invalid header", "invalid part header"]), "Malformed later header silently lost proven earlier part")
        }))
        cases.append(("LF-only pseudo framing cannot manufacture part facts", {
            let source = bytes("--unit-boundary\nContent-Disposition: form-data; name=x\n\nFALSE_PART\n--unit-boundary--\n")
            let result = display(source)
            try require(!result.contains("Part 1") && diagnostic(result, ["boundary", "delimiter", "CRLF"]), "LF-only pseudo-delimiter was silently treated as MIME framing")
        }))
        cases.append(("Nested multipart obeys its own boundary and absolute offsets", {
            let inner = envelope("Content-Disposition: attachment; name=inside\r\nContent-Type: text/plain; charset=UTF-8", bytes("INNER_VALUE"), boundary: "nested-boundary")
            let outerHeader = "Content-Disposition: form-data; name=outside\r\nContent-Type: multipart/mixed; boundary=nested-boundary"
            let source = envelope(outerHeader, inner)
            let result = display(source)
            let marker = bytes("INNER_VALUE")
            guard let range = source.range(of: marker) else { throw MultipartFailure(description: "Broken nested fixture") }
            try require(result.contains("INNER_VALUE") && result.contains("body offset \(range.lowerBound)"), "Nested body offset was relative rather than source-global")
        }))
        cases.append(("Nested depth is bounded and undisplayed data remains explicit", {
            var source = envelope("Content-Disposition: attachment; name=end", bytes("DEEPEST_SENTINEL"), boundary: "level10")
            for index in (0..<10).reversed() {
                source = envelope("Content-Type: multipart/mixed; boundary=level\(index + 1)", source, boundary: "level\(index)")
            }
            let result = display(source, types: ["multipart/mixed; boundary=level0"])
            try require(diagnostic(result, ["depth", "nesting"]) && diagnostic(result, ["limit", "unsupported"]), "Untrusted nesting bypassed the depth bound")
            try require(result.utf8.count <= 512 * 1024, "Depth-limited output exceeded total budget")
        }))
        cases.append(("Outer delimiter recovers from an unclosed nested multipart", {
            let source = bytes("--unit-boundary\r\nContent-Type: multipart/mixed; boundary=inside\r\n\r\n--inside\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\nINNER_PARTIAL\r\n--unit-boundary\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\nOUTER_SIBLING\r\n--unit-boundary--\r\n")
            let result = display(source)
            try require(result.contains("INNER_PARTIAL") && result.contains("OUTER_SIBLING"), "Malformed nested closure swallowed an established outer sibling")
            try require(diagnostic(result, ["partial", "missing closing"]), "Unclosed nested multipart was called complete")
        }))
        cases.append(("Encoded nested multipart is never silently parsed or decoded", {
            let inner = envelope("Content-Disposition: attachment; name=inner", bytes("NESTED_ENCODED_VALUE"), boundary: "inside")
            for coding in ["Content-Transfer-Encoding: base64", "Content-Encoding: gzip"] {
                let source = envelope("Content-Type: multipart/mixed; boundary=inside\r\n\(coding)", inner)
                let result = display(source)
                try require(!result.contains("Part 1.1") && result.contains("Raw hex preview") && result.contains("not decoded"), "Encoded nested body was interpreted without first owning its encoding")
            }
        }))
        cases.append(("Part header size is checked before rendering giant values", {
            let result = display(envelope("X-Giant: " + String(repeating: "a", count: 65_537), bytes("UNADMITTED_BODY")))
            try require(diagnostic(result, ["header"]) && diagnostic(result, ["limit", "large", "65536"]), "Oversized header lacked bound diagnostic")
            try require(result.utf8.count < 16 * 1024, "Oversized header was expanded before admission")
        }))
        cases.append(("Per-part preview cutoff discloses full byte length", {
            let body = bytes(String(repeating: "a", count: 4096) + "TAIL_NOT_PREVIEWED")
            let result = display(envelope("Content-Disposition: form-data; name=x\r\nContent-Type: text/plain; charset=UTF-8", body))
            try require(result.contains("\(body.count) bytes") && result.contains("4096") && diagnostic(result, ["preview", "limited"]), "Part preview clipped bytes without disclosed coverage")
            try require(!result.contains("TAIL_NOT_PREVIEWED"), "Per-part preview exceeded 4 KiB")
            let splitCharacter = bytes(String(repeating: "a", count: 4095) + "éTAIL_NOT_PREVIEWED")
            let splitResult = display(envelope("Content-Type: text/plain; charset=UTF-8", splitCharacter))
            try require(!splitResult.contains("�") && !splitResult.contains("TAIL_NOT_PREVIEWED"), "Preview cutoff fabricated invalid UTF-8 replacement characters or leaked unpreviewed bytes")
        }))
        cases.append(("Global part and output budgets bound wide multipart input", {
            let one = "--unit-boundary\r\nContent-Disposition: form-data; name=x\r\n\r\nx\r\n"
            let many = display(bytes(String(repeating: one, count: 300) + "--unit-boundary--\r\n"))
            try require(diagnostic(many, ["limit"]) && many.contains("256"), "Part count limit was not disclosed")
            try require(many.utf8.count <= 512 * 1024, "Part-limited result exceeded total output budget")
            let largePart = "--unit-boundary\r\nContent-Disposition: form-data; name=x\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n" + String(repeating: "v", count: 4096) + "\r\n"
            let wide = display(bytes(String(repeating: largePart, count: 200) + "--unit-boundary--\r\n"))
            try require(wide.utf8.count <= 512 * 1024 && diagnostic(wide, ["limit", "budget"]), "Output budget was applied after unbounded serialization")
        }))
        cases.append(("Malformed encoded bytes fail before multipart interpretation", {
            let result = BodyFormatter.render(format: .multipart, text: "--unit-boundary\r\n\r\nGUESS\r\n--unit-boundary--", base64: "not!base64", truncated: false, contentTypes: [bytes("multipart/form-data; boundary=unit-boundary")])
            try require(diagnostic(result, ["base64"]) && !result.contains("Part 1"), "Malformed base64 fell back to replacement text")
        }))
        cases.append(("Automatic viewer selection uses parsed MIME ownership", {
            for value in ["multipart/form-data; boundary=unit-boundary", "MULTIPART/Form-Data; ignored=\"semi;colon\"; boundary=\"unit-boundary\"", "multipart/form-data;\r\n\tboundary=\"unit-boundary\""] {
                try require(BodyFormatter.preferredFormat(binary: true, contentTypes: [bytes(value)]) == .multipart, "Valid quoted/folded multipart header was not recognized")
            }
            for value in ["multipartx/form-data; boundary=unit-boundary", "text/plain; note=\"multipart/form-data\"", "multipart/form-data; boundary=\"unterminated", "multipart/"] {
                try require(BodyFormatter.preferredFormat(binary: true, contentTypes: [bytes(value)]) == .hex, "Raw textual prefix selected multipart without a valid MIME value")
                try require(BodyFormatter.preferredFormat(binary: false, contentTypes: [bytes(value)]) == .json, "Invalid/nonmultipart type changed the normal text viewer default")
            }
        }))
        cases.append(("Render identity includes ordered Content-Type evidence", {
            let source = envelope("Content-Disposition: form-data; name=x", bytes("VALUE"))
            let encoded = source.base64EncodedString()
            let first = BodyRenderInput(format: .multipart, text: "", base64: encoded, truncated: false, contentTypes: [bytes("multipart/form-data; boundary=unit-boundary")])
            let second = BodyRenderInput(format: .multipart, text: "", base64: encoded, truncated: false, contentTypes: [bytes("multipart/form-data; boundary=different")])
            let absent = BodyRenderInput(format: .multipart, text: "", base64: encoded, truncated: false)
            let repeated = BodyRenderInput(format: .multipart, text: "", base64: encoded, truncated: false, contentTypes: first.contentTypes + second.contentTypes)
            let reversed = BodyRenderInput(format: .multipart, text: "", base64: encoded, truncated: false, contentTypes: second.contentTypes + first.contentTypes)
            try require(Set([first, second, absent, repeated, reversed]).count == 5, "Renderer task/cache identity ignored boundary or duplicate header order")
            let missing = display(source, types: [])
            try require(missing.contains("exactly one Content-Type") && !missing.contains("Part 1"), "Absent Content-Type reused a previously parsed boundary")
            let invalid = BodyFormatter.render(format: .multipart, text: String(decoding: source, as: UTF8.self), base64: "bad!!base64", truncated: false, contentTypes: first.contentTypes)
            try require(invalid.contains("Invalid base64") && !invalid.contains("Part 1"), "Invalid byte evidence reused prior structured facts")
        }))
        cases.append(("MIME token validity belongs to its header context", {
            let source = envelope("Content-Disposition: form-data; name=valid", bytes("VALUE"))
            for value in ["multipart; boundary=unit-boundary", "multipart/; boundary=unit-boundary"] {
                let result = display(source, types: [value])
                try require(result.contains("Invalid MIME") && !result.contains("Part 1"), "Root Content-Type without a subtype produced multipart facts")
                try require(BodyFormatter.preferredFormat(binary: true, contentTypes: [bytes(value)]) == .hex, "Invalid media type was mistaken for a valid disposition token")
            }
            for value in ["text; charset=UTF-8", "text/plain/extra; charset=UTF-8"] {
                let result = display(envelope("Content-Type: \(value)", bytes("VALUE")))
                try require(result.contains("Invalid part Content-Type") && result.contains("Raw hex preview"), "Invalid part media type asserted a declared text charset")
                try require(!result.contains("UTF-8 preview"), "Invalid Content-Type escaped raw-byte interpretation")
            }
            let disposition = display(envelope("Content-Disposition: bad/type; name=INCORRECT_IDENTITY", bytes("VALUE")))
            try require(disposition.contains("Invalid Content-Disposition") && !disposition.contains("Field name:"), "Invalid slash-containing disposition produced a field identity")
        }))
        cases.append(("Illegal header controls retain earlier proven parts", {
            let first = bytes("--unit-boundary\r\nContent-Disposition: form-data; name=first\r\n\r\nPROVEN_FIRST_PART\r\n--unit-boundary\r\nX-Bad: before")
            let suffix = bytes("after\r\nContent-Disposition: form-data; name=UNPROVEN_SECOND\r\n\r\nUNPROVEN_BODY\r\n--unit-boundary--\r\n")
            for control: UInt8 in [0x00, 0x0a, 0x0b, 0x0d, 0x1f, 0x7f] {
                let result = display(first + Data([control]) + suffix)
                try require(result.contains("PROVEN_FIRST_PART") && result.contains("Invalid control byte"), "Invalid header control was accepted or erased earlier proven facts")
                try require(!result.contains("Field name: \"UNPROVEN_SECOND\""), "Unparsed malformed part advertised a field identity")
            }
        }))
        cases.append(("Only known complete input can authorize an EOF closing delimiter", {
            let prefix = bytes("--unit-boundary\r\nContent-Disposition: form-data; name=x\r\n\r\nVALUE\r\n--unit-boundary--")
            let complete = display(prefix)
            try require(complete.contains("Closing delimiter observed") && complete.contains("· complete"), "Known complete MIME input rejected a legal EOF closing delimiter")
            let truncated = display(prefix, truncated: true)
            try require(!truncated.contains("Closing delimiter observed") && truncated.contains("· partial"), "Truncated preview EOF authorized a delimiter that may continue with non-framing bytes")
            let opening = bytes("--unit-boundary\r\nContent-Disposition: form-data; name=x\r\n\r\n")
            let ending = bytes("\r\n--unit-boundary--")
            let cappedSource = opening + Data(repeating: 0x61, count: 2 * 1024 * 1024 - opening.count - ending.count) + ending + bytes("XYZ")
            let capped = display(cappedSource)
            try require(capped.contains("scan limit") && !capped.contains("Closing delimiter observed") && capped.contains("· partial"), "Internal scan-limit EOF authorized framing despite known unexamined suffix bytes")
            let inner = bytes("--inside\r\nContent-Disposition: attachment; name=inside\r\n\r\nINNER_VALUE\r\n--inside--")
            let boundedNested = display(envelope("Content-Type: multipart/mixed; boundary=inside", inner), truncated: true)
            try require(boundedNested.contains("Part 1.1") && boundedNested.contains("INNER_VALUE") && !boundedNested.contains("Missing closing delimiter"), "Confirmed complete parent part could not authorize nested EOF closure")
        }))
        cases.append(("Invalid nested boundary reports the absolute unexamined child offset", {
            for nestedType in ["multipart/mixed", "multipart/mixed; boundary=\"bad@boundary\"", "multipart/mixed; boundary=one; boundary=two"] {
                let source = bytes("--unit-boundary\r\nContent-Disposition: form-data; name=first\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n第一证明\r\n--unit-boundary\r\nContent-Type: \(nestedType)\r\n\r\nUNINTERPRETED_CHILD\r\n--unit-boundary\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\nLAST_SIBLING\r\n--unit-boundary--\r\n")
                guard let child = source.range(of: bytes("UNINTERPRETED_CHILD")) else { throw MultipartFailure(description: "Broken child-offset fixture") }
                let result = display(source)
                try require(result.contains("第一证明") && result.contains("LAST_SIBLING"), "Invalid nested boundary discarded independent outer siblings")
                try require(result.contains("[Incomplete multipart at body offset \(child.lowerBound):"), "Nested header parameter failure reported a header-relative offset as a global body position")
                try require(!result.contains("[Incomplete multipart at body offset 0:") && !result.contains("Part 2.1"), "Unexamined nested body acquired invented offset-zero or child facts")
            }
        }))
        var failures: [String] = []
        for (name, test) in cases {
            do { try test(); print("PASS: \(name)") }
            catch { failures.append("\(name): \(error)"); print("FAIL: \(name): \(error)") }
        }
        print("Multipart formatter smoke: \(cases.count - failures.count)/\(cases.count) passed")
        if !failures.isEmpty { throw MultipartFailure(description: failures.joined(separator: "\n")) }
    }
}
