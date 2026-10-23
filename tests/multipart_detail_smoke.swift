// Real proxy details -> production Foundation model -> actor/formatter.
// Compile with Models.swift, NativeJSON.swift, JSONDocument.swift, BodyFormatting.swift and
// MultipartFormatting.swift, or import the unchanged shared native test module.
import Foundation

private struct DetailFailure: Error { let reason: String }
private func require(_ condition: @autoclosure () -> Bool, _ reason: String) throws {
    if !condition() { throw DetailFailure(reason: reason) }
}

@main private struct MultipartDetailSmoke {
    static func main() async throws {
        guard CommandLine.arguments.count == 2 else { throw DetailFailure(reason: "Supply the real wire-details directory") }
        let directory = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
        var rendered: [String: [String]] = [:]
        for name in ["form-http", "nested-https", "gzip-https", "gzip-reopened", "large-http", "large-reopened"] {
            let file = directory.appendingPathComponent(name + ".json")
            let source = try Data(contentsOf: file)
            let detail = try EngineValue(JSONSerialization.jsonObject(with: source)).decode(FlowDetail.self)
            var outputs: [String] = []
            for (side, fields, text, base64, binary, truncated) in [
                ("request", detail.requestHeaderFields, detail.requestBody, detail.requestBodyBase64, detail.requestBinary ?? false, detail.requestTruncated),
                ("response", detail.responseHeaderFields, detail.responseBody, detail.responseBodyBase64, detail.responseBinary ?? false, detail.responseTruncated)
            ] {
                let types = fields.filter { $0.nameText?.lowercased() == "content-type" }.map(\.value)
                try require(BodyFormatter.preferredFormat(binary: binary, contentTypes: types) == .multipart, "Actual \(name) \(side) did not select multipart")
                let input = BodyRenderInput(format: .multipart, text: text, base64: base64, truncated: truncated, contentTypes: types)
                guard let output = await BodyRenderWorker.shared.render(input) else { throw DetailFailure(reason: "Unexpected render cancellation") }
                try require(output.contains("body offset") && output.utf8.count <= 524288, "Missing actual parts or oversized output")
                if name.hasPrefix("large") {
                    try require(truncated && output.contains("partial") && output.contains("Missing closing delimiter") && output.contains("preview is truncated"), "Partial actual body was reported complete")
                    try require(!output.contains("after-preview-cut") && !output.contains("Closing delimiter observed"), "Unobserved actual part was invented")
                    try require(output.contains("Filename: \"large.bin\"") && output.contains("Raw hex preview (4096 of"), "Actual large binary part was not inspected")
                } else if side == "request" {
                    try require(output.components(separatedBy: "Field name: \"tag\"").count == 3 && output.contains("Filename: \"a;\\\"b.bin\""), "Actual duplicate fields/quoted filename lost")
                    try require(output.contains("X-Part: one") && output.contains("X-Part: two") && output.contains("00 ff 62 69 6e 61 72 79"), "Actual duplicate part headers/binary bytes lost")
                } else {
                    let htmlVisible = output.contains("<p>html</p>") || output.contains("<p>html<\\/p>")
                    try require(output.contains("Part 2.1") && output.contains("Part 2.2") && output.contains("\u{7b2c}\u{4e00}\u{6bb5}") && htmlVisible, "Actual nested MIME response lost: " + output)
                }
                outputs.append(output)
            }
            let unchanged = try Data(contentsOf: file)
            try require(source == unchanged, "Rendering mutated a source detail")
            rendered[name] = outputs
            print("PASS: \(name) actual request and response details survive native decoding and actor multipart rendering")
        }
        try require(rendered["form-http"] == rendered["gzip-https"] && rendered["gzip-https"] == rendered["gzip-reopened"], "Top-level gzip or HAR reopen changed decoded multipart facts")
        try require(rendered["large-http"] == rendered["large-reopened"], "HAR reopen changed actual partial preview facts")
        print("PASS: actual compressed/source/reopened multipart facts agree; full source details remain unchanged")
    }
}
