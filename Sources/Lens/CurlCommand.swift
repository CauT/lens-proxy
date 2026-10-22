import Foundation

enum CurlCommand {
    static func quote(_ value: String) -> String { "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'" }
    // Adapter for explicit Unicode inputs; captured messages use prepare(raw bytes).
    static func render(method: String, url: String, proxyPort: String, headers: [[String]], bodyFile: URL?, caCert: String? = nil) throws -> String {
        guard let separator = url.range(of: "://") else { throw EngineJSONFailure.invalid("An absolute URL is required") }
        let afterAuthority = url[separator.upperBound...].firstIndex(where: { "/?#".contains($0) })
        let suffix = afterAuthority.map { String(url[$0...]) } ?? "/"
        let target = suffix.hasPrefix("/") ? suffix : "/" + suffix
        let fields = try HTTPHeaderField.decode(nil, legacy: headers, legacyHasSourceText: false)
        return try prepare(method: Data(method.utf8), url: Data(url.utf8), target: Data(target.utf8), targetForm: "relative", proxyPort: proxyPort, headers: fields, caCert: caCert).render(bodyFile: bodyFile)
    }
    struct Plan {
        let parts: [String]
        func render(bodyFile: URL?) -> String {
            (parts + (bodyFile.map { ["--data-binary", CurlCommand.quote("@" + $0.path)] } ?? [])).joined(separator: " ")
        }
    }
    static func byteQuote(_ bytes: Data) -> String { "$'" + bytes.map { String(format: "\\x%02x", $0) }.joined() + "'" }
    static func prepare(method: Data, url: Data, target: Data, targetForm: String, proxyPort: String,
                        headers: [HTTPHeaderField], caCert: String? = nil) throws -> Plan {
        func reject(_ value: String) -> EngineJSONFailure { .invalid("Cannot faithfully copy cURL: " + value) }
        guard let methodText = String(data: method, encoding: .ascii), HTTPMessageDraft.token(methodText), methodText != "CONNECT", targetForm != "authority" else { throw reject("CONNECT/invalid methods are unsupported by this request command.") }
        guard target.first == 47 else { throw reject("this request target is not an origin path; it has not been verified for cURL.") }
        guard !url.contains(0), !target.contains(where: { $0 <= 32 || $0 == 127 }) else { throw reject("URL/target contains unsupported control bytes.") }
        let raw = Array(url)
        guard let colon = raw.firstIndex(of: 58), raw.count > colon + 2, raw[colon + 1] == 47, raw[colon + 2] == 47,
              let scheme = String(bytes: raw[..<colon], encoding: .ascii)?.lowercased(), ["http", "https"].contains(scheme) else { throw reject("a complete HTTP(S) URL is required.") }
        let start = colon + 3; let end = raw[start...].firstIndex(where: { [47,63,35].contains($0) }) ?? raw.count
        guard let authority = String(bytes: raw[start..<end], encoding: .ascii), !authority.isEmpty, !authority.hasSuffix(":"), !authority.contains("\\"),
              let parts = URLComponents(string: scheme + "://" + authority + "/"), let host = parts.host, !host.isEmpty,
              parts.user == nil, parts.password == nil, parts.port.map({ (1...65535).contains($0) }) ?? true else { throw reject("the original URL authority cannot be represented safely.") }
        let omitted: Set<String> = ["host", "content-length", "transfer-encoding", "connection", "proxy-connection", "keep-alive", "upgrade", "te", "trailer", "proxy-authorization"]
        var connectionTokens = Set<String>()
        for field in headers where field.nameText?.lowercased() == "connection" {
            guard let text = String(data: field.value, encoding: .ascii) else { throw reject("Connection tokens are not ASCII.") }
            for token in text.split(separator: ",") {
                let name = token.trimmingCharacters(in: .whitespaces)
                guard HTTPMessageDraft.token(name) else { throw reject("Connection contains an invalid token.") }
                connectionTokens.insert(name.lowercased())
            }
        }
        // Lens accepts origin-form through its explicit proxy using Host for
        // routing. Its pinned SDK rejects non-ASCII bytes in absolute-form URLs;
        // origin-form preserves those same path/query bytes on HTTP and HTTPS.
        var command = ["curl", "--globoff", "--proxy", quote("http://127.0.0.1:" + proxyPort), "--noproxy", quote(""), "-X", byteQuote(method), "--url", quote(scheme + "://" + authority + "/"), "--request-target", byteQuote(target)]
        if scheme == "https", let caCert { command += ["--cacert", quote(caCert)] }
        for field in headers {
            guard let name = field.nameText, HTTPMessageDraft.token(name) else { throw reject("a header name is not an ASCII token.") }
            if omitted.contains(name.lowercased()) || connectionTokens.contains(name.lowercased()) { continue }
            guard !field.value.contains(where: { ($0 < 32 && $0 != 9) || $0 == 127 }) else { throw reject("a header value contains unsupported control bytes.") }
            var line = field.name
            if field.value.isEmpty { line.append(59) } else { line.append(contentsOf: [58,32]); line.append(field.value) }
            command += ["-H", byteQuote(line)]
        }
        return Plan(parts: command)
    }
    static func saveBody(_ bytes: Data, directory: URL) throws -> URL {
        let manager = FileManager.default
        try manager.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try manager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
        let file = directory.appendingPathComponent(UUID().uuidString + ".bin")
        guard manager.createFile(atPath: file.path, contents: bytes, attributes: [.posixPermissions: 0o600]) else { throw CocoaError(.fileWriteUnknown) }
        return file
    }
}
