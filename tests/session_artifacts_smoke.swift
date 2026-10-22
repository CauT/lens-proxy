// Filesystem/shell-boundary checks only: no network, Keychain, or system-proxy changes.
import Foundation
import Darwin

private struct ArtifactFailure: Error, CustomStringConvertible {
    let description: String
}

private func require(_ condition: @autoclosure () throws -> Bool, _ message: String) throws {
    if try !condition() { throw ArtifactFailure(description: message) }
}

private func mode(_ url: URL) throws -> Int {
    let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
    guard let value = attributes[.posixPermissions] as? NSNumber else {
        throw ArtifactFailure(description: "Permission metadata missing for \(url.lastPathComponent)")
    }
    return value.intValue & 0o777
}

private func parsedArguments(_ command: String) throws -> [String] {
    // Substitute a shell function for curl: test its actual argv without a network call.
    let process = Process(), output = Pipe(), errors = Pipe()
    process.executableURL = URL(fileURLWithPath: "/bin/zsh")
    process.arguments = ["-c", "curl() { printf '%s\\0' \"$@\"; }\n" + command]
    process.standardOutput = output
    process.standardError = errors
    try process.run()
    let bytes = output.fileHandleForReading.readDataToEndOfFile()
    let errorBytes = errors.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    try require(process.terminationStatus == 0, "Rendered shell command failed: \(String(decoding: errorBytes, as: UTF8.self))")
    return bytes.split(separator: 0, omittingEmptySubsequences: false).dropLast().map { String(decoding: $0, as: UTF8.self) }
}

private func optionValues(_ option: String, in args: [String]) -> [String] {
    args.indices.compactMap { index in
        args[index] == option && index + 1 < args.count ? args[index + 1] : nil
    }
}

private func fixtureFlow(url: String, started: Double = 1_700_000_000.125) -> TrafficFlow {
    TrafficFlow(id: "../../synthetic-flow-id", url: url, host: "example.invalid", path: "/../source-path",
                method: "POST", status: 201, scheme: "https", httpVersion: "HTTP/2.0", started: started,
                durationMs: 125, requestSize: 3, responseSize: 5, state: "complete",
                contentType: "application/octet-stream; fixture=yes", error: nil, isWebsocket: false,
                replayed: false, websocketMessagesTruncated: nil, imported: nil)
}

@main
private struct SessionArtifactsSmoke {
    static func main() throws {
        let manager = FileManager.default
        let directory = manager.temporaryDirectory.appendingPathComponent("lens-artifacts-\(UUID().uuidString)")
        try manager.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? manager.removeItem(at: directory) }
        let marker = directory.appendingPathComponent("must-not-execute")
        let hostile = "literal ' apostrophe\n$(touch '\(marker.path)') ; backtick `touch '\(marker.path)'`"
        let sourceURL = "https://example.invalid/a'b?original=%2F&literal=$(touch${IFS}\(marker.path))"
        let bytes = Data(Array(0...255).map(UInt8.init) + [0, 255, 10])
        var cases: [(String, () throws -> Void)] = []

        cases.append(("cURL quotes actual argv and preserves duplicate/source fields", {
            let body = directory.appendingPathComponent("body ' spaced.bin")
            let ca = directory.appendingPathComponent("CA ' fixture.pem").path
            let headers = [["X-Repeat", "first"], ["X-Repeat", "second"], ["X-Hostile", hostile.replacingOccurrences(of: "\n", with: " ")],
                           ["Authorization", "Bearer synthetic-evidence"], ["Cookie", "fixture=1"],
                           ["Content-Encoding", "gzip"]]
            let command = try CurlCommand.render(method: "POST", url: sourceURL, proxyPort: "8890", headers: headers,
                                             bodyFile: body, caCert: ca)
            let args = try parsedArguments(command)
            try require(optionValues("--url", in: args) == ["https://example.invalid/"] && optionValues("--request-target", in: args) == [String(sourceURL.dropFirst("https://example.invalid".count))], "URL source value changed across shell parsing")
            try require(optionValues("-H", in: args) == headers.map { $0[0] + ": " + $0[1] }, "Repeated, sensitive-named or quoted header values changed")
            try require(optionValues("--data-binary", in: args) == ["@" + body.path], "Body file path lost literal quoting")
            try require(optionValues("--cacert", in: args) == [ca], "HTTPS did not use the explicit app CA")
            try require(optionValues("--proxy", in: args) == ["http://127.0.0.1:8890"], "Wrong explicit proxy address")
            try require(optionValues("--noproxy", in: args) == [""], "Ambient NO_PROXY could bypass the selected proxy")
            try require(!manager.fileExists(atPath: marker.path), "Shell interpreted a source value as executable code")
        }))
        cases.append(("cURL removes connection-owned headers and Connection tokens", {
            let headers = [["hOSt", "old.invalid"], ["Content-Length", "999"], ["Transfer-Encoding", "chunked"],
                           ["Connection", "keep-alive, X-Hop-One"], ["connection", "\tX-Hop-Two "],
                           ["X-Hop-One", "omit"], ["x-hop-two", "omit"], ["Proxy-Authorization", "synthetic"],
                           ["Upgrade", "websocket"], ["Proxy-Connection", "close"], ["TE", "trailers"],
                           ["Trailer", "X-End"], ["Keep-Alive", "timeout=5"], ["X-EndToEnd", "keep"]]
            let args = try parsedArguments(try CurlCommand.render(method: "GET", url: "http://example.invalid/",
                proxyPort: "8890", headers: headers, bodyFile: nil, caCert: "/synthetic/ignored-ca"))
            try require(optionValues("-H", in: args) == ["X-EndToEnd: keep"], "Hop-by-hop or Connection-nominated fields reached new connection")
            try require(optionValues("--cacert", in: args).isEmpty && optionValues("--data-binary", in: args).isEmpty,
                        "HTTP/bodyless request acquired unrelated CA/body arguments")
        }))
        cases.append(("cURL rejects malformed header pairs and control bytes", {
            for headers in [[["broken"]], [["three", "items", "invalid"]], [["X-Invalid", hostile]]] {
                do {
                    _ = try CurlCommand.render(method: "GET", url: "http://example.invalid/", proxyPort: "8890", headers: headers, bodyFile: nil)
                    throw ArtifactFailure(description: "Invalid source header was accepted")
                } catch is EngineJSONFailure { }
            }
        }))
        cases.append(("Body companion saves complete bytes privately with UUID identity", {
            let folder = directory.appendingPathComponent("body-companions")
            let file = try CurlCommand.saveBody(bytes, directory: folder)
            let actual = try Data(contentsOf: file)
            try require(actual == bytes, "Binary request body changed when saved")
            try require(UUID(uuidString: file.deletingPathExtension().lastPathComponent) != nil && file.pathExtension == "bin",
                        "Body companion name came from source data")
            try require(try mode(folder) == 0o700 && mode(file) == 0o600, "Body companion permissions are not private")
            let empty = try CurlCommand.saveBody(Data(), directory: folder)
            try require(try Data(contentsOf: empty).isEmpty && mode(empty) == 0o600, "Empty body file lost identity or privacy")
            let original = try Data(contentsOf: file)
            try require(empty != file && original == bytes, "Second save overwrote the earlier body")
        }))
        cases.append(("Body companion rejects an invalid destination", {
            let blocker = directory.appendingPathComponent("not-a-directory")
            try Data([1]).write(to: blocker)
            do {
                _ = try CurlCommand.saveBody(bytes, directory: blocker)
                throw ArtifactFailure(description: "File destination was accepted as a body directory")
            } catch is ArtifactFailure { throw ArtifactFailure(description: "Invalid body destination did not fail") }
            catch { }
            try require(try Data(contentsOf: blocker) == Data([1]), "Failed save replaced an unrelated destination")
        }))
        cases.append(("Response mirror publishes consistent metadata/body with private UUID paths", {
            let folder = directory.appendingPathComponent("mirrors")
            try manager.createDirectory(at: folder, withIntermediateDirectories: true)
            let flow = fixtureFlow(url: sourceURL)
            let name = try ResponseMirror.write(flow: flow, bytes: bytes, folder: folder)
            try require(UUID(uuidString: name) != nil, "Source URL or flow ID selected a filesystem path")
            let output = folder.appendingPathComponent(name)
            let children = try manager.contentsOfDirectory(atPath: output.path).sorted()
            try require(children == ["metadata.json", "response.bin"], "Mirror published unexpected or incomplete files")
            let body = output.appendingPathComponent("response.bin"), metadataURL = output.appendingPathComponent("metadata.json")
            let metadata = try JSONSerialization.jsonObject(with: Data(contentsOf: metadataURL)) as? [String: Any]
            try require(metadata?["url_display"] as? String == sourceURL && metadata?["flow_id"] as? String == flow.id,
                        "Original URL/identity evidence was normalized or lost")
            try require(metadata?["body_file"] as? String == "response.bin" && metadata?["body_bytes"] as? Int == bytes.count,
                        "Metadata body reference or byte count disagrees")
            try require(metadata?["method_display"] as? String == "POST" && metadata?["status"] as? Int == 201,
                        "Mirror lost method/status facts")
            try require(metadata?["captured_at"] as? Double == flow.started && metadata?["content_type_display"] as? String == flow.contentType,
                        "Mirror changed source timestamp or content type")
            try require(metadata?["representation"] as? String == "decoded response body", "Mirror body representation is ambiguous")
            try require((metadata?["source_text_facts"] as? [String: Any])?["text"] as? [Any] != nil, "Mirror omitted authoritative source text facts")
            try require(try Data(contentsOf: body) == bytes, "Mirrored body bytes disagree with source")
            try require(try mode(output) == 0o700 && mode(body) == 0o600 && mode(metadataURL) == 0o600,
                        "Mirror directory/files expose private captured content")
        }))
        cases.append(("Response mirror keeps earlier publications and never leaves staging directories", {
            let folder = directory.appendingPathComponent("repeated-mirrors")
            try manager.createDirectory(at: folder, withIntermediateDirectories: true)
            let first = try ResponseMirror.write(flow: fixtureFlow(url: sourceURL), bytes: bytes, folder: folder)
            let second = try ResponseMirror.write(flow: fixtureFlow(url: sourceURL), bytes: Data([9]), folder: folder)
            try require(first != second, "Repeated mirroring overwrote an earlier artifact")
            try require(try Data(contentsOf: folder.appendingPathComponent(first + "/response.bin")) == bytes,
                        "Earlier mirrored content changed")
            try require(try manager.contentsOfDirectory(atPath: folder.path).sorted() == [first, second].sorted(),
                        "Successful mirror left stage/residue beside its publications")
        }))
        cases.append(("Response mirror failure cleans its stage without publishing a half-pair", {
            let folder = directory.appendingPathComponent("failed-mirrors")
            try manager.createDirectory(at: folder, withIntermediateDirectories: true)
            let earlier = try ResponseMirror.write(flow: fixtureFlow(url: sourceURL), bytes: bytes, folder: folder)
            // Nonfinite boundary metadata must fail without creating a partial publication.
            do {
                _ = try ResponseMirror.write(flow: fixtureFlow(url: sourceURL, started: .nan), bytes: bytes, folder: folder)
                throw ArtifactFailure(description: "Invalid metadata was published")
            } catch is ArtifactFailure { throw ArtifactFailure(description: "Invalid mirror metadata did not fail") }
            catch { }
            try require(try manager.contentsOfDirectory(atPath: folder.path) == [earlier], "Failed mirror left a staging directory or incomplete publication")
            try require(try Data(contentsOf: folder.appendingPathComponent(earlier + "/response.bin")) == bytes,
                        "Failure cleanup modified an earlier publication")
        }))
        cases.append(("Response mirror removes staged files after a real filesystem write failure", {
            let folder = directory.appendingPathComponent("write-failed-mirrors")
            try manager.createDirectory(at: folder, withIntermediateDirectories: true)
            var original = rlimit()
            try require(getrlimit(RLIMIT_FSIZE, &original) == 0, "Cannot inspect owned test-process file-size limit")
            var limited = original
            limited.rlim_cur = min(original.rlim_cur, 512)
            let oldSignal = signal(SIGXFSZ, SIG_IGN)
            defer { _ = setrlimit(RLIMIT_FSIZE, &original); signal(SIGXFSZ, oldSignal) }
            try require(setrlimit(RLIMIT_FSIZE, &limited) == 0, "Cannot establish bounded filesystem failure fixture")
            do {
                // Body fits; large source metadata exceeds this process's per-file cap.
                _ = try ResponseMirror.write(flow: fixtureFlow(url: sourceURL + String(repeating: "x", count: 1024)),
                                             bytes: bytes, folder: folder)
                throw ArtifactFailure(description: "Filesystem write failure was ignored")
            } catch is ArtifactFailure { throw ArtifactFailure(description: "Expected metadata write to fail") }
            catch { }
            try require(try manager.contentsOfDirectory(atPath: folder.path).isEmpty,
                        "Failed stage exposed an incomplete metadata/body pair or retained residue")
        }))

        var failures: [String] = []
        for (name, test) in cases {
            do { try test(); print("PASS: \(name)") }
            catch { failures.append("\(name): \(error)"); print("FAIL: \(name): \(error)") }
        }
        print("Session artifacts smoke: \(cases.count - failures.count)/\(cases.count) passed")
        if !failures.isEmpty { throw ArtifactFailure(description: failures.joined(separator: "\n")) }
    }
}
