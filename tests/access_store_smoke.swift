// Production Store -> real engine Access Lists smoke; rejects host proxy access.
// Compile the same production files as udp_store_smoke.swift; no app window is used.
import AppKit
import Foundation

private struct AccessFailure: Error { let message: String }
@MainActor private enum Checks {
    static func require(_ value: @autoclosure () throws -> Bool, _ reason: String) throws {
        if try !value() { throw AccessFailure(message: reason) }
    }
    static func wait(_ label: String, _ value: () -> Bool) async throws {
        let deadline = Date().addingTimeInterval(15)
        while !value() {
            if Date() > deadline { throw AccessFailure(message: "Timed out: \(label)") }
            try await Task.sleep(nanoseconds: 20_000_000)
        }
    }
    static func command(_ store: LensStore, _ name: String, _ args: [String: Any] = [:]) async throws -> Any {
        var value: Any?, error: String?
        store.send(name, args, onError: { error = $0 }) { result in
            guard result.sourceFacts.text.isEmpty else { error = "Fixture unexpectedly returned source text annotations"; return }
            value = result.projection
        }
        try await wait(name) { value != nil || error != nil }
        if let error { throw AccessFailure(message: error) }
        return value!
    }
    static func apply(_ store: LensStore, expected: Bool = true) async throws {
        var result: Bool?
        store.applyRules { result = $0 }
        try await wait("native live configure") { result != nil }
        try require(result == expected, store.errorMessage ?? "Unexpected apply result")
    }
    static func shutdown(_ store: LensStore) async throws {
        var result: Bool?
        store.shutdown { result = $0 }
        try await wait("owned engine exits") { result != nil }
        try require(result == true && !store.hasEngine, "Engine cleanup failed")
    }
    static func request(_ store: LensStore, resources: URL, origin: Int, path: String) async throws -> Int {
        let output = store.dataDirectory.appendingPathComponent("request-result.json")
        try? FileManager.default.removeItem(at: output)
        let process = Process()
        process.executableURL = resources.appendingPathComponent("python/bin/python3")
        process.arguments = ["-c", #"""
import http.client,json,sys
from pathlib import Path
connection=http.client.HTTPConnection('127.0.0.1',int(sys.argv[1]),timeout=8)
connection.request('GET','http://127.0.0.1:'+sys.argv[2]+sys.argv[3])
response=connection.getresponse(); response.read()
Path(sys.argv[4]).write_text(json.dumps(response.status))
connection.close()
"""#, store.port, String(origin), path, output.path]
        try process.run()
        try await wait("actual proxied HTTP response") { !process.isRunning }
        try require(process.terminationStatus == 0, "HTTP client failed")
        return try JSONDecoder().decode(Int.self, from: Data(contentsOf: output))
    }
    static func run(_ resources: URL) async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("lens-access-store-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let system = SystemProxyController(dataDirectory: directory.appendingPathComponent("system"), runner: SystemProxyRunner(read: { _ in throw AccessFailure(message: "Host access forbidden") }, authorize: { _ in throw AccessFailure(message: "Host mutation forbidden") }))
        let store = LensStore(dataDirectory: directory.appendingPathComponent("data"), resources: resources, systemProxy: system)
        var reopenedOwner: LensStore?
        let fixture = Process(), ports = directory.appendingPathComponent("ports.json")
        fixture.executableURL = resources.appendingPathComponent("python/bin/python3")
        fixture.arguments = ["-u", "-c", #"""
import http.server,json,socket,sys
from pathlib import Path
class Handler(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  body=b'origin:'+self.path.encode()
  self.send_response(200); self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)
 def log_message(self,*args): pass
server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
server.daemon_threads=True
with socket.socket() as reservation:
 reservation.bind(('127.0.0.1',0)); port=reservation.getsockname()[1]
Path(sys.argv[1]).write_text(json.dumps([server.server_port,port]))
server.serve_forever()
"""#, ports.path]
        try fixture.run()
        defer { if fixture.isRunning { fixture.terminate() } }
        do {
            try await wait("owned HTTP origin") { FileManager.default.fileExists(atPath: ports.path) }
            let numbers = try JSONDecoder().decode([Int].self, from: Data(contentsOf: ports))
            store.port = String(numbers[1])
            let blocked = "http://127.0.0.1:\(numbers[0])/deny*"
            store.accessPolicy = AccessPolicy(blockEnabled: true, block: [blocked])
            try await apply(store)
            let restored = LensStore(dataDirectory: store.dataDirectory, resources: resources, systemProxy: system)
            try require(restored.accessPolicy == store.accessPolicy, "Access policy preferences did not roundtrip")
            store.start()
            try await wait("native Access Lists initialize") { store.isRunning || store.errorMessage != nil }
            try require(store.isRunning, store.errorMessage ?? "Launch failed")
            let deny_initialStatus = try await request(store, resources: resources, origin: numbers[0], path: "/deny-initial")
            try require(deny_initialStatus == 403, "Initialize did not apply Access Lists")
            try await wait("typed denied flow") { store.flows.contains { $0.accessDecision?.reason == "block_match" } }
            let initial = store.flows.first { $0.accessDecision != nil }!
            try require(initial.accessDecision?.matchedUrl.hasSuffix("/deny-initial") == true && initial.accessDecision?.pattern == blocked && initial.accessDecision?.action == "respond", "Native decision lost URL, pattern or action")
            print("PASS: Access Lists preferences and initialize reach the actual engine; native denial decision is typed")
            store.accessPolicy = AccessPolicy(allowEnabled: true)
            try await apply(store)
            let allow_emptyStatus = try await request(store, resources: resources, origin: numbers[0], path: "/allow-empty")
            try require(allow_emptyStatus == 403, "Enabled empty Allow List did not deny")
            try await wait("allow miss decision") { store.flows.contains { $0.accessDecision?.reason == "allow_miss" } }
            let saved = try Data(contentsOf: store.dataDirectory.appendingPathComponent("preferences.json"))
            store.accessPolicy.block = ["line\nbreak"]
            try await apply(store, expected: false)
            try require(try Data(contentsOf: store.dataDirectory.appendingPathComponent("preferences.json")) == saved, "Invalid selection changed saved preferences")
            let still_deniedStatus = try await request(store, resources: resources, origin: numbers[0], path: "/still-denied")
            try require(still_deniedStatus == 403, "Invalid selection changed active policy")
            store.errorMessage = nil
            store.accessPolicy = AccessPolicy()
            try await apply(store)
            let restoredStatus = try await request(store, resources: resources, origin: numbers[0], path: "/restored")
            try require(restoredStatus == 200, "Disabling lists failed to restore forwarding")
            try await wait("allowed flow") { store.flows.contains { $0.url.hasSuffix("/restored") && $0.status == 200 } }
            try require(store.flows.first { $0.url.hasSuffix("/restored") }?.accessDecision == nil, "Absent decision was fabricated as allowed")
            print("PASS: live configure applies empty Allow List denial, rejects invalid selection atomically, and restores forwarding")
            let har = store.dataDirectory.appendingPathComponent("access.har")
            _ = try await command(store, "save_har", ["path": har.path])
            var stopped: Bool?
            store.stop { stopped = $0 }
            try await wait("Stop saves retained decision") { stopped != nil }
            try require(stopped == true && !store.isRunning, "Stop failed")
            try require(store.flows.first { $0.id == initial.id }?.accessDecision == initial.accessDecision, "Stop lost decision")
            store.selection = initial.id; store.loadDetail()
            try await wait("stopped Request and Response readable") { store.detail?.id == initial.id || store.detailError != nil }
            try require(store.detail != nil && store.detailError == nil && !store.detail!.responseBody.isEmpty, "Stopped denial response unavailable")
            try await shutdown(store)
            let reopened = LensStore(dataDirectory: directory.appendingPathComponent("reopened"), resources: resources, systemProxy: system)
            reopenedOwner = reopened; reopened.port = store.port
            reopened.start()
            try await wait("fresh engine ready") { reopened.isRunning || reopened.errorMessage != nil }
            try require(reopened.isRunning, reopened.errorMessage ?? "Fresh engine failed")
            _ = try await command(reopened, "load_har", ["path": har.path])
            try await wait("HAR decision typed") { reopened.flows.contains { $0.accessDecision == initial.accessDecision } }
            try require(reopened.flows.first { $0.url.hasSuffix("/restored") }?.accessDecision == nil, "HAR absent decision fabricated")
            try await shutdown(reopened)
            print("PASS: stopped native Request/Response and fresh HAR preserve denial provenance and absent decisions")
            try require(AccessPolicy(block: [String(repeating: "😀", count: 4096)]).issue == nil && AccessPolicy(allow: [String(repeating: "😀", count: 4097)]).issue != nil, "Unicode scalar pattern limit differs from engine code points")
            try require(AccessPolicy(block: Array(repeating: "*", count: 501)).issue != nil && AccessPolicy(allow: [""]).issue != nil && AccessPolicy(block: ["nul\0value"]).issue != nil && AccessPolicy(allow: ["a\r\nb"]).issue != nil && AccessPolicy(action: "unknown").issue != nil, "Malformed policy accepted")
            let corruptDirectory = directory.appendingPathComponent("corrupt-preferences")
            try FileManager.default.createDirectory(at: corruptDirectory, withIntermediateDirectories: false)
            try JSONSerialization.data(withJSONObject: ["access_policy": ["allow_enabled": true]]).write(to: corruptDirectory.appendingPathComponent("preferences.json"))
            let corrupt = LensStore(dataDirectory: corruptDirectory, resources: resources, systemProxy: system)
            try require(corrupt.accessPolicy.issue != nil && corrupt.errorMessage != nil, "Malformed saved policy silently became disabled")
            corrupt.start()
            try require(!corrupt.hasEngine, "Malformed saved policy opened a capture engine")
            print("PASS: native validation covers Unicode code points, count, control characters, action and malformed saved policy")
        } catch {
            if let reopenedOwner, reopenedOwner.hasEngine { try? await shutdown(reopenedOwner) }
            if store.hasEngine { try? await shutdown(store) }
            throw error
        }
        fixture.terminate()
        try await wait("owned origin exits") { !fixture.isRunning }
    }
}
@main @MainActor private struct AccessStoreSmoke {
    static func main() {
        setbuf(stdout, nil)
        guard CommandLine.arguments.count == 2 else { exit(2) }
        var done = false, failure: Error?
        Task { @MainActor in
            do { try await Checks.run(URL(fileURLWithPath: CommandLine.arguments[1])) } catch { failure = error }
            done = true
        }
        while !done { _ = RunLoop.main.run(mode: .default, before: Date().addingTimeInterval(0.05)) }
        if let failure { fputs("FAIL: \(failure)\n", stderr); exit(1) }
    }
}
