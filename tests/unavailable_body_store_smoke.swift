// Production LensStore -> packaged (or explicit source-root) engine -> real loopback HTTP.
// All resources and captures are temporary; system proxy access always throws.
import AppKit
import Foundation

private struct UnavailableFailure: Error, LocalizedError {
    let message: String
    var errorDescription: String? { message }
}
private func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
    if !condition() { throw UnavailableFailure(message: message) }
}
@main private enum UnavailableBodyStoreSmoke {
    @MainActor static func eventually(_ label: String, _ predicate: () -> Bool) async throws {
        for _ in 0..<750 {
            if predicate() { return }
            try await Task.sleep(nanoseconds: 20_000_000)
        }
        throw UnavailableFailure(message: "Timed out: \(label)")
    }
    @MainActor static func command(_ store: LensStore, _ name: String, _ args: [String: Any]) async throws -> Any {
        try await withCheckedThrowingContinuation { continuation in
            store.send(name, args, onError: { continuation.resume(throwing: UnavailableFailure(message: $0)) }) {
                guard $0.sourceFacts.text.isEmpty else { continuation.resume(throwing: UnavailableFailure(message: "Fixture unexpectedly returned source text annotations")); return }
                continuation.resume(returning: $0.projection)
            }
        }
    }
    @MainActor static func stop(_ store: LensStore) async -> Bool {
        await withCheckedContinuation { continuation in store.shutdown { continuation.resume(returning: $0) } }
    }
    @MainActor static func main() async throws {
        guard CommandLine.arguments.count == 2 else { throw UnavailableFailure(message: "Pass absolute Lens.app/Contents/Resources, Lens.app, or mac-charles source root") }
        let root = URL(fileURLWithPath: CommandLine.arguments[1]), manager = FileManager.default
        let temporary = manager.temporaryDirectory.appendingPathComponent("lens-unavailable-store-\(UUID().uuidString)")
        try manager.createDirectory(at: temporary, withIntermediateDirectories: true)
        defer { try? manager.removeItem(at: temporary) }
        let resources: URL
        if let packaged = [root, root.appendingPathComponent("Contents/Resources")].first(where: {
            manager.isExecutableFile(atPath: $0.appendingPathComponent("python/bin/python3").path)
                && manager.fileExists(atPath: $0.appendingPathComponent("engine/engine.py").path)
                && manager.fileExists(atPath: $0.appendingPathComponent("site-packages").path)
        }) {
            resources = packaged
            print("Using packaged Resources: \(packaged.path)")
        } else {
            guard manager.isExecutableFile(atPath: root.appendingPathComponent(".runtime/bin/python3").path),
                  manager.fileExists(atPath: root.appendingPathComponent("engine/engine.py").path) else {
                throw UnavailableFailure(message: "No complete packaged Resources or source runtime found at the supplied path")
            }
            resources = temporary.appendingPathComponent("resources")
            try manager.createDirectory(at: resources, withIntermediateDirectories: true)
            try manager.createSymbolicLink(at: resources.appendingPathComponent("python"), withDestinationURL: root.appendingPathComponent(".runtime"))
            try manager.createSymbolicLink(at: resources.appendingPathComponent("engine"), withDestinationURL: root.appendingPathComponent("engine"))
            try manager.createSymbolicLink(at: resources.appendingPathComponent("site-packages"), withDestinationURL: root.appendingPathComponent(".runtime/lib/python3.13/site-packages"))
            print("Using source engine: \(root.path)")
        }
        let ready = temporary.appendingPathComponent("fixture-ready.json"), history = temporary.appendingPathComponent("history.jsonl")
        let script = #"""
import base64,http.server,json,os,socket,sys
from pathlib import Path
class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    def log_message(self,*args): pass
    def do_POST(self):
        body=self.rfile.read(int(self.headers.get('Content-Length','0')))
        with open(sys.argv[2],'a') as target: target.write(json.dumps({'body':base64.b64encode(body).decode()})+'\n')
        self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
with socket.socket() as reserve:
    reserve.bind(('127.0.0.1',0)); port=reserve.getsockname()[1]
path=Path(sys.argv[1]);stage=path.with_suffix('.tmp');stage.write_text(json.dumps({'origin':server.server_port,'proxy':port}));os.replace(stage,path)
server.serve_forever()
"""#
        let fixture = Process()
        fixture.executableURL = resources.appendingPathComponent("python/bin/python3")
        fixture.arguments = ["-u", "-c", script, ready.path, history.path]
        fixture.standardOutput = FileHandle.nullDevice; fixture.standardError = FileHandle.nullDevice
        try fixture.run()
        defer { if fixture.isRunning { fixture.terminate() }; fixture.waitUntilExit() }
        try await eventually("HTTP fixture handshake") { manager.fileExists(atPath: ready.path) }
        let endpoint = try JSONSerialization.jsonObject(with: Data(contentsOf: ready)) as! [String: Int]
        let data = temporary.appendingPathComponent("app-data")
        let denied = SystemProxyRunner(read: { _ in throw UnavailableFailure(message: "System proxy reads forbidden") }, authorize: { _ in throw UnavailableFailure(message: "System proxy writes forbidden") })
        let system = SystemProxyController(dataDirectory: temporary.appendingPathComponent("recovery"), runner: denied)
        let store = LensStore(dataDirectory: data, resources: resources, systemProxy: system)
        store.port = String(endpoint["proxy"]!)
        store.start()
        do {
            try await eventually("engine ready") { store.isRunning }
            let url = "http://127.0.0.1:\(endpoint["origin"]!)/imported-unavailable"
            let entry: [String: Any] = ["startedDateTime": "2026-01-01T00:00:00Z", "time": 12,
                "timings": ["send": 0, "wait": 12, "receive": 0],
                "request": ["method": "POST", "url": url, "httpVersion": "HTTP/1.1", "headers": [], "bodySize": -1, "postData": ["mimeType": "application/json"]],
                "response": ["status": 200, "statusText": "OK", "httpVersion": "HTTP/1.1", "headers": [], "bodySize": 9000, "content": ["size": 9000, "mimeType": "image/png"]]]
            _ = try await command(store, "import_har", ["har": ["log": ["entries": [entry]]]])
            try await eventually("native imported summary") { store.flows.count == 1 }
            let flow = store.flows[0]
            try require(flow.requestBodyAvailable == false && flow.responseBodyAvailable == false && flow.sizeLabel == "Unavailable", "Native summary fabricated available/empty body")
            store.selection = flow.id; store.loadDetail()
            try await eventually("native detail availability") { store.detail != nil }
            try require(store.detail?.requestBodyAvailable == false && store.detail?.responseBodyAvailable == false && store.detail?.requestBodyBase64 == nil, "Native detail fabricated body bytes")
            store.replay()
            try require(store.errorMessage?.contains("unavailable") == true, "Native Replay did not reject unavailable source")
            store.errorMessage = nil; store.repeatFlow(id: flow.id, count: 2, concurrency: 1, intervalMs: 0) { store.errorMessage = $0 }
            try require(store.errorMessage?.contains("unavailable") == true, "Native Repeat did not reject unavailable source")
            store.errorMessage = nil
            let clipboardChange = NSPasteboard.general.changeCount
            store.copyCurl()
            try await eventually("Copy cURL unavailable error") { store.errorMessage?.contains("unavailable") == true }
            try require(NSPasteboard.general.changeCount == clipboardChange, "Rejected cURL modified clipboard")
            let destination = temporary.appendingPathComponent("keep-existing.bin")
            try Data("previous bytes".utf8).write(to: destination)
            let export: Result<Void, Error> = await withCheckedContinuation { continuation in
                store.exportBody(side: "request", to: destination) { continuation.resume(returning: $0) }
            }
            if case .success = export { throw UnavailableFailure(message: "Unavailable body export reported success") }
            let prior = try Data(contentsOf: destination)
            try require(prior == Data("previous bytes".utf8), "Unavailable body export overwrote prior file")
            let csv = temporary.appendingPathComponent("flows.csv")
            try store.exportCSV(to: csv)
            let row = try String(contentsOf: csv, encoding: .utf8).components(separatedBy: "\r\n")[1].components(separatedBy: ",")
            try require(row[5] == "\"\"" && row[6] == "\"\"", "CSV fabricated zero-byte measurements")
            store.errorMessage = nil
            store.compose(requestEdit: ["method": "POST", "url": url, "body_base64": Data("explicit replacement".utf8).base64EncodedString()]) { store.errorMessage = $0 }
            try await eventually("Compose explicit replacement received") { store.flows.contains { $0.id != flow.id && $0.url == url && $0.state == "complete" } }
            let observed = try String(contentsOf: history, encoding: .utf8).split(separator: "\n")
            try require(observed.count == 1, "Unavailable Replay/Repeat sent a request")
            let delivered = try JSONSerialization.jsonObject(with: Data(observed[0].utf8)) as! [String: String]
            try require(Data(base64Encoded: delivered["body"]!) == Data("explicit replacement".utf8), "Explicit replacement was not delivered exactly")
            guard await stop(store) else { throw UnavailableFailure(message: "Native stop failed") }
            print("PASS: production Store/selected engine preserves unavailable summary/detail; Replay/Repeat/cURL/body-export reject; CSV unknown stays blank; explicit Compose delivers; Stop succeeds without system access")
        } catch {
            _ = await stop(store)
            throw error
        }
    }
}
