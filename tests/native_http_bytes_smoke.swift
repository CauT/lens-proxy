// Production Foundation decoder/editor/cURL -> packaged engine -> owned HTTP/TLS.
// No window or host proxy/trust changes. Run with app Resources and mac-charles root.
import AppKit
import Foundation

private struct ByteFailure: Error { let message: String }
@MainActor private enum ByteChecks {
    static func require(_ value: @autoclosure () throws -> Bool, _ message: String) throws {
        if try !value() { throw ByteFailure(message: message) }
    }
    static func wait(_ name: String, _ value: () throws -> Bool) async throws {
        let deadline = Date().addingTimeInterval(20)
        while try !value() {
            if Date() > deadline { throw ByteFailure(message: "Timed out: " + name) }
            try await Task.sleep(nanoseconds: 20_000_000)
        }
    }
    static func command(_ store: LensStore, _ name: String, _ args: [String: Any] = [:]) async throws -> EngineValue {
        var result: Result<EngineValue, Error>?
        store.send(name, args, onError: { result = .failure(ByteFailure(message: $0)) }) { result = .success($0) }
        try await wait(name) { result != nil }
        return try result!.get()
    }
    static func archiveFields(_ file: URL, _ resources: URL) throws -> Data {
        // Foundation deliberately cannot parse JSON lone surrogates. Use the
        // packaged Python parser to compare every source field, retaining array
        // order and escaped byte values while ignoring JSON object key order.
        let parser = Process(), output = Pipe(), errors = Pipe()
        parser.executableURL = resources.appendingPathComponent("python/bin/python3")
        parser.arguments = ["-c", "import json,sys; print(json.dumps(json.load(open(sys.argv[1])),sort_keys=True,ensure_ascii=True,separators=(',',':')))", file.path]
        parser.environment = ["PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1"]
        parser.standardOutput = output; parser.standardError = errors
        try parser.run()
        let result = output.fileHandleForReading.readDataToEndOfFile()
        parser.waitUntilExit()
        try require(parser.terminationStatus == 0, "Cannot independently parse saved HAR source fields")
        return result
    }
    static let fixture = #"""
import base64,http.server,json,socket,ssl,sys,threading
from pathlib import Path
sys.path.insert(0,str(Path(sys.argv[2])/'tests'))
from test_e2e import certificate_fixture
root=Path(sys.argv[1]); ca,cert,key=certificate_fixture(root,'native-byte-origin')
lock=threading.Lock()
class Handler(http.server.BaseHTTPRequestHandler):
 def do_POST(self):
  body=self.rfile.read(int(self.headers.get('Content-Length',0)))
  pairs=[[base64.b64encode(k.encode('latin1')).decode(),base64.b64encode(v.encode('latin1')).decode()] for k,v in self.headers.raw_items()]
  record=dict(path_base64=base64.b64encode(self.path.encode('latin1')).decode(),headers=pairs,body_base64=base64.b64encode(body).decode())
  with lock:
   with (root/'history.jsonl').open('a') as output: output.write(json.dumps(record)+'\n')
  payload=b'original\xffresponse'
  self.send_response(200,'raw\xff'); self.send_header('X-Bytes','\xff')
  self.send_header('Content-Type','application/x-\xff'); self.send_header('Content-Length',str(len(payload)))
  self.end_headers(); self.wfile.write(payload)
 def log_message(self,*_): pass
servers=[http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler) for _ in range(2)]
context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(cert,key)
servers[1].socket=context.wrap_socket(servers[1].socket,server_side=True)
for server in servers:
 server.daemon_threads=True; threading.Thread(target=server.serve_forever,daemon=True).start()
with socket.socket() as held:
 held.bind(('127.0.0.1',0)); proxy=held.getsockname()[1]
(root/'ports.json').write_text(json.dumps(dict(http=servers[0].server_port,https=servers[1].server_port,proxy=proxy,ca=str(ca))))
try: input()
finally:
 for server in servers: server.shutdown(); server.server_close()
"""#
    static func run(_ resources: URL, _ root: URL) async throws {
        let files = FileManager.default
        let directory = files.temporaryDirectory.appendingPathComponent("lens-http-bytes-" + UUID().uuidString)
        try files.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? files.removeItem(at: directory) }
        let process = Process(), input = Pipe(), log = Pipe()
        process.executableURL = resources.appendingPathComponent("python/bin/python3")
        process.arguments = ["-u", "-c", fixture, directory.path, root.path]
        process.environment = ["PATH": "/usr/bin:/bin", "PYTHONPATH": resources.appendingPathComponent("site-packages").path, "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1"]
        process.standardInput = input; process.standardOutput = log; process.standardError = log
        try process.run()
        defer { if process.isRunning { process.terminate() } }
        let portsFile = directory.appendingPathComponent("ports.json")
        try await wait("owned origins") { files.fileExists(atPath: portsFile.path) || !process.isRunning }
        guard process.isRunning else { throw ByteFailure(message: String(decoding: log.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)) }
        let ports = try JSONSerialization.jsonObject(with: Data(contentsOf: portsFile)) as! [String: Any]
        let denied = SystemProxyRunner(read: { _ in throw ByteFailure(message: "Host read forbidden") }, authorize: { _ in throw ByteFailure(message: "Host mutation forbidden") })
        let store = LensStore(dataDirectory: directory.appendingPathComponent("data"), resources: resources, systemProxy: SystemProxyController(dataDirectory: directory.appendingPathComponent("system"), runner: denied))
        store.port = String(ports["proxy"] as! Int); store.upstreamCA = ports["ca"] as! String
        store.start()
        do {
            try await wait("native engine ready") { store.isRunning || store.errorMessage != nil }
            try require(store.errorMessage == nil, store.errorMessage ?? "Startup failed")
            let target = Data("/raw/".utf8) + Data([255]) + Data("?x=1&x=2".utf8)
            let body = Data([0, 255, 1, 128])
            let bodyFile = try CurlCommand.saveBody(body, directory: directory.appendingPathComponent("body's folder"))
            // Lowercase names remain byte-identical if cURL negotiates HTTP/2.
            let fields = [HTTPHeaderField(name: Data("x-bytes".utf8), value: Data([255])),
                          HTTPHeaderField(name: Data("x-empty".utf8), value: Data()),
                          HTTPHeaderField(name: Data("x-dup".utf8), value: Data("first".utf8)),
                          HTTPHeaderField(name: Data("x-dup".utf8), value: Data("second".utf8)),
                          HTTPHeaderField(name: Data("x-nfd".utf8), value: Data("e\u{301}".utf8))]
            for scheme in ["http", "https"] {
                let endpoint = scheme + "://127.0.0.1:" + String(ports[scheme] as! Int)
                let plan = try CurlCommand.prepare(method: Data("POST".utf8), url: Data(endpoint.utf8) + target, target: target, targetForm: "relative", proxyPort: store.port, headers: fields, caCert: store.caCert)
                let client = Process(), output = Pipe(), errors = Pipe()
                client.executableURL = URL(fileURLWithPath: "/bin/zsh")
                client.arguments = ["-c", plan.render(bodyFile: bodyFile)]
                client.environment = ["PATH": "/usr/bin:/bin"]
                client.standardOutput = output; client.standardError = errors
                try client.run()
                defer { if client.isRunning { client.terminate() } }
                try await wait("raw cURL " + scheme) { !client.isRunning }
                let received = output.fileHandleForReading.readDataToEndOfFile()
                let diagnostic = errors.fileHandleForReading.readDataToEndOfFile()
                try require(client.terminationStatus == 0 && received == Data("original".utf8) + Data([255]) + Data("response".utf8), "Raw cURL response bytes failed for " + scheme + ": " + String(decoding: received + diagnostic, as: UTF8.self))
                try await wait("native row " + scheme) { store.flows.contains { $0.scheme == scheme && $0.state == "complete" } || store.errorMessage != nil }
                try require(store.errorMessage == nil, store.errorMessage ?? "Native flow failed")
                let flow = store.flows.first { $0.scheme == scheme }!
                try require(flow.path.contains("\\udcff") && flow.sourceFacts.contains("path"), "Native row lost opaque path source")
                var result: Result<FlowDetail, Error>?
                store.loadFlowDetail(id: flow.id) { result = $0 }
                try await wait("Foundation detail " + scheme) { result != nil }
                let detail = try result!.get()
                try require(try detail.bytes(detail.requestTargetBase64, label: "target") == target, "Native detail changed raw target")
                for field in fields { try require(detail.requestHeaderFields.contains(field), "Native detail changed a request field") }
                try require(detail.responseHeaderFields.contains { $0.nameText?.lowercased() == "x-bytes" && $0.value == Data([255]) }, "Native detail changed response header bytes")
                try require(try detail.reasonBytes() == Data("raw".utf8) + Data([255]), "Native detail changed upstream response reason bytes")
                let exported = try await command(store, "export_body", ["id": flow.id, "side": "response", "decoded": false])
                try require(exported["base64"]?.unicodeString == received.base64EncodedString() && exported["mime_type"]?.sourceFacts.text.count == 1, "Body result hung or lost non-UTF8 MIME source")
                let request = try await command(store, "export_body", ["id": flow.id, "side": "request", "decoded": false, "request_fingerprint": detail.requestFingerprint!])
                try require(request["base64"]?.unicodeString == body.base64EncodedString(), "Fingerprint-bound body export changed request bytes")
                do {
                    _ = try await command(store, "export_body", ["id": flow.id, "side": "request", "request_fingerprint": "stale"])
                    throw ByteFailure(message: "Stale source fingerprint was accepted")
                } catch let error as ByteFailure { try require(error.message != "Stale source fingerprint was accepted", error.message) }
                let archive = directory.appendingPathComponent(scheme + "-raw.har")
                _ = try await command(store, "save_har", ["path": archive.path])
                let saved = try archiveFields(archive, resources)
                store.clear()
                _ = try await command(store, "load_har", ["path": archive.path])
                try await wait("restored row " + scheme) { store.flows.contains { $0.scheme == scheme && $0.imported == true } }
                let restored = store.flows.first { $0.scheme == scheme }!
                try require(restored.requestTargetSource == "har_facts", "Restored row overstates or loses target provenance")
                result = nil
                store.loadFlowDetail(id: restored.id) { result = $0 }
                try await wait("restored Foundation detail " + scheme) { result != nil }
                let reopened = try result!.get()
                try require(reopened.requestFingerprint == detail.requestFingerprint && reopened.requestHeaderFields == detail.requestHeaderFields,
                            "HAR reopen changed raw request identity or headers")
                try require(try reopened.bytes(reopened.requestTargetBase64, label: "restored target") == target,
                            "HAR reopen changed opaque target")
                _ = try await command(store, "save_har", ["path": archive.path])
                try require(try archiveFields(archive, resources) == saved, "HAR re-export changed source archive fields")
                store.selection = restored.id
                store.replay()
                try await wait("native opaque Replay " + scheme) {
                    store.flows.contains { $0.requestOperation?.kind == "replay" && $0.requestOperation?.sourceId == restored.id && $0.state == "complete" } || store.errorMessage != nil
                }
                let draft = ComposeDraft(source: restored, detail: reopened)!
                try require(try draft.patch().isEmpty && draft.message.urlIsOpaque, "Native Keep turned opaque source text into a replacement URL")
                var composed = false, composeIssue: String?
                store.compose(sourceID: draft.sourceID, sourceFingerprint: draft.sourceFingerprint, requestEdit: try draft.patch()) {
                    composeIssue = $0; composed = true
                }
                try await wait("native opaque Compose queue " + scheme) { composed }
                try require(composeIssue == nil, composeIssue ?? "Opaque Compose rejected")
                try await wait("native opaque Compose complete " + scheme) {
                    store.flows.contains { $0.requestOperation?.kind == "compose" && $0.requestOperation?.sourceId == restored.id && $0.state == "complete" } || store.errorMessage != nil
                }
                var repeated = false, repeatIssue: String?
                store.repeatFlow(id: restored.id, count: 2, concurrency: 2, intervalMs: 0) {
                    repeatIssue = $0; repeated = true
                }
                try await wait("native opaque Repeat queue " + scheme) { repeated }
                try require(repeatIssue == nil, repeatIssue ?? "Opaque Repeat rejected")
                try await wait("native opaque Repeat complete " + scheme) {
                    store.repeatJobs.contains { $0.sourceId == restored.id && $0.finished }
                }
                let job = store.repeatJobs.first { $0.sourceId == restored.id && $0.finished }!
                try require(job.completed == 2 && job.failed == 0 && job.cancelled == 0 && store.errorMessage == nil,
                            store.errorMessage ?? "Raw-path operations failed")
                print("PASS: " + scheme + " real native Replay, Compose Keep and concurrent Repeat preserve reopened opaque target and complete source bytes")
                print("PASS: " + scheme + " cURL sends raw path/header/empty/duplicate/NFD/body bytes; real Foundation detail and body results preserve source facts and reject stale export")
                print("PASS: " + scheme + " native HAR save/reopen preserves raw target, headers, fingerprint and exact archive with explicit restored provenance")
            }
            let retained = store.flows.map(\.id)
            var stopped: Bool?
            store.stop { stopped = $0 }
            try await wait("stop keeps raw session inspectable") { stopped != nil }
            try require(stopped == true && !store.isRunning, "Stop lost retained session")
            store.start()
            try await wait("restart restores raw session") { store.isRunning && !store.flows.isEmpty && store.flows.map(\.id) != retained }
            let restarted = store.flows.first!
            try require(restarted.requestTargetSource == "har_facts", "Restart lost retained target provenance")
            var restartedDetail: Result<FlowDetail, Error>?
            store.loadFlowDetail(id: restarted.id) { restartedDetail = $0 }
            try await wait("restarted detail") { restartedDetail != nil }
            let afterRestart = try restartedDetail!.get()
            try require(try afterRestart.bytes(afterRestart.requestTargetBase64, label: "restart target") == target,
                        "Stop/start changed raw target or could not reload session")
            print("PASS: real native Stop/start reloads raw-path HAR into a new engine and renders exact request detail")
            let history = try String(contentsOf: directory.appendingPathComponent("history.jsonl"), encoding: .utf8).split(separator: "\n")
            try require(history.count == 10, "Unexpected number of upstream requests")
            for line in history {
                let record = try JSONSerialization.jsonObject(with: Data(line.utf8)) as! [String: Any]
                let pairs = record["headers"] as! [[String]]
                try require(record["path_base64"] as? String == target.base64EncodedString() && record["body_base64"] as? String == body.base64EncodedString(), "Actual origin target/body changed")
                let actual = pairs.filter { pair in fields.contains { $0.name.base64EncodedString() == pair[0] } }
                try require(actual == fields.map(\.base64Pair), "Actual origin fields changed, disappeared or reordered")
            }
            print("PASS: independent HTTP/TLS origin histories confirm all raw bytes, empty-header presence and duplicate order")
        } catch {
            var ended: Bool?; store.shutdown { ended = $0 }; try? await wait("failed native engine cleanup") { ended != nil }
            throw error
        }
        var ended: Bool?; store.shutdown { ended = $0 }
        try await wait("native engine cleanup") { ended != nil }
        try require(ended == true && !store.hasEngine, "Native engine did not exit normally")
        try input.fileHandleForWriting.write(contentsOf: Data([10])); try input.fileHandleForWriting.close()
        try await wait("origin cleanup") { !process.isRunning }
        try require(process.terminationStatus == 0, "Owned origins did not exit normally")
    }
}
@main @MainActor private struct NativeHTTPBytesSmoke {
    static func main() {
        setbuf(stdout, nil); guard CommandLine.arguments.count == 3 else { exit(2) }
        var done = false, error: Error?
        Task { @MainActor in
            do { try await ByteChecks.run(URL(fileURLWithPath: CommandLine.arguments[1]), URL(fileURLWithPath: CommandLine.arguments[2])) } catch let failure { error = failure }
            done = true
        }
        while !done { _ = RunLoop.main.run(mode: .default, before: Date().addingTimeInterval(0.03)) }
        if let error { fputs("FAIL: \(error)\n", stderr); exit(1) }
    }
}
