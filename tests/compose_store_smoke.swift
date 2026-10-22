// Production draft + Store -> actual engine -> owned HTTP origin. No app window,
// host proxy access, external network, or preview bytes used as replacement input.
import AppKit
import Foundation
import CryptoKit
private struct ComposeFailure: Error { let message: String }
@MainActor private enum Checks {
    static func require(_ value: @autoclosure () throws -> Bool, _ reason: String) throws {
        if try !value() { throw ComposeFailure(message: reason) }
    }
    static func wait(_ label: String, _ value: () -> Bool) async throws {
        let deadline = Date().addingTimeInterval(20)
        while !value() { if Date() > deadline { throw ComposeFailure(message: "Timed out: " + label) }; try await Task.sleep(nanoseconds: 20_000_000) }
    }
    static func command(_ store: LensStore, _ name: String, _ args: [String: Any] = [:]) async throws -> Any {
        var value: Any?, issue: String?
        store.send(name, args, onError: { issue = $0 }) { result in
            guard result.sourceFacts.text.isEmpty else { issue = "Fixture unexpectedly returned source text annotations"; return }
            value = result.projection
        }
        try await wait(name) { value != nil || issue != nil }
        if let issue { throw ComposeFailure(message: issue) }; return value!
    }
    static func detail(_ store: LensStore, _ id: String) async throws -> FlowDetail {
        var result: Result<FlowDetail, Error>?
        store.loadFlowDetail(id: id) { result = $0 }
        try await wait("fixed source detail") { result != nil }
        return try result!.get()
    }
    static func shutdown(_ store: LensStore) async throws {
        var result: Bool?; store.shutdown { result = $0 }
        try await wait("owned engine exit") { result != nil }
        try require(result == true && !store.hasEngine, "Engine cleanup failed: \(store.errorMessage ?? store.status)")
    }
    static func queue(_ store: LensStore, source: String? = nil, fingerprint: String? = nil, patch: [String: Any], failure: Bool = false) async throws -> TrafficFlow? {
        let previous = Set(store.flows.map(\.id))
        var done = false, issue: String?
        store.compose(sourceID: source, sourceFingerprint: fingerprint, requestEdit: patch) { issue = $0; done = true }
        try await wait("queued acknowledgement") { done }
        try require((issue != nil) == failure, issue ?? "Expected synchronous rejection")
        if failure { return nil }
        try await wait("actual captured result after queue") { store.flows.contains { !previous.contains($0.id) && $0.state == "complete" } || store.errorMessage != nil }
        try require(store.errorMessage == nil, store.errorMessage ?? "Outgoing request failed")
        return store.flows.first { !previous.contains($0.id) && $0.state == "complete" }!
    }
    static func queue(_ store: LensStore, _ draft: ComposeDraft) async throws -> TrafficFlow {
        try await queue(store, source: draft.sourceID, fingerprint: draft.sourceFingerprint, patch: draft.patch())!
    }
    static func digest(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
    static func history(_ file: URL) throws -> [[String: Any]] {
        guard FileManager.default.fileExists(atPath: file.path) else { return [] }
        return try String(contentsOf: file, encoding: .utf8).split(separator: "\n").map { try JSONSerialization.jsonObject(with: Data($0.utf8)) as! [String: Any] }
    }
    static func run(_ resources: URL) async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("lens-compose-store-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let denied = SystemProxyRunner(read: { _ in throw ComposeFailure(message: "Host read forbidden") }, authorize: { _ in throw ComposeFailure(message: "Host mutation forbidden") })
        let system = SystemProxyController(dataDirectory: directory.appendingPathComponent("system"), runner: denied)
        let store = LensStore(dataDirectory: directory.appendingPathComponent("data"), resources: resources, systemProxy: system)
        var restored: LensStore?
        let fixture = Process(), ports = directory.appendingPathComponent("ports.json"), log = directory.appendingPathComponent("history.jsonl")
        fixture.executableURL = resources.appendingPathComponent("python/bin/python3")
        fixture.arguments = ["-u", "-c", #"""
import gzip,hashlib,http.server,json,socket,sys,threading
from pathlib import Path
lock=threading.Lock()
class Handler(http.server.BaseHTTPRequestHandler):
 def do_GET(self): self.observe()
 def do_POST(self): self.observe()
 def do_PATCH(self): self.observe()
 def observe(self):
  raw=self.rfile.read(int(self.headers.get('Content-Length',0))); decoded=gzip.decompress(raw) if self.headers.get('Content-Encoding')=='gzip' else raw
  record={'method':self.command,'path':self.path,'headers':list(self.headers.items()),'wire_length':len(raw),'wire_sha256':hashlib.sha256(raw).hexdigest(),'decoded_length':len(decoded),'decoded_sha256':hashlib.sha256(decoded).hexdigest()}
  with lock:
   with open(sys.argv[2],'a') as out: out.write(json.dumps(record)+'\n')
  body=json.dumps(record).encode(); self.send_response(200); self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)
 def log_message(self,*args): pass
server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler); server.daemon_threads=True
with socket.socket() as reservation:
 reservation.bind(('127.0.0.1',0)); port=reservation.getsockname()[1]
Path(sys.argv[1]).write_text(json.dumps([server.server_port,port])); server.serve_forever()
"""#, ports.path, log.path]
        try fixture.run(); defer { if fixture.isRunning { fixture.terminate() } }
        do {
            try await wait("owned HTTP origin") { FileManager.default.fileExists(atPath: ports.path) }
            let numbers = try JSONDecoder().decode([Int].self, from: Data(contentsOf: ports))
            store.port = String(numbers[1]); store.start()
            try await wait("engine ready") { store.isRunning || store.errorMessage != nil }
            try require(store.isRunning, store.errorMessage ?? "Engine failed")
            let base = "http://127.0.0.1:\(numbers[0])"
            var large = Data([0,255,13,10]); large.append(Data(repeating: 0x81, count: 2 * 1024 * 1024))
            let file = directory.appendingPathComponent("large-binary.dat"); try large.write(to: file)
            var new = ComposeDraft(); new.message.method = "POST"; new.message.url = base + "/source"
            new.message.headers = [HTTPHeaderRow(name: "X-Repeat", value: "one"), HTTPHeaderRow(name: "X-Repeat", value: "two"), HTTPHeaderRow(name: "Content-Encoding", value: "gzip")]
            new.message.replaceBody = true; new.message.replacementFileData = try HTTPMessageDraft.readReplacement(file); new.message.replacementFileName = file.lastPathComponent
            let source = try await queue(store, new)
            let sourceDetail = try await detail(store, source.id)
            try require(sourceDetail.requestTruncated && sourceDetail.requestBinary == true && sourceDetail.requestBodyAvailable == true, "Large binary source was not retained beyond the preview")
            try require(source.requestOperation?.kind == "compose" && source.requestOperation?.sourceId == nil && source.requestOperation?.urlInput == base + "/source", "New Compose source/URL operation facts missing")
            let first = try history(log)[0]
            try require(first["decoded_length"] as? Int == large.count && first["decoded_sha256"] as? String == digest(large), "File replacement was limited to the display preview")
            let firstPairs = first["headers"] as! [[String]]
            try require(firstPairs.filter { $0[0].lowercased() == "x-repeat" }.map { $0[1] } == ["one", "two"], "New Compose duplicate header order lost")
            print("PASS: native new Compose queues >2 MiB binary file, preserves ordered duplicate headers and gzip semantics, and captures typed operation facts")

            let unchanged = ComposeDraft(source: source, detail: sourceDetail)!
            try require(try unchanged.patch().isEmpty, "Source preview became a replacement patch")
            store.selection = source.id; store.loadDetail()
            try await wait("selected source detail") { store.detail?.id == source.id && !store.detailLoading }
            store.selection = nil
            let fixedDetail = try await detail(store, source.id)
            try require(fixedDetail.id == source.id && store.selection == nil, "Independent source load redirected selection")
            let copied = try await queue(store, unchanged)
            let second = try history(log)[1]
            try require(first["wire_sha256"] as? String == second["wire_sha256"] as? String && first["wire_length"] as? Int == second["wire_length"] as? Int, "Keep did not preserve exact compressed binary wire bytes")
            try require((second["headers"] as! [[String]]) == firstPairs, "Keep changed original wire headers")
            try require(copied.requestOperation?.sourceId == source.id && copied.requestOperation?.urlInput == nil, "Based Compose facts redirected to selection")
            var headerOnly = unchanged; headerOnly.message.headers.append(HTTPHeaderRow(name: "X-Header-Only", value: "kept binary body"))
            let headerPatch = try headerOnly.patch()
            try require(headerPatch["body_base64"] == nil && headerPatch["headers_base64"] != nil, "Header-only Compose invented a preview body replacement")
            _ = try await queue(store, headerOnly)
            let headerRecord = try history(log).last!
            try require(headerRecord["wire_sha256"] as? String == first["wire_sha256"] as? String && headerRecord["decoded_sha256"] as? String == digest(large), "Header-only Compose lost complete compressed binary source bytes")
            let copiedDetail = try await detail(store, copied.id)
            var unguardedDetail = sourceDetail; unguardedDetail.requestFingerprint = nil
            try require(ComposeDraft(source: source, detail: unguardedDetail) == nil, "Source details without fingerprint became an unguarded draft")
            try require(ComposeDraft(source: source, detail: copiedDetail) == nil, "Mismatched source details became an edit baseline")
            var missingDetail: Result<FlowDetail, Error>?
            store.loadFlowDetail(id: "missing-source") { missingDetail = $0 }
            try await wait("missing source detail rejection") { missingDetail != nil }
            if case .success = missingDetail! { throw ComposeFailure(message: "Missing details silently became empty fields") }
            print("PASS: fixed-source Compose and header-only edits keep complete compressed binary bytes; independent details reject mismatched/missing sources")

            var edited = unchanged; edited.message.method = "PATCH"; edited.message.url = base + "/edited"
            edited.message.headers = [HTTPHeaderRow(name: "X-Repeat", value: "three"), HTTPHeaderRow(name: "X-Repeat", value: "four")]
            edited.message.replaceBody = true; edited.message.body = "replacement 文本"
            store.selection = copied.id
            let changed = try await queue(store, edited)
            try require(changed.method == "PATCH" && changed.url.hasSuffix("/edited") && changed.requestOperation?.sourceId == source.id, "Selection changed fixed Compose method/URL/source")
            let changedRecord = try history(log).last!
            try require(changedRecord["decoded_sha256"] as? String == digest(Data(edited.message.body.utf8)) && !(changedRecord["headers"] as! [[String]]).contains { $0[0].lowercased() == "content-encoding" }, "Explicit UTF-8 replacement inherited stale gzip headers")
            var empty = unchanged; empty.message.url = base + "/empty"; empty.message.replaceBody = true; empty.message.body = ""
            _ = try await queue(store, empty)
            try require(try history(log).last!["decoded_sha256"] as? String == digest(Data()), "Explicit empty replacement was treated as keep")
            var binary = unchanged; binary.message.url = base + "/base64"; binary.message.replaceBody = true; binary.message.encoding = .base64; binary.message.body = Data([0,254,255]).base64EncodedString()
            _ = try await queue(store, binary)
            try require(try history(log).last!["decoded_sha256"] as? String == digest(Data([0,254,255])), "Explicit Base64 replacement lost binary bytes")
            print("PASS: source Compose edits method/URL/duplicate headers and explicit UTF-8, empty or Base64 bodies without reusing preview bytes")

            var defaultRequest = ComposeDraft(); defaultRequest.message.url = base + "/default-new"
            let defaultFlow = try await queue(store, defaultRequest)
            try require(defaultFlow.method == "GET" && (try history(log).last!["decoded_sha256"] as? String) == digest(Data()), "New Compose default GET/empty body was not sent")
            let beforeInvalid = try history(log).count
            _ = try await queue(store, source: source.id, patch: ["method": "BAD METHOD"], failure: true)
            _ = try await queue(store, source: changed.id, fingerprint: unchanged.sourceFingerprint, patch: [:], failure: true)
            _ = try await queue(store, source: "missing-source", patch: [:], failure: true)
            var invalid = unchanged; invalid.message.headers.append(HTTPHeaderRow(name: "X-Bad", value: "a\r\nb"))
            try require((try? invalid.patch()) == nil, "Malformed native header accepted")
            invalid = unchanged; invalid.message.replaceBody = true; invalid.message.encoding = .base64; invalid.message.body = "AA==\n"
            try require((try? invalid.patch()) == nil, "Malformed Base64 accepted")
            try require(try history(log).count == beforeInvalid, "Rejected edit sent an outgoing request")
            var repeatDone = false, repeatIssue: String?
            store.selection = changed.id
            store.repeatFlow(id: source.id, count: 2, concurrency: 2, intervalMs: 0) { repeatIssue = $0; repeatDone = true }
            try await wait("repeat job queued") { repeatDone }
            try require(repeatIssue == nil, repeatIssue ?? "Repeat failed")
            try await wait("repeat job completed") { store.repeatJobs.contains { $0.sourceId == source.id && $0.finished } }
            let job = store.repeatJobs.first { $0.sourceId == source.id && $0.finished }!
            try require(job.completed == 2 && job.failed == 0, "Repeat did not complete both requests")
            let attempts = store.flows.filter { $0.requestOperation?.id == job.id }
            try require(attempts.count == 2 && Set(attempts.compactMap { $0.requestOperation?.attempt }) == [1,2] && attempts.allSatisfy { $0.requestOperation?.sourceId == source.id && $0.url == source.url }, "Repeat source, job or attempt facts changed with selection")
            print("PASS: invalid/missing/stale-fingerprint Compose rejects before sending; Repeat is bound to its opened source and captures job/source/attempt identity")

            let entry: [String: Any] = ["startedDateTime": "2026-01-01T00:00:00Z", "time": 1, "timings": ["send": 0, "wait": 1, "receive": 0],
                "request": ["method": "POST", "url": base + "/unavailable", "httpVersion": "HTTP/1.1", "headers": [], "bodySize": -1, "postData": ["mimeType": "application/octet-stream"]],
                "response": ["status": 200, "statusText": "OK", "httpVersion": "HTTP/1.1", "headers": [], "bodySize": 0, "content": ["size": 0, "text": ""]]]
            _ = try await command(store, "import_har", ["har": ["log": ["entries": [entry]]]])
            try await wait("unavailable imported source") { store.flows.contains { $0.url.hasSuffix("/unavailable") } }
            let unavailable = store.flows.first { $0.url.hasSuffix("/unavailable") }!
            var replacement = ComposeDraft(source: unavailable, detail: try await detail(store, unavailable.id))!
            try require((try? replacement.patch()) == nil, "Unavailable source silently became empty")
            _ = try await queue(store, source: unavailable.id, patch: [:], failure: true)
            replacement.message.replaceBody = true; replacement.message.body = "explicit replacement"
            let recovered = try await queue(store, replacement)
            try require(try history(log).last!["decoded_sha256"] as? String == digest(Data("explicit replacement".utf8)), "Unavailable source replacement bytes changed")
            try require(recovered.requestOperation?.sourceId == unavailable.id && recovered.requestBodyAvailable == true, "Corrected draft did not queue explicit unavailable-body replacement")
            let har = directory.appendingPathComponent("session.har")
            _ = try await command(store, "save_har", ["path": har.path])
            let facts = store.flows.compactMap(\.requestOperation)
            try await shutdown(store)
            let reopened = LensStore(dataDirectory: directory.appendingPathComponent("reopened"), resources: resources, systemProxy: system)
            restored = reopened; reopened.port = store.port; reopened.start()
            try await wait("fresh engine") { reopened.isRunning || reopened.errorMessage != nil }
            try require(reopened.isRunning, reopened.errorMessage ?? "Fresh engine failed")
            _ = try await command(reopened, "load_har", ["path": har.path])
            try await wait("typed HAR operation facts") { reopened.flows.compactMap(\.requestOperation).count == facts.count }
            try require(facts.allSatisfy { fact in reopened.flows.contains { $0.requestOperation == fact } }, "HAR lost native operation provenance")
            try require(reopened.flows.first { $0.url.hasSuffix("/unavailable") && $0.requestBodyAvailable == false }?.requestOperation == nil, "External source missing operation facts acquired invented provenance")
            try await shutdown(reopened)
            print("PASS: unavailable body requires explicit replacement; fresh HAR import preserves typed operation facts and external absence")
        } catch {
            if let restored, restored.hasEngine { try? await shutdown(restored) }
            if store.hasEngine { try? await shutdown(store) }
            throw error
        }
        fixture.terminate(); try await wait("owned origin cleanup") { !fixture.isRunning }
    }
}
@main @MainActor private struct ComposeStoreSmoke {
    static func main() {
        setbuf(stdout, nil); guard CommandLine.arguments.count == 2 else { exit(2) }
        var done = false, failure: Error?
        Task { @MainActor in do { try await Checks.run(URL(fileURLWithPath: CommandLine.arguments[1])) } catch { failure = error }; done = true }
        while !done { _ = RunLoop.main.run(mode: .default, before: Date().addingTimeInterval(0.05)) }
        if let failure { fputs("FAIL: \(failure)\n", stderr); exit(1) }
    }
}
