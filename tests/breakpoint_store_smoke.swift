// Actual production Store -> packaged engine -> owned HTTP origin. No host proxy
// access or live app window; tests the draft boundary separately from rendered UI.
import AppKit
import Foundation
private struct BreakpointFailure: Error { let message: String }
@MainActor private enum Checks {
    static func require(_ value: @autoclosure () throws -> Bool, _ reason: String) throws {
        if try !value() { throw BreakpointFailure(message: reason) }
    }
    static func wait(_ label: String, _ value: () -> Bool) async throws {
        let deadline = Date().addingTimeInterval(20)
        while !value() { if Date() > deadline { throw BreakpointFailure(message: "Timed out: " + label) }; try await Task.sleep(nanoseconds: 20_000_000) }
    }
    static func shutdown(_ store: LensStore) async throws {
        var result: Bool?; store.shutdown { result = $0 }
        try await wait("engine cleanup") { result != nil }
        try require(result == true && !store.hasEngine, "Engine cleanup failed")
    }
    static func detail(_ store: LensStore, _ id: String) async throws -> FlowDetail {
        store.selection = id; store.loadDetail()
        try await wait("detail") { store.detail?.id == id && !store.detailLoading || store.detailError != nil }
        try require(store.detailError == nil, store.detailError ?? "Detail failed")
        return store.detail!
    }
    static func resume(_ store: LensStore, _ draft: BreakpointDraft, edit: [String: Any]? = nil, abort: Bool = false, failure: Bool = false) async throws {
        var finished = false, issue: String?
        store.resumeBreakpoint(flowID: draft.flowID, pauseID: draft.pauseID, stage: draft.stage, edit: edit, abort: abort) { issue = $0; finished = true }
        try await wait("bound resume acknowledgement") { finished }
        try require((issue != nil) == failure, issue ?? "Expected edit rejection")
    }
    static func paused(_ store: LensStore, path: String, stage: String) async throws -> TrafficFlow {
        try await wait("paused " + stage) { store.flows.contains { $0.url.contains(path) && $0.state == "paused" && $0.breakpointStage == stage } }
        return store.flows.first { $0.url.contains(path) && $0.state == "paused" && $0.breakpointStage == stage }!
    }
    static func client(_ resources: URL, proxy: String, origin: Int, path: String, output: URL) throws -> Process {
        let process = Process(); process.executableURL = resources.appendingPathComponent("python/bin/python3")
        process.arguments = ["-c", #"""
import base64,http.client,json,sys
from pathlib import Path
try:
 c=http.client.HTTPConnection('127.0.0.1',int(sys.argv[1]),timeout=15)
 c.request('POST','http://127.0.0.1:'+sys.argv[2]+sys.argv[3],body=b'\x00original\xff',headers={'Content-Type':'application/octet-stream'})
 r=c.getresponse(); result={'status':r.status,'reason':r.reason,'headers':r.getheaders(),'body':base64.b64encode(r.read()).decode()}; c.close()
except Exception as e: result={'error':str(e)}
Path(sys.argv[4]).write_text(json.dumps(result))
"""#, proxy, String(origin), path, output.path]; try process.run(); return process
    }
    static func object(_ file: URL) throws -> [String: Any] { try JSONSerialization.jsonObject(with: Data(contentsOf: file)) as! [String: Any] }
    static func run(_ resources: URL) async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("lens-breakpoint-store-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let system = SystemProxyController(dataDirectory: directory.appendingPathComponent("system"), runner: SystemProxyRunner(read: { _ in throw BreakpointFailure(message: "Host read forbidden") }, authorize: { _ in throw BreakpointFailure(message: "Host mutation forbidden") }))
        let store = LensStore(dataDirectory: directory.appendingPathComponent("data"), resources: resources, systemProxy: system)
        let fixture = Process(), ports = directory.appendingPathComponent("ports.json"), observed = directory.appendingPathComponent("observed.json")
        fixture.executableURL = resources.appendingPathComponent("python/bin/python3")
        fixture.arguments = ["-u", "-c", #"""
import base64,http.server,json,socket,sys
from pathlib import Path
class Handler(http.server.BaseHTTPRequestHandler):
 def do_POST(self): self.handle_request()
 def do_PATCH(self): self.handle_request()
 def handle_request(self):
  body=self.rfile.read(int(self.headers.get('Content-Length',0)))
  Path(sys.argv[2]).write_text(json.dumps({'method':self.command,'path':self.path,'headers':list(self.headers.items()),'body':base64.b64encode(body).decode()}))
  payload=b'\x00original-response\xff'
  self.send_response(200,'Origin reason'); self.send_header('X-Origin','one'); self.send_header('X-Origin','two'); self.send_header('Content-Length',str(len(payload))); self.end_headers(); self.wfile.write(payload)
 def log_message(self,*args): pass
server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler); server.daemon_threads=True
with socket.socket() as reservation:
 reservation.bind(('127.0.0.1',0)); port=reservation.getsockname()[1]
Path(sys.argv[1]).write_text(json.dumps([server.server_port,port])); server.serve_forever()
"""#, ports.path, observed.path]
        try fixture.run(); defer { if fixture.isRunning { fixture.terminate() } }
        var clients: [Process] = []
        defer { for client in clients where client.isRunning { client.terminate() } }
        do {
            try await wait("owned origin") { FileManager.default.fileExists(atPath: ports.path) }
            let numbers = try JSONDecoder().decode([Int].self, from: Data(contentsOf: ports))
            store.port = String(numbers[1]); store.rules = [ProxyRule(kind: "breakpoint_request", match: "*"), ProxyRule(kind: "breakpoint_response", match: "*")]
            store.start(); try await wait("engine ready") { store.isRunning || store.errorMessage != nil }
            try require(store.isRunning, store.errorMessage ?? "Engine failed")
            let firstResult = directory.appendingPathComponent("first.json")
            let first = try client(resources, proxy: store.port, origin: numbers[0], path: "/first", output: firstResult); clients.append(first)
            let request = try await paused(store, path: "/first", stage: "request")
            let requestDetail = try await detail(store, request.id)
            var draft = BreakpointDraft(flow: request, detail: requestDetail)!
            try require(try draft.patch().isEmpty, "Default draft alters wire bytes")
            var invalid = draft; invalid.message.method = "BAD METHOD"
            try require((try? invalid.patch()) == nil, "Method token validation missing")
            invalid = draft; invalid.message.url = "http://user:pass@example.com/#frag"
            try require((try? invalid.patch()) == nil, "URL credentials/fragment accepted")
            invalid = draft; invalid.message.headers.append(HTTPHeaderRow(name: "X-Test", value: "a\r\nb"))
            try require((try? invalid.patch()) == nil, "Header injection accepted")
            invalid = draft; invalid.message.headers.append(HTTPHeaderRow(name: "Host", value: "other"))
            try require((try? invalid.patch()) == nil, "Engine-managed header accepted")
            invalid = draft; invalid.message.replaceBody = true; invalid.message.encoding = .base64; invalid.message.body = "AA==\n"
            try require((try? invalid.patch()) == nil, "Noncanonical Base64 accepted")
            invalid.message.body = ""; try require(try invalid.patch()["body_base64"] as? String == "", "Explicit empty body lost")
            var binary = Data([0, 255, 10, 13, 128]); binary.append(Data(repeating: 0x81, count: 2 * 1024 * 1024))
            let file = directory.appendingPathComponent("binary.dat")
            let oversized = directory.appendingPathComponent("oversized.dat")
            _ = FileManager.default.createFile(atPath: oversized.path, contents: Data())
            let oversizedHandle = try FileHandle(forWritingTo: oversized)
            try oversizedHandle.truncate(atOffset: UInt64(HTTPMessageDraft.fileBodyLimit + 1)); try oversizedHandle.close()
            try require((try? HTTPMessageDraft.readReplacement(oversized)) == nil && (try? HTTPMessageDraft.readReplacement(directory)) == nil, "Oversized or nonregular body input accepted")
            try binary.write(to: file); draft.message.replacementFileData = try HTTPMessageDraft.readReplacement(file); draft.message.replacementFileName = file.lastPathComponent; draft.message.replaceBody = true
            draft.message.method = "PATCH"; draft.message.url = "http://127.0.0.1:\(numbers[0])/edited"
            draft.message.headers = [HTTPHeaderRow(name: "X-Repeat", value: "one"), HTTPHeaderRow(name: "X-Repeat", value: "two")]
            store.selection = nil // A later selection cannot redirect this editor to another flow.
            try await resume(store, draft, edit: draft.patch())
            let response = try await paused(store, path: "/edited", stage: "response")
            try require(response.pauseId != request.pauseId, "Pause identity reused across stages")
            try require(BreakpointDraft(flow: response, detail: requestDetail) == nil, "Previous-stage details became a new response edit baseline")
            try await resume(store, draft, edit: ["body_base64": ""], failure: true)
            try require(store.flows.first { $0.id == response.id }?.pauseId == response.pauseId, "Stale editor resumed response stage")
            var responseDraft = BreakpointDraft(flow: response, detail: try await detail(store, response.id))!
            try require(responseDraft.message.reason == "Origin reason", "Response reason missing from detail")
            try await resume(store, responseDraft, edit: ["status_code": 99], failure: true)
            try require(store.flows.first { $0.id == response.id }?.state == "paused", "Invalid edit ended pause")
            responseDraft.message.status = "201"; responseDraft.message.reason = "Edited reason"
            responseDraft.message.headers = [HTTPHeaderRow(name: "X-Edited", value: "one"), HTTPHeaderRow(name: "X-Edited", value: "two")]
            responseDraft.message.replaceBody = true; responseDraft.message.encoding = .base64; responseDraft.message.body = Data([0, 254, 255]).base64EncodedString()
            try await resume(store, responseDraft, edit: responseDraft.patch())
            try await wait("first client response") { !first.isRunning }
            let sent = try object(observed), received = try object(firstResult)
            try require(sent["method"] as? String == "PATCH" && sent["path"] as? String == "/edited" && sent["body"] as? String == binary.base64EncodedString(), "Request file/method/URL edit lost bytes")
            let requestPairs = sent["headers"] as! [[String]]
            try require(requestPairs.filter { $0[0].lowercased() == "x-repeat" }.map { $0[1] } == ["one", "two"], "Request duplicate header order lost")
            try require(received["status"] as? Int == 201 && received["reason"] as? String == "Edited reason" && received["body"] as? String == responseDraft.message.body, "Response metadata or binary edit failed")
            let responsePairs = received["headers"] as! [[String]]
            try require(responsePairs.filter { $0[0].lowercased() == "x-edited" }.map { $0[1] } == ["one", "two"], "Response duplicate header order lost")
            print("PASS: real Store edits request method/URL/ordered duplicate headers/binary file above 2 MiB and response status/reason/headers/Base64")
            print("PASS: bound pause identities reject previous-stage details, stale and invalid edits while the new stage remains paused; selection changes cannot redirect edits")
            let secondResult = directory.appendingPathComponent("second.json")
            let second = try client(resources, proxy: store.port, origin: numbers[0], path: "/unchanged", output: secondResult); clients.append(second)
            let untouchedRequest = try await paused(store, path: "/unchanged", stage: "request")
            let untouchedDraft = BreakpointDraft(flow: untouchedRequest, detail: try await detail(store, untouchedRequest.id))!
            try await resume(store, untouchedDraft)
            let untouchedResponse = try await paused(store, path: "/unchanged", stage: "response")
            try await resume(store, BreakpointDraft(flow: untouchedResponse, detail: try await detail(store, untouchedResponse.id))!)
            try await wait("unchanged client response") { !second.isRunning }
            try require(try object(observed)["body"] as? String == Data([0] + Array("original".utf8) + [255]).base64EncodedString(), "Unchanged request binary lost")
            try require(try object(secondResult)["body"] as? String == Data([0] + Array("original-response".utf8) + [255]).base64EncodedString(), "Unchanged response binary lost")
            print("PASS: continue unchanged preserves original binary request/response wire bytes without a body patch")
            let thirdResult = directory.appendingPathComponent("third.json")
            let third = try client(resources, proxy: store.port, origin: numbers[0], path: "/abort", output: thirdResult); clients.append(third)
            let abortFlow = try await paused(store, path: "/abort", stage: "request")
            try await resume(store, BreakpointDraft(flow: abortFlow, detail: try await detail(store, abortFlow.id))!, abort: true)
            try await wait("aborted client exits") { !third.isRunning }
            try require(try object(thirdResult)["error"] != nil, "Abort produced a response")
            print("PASS: explicit empty replacement and native malformed input validation; Abort terminates the owned paused request")
            try await shutdown(store)
        } catch { if store.hasEngine { try? await shutdown(store) }; throw error }
        fixture.terminate(); try await wait("origin cleanup") { !fixture.isRunning }
    }
}
@main @MainActor private struct BreakpointStoreSmoke {
    static func main() {
        setbuf(stdout, nil); guard CommandLine.arguments.count == 2 else { exit(2) }
        var done = false, failure: Error?
        Task { @MainActor in do { try await Checks.run(URL(fileURLWithPath: CommandLine.arguments[1])) } catch { failure = error }; done = true }
        while !done { _ = RunLoop.main.run(mode: .default, before: Date().addingTimeInterval(0.05)) }
        if let failure { fputs("FAIL: \(failure)\n", stderr); exit(1) }
    }
}
