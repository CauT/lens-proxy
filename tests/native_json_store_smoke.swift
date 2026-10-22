import AppKit
import Foundation
private struct Failure: Error { let reason: String }
@MainActor private enum Checks {
    static func require(_ value: @autoclosure () throws -> Bool, _ reason: String) throws { if try !value() { throw Failure(reason: reason) } }
    static func wait(_ label: String, _ value: () -> Bool) async throws {
        let deadline = Date().addingTimeInterval(12)
        while !value() { if Date() > deadline { throw Failure(reason: "Timed out: " + label) }; try await Task.sleep(nanoseconds: 20_000_000) }
    }
    static func envelope(_ message: Any, _ text: [[String: Any]] = []) throws -> EngineValue {
        try EngineValue.message(from: JSONSerialization.data(withJSONObject: ["native_json": 1, "message": message, "source_text": text]))
    }
    static func annotation(_ path: [Any], _ raw: Data, kind: String = "value") -> [String: Any] { ["path": path, "kind": kind, "utf8_surrogatepass_base64": raw.base64EncodedString()] }
    static func run(_ root: URL) async throws {
        let original = Data([0x61,0xed,0xb3,0xbf])
        let source = try envelope(["event": "result", "command_id": "fixture", "value": ["text": "a\\udcff", "k0": 1, "k1": 2]], [annotation(["value","text"], original), annotation(["value","k0"], Data("é".utf8), kind: "key"), annotation(["value","k1"], Data("e\u{301}".utf8), kind: "key")])
        let value = source["value"]!
        try require(value.sourceFacts.text.count == 3 && value["text"]?.displayString == "a\\udcff" && value["text"]?.unicodeString == nil, "Slicing lost original text or exposed display as sendable Unicode")
        let reconstructed = String(decoding: try value.serializedSourceJSON(), as: UTF8.self)
        try require(reconstructed.contains("\\udcff") && reconstructed.contains("\\u00e9") && reconstructed.contains("\\u0065\\u0301"), "Source JSON lost original key identities or surrogate")
        try require(value["k0"] == nil && value["k1"] == nil, "Projected source keys became semantic lookup keys")
        let pair = Data([0xed,0xa0,0xbd,0xed,0xb8,0x80])
        let pairValue = try envelope(["event":"result","value":"\\ud83d\\ude00"], [annotation(["value"], pair)])["value"]!
        try require(pairValue.sourceFacts.text[0].utf8SurrogatepassBase64 != Data("😀".utf8).base64EncodedString(), "Literal surrogate pair and astral source were conflated")
        do { _ = try envelope(["event":"result","value":"bad"], [annotation(["value"], Data([0xc0,0x80]))]); throw Failure(reason: "Overlong source encoding accepted") } catch is EngineJSONFailure { }
        print("PASS: sparse source bytes, key identity, slicing and strict/display separation survive native JSON without Unicode repairs")
        let raw: [[String]] = [[Data("X-Binary".utf8).base64EncodedString(), Data([255]).base64EncodedString()]]
        let payload: [String:Any] = ["id":"fixture", "request_headers":[["X-Binary","\\udcff"]], "response_headers":[], "request_headers_base64":raw, "response_headers_base64":[], "response_reason_base64":Data([255]).base64EncodedString(), "request_body":"", "response_body":"", "request_truncated":false, "response_truncated":false, "messages":[]]
        let detail = try envelope(["event":"result", "value":payload], [annotation(["value","request_headers",0,1], Data([0xed,0xb3,0xbf]))])["value"]!.decode(FlowDetail.self)
        try require(detail.requestHeaderFields[0].value == Data([255]), "Header bytes were reconstructed from display text")
        var draft = HTTPMessageDraft(headers: detail.requestHeaderFields)
        try require(try draft.patch().isEmpty && draft.headers[0].encoding == .base64, "Unchanged binary headers became replacements")
        do { try draft.headers[0].setEncoding(.utf8); throw Failure(reason: "Invalid UTF-8 header silently changed mode") } catch is EngineJSONFailure { }
        draft.headers.append(HTTPHeaderRow(name:"X-New", value:"value"))
        let patch = try draft.patch()["headers_base64"] as! [[String]]
        try require(patch[0] == raw[0] && patch.count == 2, "Editing another row lost original binary bytes/order")
        var normalization = HTTPMessageDraft(headers:[HTTPHeaderField(name:Data("X-Normalization".utf8),value:Data("e\u{301}".utf8))])
        normalization.headers[0].value = "é"
        try require(try normalization.patch()["headers_base64"] != nil, "Swift canonical string equality hid a byte-level header edit")
        let reason = HTTPMessageDraft(stage:"response", reason: try detail.reasonBytes())
        try require(try reason.patch().isEmpty && reason.reasonEncoding == .base64, "Reason keep transcoded original bytes")
        let large = Data(repeating: 255, count: 65537)
        var largeDraft = HTTPMessageDraft(stage:"response", reason:large, headers:[HTTPHeaderField(name:Data("X-Large".utf8),value:large)])
        try require(try largeDraft.patch().isEmpty, "Unchanged large observed headers/reason were rejected by edit limits")
        largeDraft.status = "201"
        try require(try largeDraft.patch().count == 1, "Status-only edit reparsed unchanged large source bytes")
        largeDraft.headers.append(HTTPHeaderRow(name:"X-New",value:"new"))
        try require((try? largeDraft.patch()) == nil, "Explicit oversized full header replacement escaped the edit budget")
        largeDraft.headers.removeLast(); largeDraft.reason += "AA=="
        try require((try? largeDraft.patch()) == nil, "Explicit oversized reason replacement escaped the edit budget")
        print("PASS: canonical header/reason bytes own edit baselines; another-row edits preserve binary bytes and NFC/NFD edits remain dirty")
        let plan = try CurlCommand.prepare(method: Data("GET".utf8), url: Data("http://example.invalid/raw".utf8) + Data([255]), target: Data("/raw".utf8) + Data([255]), targetForm:"absolute", proxyPort:"8890", headers: [HTTPHeaderField(name:Data("X-Binary".utf8),value:Data([255])),HTTPHeaderField(name:Data("X-Empty".utf8),value:Data())])
        try require(plan.render(bodyFile:nil).utf8.allSatisfy { $0 < 128 } && plan.render(bodyFile:nil).contains("\\xff") && plan.render(bodyFile:nil).contains("\\x3b"), "cURL did not encode raw bytes/empty-header syntax as ASCII")
        do { _ = try CurlCommand.prepare(method: Data("GET".utf8), url: Data("http://example.invalid/".utf8), target: Data("/".utf8), targetForm:"absolute", proxyPort:"8890", headers:[HTTPHeaderField(name:Data("X".utf8),value:Data([0]))]); throw Failure(reason:"NUL header became a shell argument") } catch is EngineJSONFailure { }
        print("PASS: cURL plan uses ASCII byte quoting and explicit empty-header syntax; unsupported source bytes fail before publication")
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("lens-native-json-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories:true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let resources = directory.appendingPathComponent("resources"), engine = resources.appendingPathComponent("engine")
        try FileManager.default.createDirectory(at: engine, withIntermediateDirectories:true)
        try FileManager.default.createSymbolicLink(at: resources.appendingPathComponent("python"), withDestinationURL: root.appendingPathComponent(".runtime"))
        try FileManager.default.createSymbolicLink(at: resources.appendingPathComponent("site-packages"), withDestinationURL: root.appendingPathComponent(".runtime/lib/python3.13/site-packages"))
        let script = #"""
import json,sys
from pathlib import Path
def emit(v): print(json.dumps({'native_json':1,'message':v,'source_text':[]}),flush=True)
for line in sys.stdin:
 c=json.loads(line); name=c['command']; identity=c.get('command_id')
 if name=='initialize': emit({'event':'ready','capture_stopped':True,'client_certificates':[]})
 if name=='detail':
  print('{invalid-json',flush=True)
  emit({'event':'result','command_id':identity,'value':{'late':True}})
  continue
 if name in ('save_har','save_tcp','save_udp'): Path(c['path']).write_text('{}')
 emit({'event':'result','command_id':identity,'value':True})
 if name=='shutdown': break
"""#
        try script.write(to: engine.appendingPathComponent("engine.py"), atomically:true, encoding:.utf8)
        let system = SystemProxyController(dataDirectory:directory.appendingPathComponent("system"),runner:SystemProxyRunner(read:{ _ in throw Failure(reason:"Host read forbidden") },authorize:{ _ in throw Failure(reason:"Host mutation forbidden") }))
        let store = LensStore(dataDirectory:directory.appendingPathComponent("data"),resources:resources,systemProxy:system)
        store.start(); try await wait("fake engine initialize") { store.hasEngine && !store.isStarting }
        var count = 0, outcome: Result<FlowDetail,Error>?
        store.loadFlowDetail(id:"fixture") { count += 1; outcome = $0 }
        try await wait("malformed event closes pending") { outcome != nil }
        if case .success = outcome! { throw Failure(reason:"Malformed line was treated as success") }
        try await Task.sleep(nanoseconds:100_000_000)
        try require(count == 1 && store.hasEngine && store.errorMessage?.contains("outcome unknown") == true, "Protocol failure hung/repeated callback or killed capture owner")
        var exited: Bool?; store.shutdown { exited = $0 }
        try await wait("owned fixture exits") { exited != nil }
        try require(exited == true && !store.hasEngine, "Fake engine cleanup failed")
        print("PASS: malformed complete JSONL closes pending once, ignores its late reply, preserves the engine/session owner and allows explicit shutdown")
    }
}
@main @MainActor private struct NativeJSONSmoke {
    static func main() {
        setbuf(stdout,nil); guard CommandLine.arguments.count == 2 else { exit(2) }
        var done=false, failure:Error?
        Task { @MainActor in do { try await Checks.run(URL(fileURLWithPath:CommandLine.arguments[1])) } catch { failure=error }; done=true }
        while !done { _ = RunLoop.main.run(mode:.default,before:Date().addingTimeInterval(0.03)) }
        if let failure { fputs("FAIL: \(failure)\n",stderr); exit(1) }
    }
}
