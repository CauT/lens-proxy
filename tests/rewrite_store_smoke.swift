// Actual native Store -> packaged engine -> owned HTTP origin; no host settings.
import AppKit
import Foundation

private struct RewriteFailure: Error, CustomStringConvertible { let description: String }
@MainActor private enum RewriteChecks {
    static func require(_ value: @autoclosure () throws -> Bool, _ reason: String) throws {
        if try !value() { throw RewriteFailure(description: reason) }
    }
    static func wait(_ label: String, _ condition: () -> Bool) async throws {
        let end = Date().addingTimeInterval(20)
        while !condition() {
            if Date() > end { throw RewriteFailure(description: "Timed out: " + label) }
            try await Task.sleep(nanoseconds: 20_000_000)
        }
    }
    static func apply(_ store: LensStore, _ rules: [ProxyRule], success: Bool = true) async throws {
        var result: Bool?
        store.applyRules(rules) { result = $0 }
        try await wait("configure acknowledgment") { result != nil }
        try require(result == success, store.errorMessage ?? "Unexpected configure outcome")
    }
    static func shutdown(_ store: LensStore) async throws {
        var result: Bool?
        store.shutdown { result = $0 }
        try await wait("engine exit") { result != nil }
        try require(result == true && !store.hasEngine, "Engine cleanup incomplete")
    }
    static func run(_ resources: URL) async throws {
        let decoder = JSONDecoder(), encoder = JSONEncoder()
        let legacy = try decoder.decode(ProxyRule.self, from: Data(#"{"id":"legacy","enabled":true,"kind":"rewrite_response_body","match":"*","name":"old","value":"new"}"#.utf8))
        try require(legacy.rewriteMode == "set" && legacy.rewriteCount == "all" && legacy.rewriteFind.isEmpty && !legacy.rewriteRegex && !legacy.rewriteNameRegex && legacy.rewriteCaseSensitive && !legacy.rewriteWhole && legacy.rewriteTimeoutMs == 250, "Legacy semantics changed")
        var unknown = legacy; unknown.rewriteCount = "future"; unknown.rewriteMode = "future"
        let reopenedUnknown = try decoder.decode(ProxyRule.self, from: encoder.encode(unknown))
        try require(reopenedUnknown.rewriteCount == "future" && reopenedUnknown.rewriteMode == "future" && reopenedUnknown.rewriteIssue != nil, "Unknown choices were silently normalized")
        print("PASS: legacy rewrite defaults and unknown selected options survive native persistence with explicit invalid-choice feedback")
        var transition = ProxyRule(kind: "rewrite_request_header", name: "X-Value", value: "new\nline", rewriteMode: "replace", rewriteFind: "old", rewriteCount: "first")
        transition.selectRewriteMode("set")
        try require(transition.rewriteFind.isEmpty && transition.rewriteCount == "all", "Mode change retained hidden Replace options")
        transition.selectRewriteMode("remove")
        try require(transition.value.isEmpty && transition.rewriteIssue == nil, "Remove retained a hidden replacement value")
        transition = ProxyRule(kind: "rewrite_response_body", name: "old", value: "new", rewriteCount: "first")
        transition.selectKind("rewrite_response_header")
        try require(transition.rewriteCount == "all" && transition.rewriteMode == "set" && transition.rewriteFind.isEmpty, "Kind change retained hidden body options")
        transition = ProxyRule(kind: "rewrite_request_header", name: "X-Value", value: "new", rewriteMode: "replace", rewriteFind: "old", rewriteCount: "first")
        transition.selectKind("rewrite_response_header")
        try require(transition.rewriteMode == "replace" && transition.rewriteFind == "old" && transition.rewriteCount == "first", "Direction change discarded applicable header options")
        transition.selectKind("rewrite_request_query")
        try require(transition.rewriteMode == "replace" && transition.rewriteFind == "old" && transition.rewriteCount == "first", "Query discarded supported Replace options")
        transition = ProxyRule(kind: "rewrite_request_body", name: "old", value: "new", rewriteCount: "first")
        transition.selectKind("rewrite_response_body")
        try require(transition.rewriteCount == "first", "Direction change discarded applicable body count")
        print("PASS: explicit kind/operation transitions clear only inapplicable draft options while decoding preserves source choices")

        let files = FileManager.default, root = files.temporaryDirectory.appendingPathComponent("lens-rewrite-store-" + UUID().uuidString)
        try files.createDirectory(at: root, withIntermediateDirectories: false)
        defer { try? files.removeItem(at: root) }
        let info = root.appendingPathComponent("ports.json"), observed = root.appendingPathComponent("observed.json")
        let origin = Process()
        origin.executableURL = resources.appendingPathComponent("python/bin/python3")
        origin.arguments = ["-c", #"""
import http.server,json,socket,sys
from pathlib import Path
class Handler(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  Path(sys.argv[2]).write_text(json.dumps({'path':self.path,'headers':list(self.headers.items())}))
  body=b'old old'; self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
 def log_message(self,*args):pass
server=http.server.HTTPServer(('127.0.0.1',0),Handler)
with socket.socket() as reservation:
 reservation.bind(('127.0.0.1',0));proxy=reservation.getsockname()[1]
Path(sys.argv[1]).write_text(json.dumps({'origin':server.server_port,'proxy':proxy}))
server.serve_forever()
"""#, info.path, observed.path]
        try origin.run()
        let system = SystemProxyController(dataDirectory: root.appendingPathComponent("system"), runner: SystemProxyRunner(read: { _ in throw RewriteFailure(description: "Host read forbidden") }, authorize: { _ in throw RewriteFailure(description: "Host mutation forbidden") }))
        let store = LensStore(dataDirectory: root.appendingPathComponent("data"), resources: resources, systemProxy: system)
        do {
            try await wait("origin ready") { files.fileExists(atPath: info.path) || !origin.isRunning }
            let ports = try JSONSerialization.jsonObject(with: Data(contentsOf: info)) as! [String: Int]
            store.port = String(ports["proxy"]!); store.start()
            try await wait("engine ready") { store.isRunning || (!store.isStarting && store.errorMessage != nil) }
            try require(store.isRunning, store.errorMessage ?? "Engine did not start")
            let query = ProxyRule(kind: "rewrite_request_query", name: "token", value: "空 格", rewriteMode: "set")
            let url = ProxyRule(kind: "rewrite_request_url", name: "/old?", value: "/new?")
            let header = ProxyRule(kind: "rewrite_request_header", name: "X-Ordered", value: "one", rewriteMode: "add")
            let body = ProxyRule(kind: "rewrite_response_body", name: "old", value: "new", rewriteCount: "first")
            let status = ProxyRule(kind: "rewrite_response_status", name: "201", value: "Lens created")
            let selected = [query, url, header, body, status]
            try await apply(store, selected)
            let reopened = LensStore(dataDirectory: store.dataDirectory, resources: resources, systemProxy: system)
            try require(try encoder.encode(reopened.rules).count > 0 && reopened.rules.map(\.id) == selected.map(\.id) && reopened.rules[3].rewriteCount == "first", "Accepted ordered options did not persist")
            print("PASS: actual engine admits new native URL/query/header/body/status rules and saved order/options reopen intact")

            func request() async throws -> FlowDetail {
                let before = Set(store.flows.map(\.id)), output = root.appendingPathComponent(UUID().uuidString), head = root.appendingPathComponent(UUID().uuidString)
                let client = Process(); client.executableURL = URL(fileURLWithPath: "/usr/bin/curl")
                client.arguments = ["--silent", "--show-error", "--max-time", "15", "--noproxy", "", "--proxy", "http://127.0.0.1:" + store.port, "--output", output.path, "--dump-header", head.path, "http://127.0.0.1:\(ports["origin"]!)/old?x=keep&token=first&token=second"]
                try client.run(); try await wait("client exit") { !client.isRunning }
                try require(client.terminationStatus == 0, "Actual client failed")
                try await wait("new actual captured row") { store.flows.contains { !before.contains($0.id) && $0.status != nil } }
                let row = store.flows.first { !before.contains($0.id) }!
                store.selection = row.id; store.loadDetail()
                try await wait("native details") { !store.detailLoading }
                guard let detail = store.detail else { throw RewriteFailure(description: store.detailError ?? "Native detail missing") }
                let responseHead = try String(contentsOf: head, encoding: .utf8)
                try require(try Data(contentsOf: output) == Data(detail.responseBody.utf8), "Client bytes differ from native captured response")
                if store.selectedFlow?.status == 201 { try require(responseHead.hasPrefix("HTTP/1.0 201 Lens created\r\n") || responseHead.hasPrefix("HTTP/1.1 201 Lens created\r\n"), "Actual client status/reason mismatch") }
                let origin = try JSONSerialization.jsonObject(with: Data(contentsOf: observed)) as! [String: Any]
                let originHeaders = origin["headers"] as! [[String]]
                try require(originHeaders.filter { $0[0].lowercased().hasPrefix("x-order") } == detail.requestHeaders.filter { $0[0].lowercased().hasPrefix("x-order") }, "Origin header order differs from native captured fields")
                return detail
            }
            let detail = try await request()
            let captured = try JSONSerialization.jsonObject(with: Data(contentsOf: observed)) as! [String: Any]
            try require(captured["path"] as? String == "/new?x=keep&token=%E7%A9%BA%20%E6%A0%BC", "Native query/url choices changed source or encoded value")
            try require(detail.responseBody == "new old" && detail.responseReason == "Lens created" && store.selectedFlow?.status == 201, "Native count/status/reason/body facts changed")
            try require(detail.requestHeaders.contains { $0[0].lowercased() == "x-ordered" && $0[1] == "one" }, "Native header action missing")
            print("PASS: real client and typed native details agree on encoded query, effective URL, first-only body rewrite and201reason")

            let first = ProxyRule(kind: "rewrite_request_header", name: "X-Order", value: "alpha")
            let second = ProxyRule(kind: "rewrite_request_header", name: "X-Order", value: "beta", rewriteMode: "replace", rewriteFind: "alpha")
            try await apply(store, [first, second]); let forward = try await request()
            try await apply(store, [second, first]); let backward = try await request()
            func order(_ value: FlowDetail) -> String? { value.requestHeaders.first { $0[0].lowercased() == "x-order" }?[1] }
            try require(order(forward) == "beta" && order(backward) == "alpha", "Actual engine ignored native list order")
            print("PASS: reversing native draft rule order changes actual ordered header result without changing source identity")

            let rulesFile = store.dataDirectory.appendingPathComponent("rules.json"), before = try Data(contentsOf: rulesFile)
            try await apply(store, [ProxyRule(kind: "rewrite_request_header", name: "Content-Length", value: "9")], success: false)
            try require(try Data(contentsOf: rulesFile) == before && store.rules.map(\.id) == [second.id, first.id], "Rejected framing rewrite replaced accepted native/saved rules")
            print("PASS: strict managed-header rejection preserves accepted native and saved rule generation")
            var grouped = ProxyRule.rewriteSet()
            grouped.name = "Response captures"; grouped.locations = ["never", "*/old?*"]
            var pattern = ProxyRule(kind: "rewrite_response_body", name: "(old)", value: "new:$1", rewriteCount: "first")
            pattern.rewriteRegex = true; pattern.rewriteTimeoutMs = 500
            grouped.rewriteRules = [pattern]
            var finish = ProxyRule.rewriteSet(); finish.name = "Finish"; finish.locations = ["*"]
            finish.rewriteRules = [ProxyRule(kind: "rewrite_response_body", name: "new:old", value: "final")]
            try await apply(store, [grouped, finish])
            let patterned = try await request()
            try require(patterned.responseBody == "final old", "Native ordered sets or capture references failed")
            let persisted = LensStore(dataDirectory: store.dataDirectory, resources: resources, systemProxy: system)
            try require(persisted.rules.map(\.id) == [grouped.id, finish.id] && persisted.rules[0].locations == grouped.locations && persisted.rules[0].rewriteRules[0].rewriteRegex && persisted.rules[0].rewriteRules[0].rewriteTimeoutMs == 500, "Nested set choices did not reopen intact")
            grouped.enabled = false
            try await apply(store, [grouped, finish]); let disabled = try await request()
            try require(disabled.responseBody == "old old", "Disabled set still changed bytes")
            grouped.enabled = true
            try await apply(store, [finish, grouped]); let reversed = try await request()
            try require(reversed.responseBody == "new:old old", "Set order did not determine actual client bytes")
            print("PASS: native named sets, OR locations, captures, enable switches and reversed order survive Save/reopen and match real client bytes")
            let acceptedPatterns = try Data(contentsOf: rulesFile)
            var invalidPattern = pattern; invalidPattern.name = "("
            var invalidSet = grouped; invalidSet.rewriteRules = [invalidPattern]
            try await apply(store, [invalidSet], success: false)
            try require(try Data(contentsOf: rulesFile) == acceptedPatterns && store.rules.map(\.id) == [finish.id, grouped.id], "Rejected regex replaced accepted set generation")
            print("PASS: rejected pattern leaves both running native and persisted ordered sets unchanged")

            let recoveryDirectory = root.appendingPathComponent("unreadable-rules")
            try files.createDirectory(at: recoveryDirectory, withIntermediateDirectories: false)
            let unreadable = Data("[{broken original rules".utf8)
            try unreadable.write(to: recoveryDirectory.appendingPathComponent("rules.json"))
            let recovery = LensStore(dataDirectory: recoveryDirectory, resources: resources, systemProxy: system)
            try require(recovery.rulesPreferencesIssue != nil, "Unreadable saved rules became silent empty rules")
            recovery.start()
            try require(!recovery.hasEngine && recovery.rulesPreferencesIssue != nil, "Unreadable saved rules allowed live capture")
            try require(try Data(contentsOf: recoveryDirectory.appendingPathComponent("rules.json")) == unreadable, "Start changed original unreadable rules")
            try await apply(recovery, [grouped])
            let backups = try files.contentsOfDirectory(at: recoveryDirectory, includingPropertiesForKeys: nil).filter { $0.lastPathComponent.hasPrefix("rules-recovery-") }
            try require(backups.count == 1, "Explicit replacement did not retain exactly one recovery copy")
            try require(try Data(contentsOf: backups[0]) == unreadable && (files.attributesOfItem(atPath: backups[0].path)[.posixPermissions] as? NSNumber)?.intValue == 0o600, "Recovery copy changed source bytes or permissions")
            try require(recovery.rulesPreferencesIssue == nil && LensStore(dataDirectory: recoveryDirectory, resources: resources, systemProxy: system).rules[0].name == grouped.name, "Explicit reviewed replacement did not reopen")
            print("PASS: unreadable saved rules block Start; explicit replacement preserves original bytes in a private recovery copy")
            var stopped: Bool?; store.stop { stopped = $0 }; try await wait("Stop") { stopped != nil }
            try require(stopped == true && !store.isRunning && store.hasEngine && store.detail?.id == reversed.id, "Stop lost selected rewritten facts")
            try await shutdown(store)
            origin.terminate(); try await wait("origin exit") { !origin.isRunning }
            print("PASS: Stop retains rewritten selected details and shutdown confirms both owned processes exit")
        } catch {
            let original = error
            var cleanup: [String] = []
            do { try await shutdown(store) } catch { cleanup.append("engine: \(error)") }
            if origin.isRunning {
                origin.terminate()
                do { try await wait("origin cleanup") { !origin.isRunning } } catch { cleanup.append("origin: \(error)") }
            }
            if !cleanup.isEmpty { throw RewriteFailure(description: "\(original); cleanup incomplete: " + cleanup.joined(separator: "; ")) }
            throw original
        }
    }
}
@main private struct RewriteStoreSmoke {
    static func main() async {
        do {
            guard CommandLine.arguments.count == 2 else { throw RewriteFailure(description: "Pass app Resources") }
            try await RewriteChecks.run(URL(fileURLWithPath: CommandLine.arguments[1]))
        } catch { fputs("FAIL: \(error)\n", stderr); exit(1) }
    }
}
