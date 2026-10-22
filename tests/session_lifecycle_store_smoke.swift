// Actual native Store -> packaged engine -> private HTTP fixture.
import AppKit
import Foundation

private struct SessionFailure: Error, CustomStringConvertible { let description: String }
@MainActor private enum SessionChecks {
    static func require(_ value: @autoclosure () throws -> Bool, _ reason: String) throws {
        if try !value() { throw SessionFailure(description: reason) }
    }
    static func wait(_ label: String, _ condition: () -> Bool) async throws {
        let end = Date().addingTimeInterval(20)
        while !condition() {
            if Date() > end { throw SessionFailure(description: "Timed out: " + label) }
            try await Task.sleep(nanoseconds: 20_000_000)
        }
    }
    static func run(_ resources: URL) async throws {
        let files = FileManager.default, root = files.temporaryDirectory.appendingPathComponent("lens-session-close-" + UUID().uuidString)
        try files.createDirectory(at: root, withIntermediateDirectories: false)
        defer { try? files.removeItem(at: root) }
        let portsFile = root.appendingPathComponent("ports.json")
        let origin = Process(); origin.executableURL = resources.appendingPathComponent("python/bin/python3")
        origin.arguments = ["-c", #"""
import http.server,json,socket,sys
from pathlib import Path
class Handler(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  body=b'{"source":"original"}';self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
 def log_message(self,*args):pass
server=http.server.HTTPServer(('127.0.0.1',0),Handler)
with socket.socket() as reservation:
 reservation.bind(('127.0.0.1',0));proxy=reservation.getsockname()[1]
Path(sys.argv[1]).write_text(json.dumps({'origin':server.server_port,'proxy':proxy}))
server.serve_forever()
"""#, portsFile.path]
        try origin.run()
        let system = SystemProxyController(dataDirectory: root.appendingPathComponent("system"), runner: SystemProxyRunner(read: { _ in throw SessionFailure(description: "Host read forbidden") }, authorize: { _ in throw SessionFailure(description: "Host mutation forbidden") }))
        let store = LensStore(dataDirectory: root.appendingPathComponent("data"), resources: resources, systemProxy: system)
        func shutdown() async throws {
            var result: Bool?; store.shutdown { result = $0 }
            try await wait("shutdown") { result != nil }; try require(result == true, "Incomplete engine shutdown")
        }
        do {
            try await wait("origin") { files.fileExists(atPath: portsFile.path) || !origin.isRunning }
            let ports = try JSONSerialization.jsonObject(with: Data(contentsOf: portsFile)) as! [String: Int]
            store.port = String(ports["proxy"]!); store.start()
            try await wait("Start") { store.isRunning || store.errorMessage != nil }
            try require(store.isRunning, store.errorMessage ?? "Start failed")
            func request(_ path: String) async throws -> TrafficFlow {
                let before = Set(store.flows.map(\.id)), output = root.appendingPathComponent(UUID().uuidString)
                let client = Process(); client.executableURL = URL(fileURLWithPath: "/usr/bin/curl")
                client.arguments = ["--silent", "--show-error", "--max-time", "15", "--noproxy", "", "--proxy", "http://127.0.0.1:" + store.port, "--output", output.path, "http://127.0.0.1:\(ports["origin"]!)" + path]
                try client.run(); try await wait("client") { !client.isRunning }; try require(client.terminationStatus == 0, "Client failed")
                try await wait("row") { store.flows.contains { !before.contains($0.id) && $0.status == 200 } }
                return store.flows.first { !before.contains($0.id) }!
            }
            let first = try await request("/first"), firstSession = store.currentSessionID
            var renamed: Bool?; store.renameSession(firstSession, name: "API 中文") { renamed = $0 }
            try await wait("rename") { renamed != nil }
            try require(renamed == true && store.currentSessionName == "API 中文" && store.flows.first?.id == first.id, "Rename changed identity or lost records")
            store.newSession(); try await wait("new") { store.sessions.count == 2 && !store.sessionChanging }
            let secondSession = store.currentSessionID; _ = try await request("/second")
            var rejected: Bool?; store.closeSession(firstSession, backupPath: root.appendingPathComponent("missing/copy.json").path) { rejected = $0 }
            try await wait("failed copy") { rejected != nil }
            try require(rejected == false && store.sessions.contains { $0.id == firstSession } && store.flows(in: firstSession).first?.id == first.id, "Failed copy removed source session")
            store.errorMessage = nil
            let backup = root.appendingPathComponent("closed.lens.json")
            var closed: Bool?; store.closeSession(firstSession, backupPath: backup.path) { closed = $0 }
            try await wait("close") { closed != nil }
            try require(closed == true && store.sessions.map(\.id) == [secondSession] && store.currentSessionID == secondSession, "Close removed another session or kept closed tab")
            _ = try await request("/still-live")
            try require(store.flows.count == 2 && store.isRunning, "Close stopped unrelated capture")
            print("PASS: native rename retains identity; failed backup retains source; successful close preserves other live capture")
            // Opening the usual internal retention path must not let Stop
            // replace the selected file with the current, already-closed view.
            let selectedInput = store.dataDirectory.appendingPathComponent("retained-workspace.lens.json")
            let selectedBytes = try Data(contentsOf: backup)
            try selectedBytes.write(to: selectedInput)
            store.openWorkspaceCopy(path: selectedInput.path)
            try await wait("open workspace") { store.hasEngine && !store.isStarting && !store.isRunning && store.sessions.count == 2 && store.sessions.contains { $0.name == "API 中文" } }
            try require(try Data(contentsOf: selectedInput) == selectedBytes, "Open overwrote its selected workspace input")
            store.selectSession(firstSession); store.selection = first.id; store.loadDetail()
            try await wait("restored detail") { !store.detailLoading && store.detail?.id == first.id }
            try require(store.detail?.responseBody == "{\"source\":\"original\"}", "Workspace copy lost old response")
            print("PASS: native Open workspace copy stops/replaces safely and restores renamed tabs plus exact old response")
            store.start(); try await wait("restart") { store.isRunning || (!store.isStarting && store.errorMessage != nil) }
            try require(store.isRunning && store.sessions.count == 2, store.errorMessage ?? "Start lost restored workspace")
            store.newSession(); try await wait("next number") { !store.sessionChanging && store.sessions.count == 3 }
            try require(store.sessions.last?.number == 3, "Restart reused a closed session number")
            try await shutdown(); origin.terminate(); try await wait("origin exit") { !origin.isRunning }
            print("PASS: Start retains restored names/records and numbering; shutdown joins both owned processes")
        } catch {
            let original = error
            try? await shutdown()
            if origin.isRunning { origin.terminate(); try? await wait("origin cleanup") { !origin.isRunning } }
            throw original
        }
    }
}
@main private struct SessionLifecycleStoreSmoke {
    static func main() async {
        do {
            guard CommandLine.arguments.count == 2 else { throw SessionFailure(description: "Pass app Resources") }
            try await SessionChecks.run(URL(fileURLWithPath: CommandLine.arguments[1]))
        } catch { fputs("FAIL: \(error)\n", stderr); exit(1) }
    }
}
