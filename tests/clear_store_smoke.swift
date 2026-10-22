// Native Store -> actual packaged engine/origin. Only the workspace writer is
// held by an owned fixture shim to reproduce arrivals during a copy reliably.
import AppKit
import Foundation

private struct ClearFailure: Error { let message: String }
@MainActor private enum ClearChecks {
    static func require(_ value: @autoclosure () throws -> Bool, _ reason: String) throws {
        if try !value() { throw ClearFailure(message: reason) }
    }
    static func wait(_ label: String, _ predicate: () throws -> Bool) async throws {
        let end = Date().addingTimeInterval(25)
        while try !predicate() {
            if Date() > end { throw ClearFailure(message: "Timed out: " + label) }
            try await Task.sleep(nanoseconds: 15_000_000)
        }
    }
    static func object(_ url: URL) throws -> [String: Any] {
        try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as! [String: Any]
    }
    static func run(_ resources: URL) async throws {
        let files = FileManager.default, root = files.temporaryDirectory.appendingPathComponent("lens-clear-store-" + UUID().uuidString)
        try files.createDirectory(at: root, withIntermediateDirectories: false)
        defer { try? files.removeItem(at: root) }
        let fixture = root.appendingPathComponent("resources")
        try files.createDirectory(at: fixture.appendingPathComponent("engine"), withIntermediateDirectories: true)
        for name in ["python", "site-packages", "peer-process-identities"] {
            try files.createSymbolicLink(at: fixture.appendingPathComponent(name), withDestinationURL: resources.appendingPathComponent(name))
        }
        let encoder = JSONEncoder(); encoder.outputFormatting = [.withoutEscapingSlashes]
        let sourcePath = String(data: try encoder.encode(resources.appendingPathComponent("engine/engine.py").path), encoding: .utf8)!
        let shim = #"""
import asyncio,importlib.util,sys,time
from pathlib import Path
source=Path(__SOURCE__);sys.path.insert(0,str(source.parent))
spec=importlib.util.spec_from_file_location('lens_clear_production',source);module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
original=module.save_workspace
def save(path,snapshot):
 if Path(path).name.startswith('held-'):
  path=Path(path);path.with_suffix('.entered').touch();deadline=time.monotonic()+20
  while not path.with_suffix('.release').exists():
   if time.monotonic()>deadline:raise TimeoutError('Owned test copy was not released')
   time.sleep(.01)
 return original(path,snapshot)
module.save_workspace=save
asyncio.run(module.main())
"""#.replacingOccurrences(of: "__SOURCE__", with: sourcePath)
        try shim.write(to: fixture.appendingPathComponent("engine/engine.py"), atomically: true, encoding: .utf8)
        let portsFile = root.appendingPathComponent("ports.json"), origin = Process()
        origin.executableURL = resources.appendingPathComponent("python/bin/python3")
        origin.arguments = ["-c", #"""
import http.server,json,socket,sys
from pathlib import Path
class Handler(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  body=json.dumps({'source':'original','path':self.path}).encode();self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
 def log_message(self,*_):pass
server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
with socket.socket() as s:s.bind(('127.0.0.1',0));proxy=s.getsockname()[1]
Path(sys.argv[1]).write_text(json.dumps({'origin':server.server_port,'proxy':proxy}));server.serve_forever()
"""#, portsFile.path]
        try origin.run()
        let system = SystemProxyController(dataDirectory: root.appendingPathComponent("system"), runner: SystemProxyRunner(read: { _ in throw ClearFailure(message: "Host read forbidden") }, authorize: { _ in throw ClearFailure(message: "Host mutation forbidden") }))
        let store = LensStore(dataDirectory: root.appendingPathComponent("data"), resources: fixture, systemProxy: system)
        func shutdown() async throws {
            var result: Bool?; store.shutdown { result = $0 }
            try await wait("shutdown") { result != nil }; try require(result == true, store.errorMessage ?? "Shutdown failed")
        }
        let held = root.appendingPathComponent("held-first.lens.json"), heldStop = root.appendingPathComponent("held-stop.lens.json")
        do {
            try await wait("origin") { files.fileExists(atPath: portsFile.path) || !origin.isRunning }
            let ports = try object(portsFile) as! [String: Int]
            store.port = String(ports["proxy"]!); store.start()
            try await wait("Start") { store.isRunning || store.errorMessage != nil }
            try require(store.isRunning, store.errorMessage ?? "Start failed")
            var responses: [String: Data] = [:]
            func request(_ path: String) async throws -> TrafficFlow {
                let output = root.appendingPathComponent(UUID().uuidString), client = Process()
                client.executableURL = URL(fileURLWithPath: "/usr/bin/curl")
                let url = "http://127.0.0.1:\(ports["origin"]!)" + path
                client.arguments = ["--silent", "--show-error", "--max-time", "15", "--noproxy", "", "--proxy", "http://127.0.0.1:" + store.port, "--output", output.path, url]
                try client.run()
                do { try await wait("client") { !client.isRunning } }
                catch { if client.isRunning { client.terminate(); try? await wait("client cleanup") { !client.isRunning } }; throw error }
                try require(client.terminationStatus == 0, "Client failed")
                try await wait("captured response") { store.sessions.contains { room in store.flows(in: room.id).contains { $0.url == url && $0.state == "complete" } } }
                let flow = store.sessions.flatMap { store.flows(in: $0.id) }.first { $0.url == url }!
                responses[flow.id] = try Data(contentsOf: output)
                return flow
            }
            let old = try await request("/old"), first = store.currentSessionID
            store.newSession(); try await wait("second session") { !store.sessionChanging && store.sessions.count == 2 }
            let second = store.currentSessionID; let other = try await request("/other")
            store.presentSessionAction(.clearHTTP, identity: first)
            try require(store.sessionAction?.session.id == first && store.flows(in: first).count == 1 && store.currentSessionID == second, "Presenting Clear changed records or target")
            store.sessionAction = nil
            print("PASS present/cancel binds the requested room without modifying captures")
            var rejected: Bool?
            store.clear(first, backupPath: root.appendingPathComponent("missing/copy.json").path) { rejected = $0 }
            try await wait("failed copy") { rejected != nil }
            try require(rejected == false && store.flows(in: first).first?.id == old.id && store.flows(in: second).first?.id == other.id, "Failed copy cleared records")
            store.errorMessage = nil
            print("PASS actual file failure preserves both rooms and can be retried")
            store.selectSession(first); store.recordInCurrentSession(); try await wait("record target") { !store.sessionChanging && store.captureSessionID == first }
            let mirror = root.appendingPathComponent("mirror"), archives = store.archiveController(for: first)
            archives.selectMirrorPath(mirror.path); archives.setMirror(true)
            var copied: Bool?
            store.clear(first, backupPath: held.path) { copied = $0 }
            try await wait("copy admitted") { files.fileExists(atPath: held.deletingPathExtension().appendingPathExtension("entered").path) }
            let fresh = try await request("/during-copy")
            store.selectSession(second)
            try Data().write(to: held.deletingPathExtension().appendingPathExtension("release"))
            try await wait("copy/clear") { copied != nil }
            try require(copied == true && store.currentSessionID == second && store.flows(in: first).map(\.id) == [fresh.id] && store.flows.map(\.id) == [other.id], "Clear reset late arrivals or the selected other room")
            let rooms = try object(held)["sessions"] as! [[String: Any]]
            let saved = rooms.first { $0["id"] as? String == first }!
            try require(saved["flow_ids"] as? [String] == [old.id], "Snapshot included later requests or missed the original")
            let savedEntry = ((saved["har"] as! [String: Any])["log"] as! [String: Any])["entries"] as! [[String: Any]]
            try require(Data(base64Encoded: savedEntry[0]["_lensRawResponseBody"] as! String) == responses[old.id], "Snapshot changed the original response bytes")
            try await wait("future response mirror") { try files.contentsOfDirectory(at: mirror, includingPropertiesForKeys: nil).filter { !$0.lastPathComponent.hasPrefix(".") }.count == 1 }
            let folder = try files.contentsOfDirectory(at: mirror, includingPropertiesForKeys: nil).first { !$0.lastPathComponent.hasPrefix(".") }!
            let mirrored = try object(folder.appendingPathComponent("metadata.json"))
            try require(mirrored["flow_id"] as? String == fresh.id && (try Data(contentsOf: folder.appendingPathComponent("response.bin"))) == responses[fresh.id], "New response was lost, duplicated or misbound by the mirror barrier")
            print("PASS real traffic during a held copy stays captured/mirrored; saved snapshot and other view remain independent")
            var cleared: Bool?; store.clear(first) { cleared = $0 }
            try await wait("clear without copy") { cleared != nil }
            try require(cleared == true && store.flows(in: first).isEmpty && store.flows.first?.id == other.id, "Explicit Clear crossed session boundaries")
            let continuing = try await request("/after-clear")
            try require(store.flows(in: first).map(\.id) == [continuing.id] && store.isRunning, "Clear stopped capture or suppressed future requests")
            print("PASS explicit Clear keeps the session and capture continues")
            var lastClear: Bool?, stopped: Bool?
            store.clear(first, backupPath: heldStop.path) { lastClear = $0 }
            try await wait("last copy admitted") { files.fileExists(atPath: heldStop.deletingPathExtension().appendingPathExtension("entered").path) }
            store.stop { stopped = $0 }
            try Data().write(to: heldStop.deletingPathExtension().appendingPathExtension("release"))
            try await wait("Clear plus Stop") { lastClear != nil && stopped != nil }
            try require(lastClear == true && stopped == true && !store.isRunning && store.hasEngine && store.flows(in: first).isEmpty && store.flows(in: second).first?.id == other.id, "Stop did not drain the admitted copy/Clear")
            print("PASS Stop drains an admitted copy/Clear and retains the other room")
            try await shutdown(); origin.terminate(); try await wait("origin exit") { !origin.isRunning }
        } catch {
            try? Data().write(to: held.deletingPathExtension().appendingPathExtension("release"))
            try? Data().write(to: heldStop.deletingPathExtension().appendingPathExtension("release"))
            try? await shutdown()
            if origin.isRunning { origin.terminate(); try? await wait("origin cleanup") { !origin.isRunning } }
            throw error
        }
    }
}
@main private struct ClearStoreSmoke {
    static func main() async {
        do { guard CommandLine.arguments.count == 2 else { exit(2) }; try await ClearChecks.run(URL(fileURLWithPath: CommandLine.arguments[1])) }
        catch { fputs("FAIL: \(error)\n", stderr); exit(1) }
    }
}
