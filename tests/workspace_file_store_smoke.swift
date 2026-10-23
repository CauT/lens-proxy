// Actual native file owner -> packaged engine -> owned HTTP fixture.
@testable import LensNative
import AppKit
import Foundation

private struct WorkspaceFailure: Error, CustomStringConvertible { let description: String }
@MainActor private enum WorkspaceChecks {
    static func require(_ value: @autoclosure () throws -> Bool, _ reason: String) throws {
        if try !value() { throw WorkspaceFailure(description: reason) }
    }
    static func wait(_ label: String, _ value: () -> Bool) async throws {
        let deadline = Date().addingTimeInterval(20)
        while !value() {
            if Date() > deadline { throw WorkspaceFailure(description: "Timed out: " + label) }
            try await Task.sleep(nanoseconds: 20_000_000)
        }
    }
    static func run(resources: URL, root: URL) async throws {
        let files = FileManager.default
        try files.createDirectory(at: root, withIntermediateDirectories: true)
        let engineResources = root.appendingPathComponent("resources")
        try files.createDirectory(at: engineResources.appendingPathComponent("engine"), withIntermediateDirectories: true)
        for name in ["python", "site-packages", "peer-process-identities"] {
            try files.createSymbolicLink(at: engineResources.appendingPathComponent(name), withDestinationURL: resources.appendingPathComponent(name))
        }
        let sourceEncoder = JSONEncoder(); sourceEncoder.outputFormatting = [.withoutEscapingSlashes]
        let sourcePath = String(data: try sourceEncoder.encode(resources.appendingPathComponent("engine/engine.py").path), encoding: .utf8)!
        let shim = #"""
import asyncio,importlib.util,sys,time,uuid
from pathlib import Path
source=Path(__SOURCE__);sys.path.insert(0,str(source.parent))
spec=importlib.util.spec_from_file_location('lens_document_production',source);module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
original=module.save_workspace
def save(path,snapshot):
 path=Path(path)
 if path.name=='live-save.lens.json':
  path.with_suffix('.entered').touch();deadline=time.monotonic()+20
  while not path.with_suffix('.release').exists():
   if time.monotonic()>deadline:raise TimeoutError('Owned live save was not released')
   time.sleep(.01)
 return original(path,snapshot)
module.save_workspace=save
command=module.Lens.command
async def commands(self,cmd):
 result=await command(self,cmd)
 if cmd['command']=='save_workspace' and Path(cmd['path']).name=='forged-receipt.lens.json':
  result['workspace_revision']={'epoch':str(uuid.uuid4()),'generation':'0'}
 return result
module.Lens.command=commands
try:asyncio.run(module.main())
except Exception as exc:
 module.emit('fatal',message=str(exc));sys.exit(1)
"""#.replacingOccurrences(of: "__SOURCE__", with: sourcePath)
        try shim.write(to: engineResources.appendingPathComponent("engine/engine.py"), atomically: true, encoding: .utf8)
        let liveRelease = root.appendingPathComponent("live-save.lens.release")
        let portsFile = root.appendingPathComponent("ports.json")
        let origin = Process()
        origin.executableURL = resources.appendingPathComponent("python/bin/python3")
        origin.arguments = ["-B", "-c", #"""
import http.server,json,socket,sys
from pathlib import Path
class Handler(http.server.BaseHTTPRequestHandler):
 def do_POST(self):
  data=self.rfile.read(int(self.headers['Content-Length']));body=b'response:'+data
  self.send_response(200);self.send_header('Content-Type','application/octet-stream');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
 def log_message(self,*args):pass
server=http.server.HTTPServer(('127.0.0.1',0),Handler)
with socket.socket() as reservation:
 reservation.bind(('127.0.0.1',0));proxy=reservation.getsockname()[1]
Path(sys.argv[1]).write_text(json.dumps({'origin':server.server_port,'proxy':proxy}))
server.serve_forever()
"""#, portsFile.path]
        try origin.run()
        let system = SystemProxyController(dataDirectory: root.appendingPathComponent("system"), runner: SystemProxyRunner(
            read: { _ in throw WorkspaceFailure(description: "Host proxy read forbidden") },
            authorize: { _ in throw WorkspaceFailure(description: "Host proxy write forbidden") }))
        var recents: [URL] = []
        let history = WorkspaceHistory(read: { recents }, remember: { url in
            recents.removeAll { $0 == url }; recents.insert(url, at: 0)
        }, clear: { recents.removeAll() })
        let store = LensStore(dataDirectory: root.appendingPathComponent("state"), resources: engineResources, systemProxy: system, workspaceHistory: history)
        func shutdown() async throws {
            var done: Bool?
            store.shutdown { done = $0 }
            try await wait("shutdown") { done != nil }
            try require(done == true && !store.hasEngine, store.errorMessage ?? "Engine did not exit")
        }
        func saved(_ path: URL) async throws -> Bool {
            var done: Bool?
            store.saveWorkspace(path: path.path) { done = $0 }
            try await wait("workspace save") { done != nil }
            return done == true
        }
        func entries(_ path: URL) throws -> [[String: Any]] {
            let document = try JSONSerialization.jsonObject(with: Data(contentsOf: path)) as! [String: Any]
            return (document["sessions"] as! [[String: Any]]).flatMap { (($0["har"] as! [String: Any])["log"] as! [String: Any])["entries"] as! [[String: Any]] }
        }
        do {
            try await wait("origin") { files.fileExists(atPath: portsFile.path) }
            let ports = try JSONSerialization.jsonObject(with: Data(contentsOf: portsFile)) as! [String: Int]
            store.port = String(ports["proxy"]!); store.start()
            try await wait("ready") { store.isRunning || store.errorMessage != nil }
            try require(store.isRunning, store.errorMessage ?? "Start failed")
            try require(!store.needsWorkspaceSaveConfirmation, "Pristine workspace is edited")
            let payload = Data([0, 255, 65, 66, 10]), payloadFile = root.appendingPathComponent("request.bin")
            try payload.write(to: payloadFile)
            func request(_ path: String) async throws -> TrafficFlow {
                let previous = Set(store.flows.map(\.id))
                let receipt = root.appendingPathComponent(UUID().uuidString + ".response")
                let client = Process(); client.executableURL = URL(fileURLWithPath: "/usr/bin/curl")
                client.arguments = ["--silent", "--show-error", "--max-time", "8", "--noproxy", "", "--proxy", "http://127.0.0.1:\(ports["proxy"]!)", "--data-binary", "@" + payloadFile.path, "--output", receipt.path, "http://127.0.0.1:\(ports["origin"]!)" + path]
                try client.run()
                try await wait("client") { !client.isRunning }
                try require(client.terminationStatus == 0, "Client failed")
                try require(try Data(contentsOf: receipt) == Data("response:".utf8) + payload, "Client body bytes changed")
                try await wait("flow") { store.flows.contains { !previous.contains($0.id) && $0.state == "complete" } }
                return store.flows.first { !previous.contains($0.id) && $0.state == "complete" }!
            }
            let firstSession = store.currentSessionID
            let first = try await request("/workspace-first")
            try require(store.needsWorkspaceSaveConfirmation && store.workspaceWindowTitle.contains("Edited"), "New capture did not mark the workspace edited")
            store.saveWorkspace()
            try require(store.sessionAction?.kind == .saveWorkspace && store.workspaceFileURL == nil, "First Save did not ask a destination")
            store.sessionAction = nil
            try require(store.workspaceFileURL == nil && recents.isEmpty, "Cancel assigned or remembered an unsaved destination")
            let a = root.appendingPathComponent("workspace-A-\u{4e2d}\u{6587}-e\u{301}.lens.json")
            let firstSaved = try await saved(a)
            try require(firstSaved, "First Save failed")
            try require(!store.needsWorkspaceSaveConfirmation, "Quiet successful Save remained edited")
            try require(store.recentWorkspaceURLs == [a], "Successful Save was not remembered")
            try require(store.isRunning && store.workspaceFileURL?.path.utf8.elementsEqual(a.path.utf8) == true, "Save stopped capture or lost path bytes")
            let live = root.appendingPathComponent("live-save.lens.json")
            var liveSaved: Bool?
            store.saveWorkspace(path: live.path) { liveSaved = $0 }
            try await wait("live snapshot cut") { files.fileExists(atPath: root.appendingPathComponent("live-save.lens.entered").path) }
            _ = try await request("/workspace-during-save")
            try Data().write(to: liveRelease)
            try await wait("live save completion") { liveSaved != nil }
            try require(liveSaved == true && store.needsWorkspaceSaveConfirmation && (try entries(live).count) == 1, "Live save incorrectly marked its later arrival as saved")
            let newerSaved = try await saved(a)
            try require(newerSaved, "Saving the newer workspace failed")
            try require(!store.needsWorkspaceSaveConfirmation, "Second Save did not include newer traffic")
            store.newSession()
            try await wait("new session") { store.sessions.count == 2 && store.currentSessionID != firstSession }
            var renamed: Bool?
            store.renameSession(store.currentSessionID, name: "API \u{4e2d}\u{6587}") { renamed = $0 }
            try await wait("rename") { renamed != nil }
            try require(renamed == true, "Rename failed")
            _ = try await request("/workspace-second")
            store.search = "no-visible-matching-rows"
            try require(store.filteredFlows.isEmpty, "Filter fixture is not empty")
            store.saveWorkspace()
            try await wait("repeat Save") { !store.workspaceSaving }
            try require(try entries(a).count == 3 && store.isRunning && !store.needsWorkspaceSaveConfirmation, "Repeat Save omitted a room, honored the view filter or stayed edited")
            try require(recents == [a, live], "Repeat Save duplicated its recent entry")
            print("PASS: first Save/Cancel, exact Unicode destination, live repeat Save, all rooms and filtered-view independence")
            let blocked = root.appendingPathComponent("blocked.lens.json")
            try files.createDirectory(at: blocked, withIntermediateDirectories: false)
            let blockedSaved = try await saved(blocked)
            try require(!blockedSaved, "Directory target unexpectedly succeeded")
            try require(recents == [a, live] && !store.needsWorkspaceSaveConfirmation, "Failed Save As changed history or clean state")
            try require(store.workspaceFileURL?.path.utf8.elementsEqual(a.path.utf8) == true, "Failed Save As replaced the accepted destination")
            store.errorMessage = nil
            let forged = try await saved(root.appendingPathComponent("forged-receipt.lens.json"))
            try require(!forged && store.workspaceFileURL == a && store.needsWorkspaceSaveConfirmation, "Unverifiable receipt assigned a new document or claimed clean state")
            store.errorMessage = nil
            let b = root.appendingPathComponent("workspace-B.lens.json")
            let copySaved = try await saved(b)
            try require(copySaved, "Save As failed")
            try require(store.recentWorkspaceURLs == [b, a, live] && !store.needsWorkspaceSaveConfirmation, "Save As did not refresh ordering and verified clean state")
            let originalA = try Data(contentsOf: a)
            store.openWorkspaceCopy(path: a.path)
            try await wait("unbound copy") { store.hasEngine && !store.isStarting && !store.isRunning && store.workspaceFileURL == nil && store.sessions.count == 2 }
            try require(try Data(contentsOf: a) == originalA, "Open copy overwrote the input")
            try require(recents == [b, a, live] && store.needsWorkspaceSaveConfirmation, "Legacy Open copy changed history or claimed to be saved")
            store.openRecentWorkspace(a)
            try await wait("recent A") { store.hasEngine && !store.isStarting && store.workspaceFileURL == a }
            try require(recents == [a, b, live] && !store.needsWorkspaceSaveConfirmation, "Successful recent Open was not moved to the front or stayed edited")
            store.openRecentWorkspace(b)
            try await wait("bound document") { store.hasEngine && !store.isStarting && store.workspaceFileURL == b && store.sessions.count == 2 }
            store.selectSession(firstSession); store.selection = first.id; store.loadDetail()
            try await wait("restored body") { !store.detailLoading && store.detail?.id == first.id }
            try require(store.detail?.responseBodyBase64 == (Data("response:".utf8) + payload).base64EncodedString(), "Open lost complete binary body")
            let movedB = root.appendingPathComponent("retained-B.lens.json")
            try files.moveItem(at: b, to: movedB)
            store.openRecentWorkspace(b)
            try await wait("missing recent rejection") { !store.hasEngine && !store.isStarting }
            try require(store.workspaceFileURL == b && store.errorMessage != nil && recents == [b, a, live], "Missing recent file changed history or hid its failure")
            try require(store.startupIssue?.title == "Workspace could not be opened" && store.startupIssue?.isCaptureSetup == false && store.errorMessage?.contains("Click Start to resume it") == true && store.errorMessage?.contains(b.path) == true, "Missing document was reported as a proxy setup failure")
            try files.moveItem(at: movedB, to: b)
            store.errorMessage = nil; store.start()
            try await wait("recover missing recent") { store.isRunning || (!store.isStarting && store.errorMessage != nil) }
            try require(store.isRunning && store.sessions.count == 2, "Missing recent file lost the retained workspace")
            let bad = root.appendingPathComponent("malformed.lens.json"); try Data("{}".utf8).write(to: bad)
            store.openWorkspaceCopy(path: bad.path, asDocument: true)
            try await wait("malformed rejection") { !store.hasEngine && !store.isStarting }
            try require(store.workspaceFileURL == b && store.errorMessage != nil, "Failed Open adopted a malformed document")
            try require(recents == [b, a, live], "Rejected Open entered document history")
            store.errorMessage = nil; store.start()
            try await wait("recover prior workspace") { store.isRunning || (!store.isStarting && store.errorMessage != nil) }
            try require(store.isRunning && store.sessions.count == 2 && store.workspaceFileURL == b && !store.needsWorkspaceSaveConfirmation, "Start lost the prior document or verified saved baseline after rejected Open")
            print("PASS: failed Save As, copy/input protection, valid document binding, binary reopen and rejected-Open recovery")
            let otherStore = LensStore(dataDirectory: root.appendingPathComponent("other-state"), resources: resources, systemProxy: system, workspaceHistory: history)
            try require(otherStore.recentWorkspaceURLs == [b, a, live], "A new store did not read the history owner")
            store.clearRecentWorkspaces()
            try require(store.recentWorkspaceURLs.isEmpty && recents.isEmpty && store.workspaceFileURL == b && store.isRunning, "Clear Menu changed the current document or engine")
            try require(try Data(contentsOf: a) == originalA && files.fileExists(atPath: b.path), "Clear Menu removed or changed a saved file")
            print("PASS: recent-file ordering, successful-Open ownership, missing-file recovery and Clear Menu preserve workspace bytes")
            let c = root.appendingPathComponent("workspace-C.lens.json")
            var saveFinished = false, quitFinished: Bool?
            store.saveWorkspace(path: c.path) { saveFinished = $0 }
            try require(store.workspaceSaving, "Save was not admitted before Quit")
            store.quitPending = true
            store.prepareForQuit { prepared in
                if !prepared { quitFinished = false; return }
                guard !store.needsWorkspaceSaveConfirmation else { quitFinished = false; return }
                store.shutdown { success in quitFinished = success && saveFinished }
            }
            try await wait("Quit drains Save") { quitFinished != nil }
            try require(quitFinished == true && !store.hasEngine && !store.workspaceSaving, "Quit exited before the admitted Save completed")
            try require(try entries(c).count == 3, "Drained save did not preserve both sessions")
            print("PASS: live-save cut, unknown-receipt rejection and prepared clean Quit preserve all data before actual engine exit")
            origin.terminate(); try await wait("origin exit") { !origin.isRunning }
        } catch {
            let failure = error
            try? Data().write(to: liveRelease)
            try? await shutdown()
            if origin.isRunning { origin.terminate(); try? await wait("origin cleanup") { !origin.isRunning } }
            throw failure
        }
    }
}

@main private struct WorkspaceFileStoreSmoke {
    static func main() async {
        do {
            guard CommandLine.arguments.count == 3 else { throw WorkspaceFailure(description: "Pass Resources and a new evidence directory") }
            try await WorkspaceChecks.run(resources: URL(fileURLWithPath: CommandLine.arguments[1]), root: URL(fileURLWithPath: CommandLine.arguments[2]))
        } catch { fputs("FAIL: \(error)\n", stderr); exit(1) }
    }
}
