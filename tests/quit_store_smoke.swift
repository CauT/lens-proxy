import AppKit
import Foundation

private struct QuitFailure: Error { let message: String }
@MainActor private final class OriginalWindowDelegate: NSObject, NSWindowDelegate {
    var allow = true
    func windowShouldClose(_ sender: NSWindow) -> Bool { allow }
    func windowDidResize(_ notification: Notification) {}
}
@MainActor private enum QuitChecks {
    static func require(_ value: @autoclosure () throws -> Bool, _ reason: String) throws {
        if try !value() { throw QuitFailure(message: reason) }
    }
    static func wait(_ label: String, _ predicate: () throws -> Bool) async throws {
        let end = Date().addingTimeInterval(25)
        while try !predicate() {
            if Date() > end { throw QuitFailure(message: "Timed out: " + label) }
            try await Task.sleep(nanoseconds: 15_000_000)
        }
    }
    static func object(_ url: URL) throws -> [String: Any] {
        try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as! [String: Any]
    }
    static func run(_ resources: URL) async throws {
        let original = OriginalWindowDelegate(), proxy = LensWorkspaceWindowDelegate()
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 400, height: 300), styleMask: [.titled], backing: .buffered, defer: false)
        proxy.forwarded = original; var requests = 0; proxy.requestQuit = { requests += 1 }
        original.allow = false
        try require(!proxy.windowShouldClose(window) && requests == 0, "Original window veto was ignored")
        original.allow = true
        try require(!proxy.windowShouldClose(window) && requests == 1, "Close hid the window or missed Quit")
        let selector = #selector(NSWindowDelegate.windowDidResize(_:))
        try require(proxy.responds(to: selector) && proxy.forwardingTarget(for: selector) as? OriginalWindowDelegate === original, "Other window callbacks lost their owner")
        window.delegate = original
        let bridge = LensWorkspaceCloseBridge.WindowView(); window.contentView?.addSubview(bridge)
        try require(window.delegate === bridge.owner, "Close bridge did not attach")
        bridge.detach(); try require(window.delegate === original, "Close bridge did not restore SwiftUI's delegate")
        print("PASS window Close retains original veto/callbacks and restores delegate ownership")

        let files = FileManager.default, root = files.temporaryDirectory.appendingPathComponent("lens-quit-store-" + UUID().uuidString)
        try files.createDirectory(at: root, withIntermediateDirectories: false)
        defer { try? files.removeItem(at: root) }
        let engineResources = root.appendingPathComponent("resources")
        try files.createDirectory(at: engineResources.appendingPathComponent("engine"), withIntermediateDirectories: true)
        for name in ["python", "site-packages", "peer-process-identities"] {
            try files.createSymbolicLink(at: engineResources.appendingPathComponent(name), withDestinationURL: resources.appendingPathComponent(name))
        }
        let encoder = JSONEncoder(); encoder.outputFormatting = [.withoutEscapingSlashes]
        let sourcePath = String(data: try encoder.encode(resources.appendingPathComponent("engine/engine.py").path), encoding: .utf8)!
        let shim = #"""
import asyncio,importlib.util,sys,time
from pathlib import Path
source=Path(__SOURCE__);sys.path.insert(0,str(source.parent))
spec=importlib.util.spec_from_file_location('lens_quit_production',source);module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
original=module.save_workspace
def save(path,snapshot):
 path=Path(path)
 if path.name=='held-quit.lens.json':
  path.with_suffix('.entered').touch();deadline=time.monotonic()+20
  while not path.with_suffix('.release').exists():
   if time.monotonic()>deadline:raise TimeoutError('Owned quit copy was not released')
   time.sleep(.01)
 return original(path,snapshot)
module.save_workspace=save
asyncio.run(module.main())
"""#.replacingOccurrences(of: "__SOURCE__", with: sourcePath)
        try shim.write(to: engineResources.appendingPathComponent("engine/engine.py"), atomically: true, encoding: .utf8)
        let copy = root.appendingPathComponent("held-quit.lens.json"), release = root.appendingPathComponent("held-quit.lens.release")
        let portsFile = root.appendingPathComponent("ports.json"), fixture = Process()
        fixture.executableURL = resources.appendingPathComponent("python/bin/python3")
        fixture.arguments = ["-c", #"""
import http.server,json,socket,sys,threading
from pathlib import Path
class Handler(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  body=b'quit-copy\x00\xff';self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
 def log_message(self,*_):pass
server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
tcp=socket.socket();tcp.bind(('127.0.0.1',0));tcp.listen()
udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);udp.bind(('127.0.0.1',0))
def echo_tcp():
 while True:
  c,_=tcp.accept()
  with c:
   data=c.recv(1024);c.sendall(data)
def echo_udp():
 while True:
  data,peer=udp.recvfrom(1024);udp.sendto(data,peer)
threading.Thread(target=echo_tcp,daemon=True).start();threading.Thread(target=echo_udp,daemon=True).start()
ports={'origin':server.server_port,'tcp_origin':tcp.getsockname()[1],'udp_origin':udp.getsockname()[1]}
for kind in ('proxy','tcp_proxy','udp_proxy'):
 with socket.socket() as reserve:reserve.bind(('127.0.0.1',0));ports[kind]=reserve.getsockname()[1]
Path(sys.argv[1]).write_text(json.dumps(ports));server.serve_forever()
"""#, portsFile.path]
        try fixture.run()
        let system = SystemProxyController(dataDirectory: root.appendingPathComponent("system"), runner: SystemProxyRunner(read: { _ in throw QuitFailure(message: "Host read forbidden") }, authorize: { _ in throw QuitFailure(message: "Host mutation forbidden") }))
        let store = LensStore(dataDirectory: root.appendingPathComponent("data"), resources: engineResources, systemProxy: system, workspaceHistory: WorkspaceHistory(read: { [] }, remember: { _ in }, clear: {}))
        func shutdown(_ path: String? = nil) async throws -> Bool {
            var result: Bool?; store.shutdown(backupPath: path) { result = $0 }
            try await wait("shutdown acknowledgement") { result != nil }; return result == true
        }
        do {
            try require(!store.hasWorkspaceRecords, "Empty workspace prompted")
            try await wait("fixture") { files.fileExists(atPath: portsFile.path) || !fixture.isRunning }
            let ports = try object(portsFile) as! [String: Int]
            store.port = String(ports["proxy"]!)
            store.tcpForwards = [TCPForwardSelection(listenPort: String(ports["tcp_proxy"]!), targetHost: "127.0.0.1", targetPort: String(ports["tcp_origin"]!))]
            store.udpForwards = [UDPForwardSelection(listenPort: String(ports["udp_proxy"]!), targetHost: "127.0.0.1", targetPort: String(ports["udp_origin"]!))]
            store.start(); try await wait("Start") { store.isRunning || store.errorMessage != nil }
            try require(store.isRunning, store.errorMessage ?? "Start failed")
            let client = Process(), response = root.appendingPathComponent("response.bin")
            client.executableURL = resources.appendingPathComponent("python/bin/python3")
            client.arguments = ["-c", #"""
import socket,sys
from pathlib import Path
proxy,origin,tcp,udp=map(int,sys.argv[1:5]);payload=b'quit-raw\x00\xff'
with socket.create_connection(('127.0.0.1',proxy),timeout=5) as s:
 s.sendall(f'GET http://127.0.0.1:{origin}/quit HTTP/1.1\r\nHost: 127.0.0.1:{origin}\r\nConnection: close\r\n\r\n'.encode());reply=b''
 while chunk:=s.recv(4096):reply+=chunk
 Path(sys.argv[5]).write_bytes(reply.split(b'\r\n\r\n',1)[1])
with socket.create_connection(('127.0.0.1',tcp),timeout=5) as s:s.sendall(payload);assert s.recv(1024)==payload
with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:s.settimeout(5);s.sendto(payload,('127.0.0.1',udp));assert s.recv(1024)==payload
"""#, String(ports["proxy"]!), String(ports["origin"]!), String(ports["tcp_proxy"]!), String(ports["udp_proxy"]!), response.path]
            try client.run(); try await wait("client") { !client.isRunning }
            try require(client.terminationStatus == 0, "Client failed")
            try await wait("all captures") { store.flows.count == 1 && !store.tcpStreams.isEmpty && !store.udpAssociations.isEmpty }
            let capturedRoom = store.currentSessionID
            store.newSession(); try await wait("empty viewed room") { store.sessions.count == 2 && !store.sessionChanging }
            try require(store.flows.isEmpty && store.hasWorkspaceRecords, "Other room's records were missed")
            store.quitPending = true
            try require(!store.canCreateSession, "Quit prompt permitted replacing the workspace")
            store.quitPending = false
            try require(store.canCreateSession, "Cancel did not release workspace admission")
            let invalid = try await shutdown("relative.json")
            try require(!invalid && store.isRunning, "Invalid path stopped capture")
            store.errorMessage = nil
            try await wait("TCP completes before clean snapshot") { store.flows(in: capturedRoom).first?.state == "complete" }
            var savedClean: Bool?
            store.saveWorkspace(path: root.appendingPathComponent("before-stop.lens.json").path) { savedClean = $0 }
            try await wait("clean live workspace") { savedClean != nil }
            try require(savedClean == true && !store.needsWorkspaceSaveConfirmation, "Quiet live Save did not establish a clean baseline")
            store.quitPending = true
            var prepared: Bool?
            store.prepareForQuit { prepared = $0 }
            try await wait("final raw revisions") { prepared != nil }
            try require(prepared == true && !store.isRunning && store.needsWorkspaceSaveConfirmation, "Stop finalized raw records after Save without requiring confirmation")
            store.cancelQuitPreparation(); store.quitPending = false
            try require(store.hasWorkspaceRecords && store.canCreateSession, "Cancelling prepared Quit lost the stopped workspace")
            print("PASS clean live Save is rechecked after actual raw Stop; final changes require confirmation and Cancel preserves inspection")
            let failed = try await shutdown(root.appendingPathComponent("missing/copy.json").path)
            try require(!failed && store.hasEngine && !store.isRunning && store.canCreateSession, "Failed copy exited, lost the stopped engine or left file admission closed")
            try require(store.flows(in: capturedRoom).count == 1 && store.hasWorkspaceRecords, "Failed quit lost records")
            print("PASS all-room/raw records trigger confirmation; invalid path preserves capture and failed copy retains stopped inspection")
            store.quitPending = true
            var retried: Bool?; store.shutdown(backupPath: copy.path) { retried = $0 }
            try await wait("held quit copy") { files.fileExists(atPath: root.appendingPathComponent("held-quit.lens.entered").path) }
            let archive = store.archiveController(for: capturedRoom), rejectedAutosave = root.appendingPathComponent("after-stop.har")
            archive.selectAutosavePath(rejectedAutosave.path); archive.saveNow(); store.start()
            try require(!archive.saving && !store.isStarting && !store.isRunning && retried == nil && store.hasEngine, "Final copy reopened capture, admitted a new file operation or exited early")
            try Data().write(to: release)
            try await wait("final copy and exit") { retried != nil }
            try require(retried == true && !store.hasEngine && !files.fileExists(atPath: rejectedAutosave.path), "Retry did not drain file admission and finish copy before engine exit")
            print("PASS held final copy keeps capture and archive admission closed until actual copy completion")
            let saved = try object(copy), retained = try object(store.dataDirectory.appendingPathComponent("retained-workspace.lens.json"))
            try require(NSDictionary(dictionary: saved).isEqual(to: retained), "Quit copy differs from the final stopped workspace")
            let rooms = saved["sessions"] as! [[String: Any]], room = rooms.first { $0["id"] as? String == capturedRoom }!
            let entry = (((room["har"] as! [String: Any])["log"] as! [String: Any])["entries"] as! [[String: Any]])[0]
            try require(Data(base64Encoded: entry["_lensRawResponseBody"] as! String) == (try Data(contentsOf: response)), "Quit copy changed complete HTTP bytes")
            try require(!(room["tcp"] as! [Any]).isEmpty && !(room["udp"] as! [Any]).isEmpty && rooms.count == 2, "Quit copy missed raw/other sessions")
            print("PASS successful retry writes the complete final HTTP/TCP/UDP workspace before actual engine termination")
            fixture.terminate(); try await wait("fixture cleanup") { !fixture.isRunning }
        } catch {
            try? Data().write(to: release)
            _ = try? await shutdown()
            if fixture.isRunning { fixture.terminate(); try? await wait("fixture cleanup") { !fixture.isRunning } }
            throw error
        }
    }
}
@main private struct QuitStoreSmoke {
    static func main() async {
        _ = NSApplication.shared
        do { guard CommandLine.arguments.count == 2 else { exit(2) }; try await QuitChecks.run(URL(fileURLWithPath: CommandLine.arguments[1])) }
        catch { fputs("FAIL: \(error)\n", stderr); exit(1) }
    }
}
