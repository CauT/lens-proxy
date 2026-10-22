// Native Store -> packaged engine production-boundary smoke. This does not drive
// the UI or change system proxy/DNS/trust. The runner rejects all host access.
// Compile with Sources/Lens/{Models,LensStore,SystemProxy,SessionTools,
// SessionArtifacts,CurlCommand,NetworkSettingsView,LANAccess}.swift and SwiftUI/AppKit.
// Run: store-engine-smoke /absolute/Lens.app/Contents/Resources
import Foundation
import Combine
import AppKit
import Darwin

private struct StoreSmokeFailure: Error, CustomStringConvertible {
    let description: String
}

private func require(_ condition: @autoclosure () throws -> Bool, _ reason: String) throws {
    if try !condition() { throw StoreSmokeFailure(description: reason) }
}

private final class HostAccessAttempts {
    private let lock = NSLock()
    private var attempts = 0
    func rejected() throws -> Never {
        lock.lock(); attempts += 1; lock.unlock()
        throw StoreSmokeFailure(description: "System proxy access is forbidden in this test")
    }
    var count: Int { lock.lock(); defer { lock.unlock() }; return attempts }
}

@MainActor
private enum StoreEngineChecks {
    static func eventually(_ label: String, timeout: TimeInterval = 15, _ predicate: () throws -> Bool) async throws {
        let deadline = Date().addingTimeInterval(timeout)
        while true {
            if try predicate() { return }
            if Date() >= deadline { throw StoreSmokeFailure(description: "Timed out: \(label)") }
            try await Task.sleep(nanoseconds: 20_000_000)
        }
    }

    static func waitForProcess(_ process: Process, label: String, timeout: TimeInterval = 15) async throws {
        try await eventually(label, timeout: timeout) { !process.isRunning }
    }

    static func environment(_ resources: URL) -> [String: String] {
        var value = ProcessInfo.processInfo.environment
        value["PYTHONPATH"] = resources.appendingPathComponent("site-packages").path
        value["PYTHONNOUSERSITE"] = "1"
        value["PYTHONDONTWRITEBYTECODE"] = "1"
        return value
    }

    static func subprocess(resources: URL, arguments: [String], output: URL) throws -> (Process, FileHandle) {
        FileManager.default.createFile(atPath: output.path, contents: nil)
        let handle = try FileHandle(forWritingTo: output)
        let process = Process()
        process.executableURL = resources.appendingPathComponent("python/bin/python3")
        process.arguments = arguments
        process.environment = environment(resources)
        process.standardOutput = handle; process.standardError = handle
        try process.run()
        return (process, handle)
    }

    static let fixtureScript = #"""
import http.server,json,socket,sys,gzip
from pathlib import Path
class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    def do_GET(self):
        body=bytes(range(256))*12289 if self.path.startswith('/binary/') else ('small:'+self.path).encode()
        self.send_response(200)
        self.send_header('Content-Type','application/octet-stream' if self.path.startswith('/binary/') else 'text/plain; charset=utf-8')
        self.send_header('Content-Length',str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_POST(self):
        body=self.rfile.read(int(self.headers.get('Content-Length','0')))
        Path(sys.argv[2],'curl-captured.bin').write_bytes(body)
        Path(sys.argv[2],'curl-captured.json').write_text(json.dumps({'content_encoding':self.headers.get('Content-Encoding'),'repeated':self.headers.get_all('X-Repeat')}))
        answer=b'curl raw body received'
        self.send_response(200); self.send_header('Content-Length',str(len(answer)))
        self.send_header('Content-Type','text/plain'); self.end_headers(); self.wfile.write(answer)
    def log_message(self,*args): pass
Path(sys.argv[2],'curl-payload.gz').write_bytes(gzip.compress(bytes(range(256))*128,mtime=0))
server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
server.daemon_threads=True
with socket.socket() as reservation:
    reservation.bind(('127.0.0.1',0)); proxy_port=reservation.getsockname()[1]
Path(sys.argv[1]).write_text(json.dumps({'origin_port':server.server_port,'proxy_port':proxy_port}))
try: server.serve_forever()
finally: server.server_close()
"""#

    static let clientScript = #"""
import http.client,sys
from pathlib import Path
client=http.client.HTTPConnection('127.0.0.1',int(sys.argv[1]),timeout=15)
try:
    client.request('GET',sys.argv[2])
    response=client.getresponse()
    body=response.read()
    assert response.status==200,(response.status,body[:100])
    Path(sys.argv[3]).write_bytes(body)
finally: client.close()
"""#

    static func request(resources: URL, directory: URL, port: Int, url: String, observePID: ((Int32) -> Void)? = nil) async throws -> Data {
        let identity = UUID().uuidString
        let destination = directory.appendingPathComponent("client-\(identity).bin")
        let log = directory.appendingPathComponent("client-\(identity).log")
        let (process, handle) = try subprocess(resources: resources,
            arguments: ["-u", "-c", clientScript, String(port), url, destination.path], output: log)
        observePID?(process.processIdentifier)
        defer {
            if process.isRunning { process.terminate() }
            try? handle.close()
        }
        try await waitForProcess(process, label: "explicit loopback HTTP client")
        try require(process.terminationStatus == 0, "Fixture request failed: \(String(decoding: (try? Data(contentsOf: log)) ?? Data(), as: UTF8.self))")
        return try Data(contentsOf: destination)
    }

    static func harURLs(_ file: URL) throws -> Set<String> {
        let document = try JSONSerialization.jsonObject(with: Data(contentsOf: file)) as? [String: Any]
        let log = document?["log"] as? [String: Any]
        guard let entries = log?["entries"] as? [[String: Any]] else {
            throw StoreSmokeFailure(description: "Saved file is not a HAR document")
        }
        return Set(entries.compactMap { ($0["request"] as? [String: Any])?["url"] as? String })
    }

    static func mirrorFolders(_ folder: URL) throws -> [URL] {
        try FileManager.default.contentsOfDirectory(at: folder, includingPropertiesForKeys: nil)
            .filter { UUID(uuidString: $0.lastPathComponent) != nil }
    }

    static func mirror(for url: String, in folder: URL) throws -> URL? {
        for entry in try mirrorFolders(folder) {
            let metadata = try JSONSerialization.jsonObject(with: Data(contentsOf: entry.appendingPathComponent("metadata.json"))) as? [String: Any]
            if metadata?["url_display"] as? String == url { return entry }
        }
        return nil
    }

    static func checkedMirror(for url: String, in folder: URL) throws -> URL {
        guard let directory = try mirror(for: url, in: folder) else {
            throw StoreSmokeFailure(description: "Expected completed mirror missing for \(url)")
        }
        return directory
    }

    static func command(_ store: LensStore, _ name: String, _ arguments: [String: Any]) async throws -> Any {
        var value: Any?, failure: String?
        store.send(name, arguments, onError: { failure = $0 }) { result in
            guard result.sourceFacts.text.isEmpty else { failure = "Fixture unexpectedly returned source text annotations"; return }
            value = result.projection
        }
        try await eventually("native command \(name)") { value != nil || failure != nil }
        if let failure { throw StoreSmokeFailure(description: "\(name) failed: \(failure)") }
        guard let value else { throw StoreSmokeFailure(description: "\(name) completed without a result") }
        return value
    }

    static func verifyMirror(_ directory: URL, url: String, body: Data) throws {
        let metadata = try JSONSerialization.jsonObject(with: Data(contentsOf: directory.appendingPathComponent("metadata.json"))) as? [String: Any]
        try require(metadata?["url_display"] as? String == url && metadata?["method_display"] as? String == "GET" && metadata?["status"] as? Int == 200,
                    "Native mirror lost source URL, method or response status")
        try require(metadata?["body_bytes"] as? Int == body.count && metadata?["representation"] as? String == "decoded response body",
                    "Native mirror did not describe the complete decoded body")
        try require(try Data(contentsOf: directory.appendingPathComponent("response.bin")) == body,
                    "Native mirror bytes were truncated or changed")
        for (file, permission) in [(directory, 0o700), (directory.appendingPathComponent("response.bin"), 0o600),
                                    (directory.appendingPathComponent("metadata.json"), 0o600)] {
            let attributes = try FileManager.default.attributesOfItem(atPath: file.path)
            try require((attributes[.posixPermissions] as? NSNumber)?.intValue == permission, "Native mirror is not private")
        }
    }

    static func stop(_ store: LensStore) async throws {
        var stopped: Bool?
        store.stop { stopped = $0 }
        try await eventually("Store stop callback after listener and file drain", timeout: 20) { stopped != nil }
        try require(stopped == true && !store.isRunning && !store.isStarting && store.hasEngine, "Store did not retain its stopped session owner")
    }

    static func shutdown(_ store: LensStore) async throws {
        var exited: Bool?
        store.shutdown { exited = $0 }
        try await eventually("Store shutdown after actual engine exit", timeout: 20) { exited != nil }
        try require(exited == true && !store.hasEngine, "Store did not release its session engine")
    }

    static func clearStore(_ store: LensStore) async throws {
        var result: Bool?
        store.clear { result = $0 }
        try await eventually("Clear acknowledgement") { result != nil }
        try require(result == true, store.errorMessage ?? "Clear failed")
    }

    static func fence(_ store: LensStore) async throws {
        var result: Any?, failure: String?
        store.send("network_status", onError: { failure = $0 }) { value in
            guard value.sourceFacts.text.isEmpty else { failure = "Fixture unexpectedly returned source text annotations"; return }
            result = value.projection
        }
        try await eventually("production JSONL command fence") { result != nil || failure != nil }
        try require(failure == nil, "Command fence failed: \(failure ?? "")")
    }

    static func independentSessions(_ store: LensStore, resources: URL, directory: URL, origin: String,
                                    originalURL: String, originalBody: Data, filteredURL: String) async throws {
        let original = store.currentSessionID, originalCA = store.caSHA256, originalPort = store.port
        let originalCount = store.flows.count
        let selected = store.flows.first { $0.url == originalURL }!.id
        store.selection = selected; store.search = "/small/second"
        let archive = store.archives
        store.toggleRecording()
        try await fence(store)
        try require(!store.recording, "Fixture must begin New Session with recording off")
        store.newSession()
        try await eventually("New Session acknowledged") { !store.sessionChanging && store.sessions.count == 2 }
        let recordingRoom = store.currentSessionID
        try require(recordingRoom != original && store.captureSessionID == recordingRoom && store.recording && store.flows.isEmpty,
                    "New Session did not create/select/start an independent recording")
        try require(store.caSHA256 == originalCA && store.port == originalPort && store.flows(in: original).count == originalCount,
                    "New Session rebound proxy/CA or destroyed the old session")
        let freshArchive = store.archives
        try require(freshArchive !== archive && freshArchive.autosavePath.isEmpty && freshArchive.mirrorPath.isEmpty && !freshArchive.autosaveEnabled && !freshArchive.mirrorEnabled,
                    "New session inherited another session's disk destinations")
        let fresh = origin + "/small/session-new"
        _ = try await request(resources: resources, directory: directory, port: Int(store.port)!, url: fresh)
        try await eventually("new request routed to new session") { store.flows.first?.url == fresh && store.flows.first?.state == "complete" }
        try require(store.flows(in: original).count == originalCount, "New request entered the previous room")
        print("PASS: native New Session preserves old rows, shares proxy/CA, selects a fresh recording and leaves file destinations independent")

        let csv = directory.appendingPathComponent("old-room.csv")
        archive.exportFile(path: csv.path, kind: .csv)
        let text = try String(contentsOf: csv, encoding: .utf8)
        try require(text.contains(filteredURL) && !text.contains(fresh) && !text.contains(originalURL), "Old archive exported another session/filter")
        let body = directory.appendingPathComponent("old-room-response.bin")
        archive.exportFile(path: body.path, kind: .response)
        try await eventually("old selected response exports while another tab is active") { !archive.exporting && FileManager.default.fileExists(atPath: body.path) }
        try require(try Data(contentsOf: body) == originalBody, "Old archive body followed the active tab")
        let saved = directory.appendingPathComponent("old-room.har")
        archive.selectAutosavePath(saved.path); archive.saveNow()
        try await eventually("old archive HAR saved") { !archive.saving && FileManager.default.fileExists(atPath: saved.path) }
        try require(try harURLs(saved).count == originalCount, "Old HAR save followed active capture room")
        print("PASS: per-session body, filtered CSV and HAR exports keep their source while another tab is selected")

        store.selectSession(original)
        try require(store.selection == selected && store.search == "/small/second" && store.captureSessionID == recordingRoom,
                    "View switch lost selection/filter or changed the recording destination")
        let next = origin + "/small/recording-while-viewing-old"
        _ = try await request(resources: resources, directory: directory, port: Int(store.port)!, url: next)
        try await eventually("background recording room receives request") { store.flows(in: recordingRoom).contains { $0.url == next && $0.state == "complete" } }
        try require(store.flows.count == originalCount, "Viewing an old session retargeted recording")
        store.openSession(path: saved.path)
        try await eventually("HAR opens as independent view") { !store.sessionChanging && store.sessions.count == 3 && store.flows.count == originalCount }
        let opened = store.currentSessionID
        try require(opened != original && opened != recordingRoom && store.captureSessionID == recordingRoom && store.flows.allSatisfy { $0.imported == true },
                    "Open HAR merged into/replaced another room or retargeted recording")
        try await clearStore(store)
        try require(store.flows.isEmpty && store.flows(in: original).count == originalCount && store.flows(in: recordingRoom).count == 2,
                    "Clear crossed session boundaries")
        print("PASS: native view switching preserves selection/filter; Open HAR and Clear remain independent of the recording room")

        let ids = store.sessions.map(\.id)
        try await stop(store)
        store.start()
        try await eventually("whole workspace restart", timeout: 25) { store.isRunning && !store.isStarting && store.sessions.map(\.id) == ids && store.flows(in: original).count == originalCount && store.flows(in: recordingRoom).count == 2 }
        try require(store.currentSessionID == opened && store.captureSessionID == recordingRoom && store.flows.isEmpty,
                    "Workspace restart lost an empty session, selected tab or capture destination")
        store.selectSession(original)
        try require(store.flows.contains { $0.id == selected }, "Workspace restart regenerated a captured flow identity")
        print("PASS: Stop/Start restores all three session identities, exact flow ownership, an empty imported tab and the recording destination")
    }

    static func run(resources: URL) async throws {
        let manager = FileManager.default
        try require(manager.isExecutableFile(atPath: resources.appendingPathComponent("python/bin/python3").path), "Packaged Python is missing")
        for file in ["engine.py", "bounds.py", "network.py", "routing.py", "persistence.py"] {
            try require(manager.fileExists(atPath: resources.appendingPathComponent("engine/" + file).path), "Final packaged engine is missing \(file)")
        }
        let directory = manager.temporaryDirectory.appendingPathComponent("lens-store-engine-\(UUID().uuidString)")
        try manager.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? manager.removeItem(at: directory) }
        let dataDirectory = directory.appendingPathComponent("app-data")
        let blocked = HostAccessAttempts()
        let system = SystemProxyController(dataDirectory: directory.appendingPathComponent("proxy-recovery"),
            runner: SystemProxyRunner(read: { _ in try blocked.rejected() }, authorize: { _ in try blocked.rejected() }))
        let store = LensStore(dataDirectory: dataDirectory, resources: resources, systemProxy: system)
        let archive = store.archives
        let timerEpoch = Date()
        archive.selectAutosavePath("relative.har")
        try require(archive.autosavePath.isEmpty, "Relative file path must not resolve through ambient cwd")
        archive.selectMirrorPath("file:///tmp/not-a-filesystem-path")
        try require(archive.mirrorPath.isEmpty, "File URLs must not be interpreted as plain paths")
        archive.selectAutosavePath("/tmp/invalid\0name.har")
        try require(archive.autosavePath.isEmpty, "NUL path must be rejected before filesystem use")
        let mirrorFolder = directory.appendingPathComponent("explicit-mirrors")
        archive.selectMirrorPath(mirrorFolder.path)
        try require(manager.fileExists(atPath: mirrorFolder.path), "Use folder must create the explicitly selected output directory")
        print("PASS: explicit destination boundary rejects relative/URI/NUL paths and creates the selected mirror folder")
        archive.setMirror(true)
        let readyFile = directory.appendingPathComponent("fixture-ready.json")
        let (fixture, fixtureHandle) = try subprocess(resources: resources,
            arguments: ["-u", "-c", fixtureScript, readyFile.path, directory.path], output: directory.appendingPathComponent("fixture.log"))
        var observer: AnyCancellable?
        do {
            try await eventually("owned loopback fixture ready") { manager.fileExists(atPath: readyFile.path) }
            let endpoint = try JSONSerialization.jsonObject(with: Data(contentsOf: readyFile)) as? [String: Int]
            guard let origin = endpoint?["origin_port"], let port = endpoint?["proxy_port"] else { throw StoreSmokeFailure(description: "Fixture ready metadata invalid") }
            store.port = String(port)
            store.start()
            var earlyStop: Bool?
            store.stop { earlyStop = $0 }
            try await eventually("Stop during initial engine handshake", timeout: 30) { earlyStop != nil }
            try require(earlyStop == true && !store.isRunning && !store.isStarting && store.hasEngine,
                        "Late ready handshake reopened capture after Stop")
            print("PASS: Stop during initial handshake waits for listener closure and retains the session owner")
            store.start()
            try await eventually("Store receives actual packaged-engine ready", timeout: 30) { store.isRunning || (!store.isStarting && store.errorMessage != nil) }
            try require(store.isRunning && !store.caCert.isEmpty, "Store failed to launch packaged engine: \(store.errorMessage ?? store.status)")
            try await fence(store)
            print("PASS: injected native Store launches the real packaged engine; host runner remains blocked")

            var commandError: String?, unexpectedSuccess = false
            store.send("detail", ["id": "missing-test-identity"], onError: { commandError = $0 }) { _ in unexpectedSuccess = true }
            try await eventually("native command onError completion") { commandError != nil }
            try require(!unexpectedSuccess, "Error command invoked its success callback")
            print("PASS: engine JSONL error completes native onError callback")

            let firstURL = "http://127.0.0.1:\(origin)/binary/first?source=native-store"
            let firstBody = try await request(resources: resources, directory: directory, port: port, url: firstURL)
            try require(firstBody.count > 2 * 1024 * 1024 && firstBody.contains(255), "Fixture did not exercise a binary body larger than previews")
            try await eventually("first complete native response mirror") { try mirror(for: firstURL, in: mirrorFolder) != nil }
            let firstMirror = try checkedMirror(for: firstURL, in: mirrorFolder)
            try verifyMirror(firstMirror, url: firstURL, body: firstBody)
            print("PASS: new real response mirrors complete >2 MiB binary bytes and source metadata privately")

            let protected = directory.appendingPathComponent("readonly-destination")
            try manager.createDirectory(at: protected, withIntermediateDirectories: true)
            let previous = protected.appendingPathComponent("previous.har")
            let previousBytes = Data("previous target must survive".utf8)
            try previousBytes.write(to: previous)
            archive.selectAutosavePath(previous.path)
            try manager.setAttributes([.posixPermissions: 0o500], ofItemAtPath: protected.path)
            do {
                archive.saveNow()
                try require(archive.saving, "saveNow did not enter its in-flight state")
                try await eventually("failed native save callback resets saving") { !archive.saving }
                try require(archive.message.hasPrefix("Session save failed:"), "Save failure did not reach SessionArchiveController")
                try require(try Data(contentsOf: previous) == previousBytes, "Failed save overwrote the previous target")
                try require(try manager.contentsOfDirectory(atPath: protected.path) == ["previous.har"], "Failed save left a staging file")
            } catch {
                try? manager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: protected.path)
                throw error
            }
            try manager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: protected.path)
            print("PASS: actual file-save failure resets native saving and preserves the previous selected file")

            let autosave = directory.appendingPathComponent("explicit-autosave.har")
            archive.selectAutosavePath(autosave.path)
            archive.saveNow()
            try await eventually("native saveNow HAR transaction") { !archive.saving && manager.fileExists(atPath: autosave.path) }
            try require(try harURLs(autosave).contains(firstURL), "saveNow omitted real captured traffic")
            archive.setAutosave(true)
            try await eventually("initial autosave generation") { !archive.saving }
            let oldStamp = try manager.attributesOfItem(atPath: autosave.path)[.modificationDate] as? Date
            let secondURL = "http://127.0.0.1:\(origin)/small/second?generation=changed"
            let secondBody = try await request(resources: resources, directory: directory, port: port, url: secondURL)
            try await eventually("second completed captured flow") { store.flows.contains { $0.url == secondURL && $0.state == "complete" } }
            try await eventually("actual 30-second RunLoop autosave updates changed generation", timeout: 65) {
                guard !archive.saving, let stamp = try manager.attributesOfItem(atPath: autosave.path)[.modificationDate] as? Date, stamp != oldStamp else { return false }
                return try harURLs(autosave).contains(secondURL)
            }
            let elapsed = Date().timeIntervalSince(timerEpoch)
            try require(elapsed >= 29, "Autosave did not exercise the real 30-second timer")
            try await eventually("second native mirror") { try mirror(for: secondURL, in: mirrorFolder) != nil }
            try verifyMirror(try checkedMirror(for: secondURL, in: mirrorFolder), url: secondURL, body: secondBody)
            print(String(format: "PASS: saveNow and actual 30-second autosave persist changed generation (%.2fs since timer creation)", elapsed))

            let thirdURL = "http://127.0.0.1:\(origin)/binary/third?stop=while-writing"
            var stopScheduled = false, drainedStop: Bool?, saveWasInFlight = false
            observer = store.$flows.sink { rows in
                guard !stopScheduled, rows.contains(where: { $0.url == thirdURL && $0.state == "complete" }) else { return }
                stopScheduled = true
                // @Published fires before archives.received. Queue after this receive
                // turn so the mirror has been admitted before stop quiesces it.
                DispatchQueue.main.async {
                    archive.saveNow(); saveWasInFlight = archive.saving
                    store.stop { drainedStop = $0 }
                }
            }
            let thirdBody = try await request(resources: resources, directory: directory, port: port, url: thirdURL)
            try await eventually("stop waits for admitted mirror, HAR save and listener closure", timeout: 30) { drainedStop != nil }
            observer?.cancel(); observer = nil
            try require(drainedStop == true && saveWasInFlight && !store.isRunning, "Stop did not drain an active file transaction")
            try verifyMirror(try checkedMirror(for: thirdURL, in: mirrorFolder), url: thirdURL, body: thirdBody)
            try require(try harURLs(autosave).contains(thirdURL), "Stop completed before selected HAR save committed")
            let retained = dataDirectory.appendingPathComponent("retained-workspace.lens.json")
            guard let workspace = try JSONSerialization.jsonObject(with: Data(contentsOf: retained)) as? [String: Any],
                  let rooms = workspace["sessions"] as? [[String: Any]], rooms.count == 1,
                  let har = rooms[0]["har"] as? [String: Any], let retainedLog = har["log"] as? [String: Any],
                  let retainedEntries = retainedLog["entries"] as? [[String: Any]] else {
                throw StoreSmokeFailure(description: "Retained workspace omitted its complete session")
            }
            let retainedURLs = Set(retainedEntries.compactMap { ($0["request"] as? [String: Any])?["url"] as? String })
            try require(retainedURLs == Set([firstURL, secondURL, thirdURL]), "Stop did not retain the complete session")
            let beforeRestart = Set(try mirrorFolders(mirrorFolder).map(\.lastPathComponent))
            try require(beforeRestart.count == 3, "Unexpected mirror count before restart")
            print("PASS: stop drains admitted mirror and selected/retained HAR transactions while retaining the session owner")

            let stoppedRows = store.flows
            for row in stoppedRows.reversed() {
                try require(row.clientConnection?.peer.host == "127.0.0.1" && row.clientConnection?.listenerAddress.host == "127.0.0.1"
                            && row.clientConnection?.listenerAddress.port == port && row.clientConnection?.listener == "proxy_port",
                            "Native flow lost the observed public client connection")
                store.selection = row.id; store.loadDetail()
                try await eventually("stopped request/response detail") { !store.detailLoading }
                try require(store.detail?.id == row.id && store.detailError == nil, "Stopped row lost its detail identity")
                try require(!(store.detail?.responseHeaders.isEmpty ?? true), "Stopped response headers unavailable")
            }
            print("PASS: every stopped row loads request/response detail from the retained production owner")
            store.selection = stoppedRows[0].id; store.loadDetail()
            store.selection = stoppedRows[1].id; store.loadDetail()
            try await eventually("latest selection detail") { !store.detailLoading }
            try require(store.detail?.id == stoppedRows[1].id, "Late detail overwrote newer selection")
            store.selection = "missing-detail-test"; store.loadDetail()
            try await eventually("missing detail ends loading") { !store.detailLoading }
            try require(store.detail == nil && store.detailError != nil, "Missing detail remained loading or fabricated content")
            store.selection = stoppedRows[0].id; store.loadDetail()
            try await eventually("detail retry recovers") { !store.detailLoading }
            try require(store.detail?.id == stoppedRows[0].id && store.detailError == nil, "Detail did not recover after failure")
            for _ in 0..<64 { store.loadDetail() }
            try await eventually("repeated same-row refresh drains") { !store.detailLoading }
            try require(store.detail?.id == stoppedRows[0].id && store.detailError == nil, "Repeated refresh starved the inspector")
            print("PASS: rapid selection rejects stale replies; missing details finish with an error and retry recovers")

            store.start()
            store.start() // A repeated click during old-owner shutdown is ignored.
            try await eventually("Store restarts packaged engine", timeout: 30) { store.isRunning }
            try await fence(store)
            try await eventually("retained HAR reload emits imported native rows") { store.flows.count == 3 && store.flows.allSatisfy { $0.imported == true } }
            try await Task.sleep(nanoseconds: 300_000_000)
            try require(Set(try mirrorFolders(mirrorFolder).map(\.lastPathComponent)) == beforeRestart, "Imported retained rows were incorrectly mirrored again")
            let pausedPath = "/small/paused-response?source=two-breakpoints"
            let pausedURL = "http://127.0.0.1:\(origin)" + pausedPath
            store.rules = [ProxyRule(kind: "breakpoint_response", match: pausedURL),
                           ProxyRule(kind: "rewrite_response_body", match: pausedURL, name: "small:", value: "middle:"),
                           ProxyRule(kind: "breakpoint_response", match: pausedURL),
                           ProxyRule(kind: "rewrite_response_body", match: pausedURL, name: "middle:", value: "final:")]
            store.applyRules(); try await fence(store)
            let pausedRequest = Task { @MainActor in
                try await request(resources: resources, directory: directory, port: port, url: pausedURL)
            }
            try await eventually("first actual response breakpoint") { store.flows.contains { $0.url == pausedURL && $0.state == "paused" } }
            guard let pausedID = store.flows.first(where: { $0.url == pausedURL })?.id else { throw StoreSmokeFailure(description: "Paused flow has no identity") }
            try require(try mirror(for: pausedURL, in: mirrorFolder) == nil, "First response breakpoint was prematurely mirrored")
            _ = try await command(store, "resume", ["id": pausedID, "action": "continue"])
            var secondDetail: [String: Any]?
            try await eventually("second response breakpoint after intermediate rewrite") {
                store.flows.contains { $0.id == pausedID && $0.state == "paused" }
            }
            secondDetail = try await command(store, "detail", ["id": pausedID]) as? [String: Any]
            try require(secondDetail?["state"] as? String == "paused" && secondDetail?["response_body"] as? String == "middle:" + pausedPath,
                        "Resume did not reach the second breakpoint and intermediate body")
            try await Task.sleep(nanoseconds: 200_000_000)
            try require(try mirror(for: pausedURL, in: mirrorFolder) == nil, "Intermediate response resume was incorrectly admitted as complete mirror data")
            _ = try await command(store, "resume", ["id": pausedID, "action": "continue"])
            let finalBody = try await pausedRequest.value
            try require(finalBody == Data(("final:" + pausedPath).utf8), "Final response rewrite did not reach the actual client")
            try await eventually("mirror only after final response rewrite") { try mirror(for: pausedURL, in: mirrorFolder) != nil }
            try verifyMirror(try checkedMirror(for: pausedURL, in: mirrorFolder), url: pausedURL, body: finalBody)
            store.rules = []; store.applyRules(); try await fence(store)
            print("PASS: native mirror waits across two actual response breakpoints and preserves only final rewritten bytes")
            let wireBody = try Data(contentsOf: directory.appendingPathComponent("curl-payload.gz"))
            let bodyFile = try CurlCommand.saveBody(wireBody, directory: directory.appendingPathComponent("curl bodies ' literal"))
            let curlURL = "http://127.0.0.1:\(origin)/curl/raw?from=native-renderer"
            let rendered = try CurlCommand.render(method: "POST", url: curlURL, proxyPort: String(port),
                headers: [["Content-Encoding", "gzip"], ["Content-Type", "application/octet-stream"],
                          ["X-Repeat", "first"], ["X-Repeat", "second"]], bodyFile: bodyFile)
            let curl = Process(), curlLog = directory.appendingPathComponent("curl.log")
            manager.createFile(atPath: curlLog.path, contents: nil)
            let curlHandle = try FileHandle(forWritingTo: curlLog)
            curl.executableURL = URL(fileURLWithPath: "/bin/zsh")
            curl.arguments = ["-c", rendered]
            curl.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin"]
            curl.standardOutput = curlHandle; curl.standardError = curlHandle
            try curl.run()
            do { try await waitForProcess(curl, label: "real rendered cURL through explicit loopback proxy") }
            catch { if curl.isRunning { curl.terminate() }; try? curlHandle.close(); throw error }
            try curlHandle.close()
            try require(curl.terminationStatus == 0, "Rendered cURL failed: \(String(decoding: try Data(contentsOf: curlLog), as: UTF8.self))")
            try require(try Data(contentsOf: directory.appendingPathComponent("curl-captured.bin")) == wireBody,
                        "Rendered cURL changed the complete raw gzip request body")
            let captured = try JSONSerialization.jsonObject(with: Data(contentsOf: directory.appendingPathComponent("curl-captured.json"))) as? [String: Any]
            try require(captured?["content_encoding"] as? String == "gzip" && captured?["repeated"] as? [String] == ["first", "second"],
                        "Rendered cURL changed Content-Encoding or repeated header values")
            try await eventually("future cURL response remains mirrorable after retained import") { try mirror(for: curlURL, in: mirrorFolder) != nil }
            try require(try mirrorFolders(mirrorFolder).count == 5, "Imported rows or future cURL created unexpected mirror duplicates")
            print("PASS: native cURL renderer/body companion executes through real proxy with exact raw gzip bytes and repeated headers")
            archive.setAutosave(false)
            archive.saveNow()
            try await eventually("manual HAR saves latest complete session") { !archive.saving }
            let savedURLs = try harURLs(autosave)
            try await clearStore(store)
            archive.loadNow()
            try await eventually("explicit path HAR import completes") { !archive.loading && store.flows.count == savedURLs.count }
            try require(Set(store.flows.map(\.url)) == savedURLs && store.flows.allSatisfy { $0.imported == true }, "Open HAR did not restore source rows")
            try require(try mirrorFolders(mirrorFolder).count == 5, "Manual import was incorrectly mirrored")
            store.selection = store.flows.first { $0.url == firstURL }?.id
            let selectedBody = directory.appendingPathComponent("selected-response.bin")
            archive.exportFile(path: selectedBody.path, kind: .response)
            try await eventually("selected complete body export") { !archive.exporting && manager.fileExists(atPath: selectedBody.path) }
            try require(try Data(contentsOf: selectedBody) == firstBody, "Selected body export used truncated preview bytes")
            archive.exportFile(path: mirrorFolder.path, kind: .response)
            try await eventually("body export failure completes native result") { !archive.exporting }
            try require(archive.message.hasPrefix("Body export failed:"), "Invalid body target did not report a file error")
            let beforeBadImport = Set(store.flows.map(\.id))
            archive.selectAutosavePath(selectedBody.path); archive.loadNow()
            try await eventually("malformed HAR import resets loading") { !archive.loading }
            try require(archive.message.hasPrefix("Session import failed:") && Set(store.flows.map(\.id)) == beforeBadImport, "Malformed HAR changed captures or left import busy")
            archive.selectAutosavePath(autosave.path)
            store.search = "/small/second"
            let csv = directory.appendingPathComponent("filtered.csv")
            archive.exportFile(path: csv.path, kind: .csv)
            let csvText = try String(contentsOf: csv, encoding: .utf8)
            try require(csvText.contains(secondURL) && !csvText.contains(firstURL), "CSV export did not honor the visible filter")
            print("PASS: explicit HAR open/save, full selected body and filtered CSV use one path workflow with failure completion")
            try await independentSessions(store, resources: resources, directory: directory, origin: "http://127.0.0.1:\(origin)", originalURL: firstURL, originalBody: firstBody, filteredURL: secondURL)
            try await stop(store)
            store.start()
            try await shutdown(store)
            try require(blocked.count == 0 && !system.hasBackup, "Test attempted a host system-proxy read or write")
            print("PASS: retained-session restart restores rows without duplicate mirrors; quit during restart cancels reopening and confirms engine exit")

            try require(!store.identifyClientProcesses, "Client process lookup must default off")
            store.identifyClientProcesses = true
            store.applyRules()
            let preferences = LensStore(dataDirectory: dataDirectory, resources: resources, systemProxy: system)
            try require(preferences.identifyClientProcesses, "Explicit process setting was not persisted")
            store.start()
            try await eventually("process-enabled packaged engine") { store.isRunning }
            store.selectSession(store.captureSessionID)
            let processURL = "http://127.0.0.1:\(origin)/native-process"
            var clientPID: Int32 = 0
            _ = try await request(resources: resources, directory: directory, port: port, url: processURL, observePID: { clientPID = $0 })
            try await eventually("typed native process observation") { store.flows.contains { $0.url == processURL && $0.state == "complete" } }
            guard let processRow = store.flows.first(where: { $0.url == processURL }), let process = processRow.clientConnection?.process else {
                throw StoreSmokeFailure(description: "Native process observation missing")
            }
            try require(process.state == "identified" && process.pid == Int(clientPID) && process.startIdentity != nil && process.name != nil && process.scope == "host_tcp_socket", "Native process identity did not match the owned actual client")
            try await stop(store)
            store.selection = processRow.id; store.loadDetail()
            try await eventually("process-enabled stopped detail") { !store.detailLoading }
            try require(store.detail?.id == processRow.id && store.detailError == nil, "Process feature lost stopped request/response detail")
            try await shutdown(store)
            print("PASS: default-off process setting persists explicit opt-in; typed observation matches owned client PID; stopped details remain readable")
        } catch {
            observer?.cancel()
            if store.hasEngine { try? await shutdown(store) }
            if fixture.isRunning { fixture.terminate() }
            try? await waitForProcess(fixture, label: "fixture cleanup after failure", timeout: 5)
            try? fixtureHandle.close()
            let details = [store.errorMessage ?? "", archive.message,
                "detailLoading=\(store.detailLoading) selection=\(store.selection ?? "nil") detail=\(store.detail?.id ?? "nil") error=\(store.detailError ?? "nil")",
                store.logs.suffix(3).joined()].joined(separator: "\n")
            throw StoreSmokeFailure(description: "\(error)\nNative diagnostics:\n\(details)")
        }
        if fixture.isRunning { fixture.terminate() }
        try await waitForProcess(fixture, label: "owned fixture exits", timeout: 5)
        try fixtureHandle.close()
        try require(blocked.count == 0, "Host access runner was invoked")
        print("Store/packaged-engine smoke passed. Native UI interaction remains separately unverified.")
    }
}

@main
@MainActor
private struct StoreEngineSmoke {
    static func main() {
        setbuf(stdout, nil)
        guard CommandLine.arguments.count == 2 else {
            fputs("Usage: store-engine-smoke /absolute/Lens.app/Contents/Resources\n", stderr)
            exit(2)
        }
        var finished = false
        var failure: Error?
        Task { @MainActor in
            do { try await StoreEngineChecks.run(resources: URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)) }
            catch { failure = error }
            finished = true
        }
        // Drive both AppKit's main RunLoop Timer and dispatch/main-actor callbacks.
        while !finished { _ = RunLoop.main.run(mode: .default, before: Date().addingTimeInterval(0.05)) }
        if let failure { fputs("FAIL: \(failure)\n", stderr); exit(1) }
    }
}
