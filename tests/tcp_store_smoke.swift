// Compile production Models/LensStore/SystemProxy/SessionTools/SessionArtifacts/
// CurlCommand/NetworkSettingsView/LANAccess with SwiftUI/AppKit. No system mutation.
import AppKit
import Foundation

private struct Failure: Error { let message: String }

@MainActor
private enum Checks {
    static func require(_ value: @autoclosure () throws -> Bool, _ reason: String) throws {
        if try !value() { throw Failure(message: reason) }
    }
    static func wait(_ label: String, _ value: () -> Bool) async throws {
        let deadline = Date().addingTimeInterval(15)
        while !value() {
            if Date() > deadline { throw Failure(message: "Timed out: \(label)") }
            try await Task.sleep(nanoseconds: 20_000_000)
        }
    }
    static func command(_ store: LensStore, _ name: String, _ args: [String: Any] = [:]) async throws -> Any {
        var value: Any?, error: String?
        store.send(name, args, onError: { error = $0 }) { result in
            guard result.sourceFacts.text.isEmpty else { error = "Fixture unexpectedly returned source text annotations"; return }
            value = result.projection
        }
        try await wait(name) { value != nil || error != nil }
        if let error { throw Failure(message: error) }
        return value!
    }
    static func stopped(_ store: LensStore) async throws {
        var result: Bool?
        store.stop { result = $0 }
        try await wait("Stop and retained snapshots") { result != nil }
        try require(result == true && !store.isRunning && store.hasEngine, "Stopped owner missing")
    }
    static func shutdown(_ store: LensStore) async throws {
        var result: Bool?
        store.shutdown { result = $0 }
        try await wait("actual process exit") { result != nil }
        try require(result == true && !store.hasEngine, "Engine remains after shutdown")
    }
    static func run(_ resources: URL) async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("lens-tcp-store-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let data = directory.appendingPathComponent("data")
        let system = SystemProxyController(dataDirectory: directory.appendingPathComponent("system"), runner: SystemProxyRunner(read: { _ in throw Failure(message: "Host read is forbidden") },
                authorize: { _ in throw Failure(message: "Host mutation is forbidden") }))
        let store = LensStore(dataDirectory: data, resources: resources, systemProxy: system)
        var reopenedOwner: LensStore?
        var env = ProcessInfo.processInfo.environment
        env["PYTHONPATH"] = resources.appendingPathComponent("site-packages").path
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        let fixture = Process()
        fixture.executableURL = resources.appendingPathComponent("python/bin/python3")
        let ports = directory.appendingPathComponent("ports.json")
        fixture.arguments = ["-u", "-c", #"""
import json,socket,socketserver,sys
from pathlib import Path
class Handler(socketserver.BaseRequestHandler):
 def handle(self):
  self.request.settimeout(10)
  data=bytearray()
  while chunk:=self.request.recv(16384): data.extend(chunk)
  self.request.sendall(bytes(data)[::-1])
class Server(socketserver.ThreadingTCPServer): daemon_threads=True
server=Server(('127.0.0.1',0),Handler)
reservations=[socket.socket() for _ in range(2)]
for stream in reservations: stream.bind(('127.0.0.1',0))
Path(sys.argv[1]).write_text(json.dumps([server.server_address[1],*[stream.getsockname()[1] for stream in reservations]]))
for stream in reservations: stream.close()
server.serve_forever()
"""#, ports.path]
        fixture.environment = env
        try fixture.run()
        defer { if fixture.isRunning { fixture.terminate() } }
        do {
            try await wait("owned TCP origin") { FileManager.default.fileExists(atPath: ports.path) }
            let numbers = try JSONDecoder().decode([Int].self, from: Data(contentsOf: ports))
            store.port = String(numbers[1])
            store.tcpForwards = [TCPForwardSelection(listenPort: String(numbers[2]), targetHost: "127.0.0.1", targetPort: String(numbers[0]))]
            try require(LensNetworkSettingsValidation.listenerIssue(httpPort: store.port, socksPort: "0", reversePort: "0", reverseURL: "", tcpForwards: store.tcpForwards) == nil, "Native endpoint validation failed")
            store.start()
            try await wait("native TCP launch") { store.isRunning || store.errorMessage != nil }
            try require(store.isRunning, store.errorMessage ?? "Launch failed")
            let client = Process(), payload = Data((0..<(256 * 1025)).map { UInt8($0 % 256) })
            client.executableURL = fixture.executableURL
            let response = directory.appendingPathComponent("response.bin")
            client.arguments = ["-c", #"""
import socket,sys
from pathlib import Path
data=bytes(range(256))*1025
with socket.create_connection(('127.0.0.1',int(sys.argv[1])),timeout=8) as stream:
 stream.sendall(data); stream.shutdown(socket.SHUT_WR)
 result=bytearray()
 while chunk:=stream.recv(16384): result.extend(chunk)
 Path(sys.argv[2]).write_bytes(result)
"""#, String(numbers[2]), response.path]
            client.environment = env
            try client.run()
            try await wait("real TCP client exits") { !client.isRunning }
            let actualResponse = try Data(contentsOf: response)
            try require(client.terminationStatus == 0 && actualResponse == Data(payload.reversed()), "Real native-configured TCP bytes changed")
            try await wait("native stream summary") { store.tcpStreams.first?.state == "closed" }
            let identity = store.tcpStreams[0].id
            let value = try await command(store, "tcp_detail", ["id": identity])
            let decoder = JSONDecoder(); decoder.keyDecodingStrategy = .convertFromSnakeCase
            let page = try decoder.decode(TCPChunkPage.self, from: JSONSerialization.data(withJSONObject: value))
            try require(page.stream.sentBytes == payload.count && page.stream.receivedBytes == payload.count, "Native counts changed")
            var observed = page.chunks
            while observed.count < page.total {
                let result = try await command(store, "tcp_detail", ["id": identity, "offset": observed.count])
                let next = try decoder.decode(TCPChunkPage.self, from: JSONSerialization.data(withJSONObject: result))
                try require(!next.chunks.isEmpty && next.chunks.count <= 32, "Invalid bounded native page")
                observed += next.chunks
            }
            try require(page.total > 32, "Fixture must cross the native paging boundary")
            let sent = observed.filter { $0.direction == "send" }.reduce(into: Data()) { $0.append($1.data) }
            try require(sent == payload, "Native typed chunk decode lost bytes")
            print("PASS: production Store launches TCP forwarding and decodes real binary observations")
            try await stopped(store)
            let file = data.appendingPathComponent("exported-tcp.lens-tcp.json")
            _ = try await command(store, "save_tcp", ["path": file.path])
            try require(FileManager.default.fileExists(atPath: file.path), "Explicit TCP export file missing")
            let generation = store.tcpGeneration
            store.openTCPSession(file)
            try await wait("same-id file replacement resets native detail generation") {
                store.tcpGeneration > generation && store.tcpStreams.first?.id == identity
            }
            let status = try await command(store, "network_status") as? [String: Any]
            try require((status?["public_listeners"] as? [Any])?.isEmpty == true, "Stop kept listeners")
            store.start()
            try await wait("TCP restored after actual engine restart") { store.isRunning && store.tcpStreams.first?.imported == true }
            try require(store.tcpStreams[0].id == identity, "Restart lost TCP identity")
            print("PASS: Stop retains the workspace; explicit TCP export and actual restart preserve historical rows")
            try await shutdown(store)
            let reopened = LensStore(dataDirectory: data, resources: resources, systemProxy: system)
            reopenedOwner = reopened
            reopened.openTCPSession(file)
            try await wait("TCP file opens without forwarding") { reopened.tcpStreams.first?.id == identity || reopened.errorMessage != nil }
            try require(!reopened.isRunning && reopened.hasEngine && reopened.errorMessage == nil, "File open started capture or failed: \(reopened.errorMessage ?? "")")
            let inspection = try await command(reopened, "network_status") as? [String: Any]
            try require((inspection?["public_listeners"] as? [Any])?.isEmpty == true && (inspection?["internal_listeners"] as? [Any])?.isEmpty == true,
                        "Read-only file owner has listeners")
            let decoded = try await command(reopened, "tcp_detail", ["id": identity])
            let restored = try decoder.decode(TCPChunkPage.self, from: JSONSerialization.data(withJSONObject: decoded))
            try require(restored.chunks.map(\.data) == page.chunks.map(\.data), "Reopened bytes changed")
            try await shutdown(reopened)
            print("PASS: fresh Store opens TCP session with no public/internal listeners and exits cleanly")
            var malformed = value as! [String: Any]
            var chunks = malformed["chunks"] as! [[String: Any]]; chunks[0]["base64"] = "invalid"
            malformed["chunks"] = chunks
            do {
                _ = try decoder.decode(TCPChunkPage.self, from: JSONSerialization.data(withJSONObject: malformed))
                throw Failure(message: "Malformed bytes silently became empty")
            } catch is DecodingError { }
            print("PASS: malformed byte observations are explicit decoding failures")
        } catch {
            if let reopenedOwner, reopenedOwner.hasEngine { try? await shutdown(reopenedOwner) }
            if store.hasEngine { try? await shutdown(store) }
            throw error
        }
        fixture.terminate()
        try await wait("fixture process exits") { !fixture.isRunning }
    }
}

@main @MainActor
private struct TCPStoreSmoke {
    static func main() {
        setbuf(stdout, nil)
        guard CommandLine.arguments.count == 2 else { exit(2) }
        var done = false, failure: Error?
        Task { @MainActor in
            do { try await Checks.run(URL(fileURLWithPath: CommandLine.arguments[1])) } catch { failure = error }
            done = true
        }
        while !done { _ = RunLoop.main.run(mode: .default, before: Date().addingTimeInterval(0.05)) }
        if let failure { fputs("FAIL: \(failure)\n", stderr); exit(1) }
    }
}
