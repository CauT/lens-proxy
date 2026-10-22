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
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("lens-udp-store-" + UUID().uuidString)
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
  data,stream=self.request
  stream.sendto(data[::-1],self.client_address)
class Server(socketserver.UDPServer): max_packet_size=65535
server=Server(('127.0.0.1',0),Handler)
server.socket.setsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF,131072)
reservation=socket.socket(); reservation.bind(('127.0.0.1',0))
Path(sys.argv[1]).write_text(json.dumps([server.server_address[1],reservation.getsockname()[1]]))
reservation.close()
server.serve_forever()
"""#, ports.path]
        fixture.environment = env
        try fixture.run()
        defer { if fixture.isRunning { fixture.terminate() } }
        do {
            try await wait("owned UDP origin") { FileManager.default.fileExists(atPath: ports.path) }
            let numbers = try JSONDecoder().decode([Int].self, from: Data(contentsOf: ports))
            store.port = String(numbers[1])
            store.udpForwards = [UDPForwardSelection(listenPort: store.port, targetHost: "127.0.0.1", targetPort: String(numbers[0]))]
            try require(LensNetworkSettingsValidation.listenerIssue(httpPort: store.port, socksPort: "0", reversePort: "0", reverseURL: "", udpForwards: store.udpForwards) == nil, "TCP/UDP shared numeric port should be valid")
            try require(LensNetworkSettingsValidation.listenerIssue(httpPort: store.port, socksPort: "0", reversePort: "0", reverseURL: "", udpForwards: store.udpForwards + store.udpForwards) != nil, "Duplicate UDP listeners must fail")
            var configured: Bool?
            store.applyRules(completion: { configured = $0 })
            try require(configured == true, "UDP forwarding selection was not saved")
            store.start()
            try await wait("native UDP launch") { store.isRunning || store.errorMessage != nil }
            try require(store.isRunning, store.errorMessage ?? "Launch failed")
            let client = Process()
            client.executableURL = fixture.executableURL
            let response = directory.appendingPathComponent("response.bin")
            client.arguments = ["-c", #"""
import socket,sys
from pathlib import Path
payloads=[b'']+[bytes(range(256))*i for i in range(1,20)]+[bytes(i%256 for i in range(65507))]
with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as stream:
 stream.settimeout(8)
 stream.setsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF,131072)
 for data in payloads:
  stream.sendto(data,('127.0.0.1',int(sys.argv[1])))
  actual,_=stream.recvfrom(65535)
  assert actual==data[::-1]
 Path(sys.argv[2]).write_bytes(b'ok')
"""#, store.port, response.path]
            client.environment = env
            try client.run()
            try await wait("real UDP client exits") { !client.isRunning }
            if client.terminationStatus != 0 {
                let diagnosis = try await command(store, "udp_status")
                throw Failure(message: "Real UDP client failed. Status: \(diagnosis). Logs: \(store.logs.joined(separator: "\n"))")
            }
            try require((try Data(contentsOf: response)) == Data("ok".utf8), "Real UDP datagrams changed")
            try await wait("native datagram summaries") { store.udpAssociations.first?.receivedDatagrams == 21 }
            let identity = store.udpAssociations[0].id
            let value = try await command(store, "udp_detail", ["id": identity, "offset": 0, "limit": 32])
            let decoder = JSONDecoder(); decoder.keyDecodingStrategy = .convertFromSnakeCase
            let page = try decoder.decode(UDPDatagramPage.self, from: JSONSerialization.data(withJSONObject: value))
            try require(page.association.sentDatagrams == 21 && page.association.receivedDatagrams == 21, "Native datagram counts changed")
            try require(page.association.droppedClientDatagrams == 0 && page.association.droppedUpstreamDatagrams == 0 && !page.association.truncated, "Successful forwarding reported local drops or capture truncation")
            var observed = page.datagrams
            while observed.count < page.total {
                let result = try await command(store, "udp_detail", ["id": identity, "offset": observed.count, "limit": 32])
                let next = try decoder.decode(UDPDatagramPage.self, from: JSONSerialization.data(withJSONObject: result))
                try require(!next.datagrams.isEmpty && next.datagrams.count <= 32, "Invalid bounded native datagram page")
                observed += next.datagrams
            }
            try require(page.total == 42 && page.datagrams.count == 32, "Fixture must cross native datagram paging boundary")
            let sent = observed.filter { $0.direction == "send" }.map(\.data)
            let expected = [Data()] + (1..<20).map { index in Data((0..<(256 * index)).map { UInt8($0 % 256) }) } + [Data((0..<65507).map { UInt8($0 % 256) })]
            try require(sent == expected, "Typed decode lost binary/empty datagram boundaries")
            print("PASS: production Store forwards UDP alongside HTTP on same numeric port; binary, empty and maximum IPv4 payload datagrams cross pages intact")
            let preferences = LensStore(dataDirectory: data, resources: resources, systemProxy: system)
            try require(preferences.udpForwards.first?.listenPort == store.port && preferences.udpForwards.first?.targetPort == String(numbers[0]), "UDP forwarding preferences were not saved")
            try await stopped(store)
            let file = data.appendingPathComponent("exported-udp.lens-udp.json")
            _ = try await command(store, "save_udp", ["path": file.path])
            try require(FileManager.default.fileExists(atPath: file.path), "Explicit UDP export file missing")
            let generation = store.udpGeneration
            store.openUDPSession(file)
            try await wait("same-id file replacement resets native detail generation") {
                store.udpGeneration > generation && store.udpAssociations.first?.id == identity
            }
            let status = try await command(store, "network_status") as? [String: Any]
            try require((status?["public_listeners"] as? [Any])?.isEmpty == true, "Stop kept listeners")
            let stoppedUDP = try await command(store, "udp_status") as? [String: Any]
            let stoppedNetwork = stoppedUDP?["network"] as? [String: Any]
            try require((stoppedNetwork?["listeners"] as? [Any])?.isEmpty == true && stoppedNetwork?["active_associations"] as? Int == 0, "Stop retained UDP listeners or live associations")
            store.start()
            try await wait("UDP restored after actual engine restart") { store.isRunning && store.udpAssociations.first?.imported == true }
            try require(store.udpAssociations[0].id == identity, "Restart lost UDP identity")
            print("PASS: Stop retains the workspace; explicit UDP export and actual restart preserve historical associations")
            try await shutdown(store)
            let reopened = LensStore(dataDirectory: directory.appendingPathComponent("inspect-only"), resources: resources, systemProxy: system)
            reopenedOwner = reopened
            reopened.openUDPSession(file)
            try await wait("UDP file opens without forwarding") { reopened.udpAssociations.first?.id == identity || reopened.errorMessage != nil }
            try require(!reopened.isRunning && reopened.hasEngine && reopened.errorMessage == nil, "File open started capture or failed: \(reopened.errorMessage ?? "")")
            let inspection = try await command(reopened, "network_status") as? [String: Any]
            try require((inspection?["public_listeners"] as? [Any])?.isEmpty == true && (inspection?["internal_listeners"] as? [Any])?.isEmpty == true,
                        "Read-only file owner has listeners")
            let inspectionUDP = try await command(reopened, "udp_status") as? [String: Any]
            let inspectionNetwork = inspectionUDP?["network"] as? [String: Any]
            try require((inspectionNetwork?["listeners"] as? [Any])?.isEmpty == true && inspectionNetwork?["active_associations"] as? Int == 0, "UDP file inspection opened UDP listeners or associations")
            let decoded = try await command(reopened, "udp_detail", ["id": identity])
            let restored = try decoder.decode(UDPDatagramPage.self, from: JSONSerialization.data(withJSONObject: decoded))
            try require(restored.datagrams.map(\.data) == page.datagrams.map(\.data), "Reopened bytes changed")
            try require(!FileManager.default.fileExists(atPath: reopened.dataDirectory.appendingPathComponent("mitmproxy-ca.pem").path), "UDP file inspection created TLS credentials")
            try await shutdown(reopened)
            print("PASS: fresh Store opens UDP session with no public/internal listeners and exits cleanly")
            var malformed = value as! [String: Any]
            var datagrams = malformed["datagrams"] as! [[String: Any]]; datagrams[0]["base64"] = "invalid"
            malformed["datagrams"] = datagrams
            do {
                _ = try decoder.decode(UDPDatagramPage.self, from: JSONSerialization.data(withJSONObject: malformed))
                throw Failure(message: "Malformed datagram silently became empty")
            } catch is DecodingError { }
            print("PASS: malformed UDP payload is an explicit decoding failure")
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
private struct UDPStoreSmoke {
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
