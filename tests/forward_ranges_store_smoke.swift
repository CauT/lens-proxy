// Real production Store -> packaged range configuration, sockets and retained restart.
import AppKit
import Foundation

private struct Failure: Error { let message: String }

@main @MainActor
private struct ForwardRangesStoreSmoke {
    static func require(_ value: @autoclosure () throws -> Bool, _ message: String) throws {
        if try !value() { throw Failure(message: message) }
    }
    static func wait(_ name: String, _ predicate: () -> Bool) async throws {
        let deadline = Date().addingTimeInterval(20)
        while !predicate() {
            if Date() >= deadline { throw Failure(message: "Timed out: \(name)") }
            try await Task.sleep(nanoseconds: 20_000_000)
        }
    }
    static func command(_ store: LensStore, _ name: String) async throws -> [String: Any] {
        var value: [String: Any]?, error: String?
        store.send(name, onError: { error = $0 }) { result in value = result.projection as? [String: Any] }
        try await wait(name) { value != nil || error != nil }
        if let error { throw Failure(message: error) }
        return value!
    }
    static func shutdown(_ store: LensStore) async throws {
        var result: Bool?
        store.shutdown { result = $0 }
        try await wait("joined engine exit") { result != nil }
        try require(result == true && !store.hasEngine, "Engine shutdown failed")
    }
    static func run(_ resources: URL, _ root: URL) async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("lens-native-ranges-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let system = SystemProxyController(dataDirectory: directory.appendingPathComponent("system"),
            runner: SystemProxyRunner(read: { _ in throw Failure(message: "Host reads forbidden") },
                                     authorize: { _ in throw Failure(message: "Host changes forbidden") }))
        let data = directory.appendingPathComponent("state")
        let store = LensStore(dataDirectory: data, resources: resources, systemProxy: system)
        let fixture = Process(), fixtureInput = Pipe(), client = Process()
        var environment = ProcessInfo.processInfo.environment
        environment["PYTHONPATH"] = resources.appendingPathComponent("site-packages").path
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        fixture.executableURL = resources.appendingPathComponent("python/bin/python3")
        fixture.environment = environment
        fixture.standardInput = fixtureInput
        let ports = directory.appendingPathComponent("ports.json")
        fixture.arguments = ["-u", "-c", #"""
import json,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from test_forwarding_ranges import RangeOrigin,reserve_block
origin=RangeOrigin()
try:
 base,held=reserve_block(4,automatic_proxy=True)
 for stream in held:stream.close()
 Path(sys.argv[2]).write_text(json.dumps([origin.base,base,base+3]))
 input()
finally:origin.close()
"""#, root.appendingPathComponent("tests").path, ports.path]
        try fixture.run()
        func closeFixture() async throws {
            if fixture.isRunning {
                fixtureInput.fileHandleForWriting.write(Data([10]))
                fixtureInput.fileHandleForWriting.closeFile()
                try await wait("joined origin worker") { !fixture.isRunning }
            }
            try require(fixture.terminationStatus == 0, "Owned fixture failed")
        }
        do {
            try await wait("origin ready") { FileManager.default.fileExists(atPath: ports.path) }
            let numbers = try JSONDecoder().decode([Int].self, from: Data(contentsOf: ports))
            let target = numbers[0], local = numbers[1]
            store.port = String(numbers[2])
            store.tcpForwards = [TCPForwardSelection(listenPort: String(local), listenPortEnd: String(local + 2), targetHost: "127.0.0.1", targetPort: String(target))]
            store.udpForwards = [UDPForwardSelection(listenPort: String(local), listenPortEnd: String(local + 2), targetHost: "127.0.0.1", targetPort: String(target))]
            store.start()
            try await wait("native range engine ready") { store.isRunning || store.errorMessage != nil }
            try require(store.isRunning, store.errorMessage ?? "Start failed")
            client.executableURL = fixture.executableURL
            client.environment = environment
            client.arguments = ["-c", #"""
import socket,sys
base=int(sys.argv[1])
for index in (2,0,1):
 body=bytes([index,0,255])*19
 with socket.create_connection(('127.0.0.1',base+index),timeout=8) as stream:
  stream.sendall(body);stream.shutdown(socket.SHUT_WR)
  result=b''
  while part:=stream.recv(65536):result+=part
  assert result==b'TCP:'+str(index).encode()+b':'+body[::-1]
 with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as stream:
  stream.settimeout(8)
  for packet in (b'',body):
   stream.sendto(packet,('127.0.0.1',base+index))
   result,peer=stream.recvfrom(65535)
   assert peer==('127.0.0.1',base+index)
   assert result==b'UDP:'+str(index).encode()+b':'+packet[::-1]
"""#, String(local)]
            try client.run()
            try await wait("client completed six routes") { !client.isRunning }
            try require(client.terminationStatus == 0, "Actual native-configured offsets or bytes changed")
            try await wait("native summaries") {
                store.tcpStreams.count == 3 && store.tcpStreams.allSatisfy { $0.state == "closed" }
                && store.udpAssociations.count == 3 && store.udpAssociations.allSatisfy { $0.receivedDatagrams == 2 }
            }
            for index in 0..<3 {
                try require(store.tcpStreams.contains { $0.listenPort == local + index && $0.targetPort == target + index }, "TCP route facts changed")
                try require(store.udpAssociations.contains { $0.listenPort == local + index && $0.targetPort == target + index }, "UDP route facts changed")
            }
            for transport in ["tcp", "udp"] {
                let status = try await command(store, transport + "_status")
                try require((status["forwards"] as? [[String: Any]])?.count == 3, "Accepted range must expose three actual listeners")
            }
            print("PASS: production Store sends TCP/UDP ranges; three distinct remote offsets return exact binary/empty datagrams and typed route facts")
            let tcpIDs = Set(store.tcpStreams.map(\.id)), udpIDs = Set(store.udpAssociations.map(\.id))
            var stopped: Bool?
            store.stop { stopped = $0 }
            try await wait("Stop saves ranges and joins listeners") { stopped != nil }
            try require(stopped == true && !store.isRunning, "Stop failed")
            let network = try await command(store, "network_status")
            try require((network["public_listeners"] as? [Any])?.isEmpty == true, "TCP listeners remained")
            try require(((network["udp"] as? [String: Any])?["listeners"] as? [Any])?.isEmpty == true, "UDP listeners remained")
            let preferences = LensStore(dataDirectory: data, resources: resources, systemProxy: system)
            try require(preferences.tcpForwards.first?.listenPortEnd == String(local + 2)
                && preferences.udpForwards.first?.listenPortEnd == String(local + 2), "Preferences flattened or dropped the selected ranges")
            store.start()
            try await wait("actual restart restores histories") {
                store.isRunning && Set(store.tcpStreams.map(\.id)) == tcpIDs
                && Set(store.udpAssociations.map(\.id)) == udpIDs
                && store.tcpStreams.allSatisfy(\.imported) && store.udpAssociations.allSatisfy(\.imported)
            }
            try await shutdown(store)
            try await closeFixture()
            print("PASS: Stop/restart retains all six identities, range preferences remain selected, and actual owners exit cleanly")
        } catch {
            if client.isRunning {
                client.terminate()
                try? await wait("terminated owned client") { !client.isRunning }
            }
            if store.hasEngine { try? await shutdown(store) }
            if fixture.isRunning {
                fixtureInput.fileHandleForWriting.closeFile()
                try? await wait("origin cleanup") { !fixture.isRunning }
                if fixture.isRunning {
                    fixture.terminate()
                    try? await wait("terminated owned origin") { !fixture.isRunning }
                }
            }
            throw error
        }
    }
    static func main() {
        setbuf(stdout, nil)
        guard CommandLine.arguments.count == 3 else { exit(2) }
        var done = false, failure: Error?
        Task { @MainActor in
            do { try await run(URL(fileURLWithPath: CommandLine.arguments[1]), URL(fileURLWithPath: CommandLine.arguments[2])) }
            catch { failure = error }
            done = true
        }
        while !done { RunLoop.current.run(until: Date().addingTimeInterval(0.02)) }
        if let failure { fputs("FAIL: \(failure)\n", stderr); exit(1) }
    }
}
