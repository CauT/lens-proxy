// Production Store -> actual packaged WS history, without refetching HAR URLs.
import AppKit
import Foundation

private struct WSStoreFailure: Error, CustomStringConvertible { let description: String }
@MainActor private enum WSStoreChecks {
    static func require(_ value: @autoclosure () throws -> Bool, _ reason: String) throws {
        if try !value() { throw WSStoreFailure(description: reason) }
    }
    static func wait(_ label: String, _ condition: () -> Bool) async throws {
        let deadline = Date().addingTimeInterval(20)
        while !condition() {
            if Date() > deadline { throw WSStoreFailure(description: "Timed out: " + label) }
            try await Task.sleep(nanoseconds: 20_000_000)
        }
    }
    static func command(_ store: LensStore, _ name: String, _ args: [String: Any] = [:]) async throws -> EngineValue {
        var result: EngineValue?, failure: String?
        store.send(name, args, onError: { failure = $0 }) { result = $0 }
        try await wait(name) { result != nil || failure != nil }
        if let failure { throw WSStoreFailure(description: failure) }
        return result!
    }
    static func page(_ store: LensStore, id: String, offset: Int, generation: Int, fails: Bool = false) async throws -> WebSocketMessagePage? {
        var result: Result<WebSocketMessagePage, Error>?
        store.loadWebSocketPage(id: id, offset: offset, generation: generation) { result = $0 }
        try await wait("native WS page completion") { result != nil }
        switch result! {
        case .success(let value): try require(!fails, "Unexpected successful page"); return value
        case .failure: try require(fails, "Unexpected failed page"); return nil
        }
    }
    static func shutdown(_ store: LensStore) async throws {
        var result: Bool?
        store.shutdown { result = $0 }
        try await wait("owned engine exit") { result != nil }
        try require(result == true && !store.hasEngine, "Engine cleanup failed")
    }
    static func run(resources: URL, fixtures: URL) async throws {
        let files = FileManager.default, root = files.temporaryDirectory.appendingPathComponent("lens-ws-store-" + UUID().uuidString)
        try files.createDirectory(at: root, withIntermediateDirectories: false)
        defer { try? files.removeItem(at: root) }
        let system = SystemProxyController(dataDirectory: root.appendingPathComponent("system"), runner: SystemProxyRunner(read: { _ in throw WSStoreFailure(description: "Host access forbidden") }, authorize: { _ in throw WSStoreFailure(description: "Host mutation forbidden") }))
        let store = LensStore(dataDirectory: root.appendingPathComponent("data"), resources: resources, systemProxy: system)
        let port = root.appendingPathComponent("port"), allocator = Process()
        allocator.executableURL = resources.appendingPathComponent("python/bin/python3")
        allocator.arguments = ["-c", "import socket,sys;from pathlib import Path;s=socket.socket();s.bind(('127.0.0.1',0));Path(sys.argv[1]).write_text(str(s.getsockname()[1]));s.close()", port.path]
        try allocator.run(); try await wait("port allocator exits") { !allocator.isRunning }
        try require(allocator.terminationStatus == 0, "Port allocator failed")
        store.port = try String(contentsOf: port, encoding: .utf8)
        store.start()
        do {
            try await wait("real native engine ready") { store.isRunning || (!store.isStarting && store.errorMessage != nil) }
            try require(store.isRunning, store.errorMessage ?? "Engine did not start")
            _ = try await command(store, "load_har", ["path": fixtures.appendingPathComponent("paged.har").path])
            guard let flow = store.flows.first else { throw WSStoreFailure(description: "Imported flow missing") }
            store.selection = flow.id; store.loadDetail()
            try await wait("actual native first-page detail") { !store.detailLoading }
            guard let initial = try store.detail?.firstWebSocketPage() else { throw WSStoreFailure(description: store.detailError ?? "No native WS page") }
            try require(initial.total == 122 && initial.messages.count == 50 && initial.nextOffset == 50, "First-page coverage changed")
            try require(initial.messages.allSatisfy { $0.previewBytes != nil && $0.opcode == 2 }, "Native detail lost captured binary messages")
            print("PASS: real Store loads first50 typed byte previews from imported122-message history without network refetch")
            guard let second = try await page(store, id: flow.id, offset: 50, generation: initial.generation) else { throw WSStoreFailure(description: "Second page absent") }
            try require(second.messages.first?.index == 50 && second.messages.count == 50 && second.nextOffset == 100, "Native next page lost positions")
            _ = try await page(store, id: flow.id, offset: 50, generation: initial.generation + 1, fails: true)
            print("PASS: native page identity/coverage retains positions; stale generation finishes with explicit failure")
            var stopped: Bool?; store.stop { stopped = $0 }
            try await wait("Stop retains history") { stopped != nil }
            try require(stopped == true && !store.isRunning && store.hasEngine, "Stop lost the retained owner")
            guard let final = try await page(store, id: flow.id, offset: 100, generation: initial.generation) else { throw WSStoreFailure(description: "Stopped final page absent") }
            try require(final.messages.count == 22 && final.nextOffset == nil && final.messages.last?.index == 121, "Stopped retained history changed")
            print("PASS: stopped engine retains typed final22-message page without reopening listeners")
            _ = try await command(store, "clear")
            _ = try await page(store, id: flow.id, offset: 0, generation: initial.generation, fails: true)
            try await shutdown(store)
            print("PASS: Clear rejects stale history id and shutdown confirms actual engine exit")
        } catch { try await shutdown(store); throw error }
    }
}
@main private struct WebSocketStoreSmoke {
    static func main() async {
        do {
            guard CommandLine.arguments.count == 3 else { throw WSStoreFailure(description: "Pass Resources and synthetic HAR directory") }
            try await WSStoreChecks.run(resources: URL(fileURLWithPath: CommandLine.arguments[1]), fixtures: URL(fileURLWithPath: CommandLine.arguments[2]))
        } catch { fputs("FAIL: \(error)\n", stderr); exit(1) }
    }
}
