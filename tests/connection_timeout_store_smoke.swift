// Production native selection -> JSONL admission -> packaged engine and disk.
import AppKit
import Foundation

private struct TimeoutFailure: Error { let message: String }
@MainActor private enum Checks {
    static func require(_ value: @autoclosure () throws -> Bool, _ reason: String) throws {
        if try !value() { throw TimeoutFailure(message: reason) }
    }
    static func wait(_ label: String, _ condition: () -> Bool) async throws {
        let until = Date().addingTimeInterval(20)
        while !condition() {
            if Date() > until { throw TimeoutFailure(message: "Timed out: " + label) }
            try await Task.sleep(nanoseconds: 20_000_000)
        }
    }
    static func apply(_ store: LensStore, _ value: String, rules: [ProxyRule]? = nil, success: Bool = true) async throws {
        var result: Bool?
        store.applyRules(rules, connectTimeout: value) { result = $0 }
        try await wait("settings acknowledgement") { result != nil }
        try require(result == success, store.errorMessage ?? "Unexpected settings outcome")
    }
    static func status(_ store: LensStore) async throws -> Int? {
        var value: Int?, issue: String?, done = false
        store.send("network_status", onError: { issue = $0; done = true }) { result in value = result["connect_timeout_seconds"]?.integer; done = true }
        try await wait("network status") { done }
        try require(issue == nil, issue ?? "Network status failed")
        return value
    }
    static func shutdown(_ store: LensStore) async throws {
        var done: Bool?
        store.shutdown { done = $0 }
        try await wait("engine cleanup") { done != nil }
        try require(done == true && !store.hasEngine, store.errorMessage ?? store.status)
    }
    static func object(_ url: URL) throws -> [String: Any] { try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as! [String: Any] }
    static func run(_ resources: URL, port: String) async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("lens-timeout-store-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let runner = SystemProxyRunner(read: { _ in throw TimeoutFailure(message: "Host read forbidden") }, authorize: { _ in throw TimeoutFailure(message: "Host mutation forbidden") })
        let system = SystemProxyController(dataDirectory: directory.appendingPathComponent("system"), runner: runner)
        let data = directory.appendingPathComponent("data")
        try FileManager.default.createDirectory(at: data, withIntermediateDirectories: true)
        let preferences = data.appendingPathComponent("preferences.json")
        try JSONSerialization.data(withJSONObject: ["port": port, "caller_extension": ["selected": "preserve"]]).write(to: preferences)
        let store = LensStore(dataDirectory: data, resources: resources, systemProxy: system)
        try require(store.connectTimeoutSeconds == "10", "Absent field lost legacy default")
        for input in ["", "0", "601", "-1", "1.5", " 1", "１", "999999999999"] {
            try require(LensNetworkSettingsValidation.connectTimeout(input) == nil, "Invalid UI scalar accepted: " + input)
        }
        for input in ["1", "10", "600"] { try require(LensNetworkSettingsValidation.connectTimeout(input) != nil, "Valid scalar rejected") }
        print("PASS legacy default and explicit native scalar admission")
        store.start()
        do {
            try await wait("real engine ready") { store.isRunning || (!store.isStarting && store.errorMessage != nil) }
            try require(store.isRunning, store.errorMessage ?? "Startup failed")
            try await apply(store, "1")
            let initialStatus = try await status(store)
            try require(initialStatus == 1, "Engine did not apply selected deadline")
            let accepted = try Data(contentsOf: preferences)
            try await apply(store, "0", success: false)
            try require(store.connectTimeoutSeconds == "1" && (try Data(contentsOf: preferences)) == accepted, "Rejected UI scalar replaced accepted value")
            let bad = ProxyRule(kind: "map_remote", match: "*", value: "not-an-http-url")
            try await apply(store, "3", rules: [bad], success: false)
            try require(store.connectTimeoutSeconds == "1" && (try Data(contentsOf: preferences)) == accepted, "Engine-rejected snapshot replaced deadline or disk")
            let rejectedStatus = try await status(store)
            try require(rejectedStatus == 1, "Rejected snapshot changed live timeout")
            print("PASS actual settings acceptance and rejection preserve live, native and disk values")
            store.errorMessage = nil
            var first: Bool?, second: Bool?
            store.applyRules(connectTimeout: "2") { first = $0 }
            store.applyRules(connectTimeout: "3") { second = $0 }
            try require(second == false, "Overlapping timeout Save was admitted")
            try await wait("captured timeout snapshot") { first != nil }
            try require(first == true && store.connectTimeoutSeconds == "2", "Captured timeout snapshot changed")
            let saved = try object(preferences)
            try require(saved["connect_timeout_seconds"] as? String == "2", "Saved selection lost exact representation")
            try require((saved["caller_extension"] as? [String: String])?["selected"] == "preserve", "Unrelated preference field was dropped")
            try await shutdown(store)
            let reopened = LensStore(dataDirectory: data, resources: resources, systemProxy: system)
            try require(reopened.connectTimeoutSeconds == "2", "Reopen lost selected timeout")
            reopened.start()
            try await wait("reopened engine") { reopened.isRunning || (!reopened.isStarting && reopened.errorMessage != nil) }
            try require(reopened.isRunning, reopened.errorMessage ?? "Reopened startup failed")
            do { let reopenedStatus = try await status(reopened); try require(reopenedStatus == 2, "Next Start lost timeout"); try await shutdown(reopened) }
            catch { try? await shutdown(reopened); throw error }
            print("PASS snapshot Save, additive preferences, reopen and next Start")
        } catch { if store.hasEngine { try? await shutdown(store) }; throw error }
        let malformed = directory.appendingPathComponent("malformed")
        try FileManager.default.createDirectory(at: malformed, withIntermediateDirectories: true)
        let original = try JSONSerialization.data(withJSONObject: ["port": port, "connect_timeout_seconds": true, "caller_extension": ["raw": [1, 2, 3]]])
        try original.write(to: malformed.appendingPathComponent("preferences.json"))
        let recovery = LensStore(dataDirectory: malformed, resources: resources, systemProxy: system)
        recovery.start()
        try require(!recovery.hasEngine && recovery.connectionTimeoutPreferencesIssue != nil, "Malformed present setting started with a guessed default")
        try await apply(recovery, "4")
        let backups = try FileManager.default.contentsOfDirectory(at: malformed, includingPropertiesForKeys: nil).filter { $0.lastPathComponent.hasPrefix("preferences-connection-recovery-") }
        try require(backups.count == 1 && (try Data(contentsOf: backups[0])) == original, "Original malformed preference bytes were not preserved")
        try await apply(recovery, "4")
        let after = try FileManager.default.contentsOfDirectory(at: malformed, includingPropertiesForKeys: nil).filter { $0.lastPathComponent.hasPrefix("preferences-connection-recovery-") }
        try require(after.count == 1 && recovery.connectTimeoutSeconds == "4", "Recovery was not idempotent")
        try require((try object(malformed.appendingPathComponent("preferences.json")))["caller_extension"] != nil, "Recovery dropped caller extension")
        print("PASS malformed preference refusal, exact backup and idempotent explicit repair")
    }
}
@main @MainActor private struct ConnectionTimeoutStoreSmoke {
    static func main() {
        setbuf(stdout, nil)
        guard CommandLine.arguments.count == 3 else { exit(2) }
        var done = false, issue: Error?
        Task { @MainActor in do { try await Checks.run(URL(fileURLWithPath: CommandLine.arguments[1]), port: CommandLine.arguments[2]) } catch { issue = error }; done = true }
        while !done { _ = RunLoop.main.run(mode: .default, before: Date().addingTimeInterval(0.05)) }
        if let issue { fputs("FAIL: \(issue)\n", stderr); exit(1) }
    }
}
