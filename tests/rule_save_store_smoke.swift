// Production Store -> real packaged engine. No UI or host settings access.
import AppKit
import Foundation

private struct SaveFailure: Error, CustomStringConvertible { let description: String }
@MainActor private enum RuleSaveChecks {
    static func require(_ value: @autoclosure () throws -> Bool, _ reason: String) throws {
        if try !value() { throw SaveFailure(description: reason) }
    }
    static func wait(_ label: String, _ condition: () -> Bool) async throws {
        let deadline = Date().addingTimeInterval(20)
        while !condition() {
            if Date() > deadline { throw SaveFailure(description: "Timed out: " + label) }
            try await Task.sleep(nanoseconds: 20_000_000)
        }
    }
    static func apply(_ store: LensStore, succeeds: Bool = true) async throws {
        var result: Bool?
        store.applyRules { result = $0 }
        try await wait("settings completion") { result != nil }
        try require(result == succeeds, store.errorMessage ?? "Unexpected settings result")
    }
    static func shutdown(_ store: LensStore) async throws {
        var ended: Bool?
        store.shutdown { ended = $0 }
        try await wait("actual engine exit") { ended != nil }
        try require(ended == true && !store.hasEngine, "Engine remained owned after cleanup")
    }
    static func run(_ resources: URL) async throws {
        let files = FileManager.default
        let root = files.temporaryDirectory.appendingPathComponent("lens-rule-save-" + UUID().uuidString)
        try files.createDirectory(at: root, withIntermediateDirectories: false)
        defer { try? files.removeItem(at: root) }
        let runner = SystemProxyRunner(read: { _ in throw SaveFailure(description: "Host access forbidden") }, authorize: { _ in throw SaveFailure(description: "Host mutation forbidden") })
        let system = SystemProxyController(dataDirectory: root.appendingPathComponent("system"), runner: runner)
        let store = LensStore(dataDirectory: root.appendingPathComponent("data"), resources: resources, systemProxy: system)
        let ports = root.appendingPathComponent("port.json"), probe = Process()
        probe.executableURL = resources.appendingPathComponent("python/bin/python3")
        probe.arguments = ["-c", "import socket,sys; from pathlib import Path; s=socket.socket(); s.bind(('127.0.0.1',0)); Path(sys.argv[1]).write_text(str(s.getsockname()[1])); s.close()", ports.path]
        try probe.run()
        try await wait("port allocator exit") { !probe.isRunning }
        try require(probe.terminationStatus == 0, "Port allocator failed")
        store.port = try String(contentsOf: ports, encoding: .utf8)
        store.rules = [ProxyRule(kind: "map_remote", value: "http://127.0.0.1:1/retained/")]
        try await apply(store)
        let rulesURL = store.dataDirectory.appendingPathComponent("rules.json")
        let preferencesURL = store.dataDirectory.appendingPathComponent("preferences.json")
        var draftOwner: LensStore?
        store.start()
        do {
            try await wait("real engine ready") { store.isRunning || (!store.isStarting && store.errorMessage != nil) }
            try require(store.isRunning, store.errorMessage ?? "Engine did not start")
            // Ready admits its own initial configure. Wait for the real command
            // barrier before pinning disk bytes; JSON key order is not identity.
            var fenced = false, fenceFailure: String?
            store.send("network_status", onError: { fenceFailure = $0 }) { _ in fenced = true }
            try await wait("startup configure barrier") { fenced || fenceFailure != nil }
            try require(fenceFailure == nil, fenceFailure ?? "Startup fence failed")
            let savedRules = try Data(contentsOf: rulesURL), savedPreferences = try Data(contentsOf: preferencesURL)
            store.rules[0].value = "http://mapped.invalid:abc/"
            store.sslHosts = "changed.invalid"
            try await apply(store, succeeds: false)
            try require(try Data(contentsOf: rulesURL) == savedRules, "Engine-rejected rules overwrote the saved valid rules")
            try require(try Data(contentsOf: preferencesURL) == savedPreferences, "Engine-rejected configure overwrote saved companion settings")
            let reopened = LensStore(dataDirectory: store.dataDirectory, resources: resources, systemProxy: system)
            try require(reopened.rules[0].value == "http://127.0.0.1:1/retained/" && reopened.sslHosts == "*", "Reopening picked up a rejected configuration")
            print("PASS: actual engine rejects invalid Map Remote without replacing either saved file; reopen retains valid settings")

            store.rules = reopened.rules
            var submitted = store.rules
            submitted[0].value = "http://mapped.invalid:abc/"
            var rejectedDraft: Bool?
            store.applyRules(submitted) { rejectedDraft = $0 }
            try await wait("rejected sheet-owned draft") { rejectedDraft != nil }
            try require(rejectedDraft == false && store.rules[0].value == reopened.rules[0].value, "Rejected local draft replaced the in-memory startup selection")
            submitted[0].value = "http://127.0.0.1:1/accepted-sheet/"
            var acceptedDraft: Bool?
            store.applyRules(submitted) { acceptedDraft = $0 }
            try await wait("accepted sheet-owned draft") { acceptedDraft != nil }
            try require(acceptedDraft == true && store.rules[0].value == submitted[0].value, "Accepted local draft was not published")
            print("PASS: sheet-owned draft publishes only after engine acceptance; rejected edit preserves in-memory startup rules")

            store.errorMessage = nil
            store.rules[0].value = "http://127.0.0.1:1/captured/"
            store.sslHosts = "first.invalid"
            var first: Bool?, duplicate: Bool?
            store.applyRules { first = $0 }
            // These edits happen before the main actor can receive the ack.
            store.rules[0].value = "http://127.0.0.1:1/draft/"
            store.sslHosts = "second.invalid"
            store.applyRules { duplicate = $0 }
            try require(duplicate == false, "Overlapping Save was admitted while an earlier snapshot was pending")
            try await wait("first captured snapshot") { first != nil }
            try require(first == true, store.errorMessage ?? "First Save failed")
            let captured = LensStore(dataDirectory: store.dataDirectory, resources: resources, systemProxy: system)
            try require(captured.rules[0].value == "http://127.0.0.1:1/captured/" && captured.sslHosts == "first.invalid", "Callback persisted later unsent UI edits")
            try require(store.rules[0].value == "http://127.0.0.1:1/draft/" && store.sslHosts == "second.invalid", "Save discarded later draft edits")
            print("PASS: one pending Save owns its exact rule/settings snapshot; overlapping Save rejects and later edits remain drafts")
            store.errorMessage = nil
            var retry: Bool?, nested: Bool?
            store.applyRules { success in
                retry = success
                store.rules[0].value = "http://127.0.0.1:1/callback/"
                store.applyRules { nested = $0 }
            }
            try await wait("save launched from completed-save callback") { nested != nil }
            try require(retry == true && nested == true, "Completion callback still held the previous Save admission")
            let retried = LensStore(dataDirectory: store.dataDirectory, resources: resources, systemProxy: system)
            try require(retried.rules[0].value == store.rules[0].value && retried.sslHosts == "second.invalid", "Retry did not persist the later draft")
            print("PASS: explicit retry and a new Save from its completion callback persist subsequent drafts")
            let beforeFailureRules = try Data(contentsOf: rulesURL), beforeFailurePreferences = try Data(contentsOf: preferencesURL)
            try files.setAttributes([.posixPermissions: 0o500], ofItemAtPath: store.dataDirectory.path)
            do {
                store.rules[0].value = "http://127.0.0.1:1/disk-retry/"
                try await apply(store, succeeds: false)
                try require(store.errorMessage?.contains("accepted these settings") == true, "Persistence failure hid the already-applied engine outcome")
                try require(try Data(contentsOf: rulesURL) == beforeFailureRules && Data(contentsOf: preferencesURL) == beforeFailurePreferences, "Unwritable directory changed saved files")
            } catch {
                try? files.setAttributes([.posixPermissions: 0o700], ofItemAtPath: store.dataDirectory.path)
                throw error
            }
            try files.setAttributes([.posixPermissions: 0o700], ofItemAtPath: store.dataDirectory.path)
            store.errorMessage = nil
            try await apply(store)
            let diskRetried = LensStore(dataDirectory: store.dataDirectory, resources: resources, systemProxy: system)
            try require(diskRetried.rules[0].value == "http://127.0.0.1:1/disk-retry/", "File failure left Save admission stuck or retry lost the selected settings")
            print("PASS: real file permission failure reports accepted-but-unsaved settings, preserves files and permits retry")
            try await shutdown(store)

            // Stopped settings are intentionally editable drafts, not proof of
            // successful capture startup. Existing range-repair behavior relies on this.
            store.rules[0].value = "http://mapped.invalid:abc/"
            try await apply(store)
            let draft = LensStore(dataDirectory: store.dataDirectory, resources: resources, systemProxy: system)
            draftOwner = draft
            try require(draft.rules[0].value == "http://mapped.invalid:abc/", "Stopped draft was silently normalized or discarded")
            draft.start()
            try await wait("invalid draft startup fails") { !draft.isStarting && !draft.hasEngine }
            try require(!draft.isRunning && draft.errorMessage != nil, "Invalid saved draft started capture")
            print("PASS: stopped draft survives reopening while real engine startup rejects invalid destinations")
        } catch {
            if let draftOwner { try await shutdown(draftOwner) }
            try await shutdown(store)
            throw error
        }
    }
}

@main private struct RuleSaveSmoke {
    static func main() async {
        do {
            guard CommandLine.arguments.count == 2 else { throw SaveFailure(description: "Pass app Resources path") }
            try await RuleSaveChecks.run(URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true))
        } catch { fputs("FAIL: \(error)\n", stderr); exit(1) }
    }
}
