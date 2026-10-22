import Foundation

private struct Failure: Error { let message: String }
private func require(_ value: @autoclosure () -> Bool, _ message: String) throws {
    if !value() { throw Failure(message: message) }
}

@main private enum LANAccessSmoke {
    @MainActor static func main() throws {
        let disabled = try LensLANAccess.configuration(enabled: false, address: "ignored")
        try require(disabled == nil, "Disabled access must stay disabled")
        let valid = try LensLANAccess.configuration(enabled: true, address: "192.168.2.250")!
        try require(valid.address == "192.168.2.250", "LAN requires no client registration")
        for host in ["0.0.0.0", "127.0.0.1", "8.8.8.8", "*", "192.168.2.0/24"] {
            try require(LensLANAccess.issue(enabled: true, address: host) != nil, "Unsafe/ambiguous bind accepted")
        }
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("lens-lan-prefs-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let original = try JSONSerialization.data(withJSONObject: ["lan_enabled": true, "lan_address": "192.168.2.250", "lan_clients": "192.168.2.10", "unrelated": "preserved"])
        let preferencesURL = directory.appendingPathComponent("preferences.json")
        try original.write(to: preferencesURL)
        let runner = SystemProxyRunner(read: { _ in throw Failure(message: "No host reads allowed") }, authorize: { _ in throw Failure(message: "No host writes allowed") })
        let system = SystemProxyController(dataDirectory: directory, runner: runner)
        let store = LensStore(dataDirectory: directory, resources: directory, systemProxy: system)
        try require(!store.lanEnabled && store.lanAddress == "192.168.2.250", "Reloading preferences must preserve the address but require opt-in again")
        var saved = false
        store.applyRules { saved = $0 }
        try require(saved, "Legacy LAN preferences could not be saved")
        let preferences = try JSONSerialization.jsonObject(with: Data(contentsOf: preferencesURL)) as! [String: Any]
        try require(preferences["lan_clients"] == nil && preferences["unrelated"] as? String == "preserved", "Remove only the obsolete client selection")
        let backups = try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil).filter { $0.lastPathComponent.hasPrefix("preferences-lan-access-recovery-") }
        try require(backups.count == 1, "Preserve the old preferences once")
        let recovered = try Data(contentsOf: backups[0])
        try require(recovered == original, "The migration backup changed the old preferences")
        let reopened = LensStore(dataDirectory: directory, resources: directory, systemProxy: system)
        reopened.applyRules { saved = $0 }
        let laterBackups = try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil).filter { $0.lastPathComponent.hasPrefix("preferences-lan-access-recovery-") }
        try require(saved && laterBackups == backups && !reopened.lanEnabled, "Migration must be idempotent and retain launch opt-in")
        print("PASS: LAN without client registration; legacy selection backed up and removed once; unrelated preferences preserved; no host proxy/trust access")
    }
}
