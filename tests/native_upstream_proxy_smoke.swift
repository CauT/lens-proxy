import Foundation

private struct Failure: Error { let reason: String }
@main struct UpstreamProxySmoke {
    @MainActor static func main() throws {
        let root = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        func require(_ condition: @autoclosure () -> Bool, _ reason: String) throws {
            if !condition() { throw Failure(reason: reason) }
        }
        for valid in ["", "http://127.0.0.1:7897", "http://[::1]:7897", "http://proxy.example:8080"] {
            try require(LensNetworkSettingsValidation.upstreamProxyIssue(valid) == nil, "Valid endpoint rejected: " + valid)
        }
        for invalid in ["http://a..b:80", "http://user:password@proxy:80", "http://proxy", "http://proxy:0", "https://proxy:443", "http://proxy:80/path", "http://proxy:80?", "http://proxy:80#", " http://proxy:80"] {
            try require(LensNetworkSettingsValidation.upstreamProxyIssue(invalid) != nil, "Invalid endpoint accepted")
        }
        let store = LensStore(dataDirectory: root, resources: root)
        var saved = false
        store.saveHTTPUpstreamProxy("http://127.0.0.1:7897") { saved = $0 }
        try require(saved && store.httpUpstreamProxy == "http://127.0.0.1:7897", "Valid selection was not saved")
        store.saveHTTPUpstreamProxy("http://user:password@proxy:80") { saved = $0 }
        try require(!saved && store.httpUpstreamProxy == "http://127.0.0.1:7897", "Rejected selection replaced accepted endpoint")
        try require(LensStore(dataDirectory: root, resources: root).httpUpstreamProxy == store.httpUpstreamProxy, "Selection did not survive new store")
        let preferences = root.appendingPathComponent("preferences.json")
        try FileManager.default.removeItem(at: preferences)
        try FileManager.default.createDirectory(at: preferences, withIntermediateDirectories: false)
        store.saveHTTPUpstreamProxy("") { saved = $0 }
        try require(!saved && store.httpUpstreamProxy == "http://127.0.0.1:7897", "Failed persistence lost previous selection")
        let recoveryRoot = root.appendingPathComponent("malformed", isDirectory: true)
        try FileManager.default.createDirectory(at: recoveryRoot, withIntermediateDirectories: true)
        let original = Data("{\"http_upstream_proxy\":42,\"unrelated\":\"preserved\"}".utf8)
        try original.write(to: recoveryRoot.appendingPathComponent("preferences.json"))
        let malformed = LensStore(dataDirectory: recoveryRoot, resources: root)
        try require(LensNetworkSettingsValidation.upstreamProxyIssue(malformed.httpUpstreamProxy) != nil, "Malformed setting silently became direct")
        malformed.saveHTTPUpstreamProxy("http://127.0.0.1:7897") { saved = $0 }
        try require(saved, "Malformed preference could not be repaired")
        let backup = try FileManager.default.contentsOfDirectory(at: recoveryRoot, includingPropertiesForKeys: nil).first { $0.lastPathComponent.hasPrefix("preferences-upstream-recovery-") }
        try require(backup != nil, "Original malformed preferences were not retained")
        let backupBytes = try Data(contentsOf: backup!)
        try require(backupBytes == original, "Recovery copy changed original bytes")
        let repaired = try JSONSerialization.jsonObject(with: Data(contentsOf: recoveryRoot.appendingPathComponent("preferences.json"))) as! [String: Any]
        try require(repaired["unrelated"] as? String == "preserved", "Unrelated preference field was lost")
        print("PASS: endpoint validation, accepted-state preservation, persistence failure, relaunch and exact malformed-preference recovery")
    }
}
