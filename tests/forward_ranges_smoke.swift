// Compile with production Models, LensStore and shared native settings sources.
// This lane exercises saved selections and launch contracts without host network mutation.
import Foundation

private struct Failure: Error { let message: String }
private func require(_ value: @autoclosure () throws -> Bool, _ message: String) throws {
    if try !value() { throw Failure(message: message) }
}
private func listenerIssue(_ tcp: [TCPForwardSelection] = [], _ udp: [UDPForwardSelection] = [], http: String = "8890", socks: String = "0", reverse: String = "0", reverseURL: String = "") -> String? {
    LensNetworkSettingsValidation.listenerIssue(httpPort: http, socksPort: socks, reversePort: reverse, reverseURL: reverseURL, tcpForwards: tcp, udpForwards: udp)
}

@main private enum ForwardRangesSmoke {
    @MainActor static func main() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("lens-forward-range-prefs-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let legacyID = UUID()
        let legacy: [String: Any] = ["id": legacyID.uuidString, "listenPort": "19000", "targetHost": "127.0.0.1", "targetPort": "29000"]
        try JSONSerialization.data(withJSONObject: ["tcp_forwards": [legacy], "udp_forwards": [legacy]])
            .write(to: directory.appendingPathComponent("preferences.json"))
        let system = SystemProxyController(dataDirectory: directory.appendingPathComponent("system"), runner: SystemProxyRunner(
            read: { _ in throw Failure(message: "Unexpected host read") }, authorize: { _ in throw Failure(message: "Unexpected host mutation") }))
        let store = LensStore(dataDirectory: directory, resources: directory, systemProxy: system)
        try require(store.tcpForwards.count == 1 && store.udpForwards.count == 1, "Legacy saved forwards were lost")
        try require(store.tcpForwards[0].listenPortEnd == nil && store.udpForwards[0].listenPortEnd == nil, "Legacy single port acquired a range")
        let single = try store.tcpForwards[0].commandValue()
        try require(single.count == 3 && single["listen_port_end"] == nil && single["listen_port"] as? Int == 19000, "Legacy wire contract changed")
        try require(listenerIssue(store.tcpForwards, store.udpForwards) == nil, "TCP and UDP must retain separate listener namespaces")
        print("PASS: actual Store loads legacy TCP/UDP preferences and preserves the single-port launch contract")

        store.tcpForwards[0].listenPortEnd = "19002"
        store.udpForwards[0].listenPortEnd = "19002"
        var saved: Bool?
        store.applyRules { saved = $0 }
        try require(saved == true && !store.hasEngine, "Saving ranges unexpectedly requires an engine")
        let reopened = LensStore(dataDirectory: directory, resources: directory, systemProxy: system)
        try require(reopened.tcpForwards[0].id == legacyID && reopened.tcpForwards[0].listenPortEnd == "19002" && reopened.udpForwards[0].listenPortEnd == "19002", "Saved range or selection identity changed across Store reload")
        let wire = try reopened.tcpForwards[0].commandValue()
        try require(wire["listen_port_end"] as? Int == 19002 && wire["target_port"] as? Int == 29000, "Native launch omitted the selected range or changed its target base")
        try require(listenerIssue(reopened.tcpForwards, reopened.udpForwards) == nil, "Matching TCP/UDP ranges must coexist")
        print("PASS: actual Store saves and reloads ranges; selected end and target base reach launch JSON")

        let tcp = reopened.tcpForwards
        try require(listenerIssue(tcp, http: "19001") != nil, "HTTP conflict inside range was ignored")
        try require(listenerIssue(tcp, socks: "19002") != nil, "SOCKS conflict at range end was ignored")
        try require(listenerIssue(tcp, reverse: "19000", reverseURL: "http://localhost") != nil, "Reverse listener conflict at range start was ignored")
        try require(listenerIssue(tcp + [TCPForwardSelection(listenPort: "19002", targetHost: "::1", targetPort: "40000")]) != nil, "Overlapping TCP endpoint was accepted")
        try require(listenerIssue([], reopened.udpForwards + [UDPForwardSelection(listenPort: "19001", listenPortEnd: "19003", targetHost: "localhost", targetPort: "40000")]) != nil, "Overlapping UDP ranges were accepted")
        try require(listenerIssue(tcp + [TCPForwardSelection(listenPort: "19003", targetHost: "::1", targetPort: "40000")]) == nil, "Adjacent nonoverlapping TCP endpoints were rejected")
        print("PASS: all interior and boundary listener collisions are rejected; adjacent ranges and transport separation work")

        let full = TCPForwardSelection(listenPort: "20000", listenPortEnd: "20031", targetHost: "::1", targetPort: "65504")
        try require(listenerIssue([full]) == nil && ForwardEndpointValidation.configuredPortCount([full]) == 32, "Exact 32-port boundary rejected")
        try require(listenerIssue([full, TCPForwardSelection(listenPort: "21000", targetHost: "localhost", targetPort: "30000")]) != nil, "A second row bypassed total TCP capacity")
        let udpFull = UDPForwardSelection(listenPort: "20000", listenPortEnd: "20031", targetHost: "::1", targetPort: "65504")
        try require(listenerIssue([], [udpFull]) == nil, "Exact 32 UDP ports rejected")
        try require(listenerIssue([], [udpFull, UDPForwardSelection(listenPort: "21000", targetHost: "localhost", targetPort: "30000")]) != nil, "A second row bypassed total UDP capacity")
        let twoRanges = [TCPForwardSelection(listenPort: "22000", listenPortEnd: "22015", targetHost: "localhost", targetPort: "32000"), TCPForwardSelection(listenPort: "23000", listenPortEnd: "23015", targetHost: "localhost", targetPort: "33000")]
        try require(listenerIssue(twoRanges) == nil, "Capacity was mistaken for row count")
        print("PASS: total capacity counts listening ports across rows; remote offset ending at 65535 is valid")

        for end in ["18999", "65536", "true", "1.5", "999999999999999999999999999", "20032"] {
            let selection = TCPForwardSelection(listenPort: "20000", listenPortEnd: end, targetHost: "localhost", targetPort: "30000")
            try require(selection.issue != nil && listenerIssue([selection]) != nil, "Invalid range end silently became a single port: " + end)
            do { _ = try selection.commandValue(); throw Failure(message: "Invalid range emitted a command") }
            catch is ForwardEndpointFailure { }
        }
        try require(TCPForwardSelection(listenPort: "20000", listenPortEnd: "20001", targetHost: "localhost", targetPort: "65535").issue != nil, "Target range overflow accepted")
        try require(TCPForwardSelection(listenPort: "1023", targetHost: "localhost", targetPort: "1").issue != nil, "Native privileged local port accepted")
        let equal = try TCPForwardSelection(listenPort: "65535", listenPortEnd: "65535", targetHost: "localhost", targetPort: "65535").commandValue()
        try require(equal["listen_port_end"] as? Int == 65535, "Explicit one-port range lost its selected end")
        let blank = try TCPForwardSelection(listenPort: "20000", listenPortEnd: "", targetHost: "localhost", targetPort: "1").commandValue()
        try require(blank["listen_port_end"] == nil, "Blank optional range must retain legacy single-port semantics")
        var malformed = legacy; malformed["listenPortEnd"] = true
        do {
            _ = try JSONDecoder().decode(TCPForwardSelection.self, from: JSONSerialization.data(withJSONObject: malformed))
            throw Failure(message: "Boolean preference end became a port")
        } catch is DecodingError { }
        print("PASS: invalid end inputs fail closed; target overflow and privileged local start rejected; blank and explicit equal ends preserved")

        reopened.tcpForwards[0].listenPortEnd = "not-a-port"
        var invalidSaved: Bool?
        reopened.applyRules { invalidSaved = $0 }
        try require(invalidSaved == true, "Invalid draft selection could not be retained for repair")
        let invalidReopened = LensStore(dataDirectory: directory, resources: directory, systemProxy: system)
        try require(invalidReopened.tcpForwards.count == 1 && invalidReopened.tcpForwards[0].listenPortEnd == "not-a-port", "Invalid saved range silently became nil or disappeared")
        invalidReopened.start()
        try require(invalidReopened.errorMessage != nil && !invalidReopened.hasEngine && !invalidReopened.isRunning, "Invalid saved range launched an engine or silently used one port")
        print("PASS: invalid string selection survives save/reload for repair; native Start refuses it before launching an engine")

        let malformedDirectory = directory.appendingPathComponent("malformed-arrays")
        try FileManager.default.createDirectory(at: malformedDirectory, withIntermediateDirectories: false)
        var boolEnd = legacy; boolEnd["listenPortEnd"] = true
        let rawForwards: [Any] = [legacy, boolEnd]
        let original = try JSONSerialization.data(withJSONObject: ["tcp_forwards": rawForwards, "udp_forwards": rawForwards], options: [.prettyPrinted, .sortedKeys]) + Data([10])
        let path = malformedDirectory.appendingPathComponent("preferences.json")
        try original.write(to: path)
        let malformedStore = LensStore(dataDirectory: malformedDirectory, resources: directory, systemProxy: system)
        try require(malformedStore.forwardingPreferencesIssue != nil && malformedStore.errorMessage == malformedStore.forwardingPreferencesIssue, "Malformed arrays were silently treated as empty selections")
        try require(malformedStore.tcpForwardingPreferencesIssue != nil && malformedStore.udpForwardingPreferencesIssue != nil, "Malformed selections need per-sheet repair warnings")
        // Admission must depend on the owning saved-value state, not a dismissible alert.
        malformedStore.errorMessage = nil
        malformedStore.start()
        try require(!malformedStore.hasEngine && malformedStore.errorMessage == malformedStore.forwardingPreferencesIssue, "Dismissing the alert allowed malformed saved settings to start")
        malformedStore.sslHosts = "example.invalid"
        var unrelatedSaved: Bool?
        malformedStore.applyRules { unrelatedSaved = $0 }
        try require(unrelatedSaved == true, "An unrelated save should preserve the unreadable forwarding fields")
        func canonical(_ value: Any) throws -> Data { try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys, .fragmentsAllowed]) }
        var after = try JSONSerialization.jsonObject(with: Data(contentsOf: path)) as! [String: Any]
        try require(canonical(after["tcp_forwards"]!) == canonical(rawForwards) && canonical(after["udp_forwards"]!) == canonical(rawForwards), "Unrelated save lost malformed end or valid sibling selections")
        func recoveries(_ directory: URL) throws -> [URL] {
            try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil).filter { $0.lastPathComponent.hasPrefix("preferences-forwarding-recovery-") }
        }
        var backups = try recoveries(malformedDirectory)
        try require(backups.count == 1 && Data(contentsOf: backups[0]) == original, "Recovery did not retain the original complete preference bytes")
        malformedStore.applyRules()
        try require(recoveries(malformedDirectory).count == 1, "Repeated unrelated save created duplicate recovery backups")
        let malformedReloaded = LensStore(dataDirectory: malformedDirectory, resources: directory, systemProxy: system)
        try require(malformedReloaded.forwardingPreferencesIssue != nil, "Unrelated save or reload cleared the unresolved saved state")
        malformedReloaded.tcpForwards = [TCPForwardSelection(listenPort: "24000", listenPortEnd: "24002", targetHost: "localhost", targetPort: "34000")]
        try require(malformedReloaded.forwardingPreferencesIssue?.contains("UDP") == true && malformedReloaded.forwardingPreferencesIssue?.contains("TCP") == false, "TCP repair incorrectly resolved the UDP saved state")
        try require(malformedReloaded.tcpForwardingPreferencesIssue == nil && malformedReloaded.udpForwardingPreferencesIssue != nil, "Per-sheet repair warnings did not track their own saved values")
        malformedReloaded.applyRules()
        after = try JSONSerialization.jsonObject(with: Data(contentsOf: path)) as! [String: Any]
        try require(canonical(after["udp_forwards"]!) == canonical(rawForwards), "Saving repaired TCP selections overwrote unreadable UDP selections")
        try require((after["tcp_forwards"] as? [[String: Any]])?.first?["listenPortEnd"] as? String == "24002", "TCP repair did not persist its selected range")
        malformedReloaded.udpForwards = []
        try require(malformedReloaded.forwardingPreferencesIssue == nil, "Explicitly saving empty UDP selection did not resolve UDP state")
        malformedReloaded.applyRules()
        let repaired = LensStore(dataDirectory: malformedDirectory, resources: directory, systemProxy: system)
        try require(repaired.forwardingPreferencesIssue == nil && repaired.tcpForwards.first?.listenPortEnd == "24002" && repaired.udpForwards.isEmpty, "Explicit per-transport repairs did not survive reload")
        // A new Store owner may create a second recovery of the still-unreadable saved file,
        // but no backup can overwrite the first owner's original complete bytes.
        backups = try recoveries(malformedDirectory)
        try require(backups.contains { (try? Data(contentsOf: $0)) == original }, "Later repair overwrote the original recovery")
        print("PASS: malformed bool range plus valid siblings survive unrelated Save/reload; admission remains closed; TCP/UDP repairs are independent and original bytes recoverable")

        let malformedValues: [Any] = [NSNull(), true, "not-an-array", ["unexpected": "object"]]
        for (index, raw) in malformedValues.enumerated() {
            let scalarDirectory = directory.appendingPathComponent("malformed-scalar-" + String(index))
            try FileManager.default.createDirectory(at: scalarDirectory, withIntermediateDirectories: false)
            let scalarPath = scalarDirectory.appendingPathComponent("preferences.json")
            let scalarOriginal = try JSONSerialization.data(withJSONObject: ["tcp_forwards": raw])
            try scalarOriginal.write(to: scalarPath)
            let scalarStore = LensStore(dataDirectory: scalarDirectory, resources: directory, systemProxy: system)
            try require(scalarStore.forwardingPreferencesIssue != nil, "Present malformed scalar was mistaken for a missing preference")
            scalarStore.applyRules()
            let persisted = try JSONSerialization.jsonObject(with: Data(contentsOf: scalarPath)) as! [String: Any]
            try require(canonical(persisted["tcp_forwards"]!) == canonical(raw), "Saving changed a malformed scalar forwarding field")
            let scalarBackups = try recoveries(scalarDirectory)
            try require(scalarBackups.count == 1 && Data(contentsOf: scalarBackups[0]) == scalarOriginal, "Malformed scalar recovery lost original bytes")
            scalarStore.tcpForwards = []
            scalarStore.applyRules()
            try require(scalarStore.forwardingPreferencesIssue == nil && recoveries(scalarDirectory).count == 1, "Explicit scalar repair did not resolve only its transport or duplicated recovery")
        }
        print("PASS: null, boolean, string and object forwarding values remain owned malformed data, survive unrelated Save and allow explicit empty repair")

        do {
            let backupFailureDirectory = directory.appendingPathComponent("backup-write-failure")
            try FileManager.default.createDirectory(at: backupFailureDirectory, withIntermediateDirectories: false)
            let backupFailurePath = backupFailureDirectory.appendingPathComponent("preferences.json")
            let protectedOriginal = try JSONSerialization.data(withJSONObject: ["tcp_forwards": rawForwards], options: [.prettyPrinted, .sortedKeys]) + Data([10])
            try protectedOriginal.write(to: backupFailurePath)
            let protectedStore = LensStore(dataDirectory: backupFailureDirectory, resources: directory, systemProxy: system)
            let attributes = try FileManager.default.attributesOfItem(atPath: backupFailureDirectory.path)
            let originalPermissions = attributes[.posixPermissions]!
            defer { try? FileManager.default.setAttributes([.posixPermissions: originalPermissions], ofItemAtPath: backupFailureDirectory.path) }
            try FileManager.default.setAttributes([.posixPermissions: 0o500], ofItemAtPath: backupFailureDirectory.path)
            var failedSave: Bool?
            protectedStore.sslHosts = "unrelated.invalid"
            protectedStore.applyRules { failedSave = $0 }
            try require(failedSave == false && protectedStore.errorMessage != nil, "Read-only directory did not reject the first recovery backup")
            try require(Data(contentsOf: backupFailurePath) == protectedOriginal && recoveries(backupFailureDirectory).isEmpty, "Failed recovery write changed source bytes or left a purported recovery")
            try require(protectedStore.forwardingPreferencesIssue != nil, "Failed recovery write cleared the owned malformed selection")
            protectedStore.errorMessage = nil
            protectedStore.start()
            try require(!protectedStore.hasEngine && protectedStore.errorMessage == protectedStore.forwardingPreferencesIssue, "Failed recovery write allowed malformed selections to start")
            try FileManager.default.setAttributes([.posixPermissions: originalPermissions], ofItemAtPath: backupFailureDirectory.path)
            var retriedSave: Bool?
            protectedStore.applyRules { retriedSave = $0 }
            let retriedBackups = try recoveries(backupFailureDirectory)
            try require(retriedSave == true && retriedBackups.count == 1 && Data(contentsOf: retriedBackups[0]) == protectedOriginal, "Restoring directory permissions did not retry the pending original recovery")
            let retried = try JSONSerialization.jsonObject(with: Data(contentsOf: backupFailurePath)) as! [String: Any]
            try require(canonical(retried["tcp_forwards"]!) == canonical(rawForwards) && protectedStore.forwardingPreferencesIssue != nil, "Successful retry lost the unreadable source selection")
            print("PASS: real recovery write permission failure leaves source bytes and admission intact; permission restoration retries the original backup successfully")
        }
    }
}
