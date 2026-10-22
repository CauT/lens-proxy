// Synthetic only: no networksetup process, authorization prompt, or host settings mutation.
import Foundation

private func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
    if !condition() { throw SystemProxyError(message: message) }
}

private final class FixtureSystem {
    let service = "Wi-Fi's $(untrusted)"
    let original = SystemProxyEndpoint(enabled: false, server: "", port: 0, authenticated: false)
    let intended = SystemProxyEndpoint(enabled: true, server: "127.0.0.1", port: 8890, authenticated: false)
    var http: SystemProxyEndpoint
    var https: SystemProxyEndpoint
    var writes = 0
    var mode = "partial-apply"
    var primaryServiceOverride: String?
    init() { http = original; https = original }
    func text(_ endpoint: SystemProxyEndpoint) -> String {
        "Enabled: \(endpoint.enabled ? "Yes" : "No")\nServer: \(endpoint.server)\nPort: \(endpoint.port)\nAuthenticated Proxy Enabled: \(endpoint.authenticated ? 1 : 0)"
    }
    var runner: SystemProxyRunner {
        SystemProxyRunner(read: { args in
            switch args[0] {
            case "-listallnetworkservices": return "An asterisk (*) denotes that a network service is disabled.\nInactive Ethernet\n\(self.service)\n*Disabled"
            case "-getcurrentlocation": return "Automatic"
            case "-getwebproxy": return self.text(self.http)
            case "-getsecurewebproxy": return self.text(self.https)
            case "-getautoproxyurl": return "URL: http://example.com/a:b\nEnabled: No"
            case "-getproxyautodiscovery": return "Auto Proxy Discovery: Off"
            default: throw SystemProxyError(message: "Unexpected fixture command")
            }
        }, authorize: { script in
            self.writes += 1
            try require(script.contains("'Wi-Fi'\\''s $(untrusted)'"), "Service was not correctly shell quoted")
            if self.mode == "partial-apply" {
                self.http = self.intended
                throw SystemProxyError(message: "Simulated interruption after HTTP apply")
            } else if self.mode == "restore" {
                try require(!script.contains("'-setsecurewebproxy'"), "Unchanged HTTPS endpoint should not be mutated")
                self.http = self.original
            } else if self.mode == "apply-both" {
                self.http = self.intended; self.https = self.intended
            } else if self.mode == "restore-both" {
                self.http = self.original; self.https = self.original
            } else { throw SystemProxyError(message: "Unexpected mutation during read/conflict test") }
        }, primaryService: { self.primaryServiceOverride ?? self.service })
    }
}

@main
private struct SystemProxySmoke {
    @MainActor static func wait(_ controller: SystemProxyController) async throws {
        for _ in 0..<500 {
            if !controller.isBusy { return }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        throw SystemProxyError(message: "Fixture operation did not finish")
    }

    @MainActor static func main() async throws {
        let fixture = FixtureSystem()
        let operations = SystemProxyOperations(runner: fixture.runner)
        let initial = try operations.snapshot(service: fixture.service)
        try require(initial.http == fixture.original && !initial.pacEnabled && !initial.discoveryEnabled, "Snapshot parsing lost facts")
        let services = try SystemProxySnapshot.services(fixture.runner.read(["-listallnetworkservices"]))
        try require(services == ["Inactive Ethernet", fixture.service], "Disabled service parsing failed")
        do { _ = try SystemProxySnapshot.services("AuthorizationCreate() failed: -60008"); throw SystemProxyError(message: "Authorization error was treated as a service") }
        catch { try require(error.localizedDescription.contains("Unable to list"), "Unexpected service error") }
        do { _ = try SystemProxyEndpoint.parse("Enabled: Yes\nServer: x\nPort: 80"); throw SystemProxyError(message: "Missing auth state was accepted") }
        catch { try require(error.localizedDescription.contains("Cannot determine"), "Unexpected endpoint error") }
        let authenticated = try SystemProxyEndpoint.parse("Enabled: No\nServer: x\nPort: 80\nAuthenticated Proxy Enabled: 1")
        let authSnapshot = SystemProxySnapshot(service: initial.service, location: initial.location, http: authenticated, https: initial.https, pacEnabled: false, discoveryEnabled: false, rawHTTP: initial.rawHTTP, rawHTTPS: initial.rawHTTPS, rawPAC: initial.rawPAC, rawDiscovery: initial.rawDiscovery)
        try require(authSnapshot.automaticConfigurationIssue != nil, "Authenticated endpoint was accepted")
        let pacSnapshot = SystemProxySnapshot(service: initial.service, location: initial.location, http: initial.http, https: initial.https, pacEnabled: true, discoveryEnabled: false, rawHTTP: initial.rawHTTP, rawHTTPS: initial.rawHTTPS, rawPAC: initial.rawPAC, rawDiscovery: initial.rawDiscovery)
        try require(pacSnapshot.automaticConfigurationIssue != nil, "Enabled PAC was accepted")

        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("lens-system-proxy-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        let controller = SystemProxyController(dataDirectory: directory, runner: fixture.runner)
        controller.selectedService = fixture.service
        controller.refresh()
        try await wait(controller)
        try require(fixture.writes == 0, "Read-only refresh requested authorization")
        controller.useLens(port: 8890)
        try await wait(controller)
        try require(controller.hasBackup && controller.error != nil && fixture.http == fixture.intended, "Partial apply did not retain recoverable ownership")
        try require(FileManager.default.fileExists(atPath: controller.backupURL.path), "Recovery was not persisted before apply")
        // A new controller simulates recovery after the app crashes.
        let recovered = SystemProxyController(dataDirectory: directory, runner: fixture.runner)
        fixture.mode = "restore"
        recovered.restore()
        try await wait(recovered)
        try require(!recovered.hasBackup && fixture.http == fixture.original && fixture.https == fixture.original, "Crash/partial-apply restoration failed")
        try require(!FileManager.default.fileExists(atPath: recovered.backupURL.path), "Verified recovery record was not removed")

        fixture.mode = "partial-apply"
        recovered.selectedService = fixture.service
        recovered.useLens(port: 8890)
        try await wait(recovered)
        let backup = try JSONDecoder().decode(SystemProxyBackup.self, from: Data(contentsOf: recovered.backupURL))
        fixture.http = SystemProxyEndpoint(enabled: true, server: "user.example", port: 8123, authenticated: false)
        let writesBefore = fixture.writes
        recovered.restore()
        try await wait(recovered)
        try require(fixture.writes == writesBefore && recovered.hasBackup, "External changes were overwritten or recovery discarded")
        let conflict = try SystemProxyOperations.restorePlan(backup, current: operations.snapshot(service: fixture.service))
        try require(conflict.script == nil && conflict.conflicts == ["HTTP"], "Ownership conflict plan is incorrect")
        // Resume an interrupted restoration between the endpoint and its disabled flag.
        var restoring = backup
        restoring.restoreStarted = true
        fixture.http = SystemProxyEndpoint(enabled: true, server: "", port: 0, authenticated: false)
        let retry = try SystemProxyOperations.restorePlan(restoring, current: operations.snapshot(service: fixture.service))
        try require(retry.script?.contains("'-setwebproxystate'") == true && retry.conflicts.isEmpty, "Partial restoration was not retryable")
        print("PASS: proxy parsing, shell quoting, read-only refresh, partial apply, persistent crash recovery, external ownership conflict, restoration retry")

        let autoDirectory = directory.appendingPathComponent("automatic")
        let automatic = FixtureSystem(); automatic.mode = "apply-both"
        let setup = SystemProxyController(dataDirectory: autoDirectory, runner: automatic.runner)
        try require(!setup.hasCaptureChoice && setup.launchSelection == nil, "Fresh profile silently opted into host configuration")
        setup.refresh(); try await wait(setup)
        try require(setup.selectedService == automatic.service && setup.services.first == "Inactive Ethernet", "Default service followed list order instead of the active network")
        setup.useLens(port: 8890); try await wait(setup)
        try require(setup.error == nil && setup.hasCaptureChoice && setup.launchSelection != nil, "Verified explicit setup did not save launch choice")
        automatic.mode = "restore-both"
        setup.restore(); try await wait(setup)
        try require(!setup.hasBackup && setup.launchSelection != nil, "Stop restoration discarded the opt-in")
        let relaunch = SystemProxyController(dataDirectory: autoDirectory, runner: automatic.runner)
        automatic.mode = "apply-both"
        let beforeReconnect = automatic.writes
        relaunch.refresh()
        relaunch.connectAfterStart(port: 8890); try await wait(relaunch)
        try require(automatic.writes == beforeReconnect + 1 && relaunch.hasBackup && relaunch.error == nil, "Identical previous settings did not reconnect")
        let crash = SystemProxyController(dataDirectory: autoDirectory, runner: automatic.runner)
        let beforeCrash = automatic.writes
        crash.connectAfterStart(port: 8890); try await wait(crash)
        try require(automatic.writes == beforeCrash && crash.error != nil && crash.hasBackup, "Crash recovery was overwritten by automatic startup")
        automatic.mode = "restore-both"
        relaunch.restore(); try await wait(relaunch)
        let exited = SystemProxyController(dataDirectory: autoDirectory, runner: automatic.runner)
        let beforeExited = automatic.writes
        var listenerReady = true
        exited.refresh()
        exited.connectAfterStart(port: 8890, isReady: { listenerReady })
        listenerReady = false
        try await wait(exited)
        try require(automatic.writes == beforeExited && !exited.hasBackup, "Queued reconnection ignored listener exit")
        automatic.primaryServiceOverride = "Inactive Ethernet"
        relaunch.connectAfterStart(port: 8890); try await wait(relaunch)
        try require(automatic.writes == beforeExited && relaunch.error?.contains("active network service") == true, "Reconnection ignored a changed active network service")
        automatic.primaryServiceOverride = nil
        automatic.http = SystemProxyEndpoint(enabled: true, server: "changed.example", port: 7897, authenticated: false)
        let beforeChange = automatic.writes
        relaunch.connectAfterStart(port: 8890); try await wait(relaunch)
        try require(automatic.writes == beforeChange && !relaunch.hasBackup && relaunch.error?.contains("changed") == true, "Changed previous settings were automatically replaced")
        relaunch.chooseManualClients()
        let manual = SystemProxyController(dataDirectory: autoDirectory, runner: automatic.runner)
        manual.connectAfterStart(port: 8890); try await wait(manual)
        try require(manual.hasCaptureChoice && manual.launchSelection == nil && !manual.rememberOnLaunch && automatic.writes == beforeChange, "Manual selection was lost or mutated the host")
        try require(SystemProxyRouting(http: automatic.intended, https: automatic.original).usesLens(port: 8890) == false, "Partial system routing was labelled connected")
        try require(SystemProxyRouting(http: automatic.intended, https: automatic.intended).usesLens(port: 8890), "Complete system routing was not recognized")
        let preferenceFile = autoDirectory.appendingPathComponent("mac-capture-preferences.json")
        try Data("{malformed".utf8).write(to: preferenceFile)
        let malformed = SystemProxyController(dataDirectory: autoDirectory, runner: automatic.runner)
        malformed.connectAfterStart(port: 8890); try await wait(malformed)
        try require(automatic.writes == beforeChange && malformed.error != nil && !malformed.hasCaptureChoice, "Malformed preference silently changed configuration")
        malformed.chooseManualClients()
        let recoveries = try FileManager.default.contentsOfDirectory(at: autoDirectory, includingPropertiesForKeys: nil).filter { $0.lastPathComponent.hasPrefix("mac-capture-preferences-recovery-") }
        try require(recoveries.count == 1, "Malformed preference recovery copy is missing")
        let recoveredPreference = try Data(contentsOf: recoveries[0])
        try require(String(decoding: recoveredPreference, as: UTF8.self) == "{malformed", "Malformed preference was not preserved before replacement")
        print("PASS: active-service default and change refusal, explicit opt-in, queued relaunch after refresh, queued listener-exit refusal, exact-baseline refusal, crash recovery admission, manual mode, routing classification, malformed preference recovery")
    }
}
