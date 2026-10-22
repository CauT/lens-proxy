// Real packaged engine startup/exit; injected proxy runner never changes the host.
import AppKit
import Foundation

private struct StartupFailure: Error { let message: String }
private final class DelayedProxy {
    let lock = NSLock(), release = DispatchSemaphore(value: 0)
    let original = SystemProxyEndpoint(enabled: false, server: "", port: 0, authenticated: false)
    let intended: SystemProxyEndpoint
    private var http: SystemProxyEndpoint
    private var https: SystemProxyEndpoint
    private var writes = 0
    private var entered = false
    init(port: Int) {
        intended = .init(enabled: true, server: "127.0.0.1", port: port, authenticated: false)
        http = original; https = original
    }
    func facts() -> (Bool, Int, Bool) {
        lock.lock(); defer { lock.unlock() }
        return (entered, writes, http == original && https == original)
    }
    func text(_ endpoint: SystemProxyEndpoint) -> String {
        "Enabled: \(endpoint.enabled ? "Yes" : "No")\nServer: \(endpoint.server)\nPort: \(endpoint.port)\nAuthenticated Proxy Enabled: 0"
    }
    var runner: SystemProxyRunner {
        .init(read: { args in
            self.lock.lock(); defer { self.lock.unlock() }
            switch args[0] {
            case "-listallnetworkservices": return "An asterisk (*) denotes that a network service is disabled.\nFixture"
            case "-getcurrentlocation": return "Automatic"
            case "-getwebproxy": return self.text(self.http)
            case "-getsecurewebproxy": return self.text(self.https)
            case "-getautoproxyurl": return "URL: (null)\nEnabled: No"
            case "-getproxyautodiscovery": return "Auto Proxy Discovery: Off"
            default: throw StartupFailure(message: "Unexpected fixture read")
            }
        }, authorize: { _ in
            self.lock.lock(); self.writes += 1; let applying = self.writes == 1
            if applying { self.entered = true }
            self.lock.unlock()
            if applying, self.release.wait(timeout: .now() + 15) != .success {
                throw StartupFailure(message: "Delayed authorization was not released")
            }
            self.lock.lock(); defer { self.lock.unlock() }
            self.http = applying ? self.intended : self.original
            self.https = applying ? self.intended : self.original
        }, primaryService: { "Fixture" })
    }
}

@MainActor private enum StartupChecks {
    static func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
        if !condition() { throw StartupFailure(message: message) }
    }
    static func wait(_ label: String, _ condition: () -> Bool) async throws {
        let deadline = Date().addingTimeInterval(25)
        while !condition() {
            if Date() > deadline { throw StartupFailure(message: "Timed out: " + label) }
            try await Task.sleep(nanoseconds: 15_000_000)
        }
    }
    static func run(resources: URL, port: Int) async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("lens-startup-store-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let fixture = DelayedProxy(port: port)
        defer { fixture.release.signal() }
        let controller = SystemProxyController(dataDirectory: root, runner: fixture.runner)
        let store = LensStore(dataDirectory: root, resources: resources, systemProxy: controller)
        var collision: LensStore?
        store.port = String(port)
        store.openWorkspace(); store.openWorkspace()
        do {
            try await wait("normal workspace starts listener and completes read-only setup") { store.isRunning && !controller.isBusy }
            try require(fixture.facts().1 == 0 && !controller.hasCaptureChoice, "Fresh launch changed proxy settings without explicit setup")
            print("PASS normal workspace auto-start is idempotent; fresh setup only reads proxy settings")
            let collisionRoot = root.appendingPathComponent("collision")
            let second = LensStore(dataDirectory: collisionRoot, resources: resources, systemProxy: SystemProxyController(dataDirectory: collisionRoot, runner: fixture.runner))
            collision = second
            second.port = String(port); second.openWorkspace()
            try await wait("occupied port fails with actionable startup state") { !second.hasEngine && second.startupIssue != nil }
            try require(second.startupIssue?.isCaptureSetup == true && second.startupIssue?.message.contains("Connection") == true && second.startupIssue?.message.contains("port conflicts") == true && fixture.facts().1 == 0, "Occupied port failed silently or changed proxy settings")
            print("PASS occupied port retains an actionable startup error without host writes")
            controller.selectedService = "Fixture"
            store.connectMacCapture()
            try await wait("authorization is held") { fixture.facts().0 }
            var stopped: Bool?
            store.stop { stopped = $0 }
            try require(stopped == false && store.isRunning, "Stop raced an in-progress proxy transaction")
            store.send("shutdown")
            try await wait("actual owned engine exits during authorization") { !store.hasEngine }
            fixture.release.signal()
            try await wait("late apply is restored after engine exit") { !controller.isBusy && !controller.hasBackup && fixture.facts().1 == 2 }
            try require(fixture.facts().2, "Late authorization left routing pointed at an exited listener")
            print("PASS Stop refuses in-flight apply; actual engine exit before late apply triggers verified restoration")
        } catch {
            fixture.release.signal()
            try? await wait("proxy transaction cleanup") { !controller.isBusy }
            for owned in [collision, store].compactMap({ $0 }) where owned.hasEngine {
                var done: Bool?; owned.shutdown { done = $0 }
                try? await wait("owned engine cleanup") { done != nil }
            }
            throw error
        }
    }
}

@main @MainActor private struct StartupStoreSmoke {
    static func main() {
        setbuf(stdout, nil)
        guard CommandLine.arguments.count == 3, let port = Int(CommandLine.arguments[2]) else { exit(2) }
        var done = false, failure: Error?
        Task { @MainActor in
            do { try await StartupChecks.run(resources: URL(fileURLWithPath: CommandLine.arguments[1]), port: port) }
            catch { failure = error }
            done = true
        }
        while !done { _ = RunLoop.main.run(mode: .default, before: Date().addingTimeInterval(0.05)) }
        if let failure { fputs("FAIL: \(failure)\n", stderr); exit(1) }
    }
}
