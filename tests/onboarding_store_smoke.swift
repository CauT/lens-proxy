@testable import LensNative
import AppKit
import Foundation
import Combine

private struct GuideFailure: Error { let message: String }

@MainActor private enum Checks {
    static func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
        if !condition() { throw GuideFailure(message: message) }
    }
    static func wait(_ name: String, _ condition: () -> Bool) async throws {
        let deadline = Date().addingTimeInterval(30)
        while !condition() {
            if Date() > deadline { throw GuideFailure(message: "Timeout: " + name) }
            try await Task.sleep(nanoseconds: 20_000_000)
        }
    }
    static func request(_ url: String, proxy: String, ca: String? = nil) throws -> Data {
        let process = Process(), output = Pipe(), error = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/curl")
        process.arguments = ["--silent", "--show-error", "--fail", "--max-time", "10", "--noproxy", "", "--proxy", proxy]
        if let ca { process.arguments! += ["--cacert", ca] }
        process.arguments!.append(url)
        process.standardOutput = output; process.standardError = error
        try process.run()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        try require(process.terminationStatus == 0, "Client failed: " + String(decoding: error.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self))
        return data
    }
}

@main private enum OnboardingSmoke {
    @MainActor static func main() async throws {
        let arguments = CommandLine.arguments
        guard arguments.count == 6 else { throw GuideFailure(message: "Pass resources, LAN IPv4, port, test upstream CA and HTTPS URL") }
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("lens-onboarding-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let runner = SystemProxyRunner(read: { _ in throw GuideFailure(message: "Host read forbidden") }, authorize: { _ in throw GuideFailure(message: "Host write forbidden") })
        let system = SystemProxyController(dataDirectory: directory, runner: runner)
        let store = LensStore(dataDirectory: directory, resources: URL(fileURLWithPath: arguments[1]), systemProxy: system)
        let setup = LensDeviceSetup(store: store)
        let guideOpenedAt = Date().timeIntervalSince1970
        store.port = arguments[3]; store.upstreamCA = arguments[4]
        var failure: Error?
        do {
            store.openWorkspace()
            try await Checks.wait("initial loopback Ready") { store.isRunning || store.errorMessage != nil }
            try Checks.require(store.isRunning && store.activeLANAddress == nil, "Loopback must not claim device readiness")
            store.lanEnabled = true; store.lanAddress = arguments[2]
            try Checks.require(store.activeLANAddress == nil, "A draft must not claim an active LAN listener")
            setup.stop()
            try await Checks.wait("guide Stop") { !setup.busy }
            try Checks.require(!store.isRunning && setup.error == nil, "Guide Stop failed")
            setup.start(port: arguments[3], address: "127.0.0.1", sslHosts: "*")
            try Checks.require(setup.error != nil && !store.isRunning, "Invalid setup must explain the error before launch")
            let cancellation = store.$isStarting.dropFirst().filter { $0 }.first().sink { _ in
                Task { @MainActor in setup.stop() }
            }
            setup.start(port: arguments[3], address: arguments[2], sslHosts: "*")
            try await Checks.wait("cancel actual startup and late Ready") { !setup.busy && !store.captureChanging }
            withExtendedLifetime(cancellation) {}
            try Checks.require(!store.isRunning && store.activeLANAddress == nil && setup.error == nil, "Cancelled startup must not leave a ready LAN listener")
            setup.start(port: arguments[3], address: arguments[2], sslHosts: "*")
            try await Checks.wait("guide LAN Ready") { (!setup.busy && store.isRunning) || store.startupIssue != nil || setup.error != nil }
            try Checks.require(store.isRunning && store.activeLANAddress == arguments[2] && setup.error == nil, "Guide Save/Start failed: running=\(store.isRunning), LAN=\(store.activeLANAddress ?? "none"), error=\(setup.error ?? store.errorMessage ?? "none")")
            try Checks.require(system.hasCaptureChoice && !system.rememberOnLaunch && !system.hasBackup, "Device setup must use manual clients without taking Mac routing")
            let proxy = "http://\(arguments[2]):\(arguments[3])"
            let page = try Checks.request("http://lens.invalid/", proxy: proxy)
            let html = String(decoding: page, as: UTF8.self)
            try Checks.require(html.contains("已连接 Lens") && html.contains(store.caSHA256), "Phone setup page/fingerprint mismatch")
            try await Checks.wait("new LAN HTTP capture") { store.flows.contains { $0.url == "http://lens.invalid/" && $0.state == "complete" } }
            let baseline = Set(store.flows.map(\.id))
            let http = LensGuideProgress(flows: store.flows, excluding: [], since: guideOpenedAt, lanOnly: true)
            try Checks.require(http.httpCount == 1 && http.httpsCount == 0, "HTTP must not claim certificate installation or HTTPS")
            try Checks.require(LensGuideProgress(flows: store.flows, excluding: baseline, since: guideOpenedAt, lanOnly: true).latest == nil, "Old records must not advance a new guide")
            try Checks.require(LensGuideProgress(flows: store.flows, excluding: [], since: Date().timeIntervalSince1970, lanOnly: true).latest == nil, "Late restoration must not turn old timestamps into new traffic")
            let body = try Checks.request(arguments[5], proxy: proxy, ca: store.caCert)
            try await Checks.wait("strict HTTPS capture") { store.flows.contains { $0.url == arguments[5] && $0.state == "complete" } }
            let progress = LensGuideProgress(flows: store.flows, excluding: baseline, since: guideOpenedAt, lanOnly: true)
            try Checks.require(progress.httpCount == 0 && progress.httpsCount == 1, "A real strict HTTPS response must advance HTTPS only")
            guard let tls = progress.latest else { throw GuideFailure(message: "Missing latest HTTPS request") }
            store.selection = tls.id; store.loadDetail()
            try await Checks.wait("Request/Response detail") { store.detail?.id == tls.id || store.detailError != nil }
            try Checks.require(store.detailError == nil && store.detail != nil, "Guide request cannot be inspected")
            try Checks.require(store.detail?.responseBody == String(decoding: body, as: UTF8.self), "Native Response body differs from client bytes")
            try Checks.require(store.detail?.requestHeaders.isEmpty == false && store.detail?.responseHeaders.isEmpty == false, "Native Request/Response headers missing")
            try Checks.require(String(decoding: body, as: UTF8.self).contains("/onboarding-https"), "HTTPS fixture response changed")
            var imported = tls; imported.imported = true
            var replayed = tls; replayed.replayed = true
            var loopback = tls; loopback.clientConnection = nil
            var opaque = tls; opaque.method = "CONNECT"
            var pending = tls; pending.state = "pending"
            var failed = tls; failed.error = "fixture"
            let rejected = LensGuideProgress(flows: [imported, replayed, loopback, opaque, pending, failed], excluding: [], since: guideOpenedAt, lanOnly: true)
            try Checks.require(rejected.latest == nil && rejected.httpsCount == 0, "Unproven traffic must not complete phone setup")
            setup.stop()
            try await Checks.wait("final Stop") { !setup.busy }
            try Checks.require(!store.isRunning && store.activeLANAddress == nil && store.flows.count == 2, "Stop must clear listener readiness and retain inspection")
        } catch { failure = error }
        var exited: Bool?
        store.shutdown { exited = $0 }
        try await Checks.wait("owned engine shutdown") { exited != nil }
        try Checks.require(exited == true, "Owned engine cleanup failed")
        if let failure { throw failure }
        print("PASS: guide Stop/validate/Save/Start, cancel startup with late Ready, actual LAN HTTP and strict HTTPS, typed progress exclusions, inspectable detail, retained Stop and owned shutdown; no host proxy access")
    }
}
