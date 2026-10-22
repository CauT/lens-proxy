import AppKit
import Foundation
import SwiftUI
import SystemConfiguration

struct SystemProxyError: LocalizedError {
    let message: String
    var errorDescription: String? { message }
}

struct SystemProxyEndpoint: Codable, Equatable {
    let enabled: Bool
    let server: String
    let port: Int
    let authenticated: Bool

    static func parse(_ text: String) throws -> SystemProxyEndpoint {
        let fields = try SystemProxySnapshot.fields(text)
        guard let enabled = try SystemProxySnapshot.flag(fields["Enabled"]),
              let server = fields["Server"], let portText = fields["Port"],
              let port = Int(portText), (0...65535).contains(port),
              let authenticated = try SystemProxySnapshot.flag(fields["Authenticated Proxy Enabled"]) else {
            throw SystemProxyError(message: "Cannot determine all proxy settings. Use manual configuration instead.")
        }
        return SystemProxyEndpoint(enabled: enabled, server: server, port: port, authenticated: authenticated)
    }

    var summary: String { "\(enabled ? "On" : "Off") · \(server.isEmpty ? "No server" : server):\(port)\(authenticated ? " · Authenticated" : "")" }
}

struct SystemProxySnapshot: Equatable {
    let service: String
    let location: String
    let http: SystemProxyEndpoint
    let https: SystemProxyEndpoint
    let pacEnabled: Bool
    let discoveryEnabled: Bool
    // Raw getter output is used only for command-time change guards, never reinterpreted by the UI.
    let rawHTTP: String
    let rawHTTPS: String
    let rawPAC: String
    let rawDiscovery: String

    static func fields(_ text: String) throws -> [String: String] {
        var result: [String: String] = [:]
        for line in text.components(separatedBy: .newlines) where !line.isEmpty {
            guard let colon = line.firstIndex(of: ":") else { throw SystemProxyError(message: "Unexpected networksetup output: \(line)") }
            let key = String(line[..<colon]).trimmingCharacters(in: .whitespaces)
            guard result[key] == nil else { throw SystemProxyError(message: "Ambiguous networksetup field: \(key)") }
            result[key] = String(line[line.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
        }
        return result
    }

    static func flag(_ value: String?) throws -> Bool? {
        guard let value else { return nil }
        switch value.lowercased() {
        case "yes", "on", "1": return true
        case "no", "off", "0": return false
        default: throw SystemProxyError(message: "Unknown proxy flag: \(value)")
        }
    }

    static func services(_ text: String) throws -> [String] {
        let lines = text.components(separatedBy: .newlines).filter { !$0.isEmpty }
        guard lines.first == "An asterisk (*) denotes that a network service is disabled." else {
            throw SystemProxyError(message: "Unable to list network services. \(text.trimmingCharacters(in: .whitespacesAndNewlines))")
        }
        // Disabled services are shown by networksetup with an asterisk and are deliberately excluded.
        let services = lines.dropFirst().filter { !$0.hasPrefix("*") }
        guard Set(services).count == services.count else { throw SystemProxyError(message: "Network service names are ambiguous. Use manual configuration instead.") }
        return services
    }

    var automaticConfigurationIssue: String? {
        if http.authenticated || https.authenticated { return "Authenticated proxies cannot be restored without their credentials. Use manual configuration." }
        if pacEnabled || discoveryEnabled { return "PAC or automatic proxy discovery is enabled. Lens leaves it unchanged; use manual configuration." }
        if (http.enabled && (http.server.isEmpty || http.port == 0)) || (https.enabled && (https.server.isEmpty || https.port == 0)) {
            return "The current enabled proxy has incomplete settings. Use manual configuration."
        }
        return nil
    }
}

struct SystemProxyBackup: Codable {
    let version: Int
    let service: String
    let location: String
    let createdAt: Date
    let http: SystemProxyEndpoint
    let https: SystemProxyEndpoint
    let intended: SystemProxyEndpoint
    var restoreStarted: Bool? = nil
}

struct SystemProxyRestorePlan {
    let script: String?
    let conflicts: [String]
    let alreadyRestored: Bool
}

struct SystemProxyLaunchSelection: Codable, Equatable {
    let service: String
    let location: String
    let http: SystemProxyEndpoint
    let https: SystemProxyEndpoint

    init(_ snapshot: SystemProxySnapshot) {
        service = snapshot.service; location = snapshot.location
        http = snapshot.http; https = snapshot.https
    }
}

private struct SystemProxyCapturePreferences: Codable {
    let version: Int
    let selection: SystemProxyLaunchSelection?
}

struct SystemProxyRouting: Equatable {
    let http: SystemProxyEndpoint
    let https: SystemProxyEndpoint

    func usesLens(port: Int) -> Bool {
        [http, https].allSatisfy { $0.enabled && $0.server == "127.0.0.1" && $0.port == port }
    }

    static func primaryService() -> String? {
        for family in ["IPv4", "IPv6"] {
            guard let state = SCDynamicStoreCopyValue(nil, "State:/Network/Global/\(family)" as CFString) as? [String: Any],
                  let identity = state["PrimaryService"] as? String,
                  let service = SCDynamicStoreCopyValue(nil, "Setup:/Network/Service/\(identity)" as CFString) as? [String: Any],
                  let name = service["UserDefinedName"] as? String else { continue }
            return name
        }
        return nil
    }

    static func current() -> SystemProxyRouting? {
        guard let values = SCDynamicStoreCopyProxies(nil) as? [String: Any] else { return nil }
        func endpoint(_ prefix: String) -> SystemProxyEndpoint? {
            guard let enabled = values[prefix + "Enable"] as? NSNumber else { return nil }
            if !enabled.boolValue { return .init(enabled: false, server: "", port: 0, authenticated: false) }
            guard let server = values[prefix + "Proxy"] as? String, let port = values[prefix + "Port"] as? Int else { return nil }
            return .init(enabled: true, server: server, port: port, authenticated: false)
        }
        guard let http = endpoint("HTTP"), let https = endpoint("HTTPS") else { return nil }
        return .init(http: http, https: https)
    }
}

struct SystemProxyRunner {
    var read: ([String]) throws -> String
    var authorize: (String) throws -> Void
    var routing: () -> SystemProxyRouting? = { nil }
    var primaryService: () -> String? = { nil }

    static let live = SystemProxyRunner(read: { arguments in
        try process("/usr/sbin/networksetup", arguments)
    }, authorize: { script in
        let literal = "\"" + script.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"").replacingOccurrences(of: "\n", with: "\\n") + "\""
        _ = try process("/usr/bin/osascript", ["-e", "do shell script \(literal) with administrator privileges"])
    }, routing: { SystemProxyRouting.current() }, primaryService: { SystemProxyRouting.primaryService() })

    private static func process(_ executable: String, _ arguments: [String]) throws -> String {
        let task = Process(), output = Pipe()
        task.executableURL = URL(fileURLWithPath: executable)
        task.arguments = arguments
        task.environment = ["LC_ALL": "C", "LANG": "C", "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"]
        task.standardOutput = output
        task.standardError = output
        try task.run()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        task.waitUntilExit()
        let text = String(decoding: data, as: UTF8.self).trimmingCharacters(in: .newlines)
        guard task.terminationStatus == 0 else { throw SystemProxyError(message: text.isEmpty ? "System proxy command failed (\(task.terminationStatus))." : text) }
        // Some networksetup authorization errors incorrectly exit with status zero.
        guard !text.contains("AuthorizationCreate() failed"), !text.contains("** Error:") else { throw SystemProxyError(message: text) }
        return text
    }
}

struct SystemProxyOperations {
    let runner: SystemProxyRunner

    func snapshot(service: String) throws -> SystemProxySnapshot {
        let services = try SystemProxySnapshot.services(runner.read(["-listallnetworkservices"]))
        guard services.contains(service) else { throw SystemProxyError(message: "The selected network service is unavailable or disabled.") }
        let location = try runner.read(["-getcurrentlocation"])
        guard !location.isEmpty else { throw SystemProxyError(message: "Cannot identify the current network location.") }
        let http = try runner.read(["-getwebproxy", service]), https = try runner.read(["-getsecurewebproxy", service])
        let pac = try runner.read(["-getautoproxyurl", service]), discovery = try runner.read(["-getproxyautodiscovery", service])
        let pacFields = try SystemProxySnapshot.fields(pac), discoveryFields = try SystemProxySnapshot.fields(discovery)
        guard let pacEnabled = try SystemProxySnapshot.flag(pacFields["Enabled"]),
              let discoveryEnabled = try SystemProxySnapshot.flag(discoveryFields["Auto Proxy Discovery"]) else {
            throw SystemProxyError(message: "Cannot determine PAC or proxy discovery state. Use manual configuration.")
        }
        return SystemProxySnapshot(service: service, location: location, http: try .parse(http), https: try .parse(https), pacEnabled: pacEnabled, discoveryEnabled: discoveryEnabled, rawHTTP: http, rawHTTPS: https, rawPAC: pac, rawDiscovery: discovery)
    }

    static func shellQuote(_ value: String) -> String { "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'" }
    static func command(_ arguments: [String]) -> String { "/usr/bin/env LC_ALL=C /usr/sbin/networksetup " + arguments.map(shellQuote).joined(separator: " ") }
    static func guardOutput(_ arguments: [String], equals expected: String) -> String {
        "actual=$(\(command(arguments)))\n[ \"$actual\" = \(shellQuote(expected)) ] || { /bin/echo 'Network settings changed. No further changes were made.' >&2; exit 41; }"
    }

    static func applyScript(_ snapshot: SystemProxySnapshot, intended: SystemProxyEndpoint) -> String {
        ["set -eu", guardOutput(["-getcurrentlocation"], equals: snapshot.location),
         guardOutput(["-getwebproxy", snapshot.service], equals: snapshot.rawHTTP),
         guardOutput(["-getsecurewebproxy", snapshot.service], equals: snapshot.rawHTTPS),
         guardOutput(["-getautoproxyurl", snapshot.service], equals: snapshot.rawPAC),
         guardOutput(["-getproxyautodiscovery", snapshot.service], equals: snapshot.rawDiscovery),
         command(["-setwebproxy", snapshot.service, intended.server, String(intended.port), "off"]),
         command(["-setsecurewebproxy", snapshot.service, intended.server, String(intended.port), "off"])].joined(separator: "\n")
    }

    static func restorePlan(_ backup: SystemProxyBackup, current: SystemProxySnapshot) throws -> SystemProxyRestorePlan {
        guard backup.version == 1, backup.service == current.service, backup.location == current.location else {
            throw SystemProxyError(message: "The original network service or location cannot be identified. The recovery record was retained; no settings were changed.")
        }
        guard !backup.http.authenticated && !backup.https.authenticated else { throw SystemProxyError(message: "The recovery record contains authenticated settings that Lens cannot restore.") }
        var commands = ["set -eu", guardOutput(["-getcurrentlocation"], equals: current.location)]
        var conflicts: [String] = []
        var needsRestore = false
        for (label, value, original, raw, get, set, state) in [
            ("HTTP", current.http, backup.http, current.rawHTTP, "-getwebproxy", "-setwebproxy", "-setwebproxystate"),
            ("HTTPS", current.https, backup.https, current.rawHTTPS, "-getsecurewebproxy", "-setsecurewebproxy", "-setsecurewebproxystate")
        ] {
            if value == original { continue }
            let restoreIntermediate = SystemProxyEndpoint(enabled: true, server: original.server, port: original.port, authenticated: original.authenticated)
            guard value == backup.intended || (backup.restoreStarted == true && value == restoreIntermediate) else { conflicts.append(label); continue }
            needsRestore = true
            commands.append(guardOutput([get, backup.service], equals: raw))
            // Setting server/port also enables the endpoint; always restore its original enabled state afterward.
            commands.append(command([set, backup.service, original.server, String(original.port), "off"]))
            commands.append(command([state, backup.service, original.enabled ? "on" : "off"]))
        }
        return SystemProxyRestorePlan(script: needsRestore ? commands.joined(separator: "\n") : nil, conflicts: conflicts, alreadyRestored: !needsRestore && conflicts.isEmpty)
    }
}

@MainActor
final class SystemProxyController: ObservableObject {
    @Published var services: [String] = []
    @Published var selectedService = ""
    @Published private(set) var snapshot: SystemProxySnapshot?
    @Published private(set) var isBusy = false
    @Published private(set) var hasBackup = false
    @Published private(set) var backupService: String?
    @Published private(set) var message: String?
    @Published private(set) var error: String?
    @Published private(set) var routing: SystemProxyRouting?
    @Published private(set) var primaryService: String?
    @Published private(set) var hasCaptureChoice = false
    @Published private(set) var launchSelection: SystemProxyLaunchSelection?
    @Published private(set) var rememberOnLaunch = true
    private var capturePreferencesIssue: String?
    private var pendingConnection: (() -> Void)?
    private let runner: SystemProxyRunner
    let backupURL: URL
    private let capturePreferencesURL: URL
    private var backup: SystemProxyBackup?
    private let queue = DispatchQueue(label: "Lens.SystemProxy")

    init(dataDirectory: URL? = nil, runner: SystemProxyRunner = .live) {
        self.runner = runner
        let directory = dataDirectory ?? FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("Lens")
        backupURL = directory.appendingPathComponent("system-proxy-recovery.json")
        capturePreferencesURL = directory.appendingPathComponent("mac-capture-preferences.json")
        if FileManager.default.fileExists(atPath: capturePreferencesURL.path) {
            do {
                let preferences = try JSONDecoder().decode(SystemProxyCapturePreferences.self, from: Data(contentsOf: capturePreferencesURL))
                guard preferences.version == 1 else { throw SystemProxyError(message: "Unsupported Mac capture preference version.") }
                launchSelection = preferences.selection
                hasCaptureChoice = true; rememberOnLaunch = preferences.selection != nil
                selectedService = preferences.selection?.service ?? ""
            } catch {
                capturePreferencesIssue = "Saved Mac capture settings could not be read. The file is preserved; review System proxy before reconnecting."
                self.error = capturePreferencesIssue
            }
        }
        if FileManager.default.fileExists(atPath: backupURL.path) {
            hasBackup = true
            do {
                backup = try JSONDecoder().decode(SystemProxyBackup.self, from: Data(contentsOf: backupURL))
                backupService = backup?.service
                selectedService = backup?.service ?? ""
                message = "A saved proxy recovery record is available. Restore it before applying another configuration."
            } catch { self.error = "Cannot read the saved proxy recovery record: \(error.localizedDescription). It has been preserved at \(backupURL.path)." }
        }
    }

    func refreshRouting() { routing = runner.routing(); primaryService = runner.primaryService() }

    func chooseManualClients() {
        do {
            try saveCaptureChoice(nil)
            launchSelection = nil; hasCaptureChoice = true; rememberOnLaunch = false
            error = nil; message = "Manual clients selected. Mac system traffic is not automatically connected."
        } catch { self.error = error.localizedDescription }
    }

    func setRememberOnLaunch(_ enabled: Bool) {
        if !enabled, launchSelection != nil { chooseManualClients() }
        else { rememberOnLaunch = enabled }
    }

    private func saveCaptureChoice(_ selection: SystemProxyLaunchSelection?) throws {
        // An unreadable owned preference is preserved before an explicit replacement.
        if capturePreferencesIssue != nil {
            let recovery = capturePreferencesURL.deletingLastPathComponent().appendingPathComponent("mac-capture-preferences-recovery-" + UUID().uuidString + ".json")
            try FileManager.default.copyItem(at: capturePreferencesURL, to: recovery)
        }
        try FileManager.default.createDirectory(at: capturePreferencesURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        try JSONEncoder().encode(SystemProxyCapturePreferences(version: 1, selection: selection)).write(to: capturePreferencesURL, options: .atomic)
        capturePreferencesIssue = nil
    }

    // Called only after the normal workspace's listener is ready. A saved choice
    // grants reconnection only to the exact previous service/location/endpoints.
    func connectAfterStart(port: Int, isReady: @escaping () -> Bool = { true }, completion: (() -> Void)? = nil) {
        refreshRouting()
        guard isReady() else { completion?(); return }
        guard !isBusy else {
            pendingConnection = { [weak self] in self?.connectAfterStart(port: port, isReady: isReady, completion: completion) }
            return
        }
        guard !hasBackup else {
            error = "A previous proxy recovery record needs attention. Restore previous settings before reconnecting Mac capture."
            completion?()
            return
        }
        guard capturePreferencesIssue == nil else { error = capturePreferencesIssue; completion?(); return }
        guard let selection = launchSelection else { refresh(); completion?(); return }
        guard primaryService == selection.service else {
            error = "The active network service changed or could not be identified. Review Mac capture setup and choose the active service before reconnecting."
            completion?(); return
        }
        selectedService = selection.service
        applyLens(port: port, expected: selection, completion: completion)
    }

    private func finishPendingConnection() {
        let pending = pendingConnection; pendingConnection = nil; pending?()
    }

    func refresh() {
        guard !isBusy else { return }
        refreshRouting()
        isBusy = true; error = nil
        let runner = self.runner, selected = selectedService
        queue.async {
            let result = Result { () -> ([String], SystemProxySnapshot?) in
                let services = try SystemProxySnapshot.services(runner.read(["-listallnetworkservices"]))
                let active = runner.primaryService()
                let service = services.contains(selected) ? selected : active.flatMap { services.contains($0) ? $0 : nil } ?? (services.count == 1 ? services.first : nil)
                let snapshot = try service.map { try SystemProxyOperations(runner: runner).snapshot(service: $0) }
                return (services, snapshot)
            }
            Task { @MainActor in
                switch result {
                case .success(let (services, snapshot)): self.services = services; self.snapshot = snapshot; self.selectedService = snapshot?.service ?? ""
                case .failure(let error): self.snapshot = nil; self.error = error.localizedDescription
                }
                self.isBusy = false
                self.finishPendingConnection()
            }
        }
    }

    // Selection is an explicit UI action. Refresh may publish a new default without starting a second read through an onChange feedback path.
    func selectService(_ service: String) {
        guard !isBusy, services.contains(service), selectedService != service else { return }
        selectedService = service
        inspectSelection()
    }

    func inspectSelection() {
        guard !isBusy, !selectedService.isEmpty else { return }
        isBusy = true; snapshot = nil; error = nil
        let runner = self.runner, service = selectedService
        queue.async {
            let result = Result { try SystemProxyOperations(runner: runner).snapshot(service: service) }
            Task { @MainActor in
                self.isBusy = false
                switch result { case .success(let snapshot): self.snapshot = snapshot; case .failure(let error): self.error = error.localizedDescription }
                self.finishPendingConnection()
            }
        }
    }

    // Explicit setup records a launch choice only after verified application.
    // Displaying or refreshing the UI never writes system settings.
    func useLens(port: Int, completion: (() -> Void)? = nil) {
        applyLens(port: port, expected: nil, completion: completion)
    }

    private func applyLens(port: Int, expected: SystemProxyLaunchSelection?, completion: (() -> Void)?) {
        guard !isBusy else { completion?(); return }
        guard !hasBackup else { error = "Restore the existing proxy recovery record before applying Lens again."; completion?(); return }
        guard !selectedService.isEmpty, (1024...65535).contains(port) else { error = "Choose a network service and a valid Lens proxy port."; completion?(); return }
        isBusy = true; error = nil; message = nil
        let service = selectedService, runner = self.runner, backupURL = self.backupURL
        let remember = rememberOnLaunch
        queue.async {
            var saved: SystemProxyBackup?
            var selected: SystemProxyLaunchSelection?
            let result = Result { () -> SystemProxySnapshot in
                let operations = SystemProxyOperations(runner: runner)
                let snapshot = try operations.snapshot(service: service)
                if let issue = snapshot.automaticConfigurationIssue { throw SystemProxyError(message: issue) }
                if let expected, SystemProxyLaunchSelection(snapshot) != expected {
                    throw SystemProxyError(message: "The network location or previous proxy settings changed. Review System proxy and explicitly reconnect; Lens did not replace the new settings.")
                }
                selected = SystemProxyLaunchSelection(snapshot)
                let intended = SystemProxyEndpoint(enabled: true, server: "127.0.0.1", port: port, authenticated: false)
                // Refuse an indistinguishable pre-existing proxy: Lens cannot establish ownership of it.
                guard snapshot.http != intended && snapshot.https != intended else { throw SystemProxyError(message: "This service already points to Lens. Use manual configuration or restore an existing recovery record first.") }
                let backup = SystemProxyBackup(version: 1, service: service, location: snapshot.location, createdAt: Date(), http: snapshot.http, https: snapshot.https, intended: intended)
                try FileManager.default.createDirectory(at: backupURL.deletingLastPathComponent(), withIntermediateDirectories: true)
                let data = try JSONEncoder().encode(backup)
                guard !FileManager.default.fileExists(atPath: backupURL.path) else { throw SystemProxyError(message: "A recovery record already exists. It was not overwritten.") }
                try data.write(to: backupURL, options: [.withoutOverwriting])
                saved = backup
                try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: backupURL.path)
                try runner.authorize(SystemProxyOperations.applyScript(snapshot, intended: intended))
                let applied = try operations.snapshot(service: service)
                guard applied.location == snapshot.location, applied.http == intended, applied.https == intended else { throw SystemProxyError(message: "Proxy changes could not be verified. The recovery record was retained; choose Restore previous settings.") }
                return applied
            }
            Task { @MainActor in
                self.isBusy = false
                if let saved { self.backup = saved; self.hasBackup = true; self.backupService = saved.service }
                switch result {
                case .success(let snapshot):
                    self.snapshot = snapshot
                    do {
                        let choice = remember ? selected : nil
                        try self.saveCaptureChoice(choice)
                        self.launchSelection = choice; self.hasCaptureChoice = true
                        self.message = "Lens now handles HTTP and HTTPS for \(service). Previous settings are saved for recovery." + (remember ? " This service will reconnect on launch while its previous settings remain unchanged." : " Automatic reconnection is off.")
                    } catch { self.error = "Mac proxy is connected, but its launch preference could not be saved: \(error.localizedDescription). Recovery remains available." }
                case .failure(let error): self.error = error.localizedDescription + (saved == nil ? "" : " Recovery record retained; use Restore previous settings to inspect and recover.")
                }
                self.refreshRouting()
                completion?()
                self.finishPendingConnection()
            }
        }
    }

    // Safe for Stop/Quit integration. Completion runs on the main actor; false means recovery remains unresolved.
    func restore(completion: ((Bool) -> Void)? = nil) {
        guard !isBusy else { error = "A system proxy operation is still in progress. Wait for it to finish before restoring."; completion?(false); return }
        guard hasBackup else { completion?(true); return }
        guard let backup else { error = "The recovery record is unreadable. It has been preserved for manual recovery at \(backupURL.path)."; completion?(false); return }
        isBusy = true; error = nil; message = nil
        let runner = self.runner, backupURL = self.backupURL
        queue.async {
            var updatedBackup = backup
            let result = Result { () -> SystemProxySnapshot in
                let operations = SystemProxyOperations(runner: runner)
                let current = try operations.snapshot(service: backup.service)
                let plan = try SystemProxyOperations.restorePlan(backup, current: current)
                if let script = plan.script {
                    // A disabled endpoint takes two commands to restore. Journal its possible enabled intermediate state for retry after interruption.
                    updatedBackup.restoreStarted = true
                    try JSONEncoder().encode(updatedBackup).write(to: backupURL, options: .atomic)
                    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: backupURL.path)
                    try runner.authorize(script)
                }
                let restored = try operations.snapshot(service: backup.service)
                guard restored.location == backup.location, restored.http == backup.http, restored.https == backup.https else {
                    let changed = plan.conflicts.isEmpty ? "Some previous settings could not be verified." : "\(plan.conflicts.joined(separator: " and ")) settings were changed outside Lens and were not overwritten."
                    throw SystemProxyError(message: changed + " The recovery record was retained at \(backupURL.path).")
                }
                try FileManager.default.removeItem(at: backupURL)
                return restored
            }
            Task { @MainActor in
                self.isBusy = false
                self.refreshRouting()
                self.backup = updatedBackup
                switch result {
                case .success(let snapshot): self.snapshot = snapshot; self.backup = nil; self.hasBackup = false; self.backupService = nil; self.message = "Previous HTTP and HTTPS proxy settings restored."; completion?(true)
                case .failure(let error): self.error = error.localizedDescription; completion?(false)
                }
                self.finishPendingConnection()
            }
        }
    }
}
