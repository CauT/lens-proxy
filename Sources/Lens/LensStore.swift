import AppKit
import SwiftUI

private enum RawSessionInspection {
    case tcp(URL), udp(URL), workspace(URL), empty
    var arguments: [String] {
        switch self {
        case .tcp(let url): return ["--inspect-tcp", url.path]
        case .udp(let url): return ["--inspect-udp", url.path]
        case .workspace(let url): return ["--inspect-workspace", url.path]
        case .empty: return ["--inspect-empty"]
        }
    }
}

private enum WorkspaceFileBinding {
    case preserve
    case replace(URL?)
}

struct LensStartupIssue {
    let title: String
    let message: String
    let isCaptureSetup: Bool
}

@MainActor
final class LensStore: ObservableObject {
    @Published var flows: [TrafficFlow] = []
    @Published private(set) var sessions: [HTTPSessionInfo] = [.initial]
    @Published private(set) var currentSessionID = "default"
    @Published private(set) var captureSessionID = "default"
    @Published private(set) var sessionChanging = false
    @Published var quitPending = false
    @Published var sessionAction: SessionActionTarget?
    @Published private(set) var workspaceFileURL: URL?
    @Published private(set) var workspaceSaving = false
    @Published private(set) var workspaceDocument = WorkspaceDocumentState()
    private var quitPrepared = false
    @Published private(set) var recentWorkspaceURLs: [URL] = []
    private let workspaceHistory: WorkspaceHistory
    private var pendingWorkspaceFileBinding = WorkspaceFileBinding.preserve
    private struct SessionViewState {
        var flows: [TrafficFlow] = []
        var selection: String?
        var search = ""
        var host: String?
        var tcp: [TCPStreamSummary] = []
        var udp: [UDPAssociationSummary] = []
    }
    private var sessionViews: [String: SessionViewState] = [:]
    private var sessionArchives: [String: SessionArchiveController] = [:]
    private var archiveTimer: Timer?
    private var newSessionAfterLaunch = false
    private var retainedWorkspaceURL: URL?
    private var retentionDestination: URL?
    var currentSessionName: String { sessions.first { $0.id == currentSessionID }?.name ?? "Session" }
    var captureSessionName: String { sessions.first { $0.id == captureSessionID }?.name ?? "Session" }
    var canCreateSession: Bool { acceptingNativeWrites && !isStarting && !stopping && !restarting && !exiting && !sessionChanging && !workspaceSaving && !quitPending }
    var captureChanging: Bool { isStarting || stopping || restarting || exiting }
    var canSaveWorkspace: Bool { hasEngine && canCreateSession }
    var canOpenWorkspace: Bool { hasEngine && canCreateSession && sessionAction == nil }
    var workspaceWindowTitle: String {
        "Lens — " + (workspaceFileURL.map { $0.lastPathComponent + " — " } ?? "") + currentSessionName + (workspaceDocument.isEdited ? " — Edited" : "")
    }
    var needsWorkspaceSaveConfirmation: Bool { workspaceDocument.needsConfirmation(hasContent: hasWorkspaceRecords || sessions.count != 1 || sessions.first?.name != "Untitled Session 1") }
    var hasWorkspaceRecords: Bool {
        !flows.isEmpty || !tcpStreams.isEmpty || !udpAssociations.isEmpty || sessionViews.values.contains { !$0.flows.isEmpty || !$0.tcp.isEmpty || !$0.udp.isEmpty }
    }

    @Published var selection: String?
    @Published var detail: FlowDetail?
    @Published private(set) var detailLoading = false
    @Published private(set) var detailError: String?
    private var detailRequest = UUID()
    private var detailLoadingID: String?
    private var detailRefreshPending = false
    @Published var search = ""
    @Published var selectedHost: String?
    @Published var recording = true
    @Published private(set) var activeLANAddress: String?
    @Published var isRunning = false {
        didSet { if !isRunning { activeLANAddress = nil } }
    }
    @Published var isStarting = false
    @Published var status = "Ready to inspect"
    @Published private(set) var startupIssue: LensStartupIssue?
    private var startingInspection: RawSessionInspection?
    private var workspaceOpened = false
    @Published var errorMessage: String?
    @Published var rules: [ProxyRule] = []
    @Published private(set) var rulesPreferencesIssue: String?
    private var pendingRulesRecovery: Data?
    private var rulesRecoverySaved = false
    @Published private(set) var settingsSaving = false
    @Published var accessPolicy = AccessPolicy()
    @Published var sslHosts = "*"
    @Published var clientCertificates: [ClientCertificateSelection] = []
    @Published var upstreamCA = ""
    @Published private(set) var httpUpstreamProxy = ""
    private var pendingUpstreamProxyRecovery: Data?
    @Published private(set) var activeClientCertificates: [ClientCertificateInfo] = []
    @Published var port = "8890"
    @Published var uploadKbps = 0
    @Published var downloadKbps = 0
    @Published private(set) var connectTimeoutSeconds = "10"
    @Published private(set) var connectionTimeoutPreferencesIssue: String?
    private var pendingConnectionTimeoutRecovery: Data?
    private var pendingLANClientsRecovery: Data?
    private var savedPreferenceFields: [String: Any] = [:]
    @Published var tcpForwards: [TCPForwardSelection] = [] {
        didSet { forwardingSelectionChanged("tcp_forwards") }
    }
    @Published private(set) var tcpStreams: [TCPStreamSummary] = []
    @Published private(set) var tcpGeneration = 0
    @Published var udpForwards: [UDPForwardSelection] = [] {
        didSet { forwardingSelectionChanged("udp_forwards") }
    }
    @Published private(set) var udpAssociations: [UDPAssociationSummary] = []
    @Published private(set) var udpGeneration = 0
    @Published var socksPort = "0"
    @Published var identifyClientProcesses = false
    @Published var reversePort = "0"
    @Published var reverseURL = ""
    @Published var lanEnabled = false
    @Published var lanAddress = ""
    @Published var caSHA256 = ""
    @Published var showSessionStorage = false
    @Published var caCert = ""
    @Published var logs: [String] = []
    @Published var repeatJobs: [RepeatJob] = []
    private var process: Process?
    private var input: Pipe?
    private var callbacks: [String: (EngineValue) -> Void] = [:]
    private var failures: [String: (String) -> Void] = [:]
    private var stdoutBuffer = Data()
    private var stderrBuffer = Data()
    private var engineFailure: String?
    private var stopping = false
    private var restarting = false
    private var restartRequest = UUID()
    private var exiting = false
    private var acceptingNativeWrites = true
    private let nativeWrites = DispatchGroup()
    private var stopCompletions: [(Bool) -> Void] = []
    private var exitCompletions: [(Bool) -> Void] = []
    let dataDirectory: URL
    private let resources: URL
    // Decode failure is an owned saved value, never an empty forwarding selection.
    // Only an explicit replacement of that transport's selection resolves it.
    private var malformedForwardingPreferences: [String: Any] = [:]
    private var pendingForwardingRecovery: Data?
    var tcpForwardingPreferencesIssue: String? { forwardingPreferencesWarning("tcp_forwards", transport: "TCP") }
    var udpForwardingPreferencesIssue: String? { forwardingPreferencesWarning("udp_forwards", transport: "UDP") }
    private func forwardingPreferencesWarning(_ key: String, transport: String) -> String? {
        guard malformedForwardingPreferences[key] != nil else { return nil }
        return "Saved \(transport) forwarding settings could not be read. Saving the current list will replace them; an original preferences backup will be kept."
    }
    var forwardingPreferencesIssue: String? {
        let transports = [("tcp_forwards", "TCP"), ("udp_forwards", "UDP")]
            .compactMap { malformedForwardingPreferences[$0.0] != nil ? $0.1 : nil }
        guard !transports.isEmpty else { return nil }
        return "Saved \(transports.joined(separator: " and ")) forwarding preferences could not be read. Open each affected forwarding sheet, review or replace its settings, and explicitly save before starting capture. The original selections are preserved until then."
    }
    let systemProxy: SystemProxyController
    var archives: SessionArchiveController { archiveController(for: currentSessionID) }
    func archiveController(for sessionID: String) -> SessionArchiveController {
        if let controller = sessionArchives[sessionID] { return controller }
        if archiveTimer == nil {
            archiveTimer = Timer.scheduledTimer(withTimeInterval: 30, repeats: true) { [weak self] _ in
                Task { @MainActor in self?.sessionArchives.values.forEach { $0.tick() } }
            }
        }
        let controller = SessionArchiveController(store: self, sessionID: sessionID)
        sessionArchives[sessionID] = controller
        return controller
    }
    func flows(in sessionID: String) -> [TrafficFlow] {
        sessionID == currentSessionID ? flows : sessionViews[sessionID]?.flows ?? []
    }
    func selectSession(_ identity: String) {
        guard identity != currentSessionID, sessions.contains(where: { $0.id == identity }) else { return }
        sessionViews[currentSessionID] = SessionViewState(flows: flows, selection: selection, search: search, host: selectedHost, tcp: tcpStreams, udp: udpAssociations)
        currentSessionID = identity
        let state = sessionViews[identity] ?? SessionViewState()
        flows = state.flows; selection = state.selection; search = state.search; selectedHost = state.host
        tcpStreams = state.tcp; udpAssociations = state.udp
        tcpGeneration &+= 1; udpGeneration &+= 1
        resetDetail()
        loadDetail()
    }
    private func acceptSessions(_ value: EngineValue, choose: Bool = true) throws {
        let catalog = try value.decode(HTTPSessionCatalog.self)
        try catalog.validate()
        sessions = catalog.sessions; captureSessionID = catalog.captureSessionId
        if choose, let identity = catalog.viewSessionId { selectSession(identity) }
        else if !sessions.contains(where: { $0.id == currentSessionID }) { selectSession(captureSessionID) }
        let retained = Set(sessions.map(\.id))
        sessionViews = sessionViews.filter { retained.contains($0.key) }
        sessionArchives = sessionArchives.filter { retained.contains($0.key) }
        repeatJobs.removeAll { !retained.contains($0.sessionId ?? "default") }
    }
    func newSession() {
        guard canCreateSession else { return }
        if !hasEngine {
            newSessionAfterLaunch = true
            launch(inspecting: retainedWorkspaceURL.map(RawSessionInspection.workspace) ?? .empty)
            return
        }
        sessionChanging = true
        send("new_session", onError: { [weak self] reason in
            self?.sessionChanging = false; self?.errorMessage = reason
        }) { [weak self] value in
            guard let self else { return }
            self.sessionChanging = false
            do { try self.acceptSessions(value); self.recording = true }
            catch { self.errorMessage = error.localizedDescription }
        }
    }
    func openSession(path: String) {
        guard hasEngine, canCreateSession else { return }
        guard path.hasPrefix("/"), !path.contains("\0") else { errorMessage = "Select an absolute HAR file path."; return }
        sessionChanging = true
        send("open_session", ["path": path], onError: { [weak self] reason in
            self?.sessionChanging = false; self?.errorMessage = reason
        }) { [weak self] value in
            guard let self else { return }
            self.sessionChanging = false
            do { try self.acceptSessions(value) }
            catch { self.errorMessage = error.localizedDescription }
        }
    }
    func renameSession(_ identity: String, name: String, completion: @escaping (Bool) -> Void) {
        guard hasEngine, canCreateSession, sessions.contains(where: { $0.id == identity }) else { completion(false); return }
        sessionChanging = true
        send("rename_session", ["session_id": identity, "name": name], onError: { [weak self] reason in
            self?.sessionChanging = false; self?.errorMessage = reason; completion(false)
        }) { [weak self] value in
            guard let self else { completion(false); return }
            self.sessionChanging = false
            do { try self.acceptSessions(value); completion(true) }
            catch { self.errorMessage = error.localizedDescription; completion(false) }
        }
    }
    func closeSession(_ identity: String, backupPath: String? = nil, discard: Bool = false, completion: @escaping (Bool) -> Void) {
        guard hasEngine, canCreateSession, sessions.contains(where: { $0.id == identity }) else { completion(false); return }
        var arguments: [String: Any] = ["session_id": identity, "discard": discard]
        if let backupPath {
            guard backupPath.hasPrefix("/"), !backupPath.contains("\0") else { errorMessage = "Select an absolute workspace copy path."; completion(false); return }
            do { try FileManager.default.createDirectory(at: dataDirectory.appendingPathComponent("session-backups"), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700]) }
            catch { errorMessage = error.localizedDescription; completion(false); return }
            arguments["backup_path"] = backupPath
        }
        sessionChanging = true
        let controller = archiveController(for: identity)
        controller.quiesce { [weak self] in
            guard let self else { completion(false); return }
            self.send("close_session", arguments, onError: { [weak self] reason in
                controller.resumed()
                self?.sessionChanging = false; self?.errorMessage = reason; completion(false)
            }) { [weak self] value in
                guard let self else { completion(false); return }
                self.sessionChanging = false
                do { try self.acceptSessions(value); completion(true) }
                catch { self.errorMessage = error.localizedDescription; completion(false) }
            }
        }
    }
    func openWorkspaceCopy(path: String, asDocument: Bool = false) {
        guard canCreateSession, path.hasPrefix("/"), !path.contains("\0") else { return }
        let file = URL(fileURLWithPath: path)
        // The selected input may itself be our usual retention file (including
        // an alias). Save the previous workspace to a fresh private destination
        // so Stop cannot overwrite the file we are about to read.
        retentionDestination = dataDirectory.appendingPathComponent("retained-before-open-" + UUID().uuidString + ".lens.json")
        // Stop retains the current complete workspace before replacing its view.
        // The selected file is then parsed by the normal inspection owner.
        stopAndExit { [weak self] success in
            guard let self, success else { return }
            self.retentionDestination = self.dataDirectory.appendingPathComponent("retained-open-workspace-" + UUID().uuidString + ".lens.json")
            self.launch(inspecting: .workspace(file), fileBinding: .replace(asDocument ? file : nil))
        }
    }
    func saveWorkspace(chooseAnotherFile: Bool = false) {
        guard canSaveWorkspace, sessionAction == nil else { return }
        if !chooseAnotherFile, let workspaceFileURL {
            saveWorkspace(path: workspaceFileURL.path) { _ in }
        } else { presentSessionAction(.saveWorkspace) }
    }
    func recentWorkspaceTitle(for url: URL) -> String {
        let name = url.lastPathComponent
        return recentWorkspaceURLs.filter { $0.lastPathComponent == name }.count > 1
            ? name + " — " + url.deletingLastPathComponent().path : name
    }
    func openRecentWorkspace(_ url: URL) {
        guard canOpenWorkspace, url.isFileURL else { return }
        openWorkspaceCopy(path: url.path, asDocument: true)
    }
    func clearRecentWorkspaces() {
        workspaceHistory.clear()
        refreshWorkspaceHistory()
    }
    private func refreshWorkspaceHistory() {
        // Missing files stay visible: selecting one uses the normal retained
        // Open failure/recovery path instead of silently forgetting the entry.
        recentWorkspaceURLs = workspaceHistory.read().filter {
            $0.isFileURL && $0.path.hasPrefix("/") && !$0.path.contains("\0")
        }
    }
    private func rememberWorkspace(_ url: URL) {
        workspaceHistory.remember(url)
        refreshWorkspaceHistory()
    }
    func saveWorkspace(path: String, completion: @escaping (Bool) -> Void) {
        guard canSaveWorkspace else { completion(false); return }
        guard path.hasPrefix("/"), !path.contains("\0") else {
            errorMessage = "Choose an absolute workspace file path."; completion(false); return
        }
        let destination = URL(fileURLWithPath: path)
        workspaceSaving = true
        nativeWrites.enter()
        // This operation participates in Stop/Quit's existing file drain. The
        // engine owns the atomic all-session snapshot; capture keeps running.
        send("save_workspace", ["path": destination.path], onError: { [self] reason in
            workspaceSaving = false; nativeWrites.leave()
            errorMessage = "Workspace save failed: " + reason
            completion(false)
        }) { [self] value in
            workspaceSaving = false; nativeWrites.leave()
            let receipt: WorkspaceSaveReceipt
            do {
                receipt = try WorkspaceSaveReceipt(value, destination: destination)
                try workspaceDocument.acceptSave(receipt)
            } catch {
                workspaceDocument.markUnknown()
                errorMessage = "Workspace save outcome could not be verified. The previous file association is retained. " + error.localizedDescription
                completion(false); return
            }
            workspaceFileURL = destination
            rememberWorkspace(destination)
            status = "Saved " + destination.lastPathComponent + " · \(receipt.sessions) sessions" + (workspaceDocument.isEdited ? " · newer changes remain unsaved" : isRunning ? " · capture continues" : "")
            completion(true)
        }
    }
    func presentSessionAction(_ kind: SessionActionTarget.Kind, identity: String? = nil) {
        guard canCreateSession, hasEngine, let session = sessions.first(where: { $0.id == (identity ?? currentSessionID) }) else { return }
        sessionAction = SessionActionTarget(kind: kind, session: session)
    }

    func recordInCurrentSession() {
        guard hasEngine, canCreateSession else { return }
        sessionChanging = true
        send("activate_session", onError: { [weak self] reason in
            self?.sessionChanging = false; self?.errorMessage = reason
        }) { [weak self] value in
            guard let self else { return }
            self.sessionChanging = false
            do { try self.acceptSessions(value); self.recording = true }
            catch { self.errorMessage = error.localizedDescription }
        }
    }


    init(dataDirectory: URL? = nil, resources: URL? = nil, systemProxy: SystemProxyController? = nil, workspaceHistory: WorkspaceHistory? = nil) {
        self.dataDirectory = dataDirectory ?? FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("Lens")
        self.resources = resources ?? Bundle.main.resourceURL!
        self.systemProxy = systemProxy ?? SystemProxyController(dataDirectory: self.dataDirectory)
        self.workspaceHistory = workspaceHistory ?? .system
        refreshWorkspaceHistory()
        try? FileManager.default.createDirectory(at: self.dataDirectory, withIntermediateDirectories: true)
        let rulesFile = self.dataDirectory.appendingPathComponent("rules.json")
        if FileManager.default.fileExists(atPath: rulesFile.path) {
            do {
                let data = try Data(contentsOf: rulesFile)
                pendingRulesRecovery = data
                rules = try JSONDecoder().decode([ProxyRule].self, from: data)
                pendingRulesRecovery = nil
            } catch {
                rulesPreferencesIssue = "Saved traffic rules could not be read. Review the Rules sheet and save a replacement before starting. The original file will be kept as a recovery copy."
                errorMessage = rulesPreferencesIssue
            }
        }
        if let data = try? Data(contentsOf: self.dataDirectory.appendingPathComponent("preferences.json")),
           let saved = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            savedPreferenceFields = saved
            port = saved["port"] as? String ?? "8890"; sslHosts = saved["ssl_hosts"] as? String ?? "*"
            uploadKbps = saved["upload_kbps"] as? Int ?? 0; downloadKbps = saved["download_kbps"] as? Int ?? 0
            if let selected = saved["connect_timeout_seconds"] {
                connectTimeoutSeconds = selected as? String ?? "Invalid saved value"
                if LensNetworkSettingsValidation.connectTimeout(connectTimeoutSeconds) == nil {
                    connectionTimeoutPreferencesIssue = "Saved connection timeout is invalid. Choose 1–600 seconds and apply it before Start; the original preferences will be kept in a recovery copy."
                    pendingConnectionTimeoutRecovery = data
                }
            }
            socksPort = saved["socks_port"] as? String ?? "0"
            identifyClientProcesses = saved["client_process"] as? Bool ?? false
            if let raw = saved["http_upstream_proxy"] {
                httpUpstreamProxy = raw as? String ?? "Invalid saved upstream proxy"
                if LensNetworkSettingsValidation.upstreamProxyIssue(httpUpstreamProxy) != nil {
                    pendingUpstreamProxyRecovery = data
                }
            }
            reversePort = saved["reverse_port"] as? String ?? "0"; reverseURL = saved["reverse_url"] as? String ?? ""
            for key in ["tcp_forwards", "udp_forwards"] {
                guard let values = saved[key] else { continue }
                do {
                    let fieldData = try JSONSerialization.data(withJSONObject: values, options: .fragmentsAllowed)
                    if key == "tcp_forwards" { tcpForwards = try JSONDecoder().decode([TCPForwardSelection].self, from: fieldData) }
                    else { udpForwards = try JSONDecoder().decode([UDPForwardSelection].self, from: fieldData) }
                } catch {
                    malformedForwardingPreferences[key] = values
                    pendingForwardingRecovery = data
                }
            }
            if let issue = forwardingPreferencesIssue { errorMessage = issue }
            if let value = saved["access_policy"] {
                do {
                    guard let fields = value as? [String: Any], Set(fields.keys) == Set(["block_enabled", "allow_enabled", "block", "allow", "action"]) else {
                        throw NSError(domain: "LensAccessLists", code: 2)
                    }
                    let data = try JSONSerialization.data(withJSONObject: fields)
                    accessPolicy = try JSONDecoder().decode(AccessPolicy.self, from: data)
                    if let issue = accessPolicy.issue { errorMessage = "Saved Access Lists are invalid: \(issue)" }
                } catch {
                    // Missing policy means legacy defaults. A present malformed policy
                    // remains unusable until the user explicitly repairs the selection.
                    accessPolicy.action = "invalid_preferences"
                    errorMessage = "Saved Access Lists could not be read. Open Access Lists, review both lists, choose a denial action, and save before starting capture."
                }
            }
            lanAddress = saved["lan_address"] as? String ?? ""
            if saved["lan_clients"] != nil { pendingLANClientsRecovery = data }
        }
    }

    private func forwardingSelectionChanged(_ key: String) {
        let previousIssue = forwardingPreferencesIssue
        malformedForwardingPreferences.removeValue(forKey: key)
        if let previousIssue, errorMessage == previousIssue { errorMessage = forwardingPreferencesIssue }
    }

    private func preserveForwardingRecovery() throws {
        guard let original = pendingForwardingRecovery else { return }
        let backup = dataDirectory.appendingPathComponent("preferences-forwarding-recovery-" + UUID().uuidString + ".json")
        try original.write(to: backup, options: .withoutOverwriting)
        pendingForwardingRecovery = nil
    }

    private func networkSettings(connectTimeout: String? = nil) throws -> [String: Int] {
        guard let seconds = LensNetworkSettingsValidation.connectTimeout(connectTimeout ?? connectTimeoutSeconds) else {
            throw NSError(domain: "LensNetworkSettings", code: 1, userInfo: [NSLocalizedDescriptionKey: connectionTimeoutPreferencesIssue ?? "Connection timeout must be a whole number from 1 to 600 seconds."])
        }
        return ["upload_kbps": uploadKbps, "download_kbps": downloadKbps, "connect_timeout_seconds": seconds]
    }

    var selectedFlow: TrafficFlow? { flows.first { $0.id == selection } }
    var hasEngine: Bool { process != nil }
    var hosts: [String] { Array(Set(flows.map(\.host))).sorted() }
    var filteredFlows: [TrafficFlow] { filteredFlows(in: currentSessionID) }
    func filteredFlows(in room: String) -> [TrafficFlow] {
        let host = room == currentSessionID ? selectedHost : sessionViews[room]?.host
        let query = room == currentSessionID ? search : sessionViews[room]?.search ?? ""
        return flows(in: room).filter { flow in
            (host == nil || flow.host == host) &&
            (query.isEmpty || "\(flow.method) \(flow.url) \(flow.statusLabel) \(flow.contentType)".localizedCaseInsensitiveContains(query))
        }
    }
    var totalBytes: String { ByteCountFormatter.string(fromByteCount: Int64(flows.reduce(0) { $0 + $1.responseSize }), countStyle: .file) }

    func start() { startupIssue = nil; launch(inspecting: nil) }

    func openWorkspace() {
        guard !workspaceOpened else { return }
        workspaceOpened = true
        start()
    }

    func connectMacCapture(automatically: Bool = false) {
        guard isRunning, let number = Int(port) else { return }
        let owner = process
        let finished: () -> Void = { [weak self] in
            guard let self else { return }
            // Authorization can outlive the listener. Reconcile only after the
            // apply transaction has published its recovery ownership.
            if (self.process !== owner || !self.isRunning), self.systemProxy.hasBackup, !self.systemProxy.isBusy {
                self.systemProxy.restore { [weak self] restored in
                    if !restored { self?.errorMessage = self?.systemProxy.error }
                }
            }
        }
        if automatically {
            systemProxy.connectAfterStart(port: number, isReady: { [weak self] in self?.process === owner && self?.isRunning == true }, completion: finished)
        }
        else { systemProxy.useLens(port: number, completion: finished) }
    }

    private func launch(inspecting session: RawSessionInspection?, fileBinding: WorkspaceFileBinding = .preserve) {
        guard !isRunning, !isStarting, !stopping, !restarting, !exiting, !workspaceSaving, !quitPending else { return }
        quitPrepared = false
        if session == nil, let issue = rulesPreferencesIssue { errorMessage = issue; return }
        if session == nil, let issue = forwardingPreferencesIssue { errorMessage = issue; return }
        if process != nil {
            restarting = true
            restartRequest = UUID()
            let request = restartRequest
            stopAndExit { [weak self] success in
                guard let self, self.restartRequest == request else { return }
                self.restarting = false
                if success { self.launch(inspecting: session, fileBinding: fileBinding) }
            }
            return
        }
        let selectedPort = session == nil ? port : "8890"
        guard let number = Int(selectedPort), (1024...65535).contains(number) else { errorMessage = "Choose a proxy port between 1024 and 65535."; return }
        if session == nil, let issue = LensNetworkSettingsValidation.listenerIssue(httpPort: port, socksPort: socksPort, reversePort: reversePort, reverseURL: reverseURL, tcpForwards: tcpForwards, udpForwards: udpForwards) { errorMessage = issue; return }
        if session == nil, let issue = LensNetworkSettingsValidation.upstreamProxyIssue(httpUpstreamProxy, socks: socksPort, reverse: reversePort, tcpCount: tcpForwards.count, udpCount: udpForwards.count) { errorMessage = issue; return }
        let lan: LensLANConfiguration?
        do { lan = session == nil ? try LensLANAccess.configuration(enabled: lanEnabled, address: lanAddress) : nil }
        catch { errorMessage = error.localizedDescription; return }
        if session == nil && !upstreamCA.isEmpty && (!NSString(string: upstreamCA).expandingTildeInPath.hasPrefix("/") || upstreamCA.contains("\0")) {
            errorMessage = "The upstream CA bundle must be an absolute PEM file path."; return
        }
        var initialization: [String: Any] = [:]
        do {
            if session == nil {
                initialization = ["rules": try JSONSerialization.jsonObject(with: JSONEncoder().encode(rules)),
                "ssl_hosts": sslHosts, "recording": recording,
                "access_policy": try accessPolicy.commandValue(),
                "network": try networkSettings(),
                "client_process": identifyClientProcesses,
                "client_certificates": try clientCertificates.map { try $0.commandValue() },
                "tcp_forwards": try tcpForwards.map { try $0.commandValue() },
                "udp_forwards": try udpForwards.map { try $0.commandValue() }]
                if let retainedWorkspaceURL { initialization["workspace_path"] = retainedWorkspaceURL.path }
            }
        } catch { errorMessage = error.localizedDescription; return }
        let runtime = resources.appendingPathComponent("python/bin/python3")
        let engine = resources.appendingPathComponent("engine/engine.py")
        guard FileManager.default.isExecutableFile(atPath: runtime.path) else { errorMessage = "The bundled proxy runtime is missing. Rebuild Lens using scripts/build-app.sh."; return }
        let task = Process(), stdin = Pipe(), stdout = Pipe(), stderr = Pipe()
        task.executableURL = runtime
        task.arguments = ["-u", engine.path, "--native-json", "--proxy-port", String(number), "--data-dir", dataDirectory.path]
        if let session { task.arguments! += session.arguments }
        else {
            task.arguments! += ["--initialize-from-stdin"]
            if !upstreamCA.isEmpty { task.arguments! += ["--upstream-ca", upstreamCA] }
            if !httpUpstreamProxy.isEmpty { task.arguments! += ["--http-upstream-proxy", httpUpstreamProxy] }
            if let lan {
                task.arguments! += ["--lan-bind", lan.address]
            }
            if let socks = Int(socksPort), socks != 0 { task.arguments! += ["--socks-port", String(socks)] }
            if let reverse = Int(reversePort), reverse != 0 { task.arguments! += ["--reverse-port", String(reverse), "--reverse-url", reverseURL] }
        }
        task.standardInput = stdin; task.standardOutput = stdout; task.standardError = stderr
        var env = ProcessInfo.processInfo.environment
        env["PYTHONPATH"] = resources.appendingPathComponent("site-packages").path
        env["PYTHONNOUSERSITE"] = "1"
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        task.environment = env
        stdoutBuffer.removeAll(); discardingProtocolLine = false; stderrBuffer.removeAll(); engineFailure = nil
        stdout.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            if data.isEmpty { handle.readabilityHandler = nil; return }
            Task { @MainActor in
                guard let self, self.process === task else { return }
                self.receive(data)
            }
        }
        stderr.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            if data.isEmpty { handle.readabilityHandler = nil; return }
            Task { @MainActor in
                guard let self, self.process === task else { return }
                self.stderrBuffer.append(data)
                self.logs.append(String(decoding: data, as: UTF8.self))
                if self.logs.count > 100 { self.logs.removeFirst(self.logs.count - 100) }
            }
        }
        task.terminationHandler = { [weak self] ended in
            Task { @MainActor in
                guard let self, self.process === ended else { return }
                let failedDuringStartup = self.isStarting
                self.isRunning = false; self.isStarting = false; self.process = nil; self.input = nil
                self.activeClientCertificates = []
                self.stopping = false; self.exiting = false; self.newSessionAfterLaunch = false
                self.sessionArchives.values.forEach { $0.stopped() }
                self.callbacks.removeAll()
                let failures = Array(self.failures.values); self.failures.removeAll()
                failures.forEach { $0("The proxy stopped before the operation completed.") }
                let completions = self.stopCompletions + self.exitCompletions
                self.stopCompletions.removeAll(); self.exitCompletions.removeAll()
                for index in self.repeatJobs.indices where !self.repeatJobs[index].finished {
                    self.repeatJobs[index].cancelled = self.repeatJobs[index].total - self.repeatJobs[index].completed - self.repeatJobs[index].failed
                    self.repeatJobs[index].state = "cancelled"
                }
                self.status = ended.terminationStatus == 0 ? "Proxy stopped" : "Proxy exited (\(ended.terminationStatus))"
                if ended.terminationStatus != 0 {
                    let diagnostic = String(decoding: self.stderrBuffer.suffix(3000), as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
                    let reason = diagnostic.isEmpty ? "The proxy engine exited unexpectedly (status \(ended.terminationStatus))." : diagnostic
                    if let failure = self.engineFailure { self.errorMessage = failure }
                    else if failedDuringStartup {
                        self.startupIssue = self.describeStartupFailure(reason, inspection: self.startingInspection)
                        self.errorMessage = self.startupIssue?.message
                    } else { self.errorMessage = reason }
                }
                if self.systemProxy.hasBackup {
                    self.systemProxy.restore { restored in
                        if !restored { self.errorMessage = self.systemProxy.error }
                    }
                }
                completions.forEach { $0(ended.terminationStatus == 0) }
            }
        }
        do {
            process = task; input = stdin; isStarting = true; status = "Starting proxy…"
            startingInspection = session
            startupIssue = nil
            pendingWorkspaceFileBinding = fileBinding
            try task.run()
            // Credentials cross only the owned stdin pipe, before any public
            // listener opens. They are never arguments, environment or prefs.
            if session == nil { send("initialize", initialization) }
        } catch {
            process = nil; input = nil; isStarting = false
            pendingWorkspaceFileBinding = .preserve
            startupIssue = describeStartupFailure(error.localizedDescription, inspection: session)
            errorMessage = startupIssue?.message
        }
    }

    private func describeStartupFailure(_ reason: String, inspection: RawSessionInspection?) -> LensStartupIssue {
        let title: String
        let selected: URL?
        switch inspection {
        case .workspace(let url): title = "Workspace could not be opened"; selected = url
        case .tcp(let url), .udp(let url): title = "Saved capture could not be opened"; selected = url
        case .empty: title = "Session could not be opened"; selected = nil
        case nil:
            return LensStartupIssue(title: "Capture could not start", message: "Capture could not start. Review Connection for port conflicts and certificate settings, then click Start to retry.\n\n" + reason, isCaptureSetup: true)
        }
        let recovery = retainedWorkspaceURL != nil
            ? "The previous workspace was retained. Click Start to resume it, then use File → Open Workspace to select another file."
            : "Click Start to create a capture, then use File → Open Workspace to select another file."
        return LensStartupIssue(title: title, message: title + ".\n" + (selected.map { "Selected file: " + $0.path + "\n\n" } ?? "\n") + recovery + "\n\n" + reason, isCaptureSetup: false)
    }

    func stop(completion: ((Bool) -> Void)? = nil) {
        let system = systemProxy
        guard !system.isBusy else {
            errorMessage = "Wait for the system proxy operation to finish before stopping Lens."
            completion?(false); return
        }
        if system.hasBackup {
            system.restore { [weak self] restored in
                if restored { self?.prepareToStop(completion: completion) }
                else { self?.errorMessage = system.error; completion?(false) }
            }
        } else { prepareToStop(completion: completion) }
    }

    private func prepareToStop(completion: ((Bool) -> Void)?) {
        status = "Finishing session file operations…"
        drainFileOperations { [weak self] in self?.stopEngine(completion: completion) }
    }

    private func drainFileOperations(_ completion: @escaping () -> Void) {
        acceptingNativeWrites = false
        let controllers = Array(sessionArchives.values)
        let drains = DispatchGroup()
        controllers.forEach { _ in drains.enter() }
        controllers.forEach { controller in controller.quiesce { drains.leave() } }
        drains.notify(queue: .main) { [weak self] in
            guard let self else { return }
            self.nativeWrites.notify(queue: .main, execute: completion)
        }
    }

    private func resumeFileOperations() {
        acceptingNativeWrites = true
        sessionArchives.values.forEach { $0.resumed() }
    }

    private func stopEngine(completion: ((Bool) -> Void)?) {
        guard let task = process else { completion?(true); return }
        if let completion { stopCompletions.append(completion) }
        guard !stopping else { return }
        stopping = true; status = "Stopping proxy…"
        send("stop_capture", onError: { [weak self] reason in
            self?.errorMessage = "Unable to stop capture: \(reason)"
            self?.finishStopping(success: false)
        }) { [weak self] value in
            guard let self else { return }
            do {
                guard value["capture_stopped"]?.bool == true else { throw EngineJSONFailure.invalid("Stop did not confirm capture is stopped") }
                try self.workspaceDocument.observe(WorkspaceRevision(value["workspace_revision"]))
            }
            catch {
                self.workspaceDocument.markUnknown()
                self.errorMessage = "Stopped workspace state could not be verified. " + error.localizedDescription
                self.finishStopping(success: false); return
            }
            self.isRunning = false; self.isStarting = false
            self.activeClientCertificates = []
            let snapshot = retentionDestination ?? dataDirectory.appendingPathComponent("retained-workspace.lens.json")
            retainedWorkspaceURL = nil
            send("save_workspace", ["path": snapshot.path], onError: { [weak self] reason in
                self?.errorMessage = "Unable to retain the session: \(reason)"
                self?.finishStopping(success: false)
            }) { [weak self] value in
                guard let self else { return }
                do { try self.workspaceDocument.observe(WorkspaceSaveReceipt(value, destination: snapshot)) }
                catch {
                    self.workspaceDocument.markUnknown()
                    self.errorMessage = "Retained workspace state could not be verified. " + error.localizedDescription
                    self.finishStopping(success: false); return
                }
                self.retainedWorkspaceURL = snapshot
                self.finishStopping(success: true)
            }
        }
        // Retain ownership until actual process termination. A file transaction
        // may still be committing; a fixed terminate timer can destroy it.
        DispatchQueue.main.asyncAfter(deadline: .now() + 10) { [weak self] in
            if task.isRunning, self?.stopping == true { self?.status = "Waiting for proxy and file operations to finish…" }
        }
    }

    private func finishStopping(success: Bool) {
        stopping = false; resumeFileOperations()
        status = isRunning ? "Unable to stop capture" : "Proxy stopped"
        let completions = stopCompletions; stopCompletions.removeAll()
        completions.forEach { $0(success) }
    }

    func prepareForQuit(completion: @escaping (Bool) -> Void) {
        guard quitPending else { completion(false); return }
        quitPrepared = false
        // A clean UI snapshot is not exit authority: Stop must join transfers
        // and report its final revision before the delegate decides to prompt.
        stop { [weak self] success in
            self?.quitPrepared = success
            completion(success)
        }
    }

    func cancelQuitPreparation() { quitPrepared = false }

    func shutdown(backupPath: String? = nil, completion: @escaping (Bool) -> Void) {
        if let backupPath {
            guard backupPath.hasPrefix("/"), !backupPath.contains("\0") else { errorMessage = "Select an absolute workspace copy path."; completion(false); return }
            guard !exiting else { errorMessage = "Lens is already shutting down; a new workspace copy cannot be admitted."; completion(false); return }
            do { try FileManager.default.createDirectory(at: dataDirectory.appendingPathComponent("session-backups"), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700]) }
            catch { errorMessage = error.localizedDescription; completion(false); return }
        }
        restartRequest = UUID(); restarting = false
        let prepared = quitPrepared && quitPending && !isRunning && !isStarting
        quitPrepared = false
        stopAndExit(backupPath: backupPath, prepared: prepared, completion: completion)
    }

    private func stopAndExit(backupPath: String? = nil, prepared: Bool = false, completion: @escaping (Bool) -> Void) {
        if exiting { exitCompletions.append(completion); return }
        let afterStop: (Bool) -> Void = { [weak self] success in
            guard let self, success else { completion(false); return }
            let exit = {
                guard self.process != nil else { completion(true); return }
                self.acceptingNativeWrites = false
                self.exitCompletions.append(completion)
                guard !self.exiting else { return }
                self.exiting = true
                self.send("shutdown"); try? self.input?.fileHandleForWriting.close()
            }
            self.drainFileOperations {
                if let backupPath {
                    // Stop has joined transfers and file operations. Save the final
                    // stopped workspace, not a pre-Stop snapshot that can miss data.
                    self.send("save_workspace", ["path": backupPath], onError: { [weak self] reason in
                        self?.resumeFileOperations()
                        self?.errorMessage = "Unable to save the quit copy: \(reason)"; completion(false)
                    }) { value in
                        do {
                            try self.workspaceDocument.observe(WorkspaceSaveReceipt(value, destination: URL(fileURLWithPath: backupPath)))
                            exit()
                        } catch {
                            self.workspaceDocument.markUnknown()
                            self.resumeFileOperations()
                            self.errorMessage = "Quit copy outcome could not be verified. " + error.localizedDescription
                            completion(false)
                        }
                    }
                } else { exit() }
            }
        }
        if prepared { afterStop(true) }
        else { stop(completion: afterStop) }
    }

    func send(_ command: String, _ arguments: [String: Any] = [:], completion: ((EngineValue) -> Void)? = nil) {
        send(command, arguments, onError: nil, completion: completion)
    }

    func send(_ command: String, _ arguments: [String: Any] = [:], onError: ((String) -> Void)?, completion: ((EngineValue) -> Void)? = nil) {
        guard let input else { onError?("Start the proxy before performing this operation."); return }
        let id = UUID().uuidString
        var payload = arguments
        let scoped = ["tcp_detail", "tcp_status", "clear_tcp", "save_tcp", "load_tcp", "udp_detail", "udp_status", "clear_udp", "save_udp", "load_udp", "detail", "websocket_messages", "export_body", "clear", "replay", "compose", "repeat", "export_har", "save_har", "load_har", "import_har", "resume", "activate_session"]
        if scoped.contains(command), payload["session_id"] == nil { payload["session_id"] = currentSessionID }
        payload["command"] = command; payload["command_id"] = id
        do {
            var data = try JSONSerialization.data(withJSONObject: payload)
            data.append(10)
            if let completion { callbacks[id] = completion }
            failures[id] = onError ?? { [weak self] reason in self?.errorMessage = reason }
            try input.fileHandleForWriting.write(contentsOf: data)
        } catch {
            callbacks.removeValue(forKey: id); failures.removeValue(forKey: id)
            if let onError { onError(error.localizedDescription) } else { errorMessage = error.localizedDescription }
        }
    }

    private var discardingProtocolLine = false
    private static let protocolLineLimit = 512 * 1024 * 1024
    private func protocolFailure(_ reason: String) {
        workspaceDocument.markUnknown()
        let message = "Engine protocol error; operation outcome unknown. " + reason
        let pending = Array(failures.values)
        callbacks.removeAll(); failures.removeAll()
        for failure in pending { failure(message) }
        errorMessage = message; status = "Engine protocol error · outcome unknown"
        activeLANAddress = nil
        isStarting = false
    }
    private func receive(_ data: Data) {
        var remaining = data[...]
        while !remaining.isEmpty {
            let end = remaining.firstIndex(of: 10)
            let segment = end.map { remaining[..<$0] } ?? remaining
            if !discardingProtocolLine {
                if segment.count > Self.protocolLineLimit - stdoutBuffer.count {
                    stdoutBuffer.removeAll(); discardingProtocolLine = true
                    protocolFailure("A JSONL frame exceeded the 512 MiB limit.")
                } else { stdoutBuffer.append(contentsOf: segment) }
            }
            guard let end else { return }
            remaining = remaining[remaining.index(after: end)...]
            if discardingProtocolLine { discardingProtocolLine = false; continue }
            let line = stdoutBuffer; stdoutBuffer = Data()
            do { try handleMessage(EngineValue.message(from: line)) }
            catch { protocolFailure(error.localizedDescription) }
        }
    }
    private func handleMessage(_ message: EngineValue) throws {
        guard let event = message["event"]?.unicodeString else { throw EngineJSONFailure.invalid("Missing event identity") }
        if event != "ready", let revision = message["workspace_revision"] {
            try workspaceDocument.observe(WorkspaceRevision(revision))
        }
            switch event {
            case "ready":
                let binding: WorkspaceDocumentState.Binding
                switch pendingWorkspaceFileBinding {
                case .preserve: binding = .preserve
                case .replace(let destination): binding = destination == nil ? .copy : .document
                }
                try workspaceDocument.ready(message, binding: binding)
                startupIssue = nil
                startingInspection = nil
                isStarting = false; isRunning = message["capture_stopped"]?.bool != true
                if isRunning, let address = message["lan_address"]?.unicodeString {
                    activeLANAddress = try LensLANAccess.configuration(enabled: true, address: address)?.address
                } else { activeLANAddress = nil }
                status = !isRunning ? "Session opened · proxy stopped" : "Listening on 127.0.0.1:\(port)" + (activeLANAddress.map { " · LAN \($0):\(port)" } ?? "")
                caSHA256 = message["ca_sha256"]?.unicodeString ?? ""
                acceptingNativeWrites = true; sessionArchives.values.forEach { $0.resumed() }
                caCert = message["ca_cert"]?.unicodeString ?? ""
                if let values = message["client_certificates"] { activeClientCertificates = try values.elements().map { try $0.decode(ClientCertificateInfo.self) } }
                flows.removeAll(); sessionViews.removeAll();
                if message["sessions"] != nil { try acceptSessions(message, choose: false) }
                if case .replace(let destination) = pendingWorkspaceFileBinding {
                    workspaceFileURL = destination
                    if let destination { rememberWorkspace(destination) }
                }
                pendingWorkspaceFileBinding = .preserve
                tcpStreams.removeAll(); tcpGeneration &+= 1; udpAssociations.removeAll(); udpGeneration &+= 1; selection = nil; resetDetail()
                if newSessionAfterLaunch { newSessionAfterLaunch = false; newSession() }
                if isRunning, workspaceOpened { connectMacCapture(automatically: true) }
                // initialize already admitted the selected rules and recording
                // snapshot before opening listeners. Ready reports that owner;
                // it must not reapply mutable UI drafts or write preferences.
            case "session_catalog":
                try acceptSessions(message)
                if message["recording"]?.bool == true { recording = true }
            case "workspace_state":
                guard message["workspace_revision"] != nil else { throw EngineJSONFailure.invalid("Workspace state omitted its revision") }
            case "tcp_stream", "tcp_removed", "tcp_reset", "udp_association", "udp_removed", "udp_reset":
                let room = message["session_id"]?.unicodeString ?? "default"
                guard sessions.contains(where: { $0.id == room }) else { throw EngineJSONFailure.invalid("Raw capture refers to an unknown session") }
                var state = sessionViews[room] ?? SessionViewState()
                switch event {
                case "tcp_stream":
                    if let value = message["stream"] {
                        let stream = try value.decode(TCPStreamSummary.self)
                        if let index = state.tcp.firstIndex(where: { $0.id == stream.id }) { state.tcp[index] = stream }
                        else { state.tcp.append(stream) }
                    }
                case "tcp_removed":
                    if let id = message["id"]?.unicodeString { state.tcp.removeAll { $0.id == id } }
                case "tcp_reset": state.tcp.removeAll()
                case "udp_association":
                    if let value = message["association"] {
                        let association = try value.decode(UDPAssociationSummary.self)
                        if let index = state.udp.firstIndex(where: { $0.id == association.id }) { state.udp[index] = association }
                        else { state.udp.append(association) }
                    }
                case "udp_removed":
                    if let id = message["id"]?.unicodeString { state.udp.removeAll { $0.id == id } }
                default: state.udp.removeAll()
                }
                sessionViews[room] = state
                if room == currentSessionID {
                    tcpStreams = state.tcp; udpAssociations = state.udp
                    if event == "tcp_reset" { tcpGeneration &+= 1 }
                    if event == "udp_reset" { udpGeneration &+= 1 }
                }
            case "flow":
                if let value = message["flow"] {
                    let flow = try value.decode(TrafficFlow.self)
                    let room = flow.sessionId ?? "default"
                    guard sessions.contains(where: { $0.id == room }) else { throw EngineJSONFailure.invalid("Flow refers to an unknown HTTP session") }
                    var state = sessionViews[room] ?? SessionViewState()
                    if let i = state.flows.firstIndex(where: { $0.id == flow.id }) { state.flows[i] = flow } else { state.flows.append(flow) }
                    sessionViews[room] = state
                    archiveController(for: room).received(flow)
                    if room == currentSessionID {
                        flows = state.flows
                        if selection == flow.id { loadDetail() }
                    }
                }
            case "removed":
                if let id = message["id"]?.unicodeString {
                    let room = message["session_id"]?.unicodeString ?? "default"
                    sessionViews[room]?.flows.removeAll { $0.id == id }
                    archiveController(for: room).changed()
                    if room == currentSessionID {
                        flows.removeAll { $0.id == id }
                        if selection == id { selection = nil; resetDetail() }
                    }
                }
            case "repeat_progress", "repeat_done":
                do {
                    let job = try message.decode(RepeatJob.self)
                    if let index = repeatJobs.firstIndex(where: { $0.id == job.id }) { repeatJobs[index] = job }
                    else { repeatJobs.append(job) }
                }
            case "result":
                guard let id = message["command_id"]?.unicodeString, message["value"] != nil else { throw EngineJSONFailure.invalid("Result omitted its command identity or value") }
                do {
                    failures.removeValue(forKey: id)
                    callbacks.removeValue(forKey: id)?(message["value"]!)
                }
            case "error":
                let reason = message["message"]?.displayString ?? "Proxy operation failed."
                if let id = message["command_id"]?.unicodeString {
                    callbacks.removeValue(forKey: id)
                    if let failure = failures.removeValue(forKey: id) { failure(reason) } else { errorMessage = reason }
                } else { errorMessage = reason }
            case "fatal":
                startupIssue = describeStartupFailure(message["message"]?.displayString ?? "Proxy startup failed.", inspection: startingInspection)
                engineFailure = startupIssue?.message
                errorMessage = engineFailure
            case "request_failed":
                errorMessage = message["message"]?.displayString ?? "Proxy request failed."
            case "initializing", "request_finished": break
            default: throw EngineJSONFailure.invalid("Unsupported engine event: " + event)
            }
    }

    func loadDetail() {
        guard let id = selection else { resetDetail(); return }
        if detailLoading, detailLoadingID == id {
            detailRefreshPending = true
            return
        }
        if detail?.id != id { detail = nil }
        detailRequest = UUID()
        let request = detailRequest
        detailLoading = true; detailError = nil; detailLoadingID = id; detailRefreshPending = false
        let failed: (String) -> Void = { [weak self] reason in
            guard let self, self.selection == id, self.detailRequest == request else { return }
            self.detailLoading = false; self.detailError = reason
            self.detailLoadingID = nil; self.detailRefreshPending = false
        }
        loadFlowDetail(id: id) { [weak self] result in
            guard let self, self.selection == id, self.detailRequest == request else { return }
            switch result {
            case .failure(let error): failed(error.localizedDescription)
            case .success(let loaded):
                self.detail = loaded; self.detailLoading = false; self.detailLoadingID = nil
                if self.detailRefreshPending { self.loadDetail() }
            }
        }
    }

    // Independent detail consumers retain their own flow identity and loading state.
    // Decoding and identity admission have one owner, independent of UI selection.
    func loadFlowDetail(id: String, sessionID: String? = nil, completion: @escaping (Result<FlowDetail, Error>) -> Void) {
        let failed: (String) -> Void = { reason in completion(.failure(NSError(domain: "LensDetails", code: 1, userInfo: [NSLocalizedDescriptionKey: reason]))) }
        send("detail", ["id": id, "session_id": sessionID ?? currentSessionID], onError: failed) { value in
            do {
                let loaded = try value.decode(FlowDetail.self)
                guard loaded.id == id else { failed("The detail response does not match this request."); return }
                guard loaded.requestHeaders.allSatisfy({ $0.count == 2 }) && loaded.responseHeaders.allSatisfy({ $0.count == 2 }) else { failed("The detail response contains malformed header pairs."); return }
                _ = try loaded.firstWebSocketPage()
                completion(.success(loaded))
            } catch { failed("Unable to decode flow details: \(error.localizedDescription)") }
        }
    }

    func loadWebSocketPage(id: String, offset: Int, generation: Int, completion: @escaping (Result<WebSocketMessagePage, Error>) -> Void) {
        let failed: (String) -> Void = { reason in completion(.failure(EngineJSONFailure.invalid(reason))) }
        send("websocket_messages", ["id": id, "offset": offset, "limit": 50, "generation": generation], onError: failed) { value in
            do {
                let page = try value.decode(WebSocketMessagePage.self)
                try page.validate()
                guard page.id == id, page.offset == offset, page.generation == generation else { throw EngineJSONFailure.invalid("WebSocket page does not match the requested history") }
                completion(.success(page))
            } catch { failed(error.localizedDescription) }
        }
    }

    private func resetDetail() {
        detailRequest = UUID(); detail = nil; detailLoading = false; detailError = nil
        detailLoadingID = nil; detailRefreshPending = false
    }
    func toggleRecording() { recording.toggle(); send("recording", ["enabled": recording]) }
    func clear(_ identity: String? = nil, backupPath: String? = nil, completion: ((Bool) -> Void)? = nil) {
        let room = identity ?? currentSessionID
        guard hasEngine, canCreateSession, sessions.contains(where: { $0.id == room }) else { completion?(false); return }
        var arguments: [String: Any] = ["session_id": room]
        if let backupPath {
            guard backupPath.hasPrefix("/"), !backupPath.contains("\0") else { errorMessage = "Select an absolute workspace copy path."; completion?(false); return }
            do { try FileManager.default.createDirectory(at: dataDirectory.appendingPathComponent("session-backups"), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700]) }
            catch { errorMessage = error.localizedDescription; completion?(false); return }
            arguments["backup_path"] = backupPath
        }
        sessionChanging = true
        let controller = archiveController(for: room)
        controller.prepareClear { [weak self] in
            guard let self else { completion?(false); return }
            self.send("clear", arguments, onError: { [weak self] reason in
                controller.finishClear()
                self?.sessionChanging = false; self?.errorMessage = reason; completion?(false)
            }) { [weak self] _ in
                guard let self else { completion?(false); return }
                // The engine's removed events own the exact cleared IDs. A
                // blanket reset here would erase arrivals made during the copy.
                controller.changed(); controller.finishClear()
                self.sessionChanging = false; completion?(true)
            }
        }
    }
    func replay() {
        guard selectedFlow?.requestBodyAvailable != false else { errorMessage = "Cannot replay: captured request body is unavailable. Compose an explicit replacement."; return }
        if let selection { send("replay", ["id": selection]) }
    }
    func repeatFlow(id: String, sessionID: String? = nil, count: Int, concurrency: Int, intervalMs: Int, completion: @escaping (String?) -> Void) {
        let room = sessionID ?? currentSessionID
        guard let source = flows(in: room).first(where: { $0.id == id }) else { completion("The source request is no longer retained."); return }
        guard source.requestBodyAvailable != false else { completion("Cannot repeat: captured request body is unavailable. Compose an explicit replacement."); return }
        send("repeat", ["id": id, "session_id": room, "count": count, "concurrency": concurrency, "interval_ms": intervalMs], onError: { completion($0) }) { result in
            guard let job = result["job_id"]?.unicodeString, !job.isEmpty else { completion("The engine did not acknowledge the queued repeat job."); return }
            completion(nil)
        }
    }
    func cancelRepeat(_ job: RepeatJob) { send("cancel_repeat", ["job_id": job.id, "session_id": job.sessionId ?? currentSessionID]) }
    // Bind edits to the paused stage captured when its editor opened, never selection.
    func resumeBreakpoint(flowID: String, sessionID: String? = nil, pauseID: String, stage: String, edit: [String: Any]? = nil,
                          abort: Bool = false, completion: @escaping (String?) -> Void) {
        let room = sessionID ?? currentSessionID
        guard let flow = flows(in: room).first(where: { $0.id == flowID }), flow.state == "paused",
              flow.pauseId == pauseID, flow.breakpointStage == stage else {
            completion("This breakpoint is no longer paused at the stage opened by this editor."); return
        }
        guard ["request", "response"].contains(stage) else { completion("Unknown breakpoint stage."); return }
        var args: [String: Any] = ["id": flowID, "session_id": room, "pause_id": pauseID, "stage": stage, "action": abort ? "abort" : (edit == nil ? "discard" : "continue")]
        if let edit, !edit.isEmpty { args[stage + "_edit"] = edit }
        send("resume", args, onError: { completion($0) }) { _ in completion(nil) }
    }

    func compose(sourceID: String? = nil, sessionID: String? = nil, sourceFingerprint: String? = nil, requestEdit: [String: Any], completion: @escaping (String?) -> Void) {
        let room = sessionID ?? currentSessionID
        if let sourceID {
            guard let source = flows(in: room).first(where: { $0.id == sourceID }) else { completion("The source request is no longer retained."); return }
            guard source.requestBodyAvailable != false || requestEdit["body_base64"] != nil else { completion("The source body is unavailable. Supply an explicit replacement."); return }
        }
        var arguments: [String: Any] = ["request_edit": requestEdit, "session_id": room]
        arguments["source_id"] = sourceID
        arguments["source_fingerprint"] = sourceFingerprint
        send("compose", arguments, onError: { completion($0) }) { result in
            guard result["queued"]?.bool == true else { completion("The engine did not acknowledge the queued request."); return }
            completion(nil)
        }
    }
    func openTCPSession(_ url: URL) {
        guard !isRunning, !isStarting, !stopping, !restarting, !exiting else {
            errorMessage = "Stop capture before opening a TCP session."; return
        }
        if process == nil { launch(inspecting: .tcp(url), fileBinding: .replace(nil)) }
        else { send("load_tcp", ["path": url.path]) }
    }

    func openUDPSession(_ url: URL) {
        guard !isRunning, !isStarting, !stopping, !restarting, !exiting else {
            errorMessage = "Stop capture before opening a UDP session."; return
        }
        if process == nil { launch(inspecting: .udp(url), fileBinding: .replace(nil)) }
        else { send("load_udp", ["path": url.path]) }
    }

    func applyRules(_ selectedRules: [ProxyRule]? = nil, connectTimeout: String? = nil, completion: ((Bool) -> Void)? = nil) {
        guard !settingsSaving else {
            errorMessage = "A settings save is still in progress. Wait for it to finish, then save your later edits."
            completion?(false); return
        }
        guard !isStarting, !stopping, !restarting, !exiting else {
            errorMessage = "Wait for Lens to finish starting or stopping before saving settings."
            completion?(false); return
        }
        do {
            let selectedTimeout = connectTimeout ?? connectTimeoutSeconds
            let network = try networkSettings(connectTimeout: selectedTimeout)
            let access = try accessPolicy.commandValue()
            let data = try JSONEncoder().encode(selectedRules ?? rules)
            let tcp: Any = try malformedForwardingPreferences["tcp_forwards"] ?? JSONSerialization.jsonObject(with: JSONEncoder().encode(tcpForwards))
            let udp: Any = try malformedForwardingPreferences["udp_forwards"] ?? JSONSerialization.jsonObject(with: JSONEncoder().encode(udpForwards))
            // Capture both representations before the asynchronous acknowledgment.
            // Later UI edits remain drafts, never part of this admitted Save.
            var preferenceFields = savedPreferenceFields
            preferenceFields.removeValue(forKey: "lan_clients")
            preferenceFields["http_upstream_proxy"] = httpUpstreamProxy
            preferenceFields.merge(["access_policy": access, "port": port, "ssl_hosts": sslHosts, "upload_kbps": uploadKbps, "download_kbps": downloadKbps, "connect_timeout_seconds": selectedTimeout, "socks_port": socksPort, "client_process": identifyClientProcesses, "reverse_port": reversePort, "reverse_url": reverseURL, "lan_address": lanAddress, "tcp_forwards": tcp, "udp_forwards": udp]) { _, selected in selected }
            let preferences = try JSONSerialization.data(withJSONObject: preferenceFields)
            let liveSave = isRunning
            let persist = { [weak self] in
                guard let self else { completion?(false); return }
                do {
                    try self.preserveForwardingRecovery()
                    if let original = self.pendingLANClientsRecovery {
                        let backup = self.dataDirectory.appendingPathComponent("preferences-lan-access-recovery-" + UUID().uuidString + ".json")
                        try original.write(to: backup, options: .withoutOverwriting)
                        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: backup.path)
                        self.pendingLANClientsRecovery = nil
                    }
                    if let original = self.pendingUpstreamProxyRecovery {
                        let backup = self.dataDirectory.appendingPathComponent("preferences-upstream-recovery-" + UUID().uuidString + ".json")
                        try original.write(to: backup, options: .withoutOverwriting)
                        self.pendingUpstreamProxyRecovery = nil
                    }
                    if let original = self.pendingConnectionTimeoutRecovery {
                        let backup = self.dataDirectory.appendingPathComponent("preferences-connection-recovery-" + UUID().uuidString + ".json")
                        try original.write(to: backup, options: .withoutOverwriting)
                        self.pendingConnectionTimeoutRecovery = nil
                    }
                    if self.rulesPreferencesIssue != nil && !self.rulesRecoverySaved {
                        let original = try self.pendingRulesRecovery ?? Data(contentsOf: self.dataDirectory.appendingPathComponent("rules.json"))
                        let backup = self.dataDirectory.appendingPathComponent("rules-recovery-" + UUID().uuidString + ".json")
                        try original.write(to: backup, options: .withoutOverwriting)
                        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: backup.path)
                        self.rulesRecoverySaved = true
                    }
                    try data.write(to: self.dataDirectory.appendingPathComponent("rules.json"), options: .atomic)
                    try preferences.write(to: self.dataDirectory.appendingPathComponent("preferences.json"), options: .atomic)
                    self.savedPreferenceFields = preferenceFields
                    self.connectTimeoutSeconds = selectedTimeout; self.connectionTimeoutPreferencesIssue = nil
                    if !liveSave, let selectedRules { self.rules = selectedRules }
                    if self.errorMessage == self.rulesPreferencesIssue { self.errorMessage = nil }
                    self.rulesPreferencesIssue = nil; self.pendingRulesRecovery = nil
                    self.settingsSaving = false
                    completion?(true)
                } catch {
                    self.settingsSaving = false
                    self.errorMessage = (liveSave ? "The running capture accepted these settings, but they could not be saved: " : "Settings could not be saved: ") + error.localizedDescription
                    completion?(false)
                }
            }
            guard isRunning else { persist(); return }
            settingsSaving = true
            send("configure", ["rules": try JSONSerialization.jsonObject(with: data), "access_policy": access, "ssl_hosts": sslHosts, "network": network], onError: { [weak self] reason in
                self?.settingsSaving = false
                self?.errorMessage = reason; completion?(false)
            }) { [weak self] _ in
                // The Rules sheet owns its draft until the actual engine accepts
                // it. Failed edits cannot poison a subsequent Start in memory.
                if let selectedRules { self?.rules = selectedRules }
                self?.connectTimeoutSeconds = selectedTimeout; self?.connectionTimeoutPreferencesIssue = nil
                persist()
            }
        } catch { settingsSaving = false; errorMessage = error.localizedDescription; completion?(false) }
    }
    func saveHTTPUpstreamProxy(_ value: String, completion: @escaping (Bool) -> Void) {
        guard !isRunning, !isStarting, !settingsSaving else { completion(false); return }
        if let issue = LensNetworkSettingsValidation.upstreamProxyIssue(value, socks: socksPort, reverse: reversePort, tcpCount: tcpForwards.count, udpCount: udpForwards.count) {
            errorMessage = issue; completion(false); return
        }
        let previous = httpUpstreamProxy
        httpUpstreamProxy = value
        applyRules { [weak self] success in
            if !success { self?.httpUpstreamProxy = previous }
            completion(success)
        }
    }

    func exportCSV(to url: URL, sessionID: String? = nil) throws {
        func cell(_ value: String) -> String { "\"" + value.replacingOccurrences(of: "\"", with: "\"\"") + "\"" }
        var rows = [["Method (display)", "URL (display)", "Status", "Started", "Duration ms", "Request bytes", "Response bytes", "Protocol", "State", "Source text facts (UTF-8 surrogatepass Base64)"]]
        rows += try filteredFlows(in: sessionID ?? currentSessionID).map { [$0.method, $0.url, $0.status.map(String.init) ?? "", ISO8601DateFormatter().string(from: Date(timeIntervalSince1970: $0.started)), $0.durationMs.map { String($0) } ?? "", $0.requestBodyAvailable == false ? "" : String($0.requestSize), $0.responseBodyAvailable == false ? "" : String($0.responseSize), $0.httpVersion, $0.state, String(data: try JSONEncoder().encode($0.sourceFacts), encoding: .utf8)!] }
        try rows.map { $0.map(cell).joined(separator: ",") }.joined(separator: "\r\n").write(to: url, atomically: true, encoding: .utf8)
    }
    func exportBody(side: String, to url: URL, sessionID: String? = nil, completion: @escaping (Result<Void, Error>) -> Void) {
        let room = sessionID ?? currentSessionID
        let selected = room == currentSessionID ? selection : sessionViews[room]?.selection
        guard let selection = selected else { completion(.failure(BodyExportFailure(message: "Select a request first."))); return }
        send("export_body", ["id": selection, "session_id": room, "side": side, "decoded": true], onError: { reason in
            completion(.failure(BodyExportFailure(message: reason)))
        }) { value in
            guard let base64 = value["base64"]?.unicodeString, let bytes = Data(base64Encoded: base64) else {
                completion(.failure(BodyExportFailure(message: "The body export did not return valid bytes."))); return
            }
            do { try bytes.write(to: url, options: .atomic); completion(.success(())) }
            catch { completion(.failure(error)) }
        }
    }
    func revealCertificate() {
        if !caCert.isEmpty { NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: caCert)]) }
    }
    func copyCurl() {
        guard acceptingNativeWrites, let flow = selectedFlow else { return }
        let room = currentSessionID
        loadFlowDetail(id: flow.id, sessionID: room) { [weak self] result in
            guard let self, self.acceptingNativeWrites else { return }
            do {
                let detail = try result.get()
                guard detail.requestBodyAvailable == true, let fingerprint = detail.requestFingerprint else { throw EngineJSONFailure.invalid("Cannot copy cURL: captured request body or fingerprint is unavailable. Compose an explicit replacement.") }
                if detail.requestUrlBase64 == nil { throw EngineJSONFailure.invalid("Cannot faithfully copy cURL: " + (detail.requestUrlUnavailableReason ?? "original request URL bytes are unavailable.")) }
                let plan = try CurlCommand.prepare(method: detail.bytes(detail.requestMethodBase64, label: "request method"),
                    url: detail.bytes(detail.requestUrlBase64, label: "request URL"), target: detail.bytes(detail.requestTargetBase64, label: "request target"),
                    targetForm: detail.requestTargetForm ?? "", proxyPort: self.port, headers: detail.requestHeaderFields, caCert: self.caCert.isEmpty ? nil : self.caCert)
                self.send("export_body", ["id": flow.id, "session_id": room, "side": "request", "decoded": false, "request_fingerprint": fingerprint], onError: { [weak self] reason in self?.errorMessage = reason }) { [weak self] value in
                    guard let self, self.acceptingNativeWrites else { return }
                    do {
                        guard let encoded = value["base64"]?.unicodeString else { throw EngineJSONFailure.invalid("Body export omitted its bytes") }
                        let bytes = try HTTPMessageDraft.valueBytes(encoded, encoding: .base64, limit: HTTPMessageDraft.fileBodyLimit)
                        self.nativeWrites.enter()
                        Task {
                            defer { self.nativeWrites.leave() }
                            do {
                                let directory = self.dataDirectory.appendingPathComponent("curl-bodies", isDirectory: true)
                                let file = try await Task.detached(priority: .utility) { bytes.isEmpty ? nil : try CurlCommand.saveBody(bytes, directory: directory) }.value
                                guard self.acceptingNativeWrites else { return }
                                NSPasteboard.general.clearContents(); NSPasteboard.general.setString(plan.render(bodyFile: file), forType: .string)
                                self.status = file == nil ? "Copied cURL" : "Copied cURL with a complete local request-body file"
                            } catch { self.errorMessage = error.localizedDescription }
                        }
                    } catch { self.errorMessage = error.localizedDescription }
                }
            } catch { self.errorMessage = error.localizedDescription }
        }
    }

}

private struct BodyExportFailure: LocalizedError {
    let message: String
    var errorDescription: String? { message }
}
