import AppKit
import SwiftUI

private enum InspectorTab: String, CaseIterable {
    case overview = "Overview", request = "Request", response = "Response", websocket = "WebSocket"
}

struct LensWorkspaceView: View {
    @ObservedObject var store: LensStore
    @ObservedObject private var systemProxy: SystemProxyController
    @State private var composeTarget: ComposeTarget?
    @State private var showRules = false
    @State private var showAccessLists = false
    @State private var showConnection = false
    @State private var repeatTarget: RepeatTarget?
    @State private var showNetworkSettings = false
    @State private var showTCPStreams = false
    @State private var showUDPDatagrams = false
    @State private var connectionPage = LensConnectionPage.welcome

    init(store: LensStore) { self.store = store; self.systemProxy = store.systemProxy }

    var body: some View {
        VStack(spacing: 0) {
            macCaptureStatus
            Divider()
            sessionBar
            Divider()
            HSplitView {
                sidebar.frame(minWidth: 170, idealWidth: 200, maxWidth: 300)
                traffic.frame(minWidth: 420, idealWidth: 650)
                LensInspectorView(store: store).id(store.currentSessionID).frame(minWidth: 340, idealWidth: 440)
            }
            Divider()
            statusBar
        }
        .background(Color(nsColor: .windowBackgroundColor))
        .navigationTitle(store.workspaceWindowTitle)
        .toolbar { workspaceToolbar }
        .searchable(text: $store.search, placement: .toolbar, prompt: "Filter traffic")
        .sheet(item: $composeTarget) { target in LensComposeView(store: store, target: target) }
        .sheet(isPresented: $showRules) { LensRulesView(store: store) }
        .sheet(isPresented: $showAccessLists) { LensAccessListsView(store: store) }
        .sheet(isPresented: $showConnection) { LensConnectionView(store: store, page: connectionPage) }
        .sheet(item: $repeatTarget) { target in LensRepeatView(store: store, source: target.source) }
        .sheet(isPresented: $showNetworkSettings) { LensNetworkSettingsView(store: store) }
        .sheet(isPresented: $showTCPStreams) { LensTCPStreamsView(store: store).id(store.currentSessionID) }
        .sheet(isPresented: $showUDPDatagrams) { LensUDPDatagramsView(store: store).id(store.currentSessionID) }
        .sheet(item: $store.sessionAction) { target in LensSessionActionView(store: store, target: target) }
        .sheet(isPresented: $store.showSessionStorage) { LensSessionToolsView(store: store).id(store.currentSessionID) }
        .onChange(of: store.selection) { store.loadDetail() }
        .onAppear {
            if !systemProxy.hasCaptureChoice { connectionPage = .welcome; showConnection = true }
            systemProxy.refreshRouting()
        }
        .onReceive(Timer.publish(every: 5, on: .main, in: .common).autoconnect()) { _ in systemProxy.refreshRouting() }
        .alert("Lens", isPresented: Binding(get: { store.errorMessage != nil && !store.quitPending }, set: { if !$0 { store.errorMessage = nil } })) {
            Button("OK") { store.errorMessage = nil }
        } message: { Text(store.errorMessage ?? "") }
    }

    private var macCaptureStatus: some View {
        let routed = Int(store.port).map { systemProxy.routing?.usesLens(port: $0) == true } ?? false
        let lanReady = store.isRunning && store.activeLANAddress != nil
        return HStack(alignment: .center, spacing: 12) {
            Image(systemName: (routed && store.isRunning) || lanReady ? "checkmark.circle.fill" : "exclamationmark.circle")
                .foregroundStyle((routed && store.isRunning) || lanReady ? Color.green : Color.orange)
            VStack(alignment: .leading, spacing: 3) {
                Text(captureHeading)
                    .font(.callout.weight(.semibold))
                Text(captureExplanation)
                    .font(.caption).foregroundStyle(store.startupIssue == nil && systemProxy.error == nil ? Color.secondary : Color.red).textSelection(.enabled)
            }
            Spacer(minLength: 10)
            Button("Get Started") { connectionPage = .welcome; showConnection = true }
        }.padding(.horizontal, 14).padding(.vertical, 9)
    }

    private var captureHeading: String {
        if store.isStarting { return "Starting capture proxy…" }
        if let issue = store.startupIssue { return issue.title }
        if !store.isRunning { return "Proxy stopped" }
        if let address = store.activeLANAddress { return "Device proxy ready · \(address):\(store.port)" }
        if systemProxy.isBusy { return "Checking Mac proxy setup…" }
        if Int(store.port).map({ systemProxy.routing?.usesLens(port: $0) == true }) == true { return "Mac HTTP & HTTPS proxy points to Lens" }
        return systemProxy.routing == nil ? "Mac proxy status unavailable — review setup" : "Mac traffic is not connected to Lens"
    }

    private var captureExplanation: String {
        if let issue = store.startupIssue { return issue.message }
        if let error = systemProxy.error { return error }
        if store.isRunning, store.activeLANAddress != nil {
            return "Set this proxy in the device Wi-Fi settings, then open http://lens.invalid/ to verify the connection. HTTPS also requires CA trust. A ready LAN proxy does not mean the device is connected."
        }
        if store.isRunning, Int(store.port).map({ systemProxy.routing?.usesLens(port: $0) == true }) == true {
            return "Apps using the system proxy can connect. HTTPS bodies also need trusted Lens certificates and matching SSL hosts."
        }
        return "Choose this Mac, Android or iPhone, then follow Get Started to set up the proxy and HTTPS."
    }

    private var sessionBar: some View {
            HStack {
                ScrollView(.horizontal) {
                    HStack(spacing: 6) {
                        ForEach(store.sessions) { session in
                            Button { store.selectSession(session.id) } label: {
                                HStack(spacing: 5) {
                                    if session.id == store.captureSessionID { Image(systemName: "record.circle").foregroundStyle(store.recording ? Color.red : Color.secondary) }
                                    Text(session.name).lineLimit(1)
                                }.padding(.horizontal, 8).padding(.vertical, 5)
                            }.buttonStyle(.borderless)
                             .background(store.currentSessionID == session.id ? Color.accentColor.opacity(0.14) : Color.clear, in: RoundedRectangle(cornerRadius: 5))
                             .contextMenu {
                                Button("Rename Session…") { store.presentSessionAction(.rename, identity: session.id) }
                                Button("Close Session…") { store.presentSessionAction(.close, identity: session.id) }
                                Button("Clear HTTP traffic…") { store.presentSessionAction(.clearHTTP, identity: session.id) }
                                    .disabled(store.flows(in: session.id).isEmpty)
                             }
                             .accessibilityLabel(session.name + (session.id == store.captureSessionID ? ", recording session" : ""))
                        }
                    }
                }
                Button(action: store.newSession) { Label("New Session", systemImage: "plus") }.disabled(!store.canCreateSession)
            }.padding(.horizontal, 12).padding(.vertical, 6)
    }

    private var sidebar: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text("STRUCTURE").font(.caption.weight(.semibold)).foregroundStyle(.secondary).padding(14)
            List {
                Button { store.selectedHost = nil } label: {
                    Label { HStack { Text("All traffic"); Spacer(); Text("\(store.flows.count)").foregroundStyle(.secondary) } } icon: { Image(systemName: "network") }
                }
                .buttonStyle(.plain)
                .listRowBackground(store.selectedHost == nil ? Color.accentColor.opacity(0.14) : Color.clear)
                Section("Hosts") {
                    ForEach(store.hosts, id: \.self) { host in
                        DisclosureGroup {
                            ForEach(pathGroups(for: host)) { group in
                                DisclosureGroup {
                                    ForEach(group.flows) { flow in
                                        Button { store.selectedHost = host; store.selection = flow.id } label: {
                                            VStack(alignment: .leading, spacing: 2) {
                                                Text(flow.path).lineLimit(1).help(flow.url)
                                                Text("\(flow.method) · \(flow.statusLabel)").font(.caption2).foregroundStyle(.secondary)
                                            }
                                            .padding(.vertical, 2)
                                        }
                                        .buttonStyle(.plain)
                                        .listRowBackground(store.selection == flow.id ? Color.accentColor.opacity(0.14) : Color.clear)
                                    }
                                } label: {
                                    HStack { Label(group.path, systemImage: "folder").lineLimit(1); Spacer(); Text("\(group.flows.count)").font(.caption).foregroundStyle(.secondary) }
                                }
                            }
                        } label: {
                            Button { store.selectedHost = host } label: {
                                Label(host.isEmpty ? "Unknown host" : host, systemImage: "server.rack")
                                    .lineLimit(1).help(host)
                            }.buttonStyle(.plain)
                        }
                        .listRowBackground(store.selectedHost == host ? Color.accentColor.opacity(0.14) : Color.clear)
                    }
                }
            }
            .listStyle(.sidebar)
            Spacer(minLength: 0)
            VStack(alignment: .leading, spacing: 6) {
                Label("Local proxy", systemImage: "lock.shield")
                    .font(.caption.weight(.medium))
                Text("127.0.0.1:\(store.port)").font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary)
            }.padding(14)
        }
    }

    private func pathGroups(for host: String) -> [LensPathGroup] {
        let grouped = Dictionary(grouping: store.flows.filter { $0.host == host }) { flow -> String in
            let path = flow.path.split(separator: "?", maxSplits: 1, omittingEmptySubsequences: false).first ?? "/"
            return path.split(separator: "/").first.map { "/" + String($0) } ?? "/"
        }
        return grouped.keys.sorted().map { LensPathGroup(path: $0, flows: grouped[$0] ?? []) }
    }

    private var traffic: some View {
        VStack(spacing: 0) {
            HStack {
                Text("Sequence").font(.headline)
                Text("\(store.filteredFlows.count)").font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                Spacer()
                if let host = store.selectedHost {
                    Button { store.selectedHost = nil } label: { Label(host, systemImage: "xmark.circle.fill").lineLimit(1) }
                        .buttonStyle(.borderless).font(.caption)
                }
            }.padding(12)
            Divider()
            if store.filteredFlows.isEmpty {
                ContentUnavailableView {
                    Label(store.flows.isEmpty ? "Traffic starts here" : "No matching requests", systemImage: store.flows.isEmpty ? "point.3.connected.trianglepath.dotted" : "line.3.horizontal.decrease.circle")
                } description: {
                    Text(store.flows.isEmpty ? (store.isStarting ? "The proxy is starting. Wait for it to become ready." : !store.isRunning ? "Choose a device to inspect. The guide will help you start the proxy and connect it." : !store.recording ? "The proxy is forwarding traffic, but recording is paused. Resume recording to see new requests here." : store.activeLANAddress != nil ? "Your device must use the Mac LAN proxy. Open http://lens.invalid/ in its browser, then follow the guide to set up HTTPS." : "The local proxy is running. Enable LAN access for devices, or connect the Mac browser through the system proxy.") : "Try another filter or choose All traffic.")
                } actions: {
                    if store.flows.isEmpty {
                        HStack {
                            Button("Android") { connectionPage = .android; showConnection = true }
                            Button("iPhone / iPad") { connectionPage = .ios; showConnection = true }
                            Button("This Mac") { connectionPage = .system; showConnection = true }
                        }
                        if store.isRunning && !store.recording { Button("Resume Recording", action: store.toggleRecording) }
                    } else {
                        Button("Clear Filters") { store.search = ""; store.selectedHost = nil }
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                Table(store.filteredFlows, selection: $store.selection) {
                    TableColumn("Method") { flow in Text(flow.method).font(.system(.caption, design: .monospaced).weight(.semibold)) }.width(62)
                    TableColumn("Status") { flow in Text(flow.statusLabel).foregroundStyle(statusColor(flow)).font(.caption.monospacedDigit()) }.width(62)
                    TableColumn("Host", value: \.host).width(min: 100, ideal: 150)
                    TableColumn("Path") { flow in HStack(spacing: 4) { if flow.replayed { Image(systemName: "arrow.clockwise").help("Replayed request") }; Text(flow.path).lineLimit(1).help(flow.url) } }.width(min: 110, ideal: 240)
                    TableColumn("Time") { flow in Text(flow.durationLabel).font(.caption.monospacedDigit()).foregroundStyle(.secondary) }.width(75)
                    TableColumn("Size") { flow in Text(flow.sizeLabel).font(.caption.monospacedDigit()).foregroundStyle(.secondary) }.width(72)
                }
                .contextMenu {
                    Button("Replay", action: store.replay).disabled(store.selection == nil || !store.isRunning)
                    Button("Copy cURL", action: store.copyCurl).disabled(store.selection == nil || !store.isRunning)
                }
            }
        }
    }

    private var statusBar: some View {
        HStack(spacing: 8) {
            Circle().fill(store.isRunning ? (store.recording ? Color.green : Color.orange) : Color.secondary).frame(width: 7, height: 7)
            Text(store.status).lineLimit(1)
            if store.currentSessionID != store.captureSessionID { Text("Recording into " + store.captureSessionName).foregroundStyle(.orange) }
            if store.isRunning && !store.recording { Text("Recording paused").foregroundStyle(.orange) }
            Spacer()
            Text("\(store.flows.count) requests")
            Text("·")
            Text(store.totalBytes)
        }
        .font(.caption).foregroundStyle(.secondary).padding(.horizontal, 14).padding(.vertical, 8)
    }

    @ToolbarContentBuilder private var workspaceToolbar: some ToolbarContent {
        ToolbarItemGroup(placement: .navigation) {
            Button { store.isRunning || store.isStarting ? store.stop() : store.start() } label: {
                Label(store.isRunning || store.isStarting ? "Stop" : "Start", systemImage: store.isRunning || store.isStarting ? "stop.fill" : "play.fill")
            }.help("Start or stop the local proxy")
            Button(action: store.toggleRecording) { Label(store.recording ? "Pause recording" : "Resume recording", systemImage: store.recording ? "pause.circle" : "record.circle") }
                .help(store.recording ? "Pause capture" : "Resume capture")
            Button { store.presentSessionAction(.clearHTTP) } label: { Label("Clear", systemImage: "trash") }
                .help("Clear HTTP traffic in this session").disabled(!store.hasEngine || !store.canCreateSession || store.flows.isEmpty)
        }
        ToolbarItemGroup {
            Button(action: store.replay) { Label("Replay", systemImage: "arrow.clockwise") }.disabled(store.selection == nil || !store.isRunning)
            Button { if let source = store.selectedFlow { repeatTarget = RepeatTarget(source: source) } } label: { Label("Repeat", systemImage: "repeat") }.disabled(store.selection == nil || !store.isRunning)
            Menu {
                Button("Compose selected request…") { composeTarget = ComposeTarget(source: store.selectedFlow, sessionID: store.currentSessionID) }.disabled(store.selectedFlow == nil)
                Button("Compose new request…") { composeTarget = ComposeTarget(source: nil, sessionID: store.currentSessionID) }
            } label: { Label("Compose", systemImage: "square.and.pencil") }
              primaryAction: { composeTarget = ComposeTarget(source: store.selectedFlow, sessionID: store.currentSessionID) }
                .disabled(!store.isRunning)
            Button { showRules = true } label: { Label("Rules", systemImage: "slider.horizontal.3") }
            Button { showAccessLists = true } label: { Label("Access Lists", systemImage: "hand.raised") }
            Menu {
                Button("New Session", action: store.newSession).disabled(!store.canCreateSession)
                Button("Rename Session…") { store.presentSessionAction(.rename) }.disabled(!store.hasEngine || !store.canCreateSession)
                Button("Close Session…") { store.presentSessionAction(.close) }.disabled(!store.hasEngine || !store.canCreateSession)
                Button("Clear HTTP traffic…") { store.presentSessionAction(.clearHTTP) }.disabled(!store.hasEngine || !store.canCreateSession || store.flows.isEmpty)
                Button("Open workspace copy…") { store.presentSessionAction(.openWorkspace) }.disabled(!store.hasEngine || !store.canCreateSession)
                Button("Record in this session", action: store.recordInCurrentSession).disabled(!store.hasEngine || store.currentSessionID == store.captureSessionID)
                Divider()
                Button("Session files…") { store.showSessionStorage = true }
                Divider()
                Button("Copy cURL", action: store.copyCurl).disabled(store.selection == nil || !store.isRunning)
            } label: { Label("Session", systemImage: "square.and.arrow.up") }
            Button { showNetworkSettings = true } label: { Label("Network", systemImage: "speedometer") }
            Button { showTCPStreams = true } label: { Label("TCP streams", systemImage: "arrow.left.arrow.right") }
            Button { showUDPDatagrams = true } label: { Label("UDP datagrams", systemImage: "point.3.connected.trianglepath.dotted") }
            Menu {
                Button("Get Started") { connectionPage = .welcome; showConnection = true }
                Button("Android") { connectionPage = .android; showConnection = true }
                Button("iPhone / iPad") { connectionPage = .ios; showConnection = true }
                Button("Mac capture setup") { connectionPage = .system; showConnection = true }
                Button("Other clients") { connectionPage = .client; showConnection = true }
            } label: { Label("Connection", systemImage: "cable.connector") }
              primaryAction: { connectionPage = .welcome; showConnection = true }
        }
    }

    private func statusColor(_ flow: TrafficFlow) -> Color {
        if flow.state == "paused" { return .orange }
        if flow.error != nil || (flow.status ?? 0) >= 400 { return .red }
        if (flow.status ?? 0) >= 200 && (flow.status ?? 0) < 300 { return .green }
        return .secondary
    }
}

private struct LensInspectorView: View {
    @ObservedObject var store: LensStore
    @State private var tab = InspectorTab.overview
    @State private var breakpointDraft: BreakpointDraft?

    var body: some View {
        VStack(spacing: 0) {
            HStack { Text("Inspector").font(.headline); Spacer(); Button(action: store.copyCurl) { Image(systemName: "terminal") }.buttonStyle(.borderless).help("Copy as cURL").disabled(store.selectedFlow == nil) }.padding(12)
            Divider()
            if let flow = store.selectedFlow {
                VStack(alignment: .leading, spacing: 12) {
                    HStack { Text(flow.method).font(.caption.weight(.bold)); Text(flow.statusLabel).font(.caption).foregroundStyle(flow.state == "paused" ? .orange : .secondary); Spacer(); if flow.isWebsocket { Image(systemName: "arrow.left.arrow.right").help("WebSocket") } }
                    Text(flow.url).font(.system(.caption, design: .monospaced)).textSelection(.enabled).lineLimit(3)
                    Picker("Inspector", selection: $tab) { ForEach(InspectorTab.allCases, id: \.self) { Text($0.rawValue).tag($0) } }.pickerStyle(.segmented).labelsHidden()
                }.padding(12)
                Divider()
                if let error = flow.error, !error.isEmpty {
                    HStack(alignment: .top, spacing: 8) {
                        Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.red)
                        LensBodyTextView(text: error, title: "Transaction error").frame(height: 80)
                    }.padding(12)
                    Divider()
                }
                inspectorContent(flow)
                if flow.state == "paused" {
                    Divider()
                    VStack(alignment: .leading, spacing: 8) {
                        Label("Breakpoint paused", systemImage: "pause.circle.fill").font(.caption.weight(.semibold)).foregroundStyle(.orange)
                        Text("Edit the paused message, continue with its original bytes, or abort.").font(.caption).foregroundStyle(.secondary)
                        if let deadline = flow.pauseDeadline {
                            Text("Aborts at \(Date(timeIntervalSince1970: deadline).formatted(date: .omitted, time: .standard)) · \(flow.pauseTimeoutSeconds ?? 60)s limit")
                                .font(.caption).foregroundStyle(.orange)
                        }
                        HStack {
                            Button("Abort", role: .destructive) { resume(flow, abort: true) }
                            Spacer()
                            Button("Edit message…") { if let detail = store.detail { breakpointDraft = BreakpointDraft(flow: flow, detail: detail) } }.disabled(store.detail?.id != flow.id || store.detailLoading || store.detailError != nil || flow.pauseId == nil || store.detail?.pauseId != flow.pauseId || store.detail?.pauseStage != flow.breakpointStage)
                            Button("Continue unchanged") { resume(flow) }.buttonStyle(.borderedProminent).disabled(flow.pauseId == nil)
                        }
                    }.padding(12)
                }
            } else {
                ContentUnavailableView("Inspect a request", systemImage: "sidebar.right", description: Text("Select a row to inspect headers, bodies, timing, and WebSocket messages."))
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .sheet(item: $breakpointDraft) { draft in BreakpointEditor(store: store, draft: draft) }
    }

    @ViewBuilder private func inspectorContent(_ flow: TrafficFlow) -> some View {
        switch tab {
        case .overview:
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    if let original = flow.originalUrl, original != flow.url { detailRow("Original URL", original) }
                    detailRow("URL", flow.url)
                    detailRow("Request target source", flow.requestTargetSourceLabel)
                    if let routed = flow.routedUrl, Data(routed.utf8) != Data(flow.url.utf8) {
                        detailRow(flow.requestTargetSource == "har_url" ? "HAR-derived routing URL" : "Routing URL", routed)
                    }
                    if let edited = flow.breakpointUrl { detailRow("Edited URL input", edited) }
                    if let address = flow.dnsAddress { detailRow("DNS mapping (configured IP)", address) }
                    detailRow("Host", flow.host)
                    detailRow("Protocol", "\(flow.scheme.uppercased()) · \(flow.httpVersion)")
                    detailRow("Started", Date(timeIntervalSince1970: flow.started).formatted(date: .abbreviated, time: .standard))
                    detailRow("Duration", flow.durationLabel)
                    detailRow("Request size", flow.requestBodyAvailable == false ? "Unavailable" : ByteCountFormatter.string(fromByteCount: Int64(flow.requestSize), countStyle: .file))
                    detailRow("Response size", flow.sizeLabel)
                    detailRow("Content type", flow.contentType.isEmpty ? "—" : flow.contentType)
                    detailRow("State", flow.state)
                    if let operation = flow.requestOperation {
                        detailRow("Request operation", operation.kind.capitalized)
                        detailRow("Operation ID", operation.id)
                        detailRow("Source flow ID", operation.sourceId ?? "Not supplied")
                        if let attempt = operation.attempt { detailRow("Repeat attempt", String(attempt)) }
                        if let input = operation.urlInput { detailRow("Composed URL input", input) }
                    } else { detailRow("Request operation", "Not recorded") }
                    if let decision = flow.accessDecision {
                        detailRow("Access List decision", decision.reasonLabel)
                        detailRow("Denial action", decision.actionLabel)
                        detailRow("Policy URL", decision.matchedUrl)
                        if let pattern = decision.pattern { detailRow("Matched URL pattern", pattern) }
                    } else {
                        detailRow("Access List decision", "Not recorded")
                    }
                    if let connection = flow.clientConnection {
                        detailRow("Observed TCP peer", connection.peer.label)
                        detailRow("Proxy listener", "\(connection.listenerLabel) · \(connection.listenerAddress.label)")
                        detailRow("Client connection ID", connection.id)
                        if let process = connection.process {
                            detailRow("Host client process", process.label)
                            if let identity = process.startIdentity { detailRow("Process start identity", identity) }
                            if let bytes = process.nameBytesBase64 { detailRow("Process name bytes (Base64)", bytes) }
                            detailRow("Process observed", Date(timeIntervalSince1970: process.observedAt).formatted(date: .abbreviated, time: .standard))
                            Text("Host TCP socket ownership observed at connection time. An emulator or forwarding process does not identify an app on the remote device.").font(.caption).foregroundStyle(.secondary)
                        } else {
                            detailRow("Host client process", "Not recorded")
                        }
                        Text(flow.imported == true ? "Connection facts were retained from the imported source." : "Socket observations identify the connected peer. Forwarded headers and NAT do not establish an original device or process identity.")
                            .font(.caption).foregroundStyle(.secondary)
                    } else {
                        detailRow("Observed TCP peer", "Not recorded")
                    }
                    if flow.replayed && flow.requestOperation == nil { Label("Replayed request", systemImage: "arrow.clockwise").font(.caption).foregroundStyle(.secondary) }
                }.padding(16).frame(maxWidth: .infinity, alignment: .leading)
            }
        case .request:
            if let detail = store.detail { LensMessageView(title: "Request", headers: detail.requestHeaderFields, rawBody: detail.requestBody, available: detail.requestBodyAvailable ?? flow.requestBodyAvailable ?? true, truncated: detail.requestTruncated, bodyBase64: detail.requestBodyBase64, binary: detail.requestBinary ?? false).id(flow.id + "/request") } else { detailPlaceholder }
        case .response:
            if let detail = store.detail { LensMessageView(title: "Response", headers: detail.responseHeaderFields, rawBody: detail.responseBody, available: detail.responseBodyAvailable ?? flow.responseBodyAvailable ?? true, truncated: detail.responseTruncated, bodyBase64: detail.responseBodyBase64, binary: detail.responseBinary ?? false).id(flow.id + "/response") } else { detailPlaceholder }
        case .websocket:
            if let detail = store.detail { LensWebSocketView(store: store, detail: detail).id(flow.id) }
            else { detailPlaceholder }
        }
    }

    @ViewBuilder private var detailPlaceholder: some View {
        if store.detailLoading {
            VStack { ProgressView(); Text("Loading details…").font(.caption).foregroundStyle(.secondary) }.frame(maxWidth: .infinity, maxHeight: .infinity)
        } else {
            VStack(spacing: 12) {
                Label("Details unavailable", systemImage: "exclamationmark.triangle")
                Text(store.detailError ?? "Select the request again to load its details.").font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
                Button("Retry", action: store.loadDetail)
            }.padding().frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }
    private func detailRow(_ name: String, _ value: String) -> some View { VStack(alignment: .leading, spacing: 4) { Text(name).font(.caption.weight(.semibold)).foregroundStyle(.secondary); Text(value).font(.system(.callout, design: .monospaced)).textSelection(.enabled) } }
    private func resume(_ flow: TrafficFlow, abort: Bool = false) {
        guard let pause = flow.pauseId else { store.errorMessage = "This paused flow has no current breakpoint identity."; return }
        store.resumeBreakpoint(flowID: flow.id, sessionID: flow.sessionId, pauseID: pause, stage: flow.breakpointStage, abort: abort) { error in
            if let error { store.errorMessage = error }
        }
    }
}

private struct LensMessageView: View {
    let title: String
    let headers: [HTTPHeaderField]
    let rawBody: String
    let available: Bool
    let truncated: Bool
    let bodyBase64: String?
    let binary: Bool
    @State private var format = BodyFormat.json
    @State private var renderedBody = ""
    @State private var renderedInput: BodyRenderInput?
    @State private var jsonPresentation: JSONPresentation?
    @State private var headersExpanded = true

    private var contentTypes: [Data] { headers.filter { $0.nameText?.lowercased() == "content-type" }.map(\.value) }
    private var preferredFormat: BodyFormat { BodyFormatter.preferredFormat(binary: binary, contentTypes: contentTypes) }
    private var renderInput: BodyRenderInput { BodyRenderInput(format: format, text: rawBody, base64: bodyBase64, truncated: truncated, contentTypes: contentTypes) }
    private var hasPreview: Bool { !rawBody.isEmpty || !(bodyBase64 ?? "").isEmpty }
    private var renderingComplete: Bool { renderedInput == renderInput }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                DisclosureGroup(isExpanded: $headersExpanded) {
                    if headers.isEmpty { Text("No headers captured").font(.caption).foregroundStyle(.secondary) }
                    else { Text(headersText).font(.system(.caption, design: .monospaced)).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading) }
                } label: {
                    HStack { Text("Headers · \(headers.count)").font(.subheadline.weight(.semibold)); Spacer(); copyButton(headersText) }
                }
                Divider().padding(.vertical, 4)
                HStack {
                    Text("Body").font(.subheadline.weight(.semibold))
                    Spacer()
                    Picker("Format", selection: $format) {
                        ForEach(BodyFormat.allCases) { Text($0.label).tag($0) }
                    }.labelsHidden().frame(width: 130)
                    if format != .json || jsonPresentation?.document == nil {
                        copyButton(renderedBody).disabled(!available || !renderingComplete).help("Copy displayed body")
                    }
                }
                if truncated {
                    Label("Preview limited to 2 MiB. Save the body for retained bytes; capture is limited to 32 MiB per body.", systemImage: "exclamationmark.triangle")
                        .font(.caption).foregroundStyle(.orange)
                }
                if !available {
                    Label("Body unavailable", systemImage: "questionmark.square.dashed").font(.subheadline).foregroundStyle(.secondary)
                    Text("The capture does not include these bytes. An unavailable body is different from a captured empty body.").font(.caption).foregroundStyle(.secondary)
                } else if !hasPreview { Text("Empty body").font(.caption).foregroundStyle(.secondary) }
                else if renderingComplete {
                    if let document = jsonPresentation?.document, format == .json {
                        LensJSONBodyView(document: document, title: title).id(document.id)
                    } else {
                        if format == .json, let issue = jsonPresentation?.issue {
                            Label(issue, systemImage: "exclamationmark.triangle").font(.caption).foregroundStyle(.orange)
                        }
                        LensBodyTextView(text: renderedBody, title: title).frame(height: 420)
                    }
                } else { ProgressView("Formatting…").controlSize(.small).font(.caption) }
            }.padding(14)
        }
        .onAppear { format = preferredFormat }
        .onChange(of: binary) { format = preferredFormat }
        .onChange(of: contentTypes) { format = preferredFormat }
        // State retains this exact input's result across unrelated flow updates.
        // Changing the input cancels its task; the shared actor owns bounded CPU work.
        .task(id: !available ? nil : renderInput) {
            renderedInput = nil
            renderedBody = ""
            jsonPresentation = nil
            guard available, hasPreview else { return }
            let input = renderInput
            if input.format == .json {
                guard let result = await BodyRenderWorker.shared.renderJSON(input), !Task.isCancelled else { return }
                jsonPresentation = result; renderedBody = result.text; renderedInput = input
                return
            }
            guard let result = await BodyRenderWorker.shared.render(input), !Task.isCancelled else { return }
            renderedBody = result
            renderedInput = input
        }
    }
    private var headersText: String { headers.map { $0.displayName + ": " + $0.displayValue }.joined(separator: "\n") }
    private func copyButton(_ value: String) -> some View { Button { lensCopy(value) } label: { Image(systemName: "doc.on.doc") }.buttonStyle(.borderless).help("Copy \(title.lowercased()) content") }
}


func lensCopy(_ value: String) { NSPasteboard.general.clearContents(); NSPasteboard.general.setString(value, forType: .string) }

private struct LensPathGroup: Identifiable {
    let path: String
    let flows: [TrafficFlow]
    var id: String { path }
}
