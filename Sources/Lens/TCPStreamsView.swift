import AppKit
import SwiftUI

struct LensTCPStreamsView: View {
    @ObservedObject var store: LensStore
    @Environment(\.dismiss) private var dismiss
    @State private var forwards: [TCPForwardSelection] = []
    @State private var selection: String?
    @State private var page: TCPChunkPage?
    @State private var offset = 0
    @State private var request = UUID()
    @State private var loading = false
    @State private var message = "TCP chunks are byte-stream observations, not application messages. TLS stays encrypted."
    @State private var showHex = true
    private var locked: Bool { store.isRunning || store.isStarting }
    private var issue: String? {
        LensNetworkSettingsValidation.listenerIssue(httpPort: store.port, socksPort: store.socksPort,
            reversePort: store.reversePort, reverseURL: store.reverseURL, tcpForwards: forwards)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("TCP forwarding & streams").font(.title2.weight(.semibold))
                Spacer()
                Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
            }
            DisclosureGroup("Forwarding endpoints · 127.0.0.1 only · changes apply on next Start") {
                Group {
                if let warning = store.tcpForwardingPreferencesIssue {
                    Label(warning, systemImage: "exclamationmark.triangle").font(.caption).foregroundStyle(.orange)
                }
                Text("Optional end includes every local port through that end. Each forwards to target base + local offset. Up to 32 listening ports per transport.")
                    .font(.caption).foregroundStyle(.secondary)
                ScrollView {
                    VStack {
                        ForEach($forwards) { $forward in
                            HStack {
                                TextField("Local start", text: $forward.listenPort).frame(width: 90)
                                Text("–")
                                TextField("End (optional)", text: Binding(get: { forward.listenPortEnd ?? "" }, set: { forward.listenPortEnd = $0.isEmpty ? nil : $0 })).frame(width: 110)
                                Text("→")
                                TextField("Target hostname or IP", text: $forward.targetHost)
                                TextField("Target base port", text: $forward.targetPort).frame(width: 100)
                                Button { forwards.removeAll { $0.id == forward.id } } label: { Image(systemName: "trash") }
                            }
                        }
                    }.textFieldStyle(.roundedBorder)
                }.frame(maxHeight: 130)
                HStack {
                    Button("Add TCP forward") { forwards.append(TCPForwardSelection()) }.disabled(ForwardEndpointValidation.configuredPortCount(forwards) >= ForwardEndpointValidation.maximumPorts)
                    if let issue { Text(issue).font(.caption).foregroundStyle(.orange) }
                    Spacer()
                    Button("Save forwarding settings") {
                        store.tcpForwards = forwards
                        store.applyRules { success in message = success ? "Saved. Start Lens to listen on these ports." : "Could not save settings." }
                    }.disabled(issue != nil || store.settingsSaving)
                }
                }.disabled(locked)
            }
            HStack {
                Text("\(store.tcpStreams.count) retained streams").foregroundStyle(.secondary)
                Spacer()
                Button("Open TCP session…", action: open).disabled(locked || loading)
                Button("Save TCP session…", action: save).disabled(!store.hasEngine || loading)
                Button("Clear streams") { store.send("clear_tcp") }.disabled(!store.hasEngine || loading)
            }
            Table(store.tcpStreams, selection: $selection) {
                TableColumn("Local") { Text(String($0.listenPort)) }.width(65)
                TableColumn("Target", value: \.target)
                TableColumn("State", value: \.state).width(85)
                TableColumn("Sent") { Text(String($0.sentBytes)) }.width(90)
                TableColumn("Received") { Text(String($0.receivedBytes)) }.width(90)
            }.frame(minHeight: 140, maxHeight: 220)
            HStack {
                Button("Refresh") { refresh() }.disabled(selection == nil || loading)
                Button("Previous") { offset = max(0, offset - 32); refresh() }.disabled(offset == 0 || loading)
                Button("Next") { offset += 32; refresh() }.disabled(page == nil || offset + 32 >= (page?.total ?? 0) || loading)
                if let page { Text("\(page.offset + 1)–\(min(page.offset + 32, page.total)) / \(page.total) retained chunks").font(.caption) }
                Spacer()
                Toggle("Hex", isOn: $showHex).toggleStyle(.switch)
            }
            if loading { ProgressView("Loading byte observations…") }
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    if let page {
                        Text("Observed peer: \(page.stream.peerLabel) · retained \(page.stream.retainedBytes) bytes")
                        if let source = page.stream.sourceState { Text("Historical source state: \(source). This is not a live connection.").foregroundStyle(.secondary) }
                        if page.stream.truncated { Label("Capture limit reached. These bytes are incomplete; forwarding continued.", systemImage: "exclamationmark.triangle").foregroundStyle(.orange) }
                        if let error = page.stream.error { Text(error).foregroundStyle(.red) }
                        ForEach(page.chunks) { chunk in
                            Text("#\(chunk.sequence) \(chunk.direction) · observed \(chunk.observedBytes) B, retained \(chunk.data.count) B · \(chunk.timestampLabel)").font(.caption).foregroundStyle(.secondary)
                            Text(showHex ? chunk.hex : chunk.text).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                        }
                    }
                }.frame(maxWidth: .infinity, alignment: .leading)
            }.frame(minHeight: 150)
            Text(message).font(.caption).foregroundStyle(.secondary)
            Text("Recording is selected when a connection starts. 4 MiB / 1024 chunks per stream; 32 MiB total including chunk accounting. HTTP HAR files do not contain these raw streams.").font(.caption).foregroundStyle(.secondary)
        }.padding(22).frame(width: 940, height: 780)
        .onAppear { forwards = store.tcpForwards }
        .onChange(of: selection) { offset = 0; refresh() }
        .onChange(of: store.tcpGeneration) {
            selection = nil; page = nil; loading = false; offset = 0; request = UUID()
        }
        .onChange(of: store.tcpStreams.map(\.id)) {
            if let selection, !store.tcpStreams.contains(where: { $0.id == selection }) {
                self.selection = nil; page = nil; loading = false; request = UUID()
            }
        }
    }

    private func refresh() {
        request = UUID(); let token = request
        page = nil
        guard let selection else { loading = false; return }
        loading = true
        store.send("tcp_detail", ["id": selection, "offset": offset], onError: { reason in
            guard request == token else { return }; loading = false; message = reason
        }) { value in
            guard request == token, self.selection == selection else { return }
            loading = false
            do {
                page = try value.decode(TCPChunkPage.self)
                message = "Chunks preserve bytes and direction. Their boundaries are local observations."
            } catch { message = "Cannot read TCP details: \(error.localizedDescription)" }
        }
    }
    private func open() {
        let panel = NSOpenPanel(); panel.canChooseDirectories = false; panel.allowsMultipleSelection = false
        panel.begin { response in
            guard response == .OK, let url = panel.url else { return }
            store.openTCPSession(url)
        }
    }
    private func save() {
        let panel = NSSavePanel(); panel.nameFieldStringValue = "capture.lens-tcp.json"
        panel.begin { response in
            guard response == .OK, let url = panel.url else { return }
            loading = true
            store.send("save_tcp", ["path": url.path], onError: { reason in loading = false; message = reason }) { _ in
                loading = false; message = "Saved TCP session to \(url.path)."
            }
        }
    }
}
