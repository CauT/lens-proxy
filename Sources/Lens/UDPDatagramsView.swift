import AppKit
import SwiftUI

struct LensUDPDatagramsView: View {
    @ObservedObject var store: LensStore
    @Environment(\.dismiss) private var dismiss
    @State private var forwards: [UDPForwardSelection] = []
    @State private var selection: String?
    @State private var page: UDPDatagramPage?
    @State private var datagramPreviews: [Int: DatagramPreview] = [:]
    @State private var expandedSequence: Int?
    @State private var expandedPreview: DatagramPreview?
    @State private var offset = 0
    @State private var request = UUID()
    @State private var loading = false
    @State private var message = "UDP observations preserve individual forwarded datagrams, including empty payloads. Encrypted protocols stay encrypted."
    @State private var showHex = true
    private var locked: Bool { store.isRunning || store.isStarting }
    private var issue: String? {
        LensNetworkSettingsValidation.listenerIssue(httpPort: store.port, socksPort: store.socksPort,
            reversePort: store.reversePort, reverseURL: store.reverseURL, tcpForwards: store.tcpForwards, udpForwards: forwards)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("UDP forwarding & datagrams").font(.title2.weight(.semibold))
                Spacer()
                Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
            }
            DisclosureGroup("Forwarding endpoints · 127.0.0.1 only · changes apply on next Start") {
                Group {
                if let warning = store.udpForwardingPreferencesIssue {
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
                    Button("Add UDP forward") { forwards.append(UDPForwardSelection()) }.disabled(ForwardEndpointValidation.configuredPortCount(forwards) >= ForwardEndpointValidation.maximumPorts)
                    if let issue { Text(issue).font(.caption).foregroundStyle(.orange) }
                    Spacer()
                    Button("Save forwarding settings") {
                        store.udpForwards = forwards
                        store.applyRules { success in message = success ? "Saved. Start Lens to listen on these ports." : "Could not save settings." }
                    }.disabled(issue != nil || store.settingsSaving)
                }
                }.disabled(locked)
            }
            HStack {
                Text("\(store.udpAssociations.count) retained associations").foregroundStyle(.secondary)
                Spacer()
                Button("Open UDP session…", action: open).disabled(locked || loading)
                Button("Save UDP session…", action: save).disabled(!store.hasEngine || loading)
                Button("Clear associations") { store.send("clear_udp") }.disabled(!store.hasEngine || loading)
            }
            Table(store.udpAssociations, selection: $selection) {
                TableColumn("Local") { Text(String($0.listenPort)) }.width(65)
                TableColumn("Target", value: \.target)
                TableColumn("State", value: \.state).width(85)
                TableColumn("Sent") { Text("\($0.sentDatagrams) / \($0.sentBytes) B") }.width(115)
                TableColumn("Received") { Text("\($0.receivedDatagrams) / \($0.receivedBytes) B") }.width(115)
            }.frame(minHeight: 140, maxHeight: 220)
            HStack {
                Button("Refresh") { refresh() }.disabled(selection == nil || loading)
                Button("Previous") { offset = max(0, offset - 32); refresh() }.disabled(offset == 0 || loading)
                Button("Next") { offset += 32; refresh() }.disabled(page == nil || offset + 32 >= (page?.total ?? 0) || loading)
                if let page { Text(page.total == 0 ? "0 retained datagrams" : "\(page.offset + 1)–\(min(page.offset + 32, page.total)) / \(page.total) retained datagrams").font(.caption) }
                Spacer()
                Toggle("Hex", isOn: $showHex).toggleStyle(.switch)
            }
            if loading { ProgressView("Loading datagrams…") }
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    if let page {
                        Text("Client: \(page.association.client.label) → Listener: \(page.association.listenerAddress.label)")
                        Text("Observed upstream peer: \(page.association.peerLabel) · retained \(page.association.retainedBytes) bytes")
                        Text("State: \(page.association.state). Idle means the association expired after 30 seconds; UDP has no connection FIN.").font(.caption).foregroundStyle(.secondary)
                        Text("Local queue/cleanup drops: client \(page.association.droppedClientDatagrams) datagrams / \(page.association.droppedClientBytes) B; upstream \(page.association.droppedUpstreamDatagrams) datagrams / \(page.association.droppedUpstreamBytes) B. These counts do not measure network packet loss.").font(.caption).foregroundStyle(.secondary)
                        if let source = page.association.sourceState { Text("Historical source state: \(source). This is a historical UDP association.").foregroundStyle(.secondary) }
                        if page.association.truncated { Label("Capture limit reached. Retained datagrams are incomplete; forwarding continued.", systemImage: "exclamationmark.triangle").foregroundStyle(.orange) }
                        if let error = page.association.error { Text(error).foregroundStyle(.red) }
                        ForEach(page.datagrams) { datagram in
                            Text("#\(datagram.sequence) \(datagram.direction) · observed \(datagram.observedBytes) B, retained \(datagram.data.count) B · \(datagram.timestampLabel)").font(.caption).foregroundStyle(.secondary)
                            if let preview = expandedSequence == datagram.sequence ? expandedPreview : datagramPreviews[datagram.sequence] {
                                HStack {
                                    Text("Preview \(preview.count) / \(datagram.data.count) bytes").font(.caption).foregroundStyle(.secondary)
                                    if datagram.data.count > 4096 {
                                        Button(expandedSequence == datagram.sequence ? "Show preview" : "Show full datagram") { toggleExpanded(datagram) }
                                            .font(.caption)
                                    }
                                }
                                Text(datagram.data.isEmpty ? "〈empty datagram · 0 bytes〉" : (showHex ? preview.hex : preview.text))
                                    .font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                            }
                        }
                    }
                }.frame(maxWidth: .infinity, alignment: .leading)
            }.frame(minHeight: 150)
            Text(message).font(.caption).foregroundStyle(.secondary)
            Text("Recording is selected when a UDP association starts. Only forwarded datagrams are captured: 4 MiB / 1024 per association; 32 MiB total including 512 B accounting per retained datagram. HAR and TCP files do not contain UDP data.").font(.caption).foregroundStyle(.secondary)
        }.padding(22).frame(width: 940, height: 780)
        .onAppear { forwards = store.udpForwards }
        .onChange(of: selection) { offset = 0; refresh() }
        .onChange(of: store.udpGeneration) {
            selection = nil; clearPage(); loading = false; offset = 0; request = UUID()
        }
        .onChange(of: store.udpAssociations.map(\.id)) {
            if let selection, !store.udpAssociations.contains(where: { $0.id == selection }) {
                self.selection = nil; clearPage(); loading = false; request = UUID()
            }
        }
    }

    private func refresh() {
        request = UUID(); let token = request
        clearPage()
        guard let selection else { loading = false; return }
        loading = true
        store.send("udp_detail", ["id": selection, "offset": offset, "limit": 32], onError: { reason in
            guard request == token else { return }; loading = false; message = reason
        }) { value in
            guard request == token, self.selection == selection else { return }
            loading = false
            do {
                let decoded = try value.decode(UDPDatagramPage.self)
                // Format only admitted preview bytes, once per loaded page.
                // Frequent association summaries never reformat payload text.
                datagramPreviews = Dictionary(decoded.datagrams.map {
                    ($0.sequence, DatagramPreview($0.data.prefix(4096)))
                }, uniquingKeysWith: { first, _ in first })
                page = decoded
                message = "Each row is one forwarded UDP datagram. No application message semantics are inferred."
            } catch { message = "Cannot read UDP details: \(error.localizedDescription)" }
        }
    }
    private func clearPage() {
        page = nil; datagramPreviews.removeAll(keepingCapacity: true)
        expandedSequence = nil; expandedPreview = nil
    }

    private func toggleExpanded(_ datagram: UDPDatagramPage.Datagram) {
        if expandedSequence == datagram.sequence {
            expandedSequence = nil; expandedPreview = nil
        } else {
            // Keep one full representation for this page. Selecting another
            // datagram releases the preceding full representation.
            expandedPreview = DatagramPreview(datagram.data.prefix(datagram.data.count))
            expandedSequence = datagram.sequence
        }
    }

    private func open() {
        let panel = NSOpenPanel(); panel.canChooseDirectories = false; panel.allowsMultipleSelection = false
        panel.begin { response in
            guard response == .OK, let url = panel.url else { return }
            store.openUDPSession(url)
        }
    }
    private func save() {
        let panel = NSSavePanel(); panel.nameFieldStringValue = "capture.lens-udp.json"
        panel.begin { response in
            guard response == .OK, let url = panel.url else { return }
            loading = true
            store.send("save_udp", ["path": url.path], onError: { reason in loading = false; message = reason }) { _ in
                loading = false; message = "Saved UDP session to \(url.path)."
            }
        }
    }
}

private struct DatagramPreview {
    let count: Int
    let hex: String
    let text: String
    init(_ bytes: Data.SubSequence) {
        count = bytes.count
        hex = bytes.map { String(format: "%02x", $0) }.joined(separator: " ")
        text = String(decoding: bytes, as: UTF8.self)
    }
}
