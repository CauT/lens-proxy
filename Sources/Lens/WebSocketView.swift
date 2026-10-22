import AppKit
import SwiftUI

struct LensWebSocketView: View {
    @ObservedObject var store: LensStore
    let detail: FlowDetail
    @State private var page: WebSocketMessagePage?
    @State private var request = UUID()
    @State private var loading = false
    @State private var error: String?

    private var messages: [SocketMessage] { page?.messages ?? detail.messages }
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                if let page {
                    Text(page.total == 0 ? "No retained messages" : "Messages \(page.offset + 1)–\(page.offset + page.messages.count) of \(page.total)")
                        .font(.caption).foregroundStyle(.secondary)
                    Spacer()
                    Button("Previous") { load(max(0, page.offset - page.limit), generation: page.generation) }.disabled(loading || page.offset == 0)
                    Button("Next") { if let next = page.nextOffset { load(next, generation: page.generation) } }.disabled(loading || page.nextOffset == nil)
                } else { Text("Legacy message previews").font(.caption).foregroundStyle(.secondary); Spacer() }
                Button("Refresh") { reset(); store.loadDetail() }.disabled(loading)
                if loading { ProgressView().controlSize(.small) }
            }
            Text("Reassembled messages, not individual wire frames. Payload previews show up to 4 KiB each; HAR retains captured message bytes.")
                .font(.caption).foregroundStyle(.secondary)
            if page?.retentionTruncated == true || detail.messagesTruncated == true {
                Label("Some messages were omitted by capture retention limits.", systemImage: "exclamationmark.triangle").font(.caption).foregroundStyle(.orange)
            } else if page?.retentionTruncated == nil && detail.messagesTruncated == nil {
                Text("The source did not record whether messages were omitted.").font(.caption).foregroundStyle(.secondary)
            }
            if let error { Text(error + " Refresh to read the current history.").font(.caption).foregroundStyle(.orange).textSelection(.enabled) }
            if messages.isEmpty {
                ContentUnavailableView("No WebSocket messages", systemImage: "arrow.left.arrow.right", description: Text("Messages will appear as they arrive. An empty retained history can also follow an explicitly reported capture omission."))
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 12) {
                        // Positions identify entries within this history generation.
                        // Equal timestamp/direction/content values remain separate messages.
                        ForEach(Array(messages.enumerated()), id: \.offset) { _, message in
                            LensWebSocketMessageCard(message: message)
                        }
                    }.padding(.vertical, 4)
                }.id("\(page?.generation ?? -1):\(page?.offset ?? 0)")
            }
        }.padding(12)
        .task(id: detail.messagesGeneration) { reset() }
        .onDisappear { request = UUID() }
    }

    private func reset() {
        request = UUID(); loading = false; error = nil
        do { page = try detail.firstWebSocketPage() }
        catch { page = nil; self.error = error.localizedDescription }
    }
    private func load(_ offset: Int, generation: Int) {
        let token = UUID(); request = token; loading = true; error = nil
        store.loadWebSocketPage(id: detail.id, offset: offset, generation: generation) { result in
            guard request == token else { return }
            loading = false
            switch result {
            case .success(let loaded): page = loaded
            case .failure(let failure): error = failure.localizedDescription
            }
        }
    }
}

private struct LensWebSocketMessageCard: View {
    let message: SocketMessage
    @State private var hex = false
    @State private var rendered = ""
    @State private var renderedInput: BodyRenderInput?
    private var input: BodyRenderInput {
        BodyRenderInput(format: hex && message.previewBytes != nil ? .hex : .text,
            text: message.previewText, base64: message.contentBase64, truncated: false)
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Label(message.direction, systemImage: message.direction == "send" ? "arrow.up.right" : "arrow.down.left")
                Text(message.kindLabel)
                if let count = message.contentBytes { Text("\(count) bytes") }
                Spacer()
                Text(Date(timeIntervalSince1970: message.timestamp), style: .time)
            }.font(.caption).foregroundStyle(.secondary)
            if message.dropped == true { Label("Not forwarded", systemImage: "hand.raised").font(.caption) }
            if message.injected == true { Text("Injected message").font(.caption) }
            if message.dropped == nil || message.injected == nil { Text("Forwarding/injection facts not recorded.").font(.caption).foregroundStyle(.secondary) }
            HStack {
                Picker("Message preview", selection: $hex) {
                    Text("Text").tag(false)
                    if message.previewBytes != nil { Text("Hex").tag(true) }
                }.pickerStyle(.segmented).frame(width: 160)
                Spacer()
                Button { NSPasteboard.general.clearContents(); NSPasteboard.general.setString(rendered, forType: .string) } label: { Image(systemName: "doc.on.doc") }
                    .buttonStyle(.borderless).help("Copy displayed message preview").disabled(renderedInput != input)
            }
            if message.previewBytes == nil {
                Text("Legacy display text only. Original bytes, type and preview completeness may not have been recorded.").font(.caption).foregroundStyle(.orange)
            } else if message.opcode != 1 && !hex {
                Text("Text interprets the preview bytes as UTF-8; it does not change the recorded message type.").font(.caption).foregroundStyle(.secondary)
            }
            if message.previewTruncated == true {
                Label("Showing \(message.previewBytes?.count ?? 0) of \(message.contentBytes ?? 0) bytes. Save HAR for retained complete payloads.", systemImage: "exclamationmark.triangle")
                    .font(.caption).foregroundStyle(.orange)
            }
            if renderedInput == input {
                LensBodyTextView(text: rendered.isEmpty ? "[Empty message]" : rendered, title: "WebSocket message")
                    .frame(height: 180)
            } else { ProgressView("Formatting…").controlSize(.small) }
        }.padding(10).frame(maxWidth: .infinity, alignment: .leading)
        .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 6))
        .onAppear { hex = message.preferredHex }
        .onChange(of: message.index) { hex = message.preferredHex }
        .task(id: input) {
            renderedInput = nil
            let captured = input
            guard let value = await BodyRenderWorker.shared.render(captured), !Task.isCancelled else { return }
            rendered = value; renderedInput = captured
        }
    }
}
