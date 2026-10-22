import SwiftUI

struct ComposeTarget: Identifiable {
    let id = UUID()
    let source: TrafficFlow?
    var sessionID: String? = nil
}

struct ComposeDraft {
    let sourceID: String?
    let sourceFingerprint: String?
    let sourceBodyAvailable: Bool
    var message: HTTPMessageDraft
    init() {
        sourceID = nil; sourceFingerprint = nil; sourceBodyAvailable = true
        message = HTTPMessageDraft(newRequest: true)
    }
    init?(source: TrafficFlow, detail: FlowDetail) {
        guard source.id == detail.id, let fingerprint = detail.requestFingerprint, !fingerprint.isEmpty,
              let method = detail.method, let url = detail.url, let available = detail.requestBodyAvailable else { return nil }
        sourceID = source.id; sourceFingerprint = fingerprint
        sourceBodyAvailable = available
        message = HTTPMessageDraft(method: method, url: url,
                                   headers: detail.requestHeaderFields, available: sourceBodyAvailable,
                                   binary: detail.requestBinary == true, truncated: detail.requestTruncated)
        message.methodIsOpaque = detail.sourceFacts.contains("method")
        message.urlIsOpaque = detail.sourceFacts.contains("url")
    }
    func patch() throws -> [String: Any] {
        if !sourceBodyAvailable && !message.replaceBody {
            throw NSError(domain: "LensCompose", code: 1, userInfo: [NSLocalizedDescriptionKey: "The source body is unavailable. Supply an explicit replacement before queuing this request."])
        }
        if sourceID == nil && message.url.isEmpty {
            throw NSError(domain: "LensCompose", code: 1, userInfo: [NSLocalizedDescriptionKey: "Enter an absolute HTTP(S) URL for the new request."])
        }
        return try message.patch()
    }
}

struct LensComposeView: View {
    @ObservedObject var store: LensStore
    let target: ComposeTarget
    @Environment(\.dismiss) private var dismiss
    @State private var draft: ComposeDraft?
    @State private var loading = false
    @State private var issue: String?
    @State private var sending = false
    @State private var readingFile = false
    @State private var loadID = UUID()
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Compose request").font(.title2.weight(.semibold))
            if let source = target.source {
                Text("Source flow \(source.id)").font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
                if draft != nil { Button("Reload source (discard edits)", action: loadSource).font(.caption).disabled(loading) }
            } else { Text("New request").font(.caption).foregroundStyle(.secondary) }
            Text("Queueing sends a separate request through your current rules and capture settings. Queued requests can still fail; inspect their captured results.").font(.caption).foregroundStyle(.secondary)
            if let draft {
                ScrollView {
                    HTTPMessageFieldsEditor(draft: Binding(get: { self.draft?.message ?? draft.message }, set: { self.draft?.message = $0 }), readingFile: $readingFile, issue: $issue)
                }
            } else if loading {
                VStack { ProgressView(); Text("Loading the fixed source request details…").font(.caption) }.frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                VStack(spacing: 10) {
                    Label("Source details unavailable", systemImage: "exclamationmark.triangle")
                    Text("The source headers and body state must load before editing.").font(.caption).foregroundStyle(.secondary)
                    Button("Retry source details", action: loadSource)
                }.frame(maxWidth: .infinity, maxHeight: .infinity)
            }
            if let issue { Text(issue).font(.caption).foregroundStyle(.red).textSelection(.enabled) }
            HStack {
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Spacer()
                Button(sending ? "Queueing…" : "Queue request") { submit() }
                    .buttonStyle(.borderedProminent).disabled(draft == nil || loading || !store.isRunning)
            }
        }.padding(20).frame(minWidth: 760, minHeight: 580).disabled(sending || readingFile).interactiveDismissDisabled(sending || readingFile)
        .task(id: target.id) { loadSource() }
        .onDisappear { loadID = UUID() }
    }
    private func loadSource() {
        guard let source = target.source else { draft = ComposeDraft(); return }
        let request = UUID(); loadID = request; draft = nil; loading = true; issue = nil
        store.loadFlowDetail(id: source.id, sessionID: source.sessionId ?? target.sessionID) { result in
            guard loadID == request else { return }
            loading = false
            switch result {
            case .failure(let error): issue = error.localizedDescription
            case .success(let detail):
                guard let loaded = ComposeDraft(source: source, detail: detail) else { issue = "Complete request details and a matching source fingerprint are required. Reload source details before queuing."; return }
                draft = loaded
            }
        }
    }
    private func submit() {
        guard let draft, !readingFile else { return }
        do {
            let patch = try draft.patch(); sending = true; issue = nil
            store.compose(sourceID: draft.sourceID, sessionID: target.source?.sessionId ?? target.sessionID, sourceFingerprint: draft.sourceFingerprint, requestEdit: patch) { error in
                sending = false
                if let error { issue = error } else { dismiss() }
            }
        } catch { issue = error.localizedDescription }
    }
}
