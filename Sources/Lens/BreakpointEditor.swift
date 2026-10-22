import SwiftUI

struct BreakpointDraft: Identifiable {
    let id = UUID()
    let flowID: String
    let sessionID: String?
    let pauseID: String
    let stage: String
    var message: HTTPMessageDraft
    init?(flow: TrafficFlow, detail: FlowDetail) {
        guard let pause = flow.pauseId, flow.state == "paused", flow.id == detail.id,
              detail.pauseId == pause, detail.pauseStage == flow.breakpointStage else { return nil }
        flowID = flow.id; sessionID = flow.sessionId; pauseID = pause; stage = flow.breakpointStage
        guard let reason = try? detail.reasonBytes() else { return nil }
        message = HTTPMessageDraft(stage: stage, method: flow.method, url: flow.url, status: flow.status,
                                   reason: reason,
                                   headers: stage == "request" ? detail.requestHeaderFields : detail.responseHeaderFields,
                                   available: stage == "request" ? detail.requestBodyAvailable != false : detail.responseBodyAvailable != false,
                                   binary: stage == "request" ? detail.requestBinary == true : detail.responseBinary == true,
                                   truncated: stage == "request" ? detail.requestTruncated : detail.responseTruncated)
        message.methodIsOpaque = detail.sourceFacts.contains("method")
        message.urlIsOpaque = detail.sourceFacts.contains("url")
    }
    func patch() throws -> [String: Any] { try message.patch() }
}

struct BreakpointEditor: View {
    @ObservedObject var store: LensStore
    @Environment(\.dismiss) private var dismiss
    @State var draft: BreakpointDraft
    @State private var issue: String?
    @State private var sending = false
    @State private var readingFile = false
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Edit paused \(draft.stage)").font(.title2.weight(.semibold))
            Text("Flow \(draft.flowID) · this paused stage only").font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
            ScrollView { HTTPMessageFieldsEditor(draft: $draft.message, readingFile: $readingFile, issue: $issue) }
            if let issue { Text(issue).font(.caption).foregroundStyle(.red).textSelection(.enabled) }
            HStack {
                Button("Cancel editing") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Abort", role: .destructive) { submit(abort: true) }
                Spacer()
                Button("Continue unchanged") { submit(unchanged: true) }
                Button(sending ? "Continuing…" : "Apply and continue") { submit() }.buttonStyle(.borderedProminent)
            }
        }.padding(20).frame(minWidth: 760, minHeight: 580).disabled(sending || readingFile).interactiveDismissDisabled(sending || readingFile)
    }
    private func submit(abort: Bool = false, unchanged: Bool = false) {
        do {
            guard !readingFile else { return }
            let patch = abort || unchanged ? nil : try draft.patch()
            sending = true; issue = nil
            store.resumeBreakpoint(flowID: draft.flowID, sessionID: draft.sessionID, pauseID: draft.pauseID, stage: draft.stage, edit: patch, abort: abort) { error in
                sending = false
                if let error { issue = error } else { dismiss() }
            }
        } catch { issue = error.localizedDescription }
    }
}
