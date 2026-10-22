import SwiftUI

private struct AccessPatternDraft: Identifiable {
    let id = UUID()
    var text: String
}

struct LensAccessListsView: View {
    @ObservedObject var store: LensStore
    @Environment(\.dismiss) private var dismiss
    @State private var policy = AccessPolicy()
    @State private var blockPatterns: [AccessPatternDraft] = []
    @State private var allowPatterns: [AccessPatternDraft] = []
    @State private var saving = false
    @State private var message: String?

    private var selectedPolicy: AccessPolicy {
        var selected = policy
        selected.block = blockPatterns.map(\.text)
        selected.allow = allowPatterns.map(\.text)
        return selected
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Text("Access Lists").font(.title2.weight(.semibold))
                Spacer()
                Button("Done") { dismiss() }.keyboardShortcut(.cancelAction)
            }
            Text("Control HTTP requests with URL globs. * matches any characters; ? matches one. Block List matches win. With Allow List enabled, an empty list denies every request.")
                .foregroundStyle(.secondary)
            Text("Both the original request URL and each mapped destination must pass these lists. This also applies to Compose, Replay and Repeat. HTTPS is covered only when Lens can decrypt the request. Opaque CONNECT tunnels, raw TCP and UDP are outside this policy; the local certificate download is exempt. Device connection permissions remain in Connection.")
                .font(.caption).foregroundStyle(.secondary)
            HStack(alignment: .top, spacing: 16) {
                patternList("Block List", enabled: $policy.blockEnabled, patterns: $blockPatterns)
                patternList("Allow List", enabled: $policy.allowEnabled, patterns: $allowPatterns)
            }
            Picker("When denied", selection: $policy.action) {
                Text("Respond with HTTP 403").tag("respond")
                Text("Abort request").tag("close")
            }.pickerStyle(.segmented)
            Text("Abort request closes HTTP/1 connections; HTTP/2 may reset only the affected stream.")
                .font(.caption).foregroundStyle(.secondary)
            if let issue = selectedPolicy.issue { Text(issue).foregroundStyle(.orange).font(.caption) }
            if let message { Text(message).font(.caption).foregroundStyle(.secondary) }
            HStack {
                Text(store.isRunning ? "Save applies immediately to subsequent requests." : "Save keeps the selection for the next Start.")
                    .font(.caption).foregroundStyle(.secondary)
                Spacer()
                Button(store.isRunning ? "Save and apply" : "Save for next Start") {
                    guard selectedPolicy.issue == nil else { return }
                    saving = true
                    store.accessPolicy = selectedPolicy
                    store.applyRules { success in
                        saving = false
                        message = success ? (store.isRunning ? "Access Lists applied." : "Access Lists saved. Start capture to apply.") : "Could not apply Access Lists. Check the Lens error message."
                    }
                }.buttonStyle(.borderedProminent).disabled(selectedPolicy.issue != nil || saving || store.settingsSaving)
            }
        }.padding(22).frame(width: 840, height: 620)
        .onAppear {
            policy = store.accessPolicy
            blockPatterns = policy.block.map { AccessPatternDraft(text: $0) }
            allowPatterns = policy.allow.map { AccessPatternDraft(text: $0) }
        }
    }

    private func patternList(_ title: String, enabled: Binding<Bool>, patterns: Binding<[AccessPatternDraft]>) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Toggle("Enable \(title)", isOn: enabled)
            HStack {
                Text("\(patterns.wrappedValue.count) / 500 URL patterns").font(.caption).foregroundStyle(.secondary)
                Spacer()
                Button { patterns.wrappedValue.append(AccessPatternDraft(text: "*")) } label: { Label("Add", systemImage: "plus") }
                    .disabled(patterns.wrappedValue.count >= 500)
            }
            ScrollView {
                LazyVStack(spacing: 8) {
                    ForEach(patterns) { row in
                        HStack {
                            TextField("https://example.com/*", text: row.text)
                                .font(.system(.body, design: .monospaced)).textFieldStyle(.roundedBorder)
                            Button { patterns.wrappedValue.removeAll { $0.id == row.wrappedValue.id } } label: { Image(systemName: "minus.circle") }
                                .buttonStyle(.borderless).help("Remove URL pattern")
                        }
                    }
                    if patterns.wrappedValue.isEmpty {
                        Text(title == "Allow List" ? "No patterns. Enabling this list denies every request." : "No patterns to block.")
                            .font(.caption).foregroundStyle(.secondary).frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
            }.frame(maxWidth: .infinity, maxHeight: .infinity)
        }.padding(12).background(.quaternary.opacity(0.3)).clipShape(RoundedRectangle(cornerRadius: 8))
    }
}
