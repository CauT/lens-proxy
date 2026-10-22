import AppKit
import SwiftUI

struct SessionActionTarget: Identifiable {
    enum Kind { case rename, close, clearHTTP, openWorkspace, openWorkspaceDocument, saveWorkspace }
    let id = UUID()
    let kind: Kind
    let session: HTTPSessionInfo
}

struct LensSessionActionView: View {
    @ObservedObject var store: LensStore
    let target: SessionActionTarget
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var path = ""
    @State private var failure: String?
    @State private var replaceExisting = false
    @State private var pickerConfirmedPath: String?
    private var validName: Bool {
        !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && name.utf8.count <= 4096 && !name.contains(where: { "\0\r\n".contains($0) })
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text(title).font(.title2.weight(.semibold))
            switch target.kind {
            case .rename:
                TextField("Session name", text: $name).textFieldStyle(.roundedBorder).accessibilityLabel("Session name")
                Text("The name stays with this session when the workspace is saved or restored.").font(.callout).foregroundStyle(.secondary)
            case .close:
                Text("Close \(target.session.name)? Its recorded data will be removed from the current workspace. A workspace copy keeps every session, including HTTP, WebSocket, TCP and UDP captures.")
                Text("Active transfers continue without further capture in the closed session. Paused requests and Repeat jobs in this session stop.").font(.callout).foregroundStyle(.secondary)
                pathField
                Text("Save copy and Close writes a snapshot at the close boundary. You can reopen it using Open workspace copy.").font(.caption).foregroundStyle(.secondary)
            case .clearHTTP:
                Text("Clear HTTP traffic in \(target.session.name)? This removes its HTTP requests and WebSocket messages from the current workspace.")
                Text("Paused requests in cleared records continue without further breakpoints. Capture stays active. TCP/UDP records and other sessions remain available.").font(.callout).foregroundStyle(.secondary)
                pathField
                Text("Save copy and Clear first saves every session as a workspace snapshot. Requests arriving while it saves stay in the current session. If saving fails, nothing is cleared.").font(.caption).foregroundStyle(.secondary)
            case .openWorkspace, .openWorkspaceDocument:
                Text("Open a saved Lens workspace copy. This stops the proxy and retains the current workspace before displaying the selected copy. Use Start when ready to resume capture.")
                pathField
                if target.kind == .openWorkspaceDocument {
                    Text("After a successful Open, Save Workspace (⌘S) updates this selected file. Open workspace copy keeps the input separate instead.").font(.caption).foregroundStyle(.secondary)
                }
            case .saveWorkspace:
                Text("Save every session, including HTTP, WebSocket, TCP and UDP, in one Lens workspace file. Display filters do not limit this snapshot.")
                pathField
                Text("Capture continues. Traffic arriving after the snapshot needs another Save. The file becomes the destination for ⌘S only after saving succeeds.").font(.caption).foregroundStyle(.secondary)
            }
            if let failure { Label(failure, systemImage: "exclamationmark.triangle").font(.callout).foregroundStyle(.orange).textSelection(.enabled) }
            HStack {
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Spacer()
                switch target.kind {
                case .rename:
                    Button("Rename") { store.renameSession(target.session.id, name: name, completion: finish) }
                        .buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction).disabled(!validName)
                case .close:
                    Button("Discard and Close", role: .destructive) { close(discard: true) }
                    Button("Save copy and Close") { close(discard: false) }
                        .buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction).disabled(!path.hasPrefix("/") || path.contains("\0"))
                case .clearHTTP:
                    Button("Clear without copy", role: .destructive) { clear(copy: false) }
                    Button("Save copy and Clear") { clear(copy: true) }
                        .buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction).disabled(!path.hasPrefix("/") || path.contains("\0"))
                case .openWorkspace:
                    Button("Open copy") { dismiss(); store.openWorkspaceCopy(path: path) }
                        .buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction).disabled(!path.hasPrefix("/") || path.contains("\0"))
                case .openWorkspaceDocument:
                    Button("Open Workspace") { dismiss(); store.openWorkspaceCopy(path: path, asDocument: true) }
                        .buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction).disabled(!path.hasPrefix("/") || path.contains("\0"))
                case .saveWorkspace:
                    Button("Save Workspace") {
                        let confirmed = pickerConfirmedPath.map { $0.utf8.elementsEqual(path.utf8) } ?? false
                        var directory = ObjCBool(false)
                        let exists = FileManager.default.fileExists(atPath: path, isDirectory: &directory)
                        if directory.boolValue { failure = "Choose a file path, not an existing directory." }
                        else if exists && !confirmed { replaceExisting = true }
                        else { save() }
                    }.buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction).disabled(!path.hasPrefix("/") || path.contains("\0"))
                }
            }
        }.padding(24).frame(width: 650).disabled(store.sessionChanging || store.workspaceSaving)
         .alert("Replace existing workspace file?", isPresented: $replaceExisting) {
             Button("Replace", role: .destructive, action: save)
             Button("Cancel", role: .cancel) { }
         } message: { Text("The selected file will be replaced by a snapshot of every session.\n" + path) }
         .onChange(of: path) { _, updated in
             if pickerConfirmedPath.map({ $0.utf8.elementsEqual(updated.utf8) }) != true { pickerConfirmedPath = nil }
         }
         .onAppear {
             name = target.session.name
             if target.kind == .close || target.kind == .clearHTTP {
                 path = store.dataDirectory.appendingPathComponent("session-backups/session-" + UUID().uuidString + ".lens.json").path
             }
             if target.kind == .saveWorkspace {
                 if let source = store.workspaceFileURL {
                     let name = source.lastPathComponent.hasSuffix(".lens.json") ? String(source.lastPathComponent.dropLast(10)) : source.deletingPathExtension().lastPathComponent
                     path = source.deletingLastPathComponent().appendingPathComponent(name + " copy.lens.json").path
                 } else {
                     path = store.dataDirectory.appendingPathComponent("capture-" + UUID().uuidString + ".lens.json").path
                 }
             }
         }
    }
    private var title: String {
        switch target.kind { case .rename: return "Rename Session"; case .close: return "Close Session"; case .clearHTTP: return "Clear HTTP traffic"; case .openWorkspace: return "Open workspace copy"; case .openWorkspaceDocument: return "Open Workspace"; case .saveWorkspace: return "Save Workspace As" }
    }
    private var pathField: some View {
        HStack {
            TextField("Absolute workspace file path", text: $path).textFieldStyle(.roundedBorder).accessibilityLabel(target.kind == .saveWorkspace || target.kind == .openWorkspaceDocument ? "Workspace file path" : "Workspace copy path")
            Button("Choose…") {
                if target.kind == .openWorkspace || target.kind == .openWorkspaceDocument {
                    let panel = NSOpenPanel(); panel.canChooseDirectories = false; panel.allowsMultipleSelection = false
                    panel.begin { if $0 == .OK, let url = panel.url { path = url.path } }
                } else {
                    let panel = NSSavePanel(); panel.nameFieldStringValue = "capture.lens.json"
                    if target.kind == .saveWorkspace {
                        panel.nameFieldStringValue = URL(fileURLWithPath: path).lastPathComponent
                        panel.directoryURL = URL(fileURLWithPath: path).deletingLastPathComponent()
                    }
                    panel.begin { if $0 == .OK, let url = panel.url { path = url.path; pickerConfirmedPath = url.path } }
                }
            }
        }
    }
    private func finish(_ success: Bool) {
        if success { dismiss() }
        else {
            // A sheet owns its expected operation failure. Presenting the
            // workspace alert underneath it hides feedback until Cancel.
            failure = store.errorMessage ?? "The session operation could not finish."
            store.errorMessage = nil
        }
    }
    private func close(discard: Bool) {
        store.closeSession(target.session.id, backupPath: discard ? nil : path, discard: discard, completion: finish)
    }
    private func clear(copy: Bool) {
        store.clear(target.session.id, backupPath: copy ? path : nil, completion: finish)
    }
    private func save() { store.saveWorkspace(path: path, completion: finish) }
}
