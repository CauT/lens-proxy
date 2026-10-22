import Foundation
import SwiftUI

enum SessionExportKind: String { case csv, request, response }

@MainActor
final class SessionArchiveController: ObservableObject {
    @Published private(set) var autosavePath = ""
    @Published private(set) var mirrorPath = ""
    @Published private(set) var autosaveEnabled = false
    @Published private(set) var mirrorEnabled = false
    @Published private(set) var saving = false
    @Published private(set) var loading = false
    @Published private(set) var exporting = false
    @Published private(set) var message = "Choose where to save captured traffic."
    weak var store: LensStore?
    let sessionID: String
    private let preferencesURL: URL
    private var generation: UInt64 = 0
    private var savedGeneration: UInt64?
    private var mirrorSeen = Set<String>()
    private var mirrorQueue: [TrafficFlow] = []
    private var mirroring = false
    private var quiescing = false
    private var clearing = false
    private var drainCompletions: [() -> Void] = []

    init(store: LensStore, sessionID: String = "default") {
        self.store = store; self.sessionID = sessionID
        self.preferencesURL = sessionID == "default" ? store.dataDirectory.appendingPathComponent("storage-preferences.json") : store.dataDirectory.appendingPathComponent("session-storage", isDirectory: true).appendingPathComponent(sessionID + ".json")
        // A destination persists for convenience; background recording to disk
        // must be enabled explicitly for each app launch.
        let url = preferencesURL
        if let data = try? Data(contentsOf: url), let saved = try? JSONSerialization.jsonObject(with: data) as? [String: String] {
            autosavePath = saved["autosave_path"] ?? ""; mirrorPath = saved["mirror_path"] ?? ""
        }
    }

    func tick() { saveIfChanged() }

    private func absoluteURL(_ path: String) -> URL? {
        guard path.hasPrefix("/"), !path.contains("\0") else {
            message = "Enter an absolute filesystem path beginning with / (not a file URL or ~ path)."; return nil
        }
        return URL(fileURLWithPath: path)
    }
    func selectAutosavePath(_ path: String) {
        guard !saving, !loading, let url = absoluteURL(path) else { return }
        autosavePath = url.path; savedGeneration = nil
        if persist() { message = "Using \(autosavePath). Save now or enable rolling autosave to write this file." }
    }
    func selectMirrorPath(_ path: String) {
        guard !mirrorEnabled, let url = absoluteURL(path) else { return }
        do {
            try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            mirrorPath = url.path
            if persist() { message = "Using \(mirrorPath). Enable mirroring to save future responses." }
        } catch { message = "Cannot use this mirror folder: \(error.localizedDescription)" }
    }
    func setAutosave(_ enabled: Bool) {
        autosaveEnabled = enabled && !autosavePath.isEmpty
        if autosaveEnabled { savedGeneration = nil; saveIfChanged() }
    }
    func setMirror(_ enabled: Bool) {
        mirrorEnabled = enabled && !mirrorPath.isEmpty
        // Existing/imported rows are outside the prospective mirror operation.
        mirrorSeen = Set(store?.flows(in: sessionID).map(\.id) ?? [])
        mirrorQueue.removeAll()
        message = mirrorEnabled ? "Future completed responses will be saved. An in-progress write finishes when disabled." : "Response mirroring is off."
    }
    func changed() { generation &+= 1 }
    func stopped() { mirrorQueue.removeAll() }
    func resumed() { quiescing = false }
    func quiesce(_ completion: @escaping () -> Void) {
        quiescing = true; mirrorQueue.removeAll(); drainCompletions.append(completion); completeDrain()
    }
    func prepareClear(_ completion: @escaping () -> Void) {
        // Drain admitted I/O but queue future mirrors until the exact removed
        // events arrive. Stop's quiesce intentionally has different ownership.
        clearing = true; drainCompletions.append(completion); completeDrain()
    }
    func finishClear() {
        clearing = false
        let retained = Set(store?.flows(in: sessionID).map(\.id) ?? [])
        mirrorQueue.removeAll { !retained.contains($0.id) }
        mirrorSeen.formIntersection(retained)
        mirrorNext()
    }
    private func completeDrain() {
        guard quiescing || clearing, !saving, !loading, !exporting, !mirroring else { return }
        let completions = drainCompletions; drainCompletions.removeAll(); completions.forEach { $0() }
    }
    func received(_ flow: TrafficFlow) {
        changed()
        guard !quiescing, mirrorEnabled, flow.state == "complete", flow.status != nil, flow.imported != true,
              mirrorSeen.insert(flow.id).inserted else { return }
        mirrorQueue.append(flow)
        if mirrorSeen.count > 4000 { mirrorSeen.formIntersection(Set(store?.flows(in: sessionID).map(\.id) ?? [])) }
        mirrorNext()
    }
    func saveNow() { savedGeneration = nil; saveIfChanged(force: true) }
    func loadNow() {
        guard !quiescing, !clearing, !saving, !loading, !autosaveEnabled, !autosavePath.isEmpty, let store, store.hasEngine else { return }
        loading = true
        store.send("load_har", ["path": autosavePath, "session_id": sessionID], onError: { [weak self] reason in
            self?.loading = false; self?.message = "Session import failed: \(reason)"; self?.completeDrain()
        }) { [weak self] value in
            guard let self else { return }
            self.loading = false
            let count = value["imported"]?.integer
            self.message = count.map { "Imported \($0) requests into this session." } ?? "Import completed; entry count unavailable."
            self.completeDrain()
        }
    }
    func exportFile(path: String, kind: SessionExportKind) {
        guard !quiescing, !clearing, !exporting, let store, let url = absoluteURL(path) else { return }
        if kind == .csv {
            do { try store.exportCSV(to: url, sessionID: sessionID); message = "Saved filtered CSV to \(path)." }
            catch { message = "CSV export failed: \(error.localizedDescription)" }
        } else {
            exporting = true
            store.exportBody(side: kind.rawValue, to: url, sessionID: sessionID) { [weak self] result in
                guard let self else { return }
                self.exporting = false
                switch result {
                case .success: self.message = "Saved complete decoded \(kind.rawValue) bytes to \(path)."
                case .failure(let error): self.message = "Body export failed: \(error.localizedDescription)"
                }
                self.completeDrain()
            }
        }
    }
    private func saveIfChanged(force: Bool = false) {
        guard !quiescing, !clearing, !loading, (autosaveEnabled || force), !autosavePath.isEmpty, !saving,
              let store, store.hasEngine, savedGeneration != generation else { return }
        let snapshot = generation, path = autosavePath
        saving = true
        store.send("save_har", ["path": path, "session_id": sessionID], onError: { [weak self] reason in
            self?.saving = false; self?.message = "Session save failed: \(reason)"
            self?.completeDrain()
        }) { [weak self] _ in
            guard let self else { return }
            self.saving = false
            if self.autosavePath == path { self.savedGeneration = snapshot }
            self.message = "Saved \(URL(fileURLWithPath: path).lastPathComponent) at \(Date().formatted(date: .omitted, time: .standard))."
            self.completeDrain()
        }
    }
    private func persist() -> Bool {
        guard store != nil else { return false }
        do {
            try FileManager.default.createDirectory(at: preferencesURL.deletingLastPathComponent(), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            try JSONSerialization.data(withJSONObject: ["autosave_path": autosavePath, "mirror_path": mirrorPath]).write(to: preferencesURL, options: .atomic)
            return true
        } catch { message = error.localizedDescription; return false }
    }
    private func mirrorNext() {
        guard !quiescing, !clearing, !mirroring, mirrorEnabled, !mirrorQueue.isEmpty, let store, store.hasEngine else { return }
        let flow = mirrorQueue.removeFirst(), folder = URL(fileURLWithPath: mirrorPath)
        mirroring = true
        store.send("export_body", ["id": flow.id, "session_id": sessionID, "side": "response", "decoded": true], onError: { [weak self] reason in
            self?.mirrorFinished("Response mirror failed: \(reason)")
        }) { [weak self] value in
            guard let base64 = value["base64"]?.unicodeString,
                  let bytes = Data(base64Encoded: base64) else { self?.mirrorFinished("Response mirror returned invalid bytes."); return }
            Task {
                let result = await Task.detached(priority: .utility) { () -> String in
                    do { let name = try ResponseMirror.write(flow: flow, bytes: bytes, folder: folder); return "Mirrored response to \(name)." }
                    catch { return "Response mirror failed: \(error.localizedDescription)" }
                }.value
                self?.mirrorFinished(result)
            }
        }
    }
    private func mirrorFinished(_ result: String) { mirroring = false; message = result; completeDrain(); mirrorNext() }
}

struct LensSessionToolsView: View {
    @ObservedObject var store: LensStore
    @ObservedObject private var archives: SessionArchiveController
    @Environment(\.dismiss) private var dismiss
    @State private var autosaveDraft = ""
    @State private var mirrorDraft = ""
    @State private var exportDraft = ""
    init(store: LensStore) { self.store = store; self.archives = store.archives }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Session storage").font(.title2.weight(.semibold))
            Form {
                Section("HAR session") {
                    Text("Save replaces the selected file atomically. Merge HAR adds entries to this session; Open as new session preserves it. Autosave writes the latest changing session every 30 seconds.").font(.caption).foregroundStyle(.secondary)
                    Text("Lens HAR preserves unknown timings and unavailable bodies. Strict HAR tools may reject incomplete entries.").font(.caption).foregroundStyle(.secondary)
                    HStack {
                        TextField("Absolute HAR file path", text: $autosaveDraft).accessibilityLabel("Autosave file path")
                        Button("Use file") { archives.selectAutosavePath(autosaveDraft) }.disabled(archives.saving || archives.autosaveEnabled)
                    }.disabled(archives.saving || archives.loading || archives.autosaveEnabled)
                    Text(archives.autosavePath.isEmpty ? "No file selected" : "Selected: " + archives.autosavePath).font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
                    Toggle("Enable autosave for this app launch", isOn: Binding(get: { archives.autosaveEnabled }, set: archives.setAutosave)).disabled(archives.autosavePath.isEmpty)
                    HStack {
                        Button(archives.saving ? "Saving…" : "Save now", action: archives.saveNow).disabled(!store.hasEngine || archives.saving || archives.loading || archives.autosavePath.isEmpty)
                        Button(archives.loading ? "Opening…" : "Merge HAR", action: archives.loadNow).disabled(!store.hasEngine || archives.saving || archives.loading || archives.autosaveEnabled || archives.autosavePath.isEmpty)
                        Button("Open as new session") { store.openSession(path: archives.autosavePath) }
                            .disabled(!store.hasEngine || store.sessionChanging || archives.saving || archives.loading || archives.autosaveEnabled || archives.autosavePath.isEmpty)
                    }
                }
                Section("Mirror future responses") {
                    Text("Save each new completed response as complete decoded bytes and a metadata file in a unique folder. Existing and imported requests are skipped. These files can contain captured private content.").font(.caption).foregroundStyle(.secondary)
                    HStack {
                        TextField("Absolute output folder path", text: $mirrorDraft).accessibilityLabel("Response mirror folder path")
                        Button("Use folder") { archives.selectMirrorPath(mirrorDraft) }
                    }.disabled(archives.mirrorEnabled)
                    Text(archives.mirrorPath.isEmpty ? "No folder selected. Use folder creates missing directories." : "Selected: " + archives.mirrorPath).font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
                    Toggle("Enable response mirroring for this app launch", isOn: Binding(get: { archives.mirrorEnabled }, set: archives.setMirror)).disabled(archives.mirrorPath.isEmpty)
                }
                Section("Other exports") {
                    TextField("Absolute output file path", text: $exportDraft).accessibilityLabel("Other export file path")
                    Text("Exports replace this file. Body exports use the complete decoded bytes of the selected request.").font(.caption).foregroundStyle(.secondary)
                    HStack {
                        Button("Export filtered CSV") { archives.exportFile(path: exportDraft, kind: .csv) }
                        Button("Save request body") { archives.exportFile(path: exportDraft, kind: .request) }.disabled(!store.isRunning || store.selection == nil)
                        Button("Save response body") { archives.exportFile(path: exportDraft, kind: .response) }.disabled(!store.isRunning || store.selectedFlow?.status == nil)
                    }.disabled(archives.exporting)
                }
            }.formStyle(.grouped)
            Text(archives.message).font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
            HStack { Spacer(); Button("Done") { dismiss() }.keyboardShortcut(.defaultAction) }
        }.padding(22).frame(width: 680, height: 690)
        .onAppear { autosaveDraft = archives.autosavePath; mirrorDraft = archives.mirrorPath }
    }
}
