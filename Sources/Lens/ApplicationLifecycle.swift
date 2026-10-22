import AppKit
import SwiftUI

@MainActor
final class LensAppDelegate: NSObject, NSApplicationDelegate {
    weak var store: LensStore?
    private var isTerminating = false
    private var copyPath: String?

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard !isTerminating else { return .terminateLater }
        guard let store else { return .terminateNow }
        guard store.hasEngine || store.systemProxy.hasBackup || store.systemProxy.isBusy || store.needsWorkspaceSaveConfirmation else { return .terminateNow }
        isTerminating = true
        copyPath = nil  // A new Quit request owns a fresh destination; retry keeps it.
        store.quitPending = true
        if store.needsWorkspaceSaveConfirmation { presentQuit(sender, store: store) }
        else {
            store.prepareForQuit { [self] success in
                if !success || store.needsWorkspaceSaveConfirmation {
                    let failure = success ? nil : store.errorMessage ?? "Unable to finish stopping capture. Retry or cancel."
                    store.errorMessage = nil
                    presentQuit(sender, store: store, failure: failure)
                } else { finishQuit(sender, store: store, backupPath: nil) }
            }
        }
        return .terminateLater
    }

    private func presentQuit(_ sender: NSApplication, store: LensStore, failure: String? = nil) {
        let alert = NSAlert()
        alert.messageText = "Save workspace changes before quitting?"
        alert.informativeText = "The workspace has changes beyond its last verified Save. The path below receives the final snapshot of every HTTP, WebSocket, TCP and UDP session. " + (store.isRunning || store.isStarting ? "Saving first stops capture and finishes session file operations. Cancel keeps Lens open." : "Capture is stopped. Cancel keeps the retained workspace open; use Start to resume capture.") + " A private recovery copy is retained by the normal Stop process."
        alert.addButton(withTitle: "Save and Quit")
        alert.addButton(withTitle: "Cancel").keyEquivalent = "\u{1b}"
        alert.addButton(withTitle: "Quit without saving")
        let path = NSTextField(string: copyPath ?? store.workspaceFileURL?.path ?? store.dataDirectory.appendingPathComponent("session-backups/quit-" + UUID().uuidString + ".lens.json").path)
        path.setAccessibilityLabel("Workspace copy path")
        path.placeholderString = "Absolute workspace file path"
        let label = NSTextField(labelWithString: "Workspace copy path")
        var fields: [NSView] = [label, path]
        if let failure {
            let error = NSTextField(wrappingLabelWithString: failure)
            error.textColor = .systemRed
            error.widthAnchor.constraint(equalToConstant: 520).isActive = true
            fields.append(error)
        }
        let accessory = NSStackView(views: fields)
        accessory.orientation = .vertical; accessory.alignment = .leading; accessory.spacing = 8
        accessory.setFrameSize(NSSize(width: 520, height: failure == nil ? 55 : 110))
        path.widthAnchor.constraint(equalToConstant: 520).isActive = true
        alert.accessoryView = accessory
        let chosen: (NSApplication.ModalResponse) -> Void = { [self] response in
            copyPath = path.stringValue
            if response == .alertSecondButtonReturn {
                store.cancelQuitPreparation()
                isTerminating = false; store.quitPending = false
                sender.reply(toApplicationShouldTerminate: false)
            } else {
                finishQuit(sender, store: store, backupPath: response == .alertFirstButtonReturn ? path.stringValue : nil)
            }
        }
        if let window = sender.mainWindow ?? sender.windows.first(where: { $0.isVisible && $0.identifier?.rawValue == "workspace" }) {
            alert.beginSheetModal(for: window, completionHandler: chosen)
        } else { chosen(alert.runModal()) }
    }

    private func finishQuit(_ sender: NSApplication, store: LensStore, backupPath: String?) {
        store.shutdown(backupPath: backupPath) { [self] success in
            if success { sender.reply(toApplicationShouldTerminate: true) }
            else {
                // Keep the same pending application request and editable path.
                // A stopped engine remains available for inspection and retry.
                let failure = store.errorMessage ?? "Unable to finish quitting. Retry or cancel."
                store.errorMessage = nil
                presentQuit(sender, store: store, failure: failure)
            }
        }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
}

// Preserve SwiftUI's delegate and all its other callbacks. Ordinary window
// Close enters the same cancellable application request before hiding anything.
@MainActor
final class LensWorkspaceWindowDelegate: NSObject, NSWindowDelegate {
    weak var forwarded: NSWindowDelegate?
    var requestQuit: () -> Void = {}
    func windowShouldClose(_ sender: NSWindow) -> Bool {
        guard forwarded?.windowShouldClose?(sender) != false else { return false }
        requestQuit(); return false
    }
    override func responds(to selector: Selector!) -> Bool {
        super.responds(to: selector) || forwarded?.responds(to: selector) == true
    }
    override func forwardingTarget(for selector: Selector!) -> Any? {
        forwarded?.responds(to: selector) == true ? forwarded : super.forwardingTarget(for: selector)
    }
}

struct LensWorkspaceCloseBridge: NSViewRepresentable {
    let requestQuit: () -> Void
    func makeNSView(context: Context) -> WindowView {
        let view = WindowView(); view.owner.requestQuit = requestQuit; return view
    }
    func updateNSView(_ view: WindowView, context: Context) { view.owner.requestQuit = requestQuit }
    static func dismantleNSView(_ view: WindowView, coordinator: ()) { view.detach() }
    final class WindowView: NSView {
        let owner = LensWorkspaceWindowDelegate()
        private weak var attached: NSWindow?
        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow(); detach()
            guard let window else { return }
            owner.forwarded = window.delegate; window.delegate = owner; attached = window
        }
        func detach() {
            if let attached, attached.delegate === owner { attached.delegate = owner.forwarded }
            attached = nil
        }
    }
}
