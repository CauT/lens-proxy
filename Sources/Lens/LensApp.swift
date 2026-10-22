import AppKit
import SwiftUI

@main
struct LensApp: App {
    @NSApplicationDelegateAdaptor(LensAppDelegate.self) private var delegate
    @StateObject private var store = LensStore()

    var body: some Scene {
        Window("Lens", id: "workspace") {
            LensWorkspaceView(store: store)
                .onAppear { delegate.store = store; store.openWorkspace() }
                .background(LensWorkspaceCloseBridge { NSApp.terminate(nil) })
                .frame(minWidth: 1120, minHeight: 680)
        }
        .defaultSize(width: 1480, height: 920)
        .windowStyle(.titleBar)
        .commands {
            CommandGroup(replacing: .newItem) {
                Button("New Session", action: store.newSession)
                    .keyboardShortcut("n", modifiers: [.command])
                    .disabled(!store.canCreateSession)
                Button("Open Workspace…") { store.presentSessionAction(.openWorkspaceDocument) }
                    .keyboardShortcut("o", modifiers: [.command])
                    .disabled(!store.canOpenWorkspace)
                Menu("Open Recent") {
                    if store.recentWorkspaceURLs.isEmpty { Text("No Recent Workspaces") }
                    ForEach(store.recentWorkspaceURLs, id: \.self) { url in
                        Button(store.recentWorkspaceTitle(for: url)) { store.openRecentWorkspace(url) }
                            .help(url.path)
                            .disabled(!store.canOpenWorkspace)
                    }
                    Divider()
                    Button("Clear Menu", action: store.clearRecentWorkspaces)
                        .disabled(store.recentWorkspaceURLs.isEmpty)
                }
                Button("Rename Session…") { store.presentSessionAction(.rename) }
                    .disabled(!store.hasEngine || !store.canCreateSession)
                Button("Close Session…") { store.presentSessionAction(.close) }
                    .keyboardShortcut("w", modifiers: [.command, .shift])
                    .disabled(!store.hasEngine || !store.canCreateSession)
                Button("Clear HTTP traffic…") { store.presentSessionAction(.clearHTTP) }
                    .disabled(!store.hasEngine || !store.canCreateSession || store.flows.isEmpty)
                Button("Open workspace copy…") { store.presentSessionAction(.openWorkspace) }
                    .disabled(!store.hasEngine || !store.canCreateSession)
                Divider()
                Button("Session files…") { store.showSessionStorage = true }
                    .keyboardShortcut("s", modifiers: [.command, .option])
            }
            CommandGroup(replacing: .saveItem) {
                Button("Save Workspace") { store.saveWorkspace() }
                    .keyboardShortcut("s", modifiers: [.command])
                    .disabled(!store.canSaveWorkspace || store.sessionAction != nil)
                Button("Save Workspace As…") { store.saveWorkspace(chooseAnotherFile: true) }
                    .keyboardShortcut("s", modifiers: [.command, .shift])
                    .disabled(!store.canSaveWorkspace || store.sessionAction != nil)
            }
        }
    }
}
