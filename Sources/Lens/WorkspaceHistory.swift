import AppKit

/// AppKit owns recent-document persistence, ordering and capacity. Recording a
/// file here does not grant write authority or make it the current workspace.
@MainActor
struct WorkspaceHistory {
    let read: () -> [URL]
    let remember: (URL) -> Void
    let clear: () -> Void

    static var system: WorkspaceHistory {
        let controller = NSDocumentController.shared
        return WorkspaceHistory(
            read: { controller.recentDocumentURLs },
            remember: { controller.noteNewRecentDocumentURL($0) },
            clear: { controller.clearRecentDocuments(nil) })
    }
}
