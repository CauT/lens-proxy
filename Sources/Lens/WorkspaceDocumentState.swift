import Foundation

struct WorkspaceRevision: Equatable {
    let epoch: UUID
    let generation: String

    init(_ value: EngineValue?) throws {
        guard let source = value?["epoch"]?.unicodeString, let epoch = UUID(uuidString: source),
              let generation = value?["generation"]?.unicodeString, !generation.isEmpty,
              generation.utf8.allSatisfy({ (48...57).contains($0) }),
              generation == "0" || generation.first != "0" else {
            throw EngineJSONFailure.invalid("Invalid workspace revision")
        }
        self.epoch = epoch; self.generation = generation
    }

    func isAtMost(_ other: WorkspaceRevision) -> Bool {
        epoch == other.epoch && (generation.utf8.count < other.generation.utf8.count ||
            (generation.utf8.count == other.generation.utf8.count && generation <= other.generation))
    }
}

struct WorkspaceSaveReceipt {
    let sessions: Int
    let snapshot: WorkspaceRevision
    let current: WorkspaceRevision

    init(_ value: EngineValue, destination: URL) throws {
        guard let path = value["path"]?.unicodeString, path.utf8.elementsEqual(destination.path.utf8),
              let sessions = value["sessions"]?.integer, sessions > 0,
              let entries = value["entries"]?.integer, entries >= 0 else {
            throw EngineJSONFailure.invalid("Unverifiable workspace save receipt")
        }
        self.sessions = sessions
        snapshot = try WorkspaceRevision(value["workspace_revision"])
        current = try WorkspaceRevision(value["current_workspace_revision"])
        guard snapshot.isAtMost(current) else { throw EngineJSONFailure.invalid("Workspace save revision is ahead of its current state") }
    }
}

/// The engine owns mutations and snapshot cuts. This owner binds an explicitly
/// saved document to one cut, independent of filters, private copies or recents.
struct WorkspaceDocumentState {
    enum Binding { case preserve, document, copy }
    private(set) var current: WorkspaceRevision?
    private var savedRevision: WorkspaceRevision?
    private var uncertain = false

    var isEdited: Bool { uncertain || (current != nil && current != savedRevision) }
    func needsConfirmation(hasContent: Bool) -> Bool {
        uncertain || (current == nil ? hasContent : isEdited)
    }
    mutating func markUnknown() { uncertain = true }

    mutating func ready(_ value: EngineValue, binding: Binding) throws {
        let baseline = try WorkspaceRevision(value["workspace_base_revision"])
        let revision = try WorkspaceRevision(value["workspace_revision"])
        guard baseline.isAtMost(revision), let hasContent = value["workspace_base_has_content"]?.bool else {
            throw EngineJSONFailure.invalid("Workspace readiness omitted its baseline")
        }
        let wasEdited = isEdited
        switch binding {
        case .document: savedRevision = baseline
        case .copy: savedRevision = hasContent ? nil : baseline
        case .preserve: savedRevision = wasEdited || (current == nil && hasContent) ? nil : baseline
        }
        current = revision; uncertain = false
    }

    mutating func observe(_ revision: WorkspaceRevision) throws {
        guard let current, current.isAtMost(revision) else {
            throw EngineJSONFailure.invalid("Workspace revision changed epoch or moved backwards")
        }
        self.current = revision
    }

    mutating func observe(_ receipt: WorkspaceSaveReceipt) throws {
        try observe(receipt.current)
    }

    mutating func acceptSave(_ receipt: WorkspaceSaveReceipt) throws {
        try observe(receipt)
        savedRevision = receipt.snapshot
        uncertain = false
    }
}
