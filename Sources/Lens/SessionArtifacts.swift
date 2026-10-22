import Foundation

enum ResponseMirror {
    private struct Metadata: Encodable {
        let urlDisplay: String, methodDisplay: String
        let status: Int?
        let capturedAt: Double
        let contentTypeDisplay: String, bodyFile: String
        let sourceTextFacts: EngineSourceFacts
        let bodyBytes: Int
        let representation: String, flowId: String
    }
    static func write(flow: TrafficFlow, bytes: Data, folder: URL) throws -> String {
        let fileManager = FileManager.default, name = UUID().uuidString
        let encoder = JSONEncoder(); encoder.keyEncodingStrategy = .convertToSnakeCase
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        // Typed encoding rejects nonfinite boundary values with a Swift error
        // before creating anything, rather than an Objective-C exception.
        let data = try encoder.encode(Metadata(urlDisplay: flow.url, methodDisplay: flow.method, status: flow.status,
            capturedAt: flow.started, contentTypeDisplay: flow.contentType, bodyFile: "response.bin", sourceTextFacts: flow.sourceFacts, bodyBytes: bytes.count,
            representation: "decoded response body", flowId: flow.id))
        let stage = folder.appendingPathComponent(".lens-" + name, isDirectory: true)
        let destination = folder.appendingPathComponent(name, isDirectory: true)
        try fileManager.createDirectory(at: stage, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        do {
            guard fileManager.createFile(atPath: stage.appendingPathComponent("response.bin").path, contents: bytes, attributes: [.posixPermissions: 0o600]),
                  fileManager.createFile(atPath: stage.appendingPathComponent("metadata.json").path, contents: data, attributes: [.posixPermissions: 0o600]) else {
                throw CocoaError(.fileWriteUnknown)
            }
            try fileManager.moveItem(at: stage, to: destination)
            return name
        } catch { try? fileManager.removeItem(at: stage); throw error }
    }
}
