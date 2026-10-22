import Foundation

// This standalone reader exposes process start identities only.
@main
struct PeerIdentityMain {
    struct Response: Encodable {
        let version = 1
        let results: [ProcessIdentityObservation]
    }
    static func main() {
        let arguments = Array(CommandLine.arguments.dropFirst())
        let pids = arguments.compactMap(Int32.init)
        guard !pids.isEmpty, pids.count <= 16, pids.count == arguments.count,
              pids.allSatisfy({ $0 > 0 }) else {
            fputs("Expected 1–16 positive process IDs\n", stderr); exit(64)
        }
        do {
            let data = try JSONEncoder().encode(Response(results: readProcessIdentities(pids: pids)))
            FileHandle.standardOutput.write(data)
        } catch { fputs("Could not encode process identities\n", stderr); exit(70) }
    }
}
