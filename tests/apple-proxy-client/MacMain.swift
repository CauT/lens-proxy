import Foundation

@main private enum AppleProxyProbeCLI {
    static func main() async throws {
        guard CommandLine.arguments.count == 2 else {
            throw NSError(domain: "LensAppleProbe", code: 1, userInfo: [NSLocalizedDescriptionKey: "Pass one explicit request JSON file"])
        }
        let input = try JSONDecoder().decode(AppleProxyProbeConfiguration.self,
            from: Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1])))
        let result = try await AppleProxyProbe.run(input)
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        FileHandle.standardOutput.write(try encoder.encode(result))
        FileHandle.standardOutput.write(Data([10]))
    }
}
