import Foundation

struct TrafficFlow: Codable, Identifiable, EngineSourced {
    var sourceFacts = EngineSourceFacts()
    let id: String
    var sessionId: String?
    var url: String
    var host: String
    var path: String
    var method: String
    var status: Int?
    var scheme: String
    var httpVersion: String
    var started: Double
    var durationMs: Double?
    var requestSize: Int
    var responseSize: Int
    var state: String
    var contentType: String
    var error: String?
    var isWebsocket: Bool
    var replayed: Bool
    var websocketMessagesTruncated: Bool?
    var imported: Bool?
    var originalUrl: String?
    var routedUrl: String?
    var requestTargetSource: String?
    var breakpointUrl: String?
    var dnsAddress: String?
    var pauseId: String?
    var pauseStage: String?
    var pauseDeadline: Double?
    var pauseTimeoutSeconds: Int?
    var requestBodyAvailable: Bool?
    var responseBodyAvailable: Bool?
    var clientConnection: ClientConnectionInfo?
    var accessDecision: AccessDecision?
    var requestOperation: RequestOperationInfo?

    enum CodingKeys: String, CodingKey { case id, sessionId, url, host, path, method, status, scheme, httpVersion, started, durationMs, requestSize, responseSize, state, contentType, error, isWebsocket, replayed, websocketMessagesTruncated, imported, originalUrl, routedUrl, requestTargetSource, breakpointUrl, dnsAddress, pauseId, pauseStage, pauseDeadline, pauseTimeoutSeconds, requestBodyAvailable, responseBodyAvailable, clientConnection, accessDecision, requestOperation }

    var requestTargetSourceLabel: String {
        switch requestTargetSource {
        case "capture": return "Captured SDK fields"
        case "har_facts": return "Restored from HAR request facts"
        case "har_url": return "Derived from HAR URL · original routing and target form not recorded"
        default: return "Not recorded"
        }
    }

    var breakpointStage: String { pauseStage ?? (status == nil ? "request" : "response") }

    var durationLabel: String { durationMs.map { String(format: "%.0f ms", $0) } ?? "—" }
    var sizeLabel: String { responseBodyAvailable == false ? "Unavailable" : ByteCountFormatter.string(fromByteCount: Int64(responseSize), countStyle: .file) }
    var statusLabel: String { state == "paused" ? "Paused" : status.map(String.init) ?? (state == "error" ? "Error" : "…") }
}

struct RequestOperationInfo: Codable, Equatable {
    let kind: String
    let id: String
    let sourceId: String?
    let urlInput: String?
    let attempt: Int?
}

struct FlowDetail: Decodable, EngineSourced {
    var sourceFacts = EngineSourceFacts()
    var requestHeaderFields: [HTTPHeaderField] = []
    var responseHeaderFields: [HTTPHeaderField] = []
    var requestHeadersBase64: [[String]]?
    var responseHeadersBase64: [[String]]?
    var requestMethodBase64: String?
    var requestTargetBase64: String?
    var requestUrlBase64: String?
    var requestUrlUnavailableReason: String?
    var requestPort: Int?
    var requestTargetForm: String?
    var responseReasonBase64: String?
    let id: String
    var requestFingerprint: String?
    var method: String?
    var url: String?
    var pauseId: String?
    var pauseStage: String?
    var requestHeaders: [[String]]
    var responseHeaders: [[String]]
    var responseReason: String?
    var requestBody: String
    var responseBody: String
    var requestTruncated: Bool
    var responseTruncated: Bool
    var messages: [SocketMessage]
    var messagesTruncated: Bool?
    var messagesTotal: Int?
    var messagesOffset: Int?
    var messagesLimit: Int?
    var messagesNextOffset: Int?
    var messagesGeneration: Int?
    var messagesPreviewLimit: Int?
    var requestBodyBase64: String?
    var responseBodyBase64: String?
    var requestBinary: Bool?
    var responseBinary: Bool?
    var requestBodyAvailable: Bool?
    var responseBodyAvailable: Bool?
    enum CodingKeys: String, CodingKey { case requestHeadersBase64, responseHeadersBase64, requestMethodBase64, requestTargetBase64, requestUrlBase64, requestUrlUnavailableReason, requestPort, requestTargetForm, responseReasonBase64, id, requestFingerprint, method, url, pauseId, pauseStage, requestHeaders, responseHeaders, responseReason, requestBody, responseBody, requestTruncated, responseTruncated, messages, messagesTruncated, messagesTotal, messagesOffset, messagesLimit, messagesNextOffset, messagesGeneration, messagesPreviewLimit, requestBodyBase64, responseBodyBase64, requestBinary, responseBinary, requestBodyAvailable, responseBodyAvailable }

    func firstWebSocketPage() throws -> WebSocketMessagePage? {
        if messagesTotal == nil && messagesOffset == nil && messagesLimit == nil && messagesNextOffset == nil && messagesGeneration == nil && messagesPreviewLimit == nil { return nil }
        guard let total = messagesTotal, let offset = messagesOffset, let limit = messagesLimit,
              let generation = messagesGeneration, let preview = messagesPreviewLimit else {
            throw EngineJSONFailure.invalid("Incomplete WebSocket page facts")
        }
        let page = WebSocketMessagePage(id: id, messages: messages, total: total, offset: offset, limit: limit,
            nextOffset: messagesNextOffset, generation: generation, previewLimit: preview, retentionTruncated: messagesTruncated)
        try page.validate()
        return page
    }

    mutating func attachSourceFacts(_ facts: EngineSourceFacts) throws {
        sourceFacts = facts
        requestHeaderFields = try HTTPHeaderField.decode(requestHeadersBase64, legacy: requestHeaders, legacyHasSourceText: facts.containsPrefix("request_headers"))
        responseHeaderFields = try HTTPHeaderField.decode(responseHeadersBase64, legacy: responseHeaders, legacyHasSourceText: facts.containsPrefix("response_headers"))
    }
    func bytes(_ value: String?, label: String) throws -> Data {
        guard let value, let bytes = Data(base64Encoded: value), bytes.base64EncodedString() == value else { throw EngineJSONFailure.invalid("Missing or invalid " + label + " bytes") }
        return bytes
    }
    func reasonBytes() throws -> Data {
        if responseReasonBase64 != nil { return try bytes(responseReasonBase64, label: "response reason") }
        guard !sourceFacts.contains("response_reason"), let value = (responseReason ?? "").data(using: .isoLatin1, allowLossyConversion: false) else { throw EngineJSONFailure.invalid("Original response reason bytes are unavailable") }
        return value
    }

}

struct SocketMessage: Decodable {
    var direction: String
    var text: String
    var timestamp: Double
    var index: Int?
    var opcode: Int?
    var contentBase64: String?
    var contentBytes: Int?
    var previewTruncated: Bool?
    var dropped: Bool?
    var injected: Bool?
    var previewBytes: Data?
    private enum CodingKeys: String, CodingKey { case direction, text, timestamp, index, opcode, contentBase64, contentBytes, previewTruncated, dropped, injected }
    var kindLabel: String { opcode == 1 ? "Text" : opcode == 2 ? "Binary" : "Type not recorded" }
    var preferredHex: Bool {
        guard let previewBytes else { return false }
        return opcode != 1 || String(data: previewBytes, encoding: .utf8) == nil
    }
    var previewText: String {
        guard let previewBytes else { return text }
        return String(data: previewBytes, encoding: .utf8) ?? "[Preview is not valid UTF-8. Use Hex for captured bytes.]"
    }
}

extension SocketMessage {
    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        direction = try values.decode(String.self, forKey: .direction)
        text = try values.decode(String.self, forKey: .text)
        timestamp = try values.decode(Double.self, forKey: .timestamp)
        index = try values.decodeIfPresent(Int.self, forKey: .index)
        opcode = try values.decodeIfPresent(Int.self, forKey: .opcode)
        contentBase64 = try values.decodeIfPresent(String.self, forKey: .contentBase64)
        contentBytes = try values.decodeIfPresent(Int.self, forKey: .contentBytes)
        previewTruncated = try values.decodeIfPresent(Bool.self, forKey: .previewTruncated)
        dropped = try values.decodeIfPresent(Bool.self, forKey: .dropped)
        injected = try values.decodeIfPresent(Bool.self, forKey: .injected)
        guard ["send", "receive"].contains(direction), timestamp.isFinite,
              index.map({ $0 >= 0 }) ?? true, opcode.map({ [1, 2].contains($0) }) ?? true else {
            throw EngineJSONFailure.invalid("Invalid WebSocket message facts")
        }
        if let encoded = contentBase64 {
            guard encoded.utf8.count <= ((4096 + 2) / 3) * 4,
                  let bytes = Data(base64Encoded: encoded), bytes.count <= 4096,
                  bytes.base64EncodedString() == encoded,
                  let total = contentBytes, (bytes.count...(32 * 1024 * 1024)).contains(total),
                  previewTruncated == (bytes.count < total) else {
                throw EngineJSONFailure.invalid("Invalid WebSocket preview bytes or completeness")
            }
            previewBytes = bytes
        } else {
            guard contentBytes == nil, previewTruncated == nil else { throw EngineJSONFailure.invalid("WebSocket preview omitted its captured bytes") }
            previewBytes = nil
        }
    }
}

struct WebSocketMessagePage: Decodable, EngineSourced {
    var sourceFacts = EngineSourceFacts()
    let id: String
    let messages: [SocketMessage]
    let total: Int
    let offset: Int
    let limit: Int
    let nextOffset: Int?
    let generation: Int
    let previewLimit: Int
    let retentionTruncated: Bool?
    enum CodingKeys: String, CodingKey { case id, messages, total, offset, limit, nextOffset, generation, previewLimit, retentionTruncated }
    func validate() throws {
        guard (0...2000).contains(total), (0...total).contains(offset), (1...50).contains(limit),
              generation >= 0, previewLimit == 4096, messages.count == min(limit, total - offset),
              messages.enumerated().allSatisfy({ $0.element.index == offset + $0.offset && $0.element.previewBytes != nil }),
              nextOffset == (offset + messages.count < total ? offset + messages.count : nil) else {
            throw EngineJSONFailure.invalid("Invalid WebSocket page coverage")
        }
    }
}

// Intentionally not Codable: passwords and selected identities are memory-only.
struct ClientCertificateSelection: Identifiable {
    var id = UUID()
    var host = ""
    var port = "443"
    var path = ""
    var password = ""

    var issue: String? {
        if host.isEmpty || host.unicodeScalars.count > 1024 { return "Enter an exact hostname or IP address (at most 1024 characters)." }
        guard let number = Int(port), (1...65535).contains(number) else { return "Target port must be between 1 and 65535." }
        if !NSString(string: path).expandingTildeInPath.hasPrefix("/") || path.contains("\0") { return "Choose an absolute certificate file path." }
        return nil
    }

    func commandValue() throws -> [String: Any] {
        if let issue { throw NSError(domain: "LensClientCertificates", code: 1, userInfo: [NSLocalizedDescriptionKey: issue]) }
        return ["host": host, "port": Int(port)!, "path": path, "password": password]
    }
}

struct ClientCertificateInfo: Decodable, Identifiable, EngineSourced {
    var sourceFacts = EngineSourceFacts()
    let host: String
    let port: Int
    let path: String
    let sha256: String
    let subject: String
    let expires: String
    var endpointLabel: String { "\(host.contains(":") ? "[\(host)]" : host):\(port)" }
    var id: String { "\(host):\(port)" }
    enum CodingKeys: String, CodingKey { case host, port, path, sha256, subject, expires }

}

struct RemoteDestination: Codable, Equatable {
    var scheme = "", host = "", port = "", path = "", query = ""
    var queryMode = "preserve"
    enum CodingKeys: String, CodingKey { case scheme, host, port, path, query; case queryMode = "query_mode" }
    init() {}
    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        scheme = try values.decodeIfPresent(String.self, forKey: .scheme) ?? ""
        host = try values.decodeIfPresent(String.self, forKey: .host) ?? ""
        if let number = try? values.decode(Int.self, forKey: .port) { port = String(number) }
        else { port = try values.decodeIfPresent(String.self, forKey: .port) ?? "" }
        path = try values.decodeIfPresent(String.self, forKey: .path) ?? ""
        query = try values.decodeIfPresent(String.self, forKey: .query) ?? ""
        queryMode = try values.decodeIfPresent(String.self, forKey: .queryMode) ?? "preserve"
    }
    var issue: String? {
        if !["", "http", "https"].contains(scheme) { return "Choose Original, HTTP or HTTPS." }
        if !port.isEmpty && !(port.utf8.allSatisfy({ (48...57).contains($0) }) && port.count <= 5 && (1...65535).contains(Int(port) ?? 0)) { return "Port must be blank or 1–65535." }
        if !path.isEmpty && (!path.hasPrefix("/") || path.contains("?")) { return "Use an absolute /path and the separate query selection." }
        if !["preserve", "replace"].contains(queryMode) { return "Choose Preserve or Replace query." }
        return nil
    }
}

struct ProxyRule: Codable, Identifiable {
    var id = UUID().uuidString
    var enabled = true
    var kind = "rewrite_response_header"
    var match = "*"
    var name = ""
    var value = ""
    var timeoutSeconds = 60
    var pathMode = "relative"
    var mapDestination: RemoteDestination?
    var rewriteMode = "set"
    var rewriteFind = ""
    var rewriteCount = "all"
    var rewriteRegex = false
    var rewriteNameRegex = false
    var rewriteWhole = false
    var rewriteCaseSensitive = true
    var rewriteNewName = ""
    var rewriteTimeoutMs = 250
    var locations: [String] = []
    var rewriteRules: [ProxyRule] = []

    static func rewriteSet() -> ProxyRule {
        ProxyRule(kind: "rewrite_set", name: "Untitled Set", locations: ["*"])
    }
    var remoteIssue: String? {
        guard kind == "map_remote" else { return mapDestination == nil ? nil : "Individual destination fields require Map Remote." }
        if !["relative", "append"].contains(pathMode) { return "Choose a supported path mapping mode." }
        if let mapDestination { return mapDestination.issue }
        return value.isEmpty ? "Enter an absolute HTTP(S) destination URL." : nil
    }
    var isRewriteSet: Bool { kind == "rewrite_set" }
    var configurationRowCount: Int { 1 + (isRewriteSet ? locations.count + rewriteRules.count : 0) }

    static let breakpointTimeoutRange = 1...3600
    private enum CodingKeys: String, CodingKey {
        case id, enabled, kind, match, name, value
        case timeoutSeconds = "timeout_seconds"
        case pathMode = "path_mode"
        case mapDestination = "map_destination"
        case rewriteMode = "rewrite_mode", rewriteFind = "rewrite_find", rewriteCount = "rewrite_count"
        case rewriteRegex = "rewrite_regex", rewriteNameRegex = "rewrite_name_regex", rewriteWhole = "rewrite_whole"
        case rewriteCaseSensitive = "rewrite_case_sensitive", rewriteNewName = "rewrite_new_name", rewriteTimeoutMs = "rewrite_timeout_ms"
        case locations, rewriteRules = "rewrite_rules"
    }

    static let kinds: [(String, String)] = [
        ("rewrite_request_header", "Request header"), ("rewrite_response_header", "Response header"),
        ("rewrite_request_body", "Request body"), ("rewrite_response_body", "Response body"),
        ("rewrite_request_url", "Request URL"), ("rewrite_request_query", "Query parameter"),
        ("rewrite_response_status", "Response status"),
        ("map_remote", "Map Remote"), ("map_local", "Map Local"), ("block", "Block"),
        ("breakpoint_request", "Request breakpoint"), ("breakpoint_response", "Response breakpoint"),
        ("delay", "Latency (ms)"), ("no_cache", "Disable caching"), ("block_cookies", "Block cookies"),
        ("dns_spoof", "DNS mapping")
    ]
    var label: String { if isRewriteSet { return "Rewrite set" }; return Self.kinds.first { $0.0 == kind }?.1 ?? kind }
    var isHeaderRewrite: Bool { ["rewrite_request_header", "rewrite_response_header"].contains(kind) }
    var isQueryRewrite: Bool { kind == "rewrite_request_query" }
    var rewriteModes: [String] { isHeaderRewrite ? ["set", "add", "remove", "replace"] : isQueryRewrite ? ["set", "add", "remove", "replace"] : [] }
    var needsLiteralFind: Bool { kind.hasSuffix("_body") || kind == "rewrite_request_url" }
    var needsReplacementCount: Bool { needsLiteralFind || ((isHeaderRewrite || isQueryRewrite) && rewriteMode == "replace") }
    var supportsNamePattern: Bool { (isHeaderRewrite || isQueryRewrite) && ["replace", "remove"].contains(rewriteMode) }
    var hasPatternOptions: Bool { rewriteRegex || rewriteNameRegex || rewriteWhole || !rewriteCaseSensitive }
    var isRewriteAction: Bool { kind.hasPrefix("rewrite_") && !isRewriteSet }
    var rewriteIssue: String? {
        if isRewriteSet {
            if name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { return "Enter a name for this Rewrite set." }
            if locations.contains(where: { $0.isEmpty || $0.contains(where: { "\0\r\n".contains($0) }) }) { return "Use one nonempty URL glob per location, without NUL or line breaks." }
            if rewriteRules.contains(where: { !$0.isRewriteAction }) { return "A Rewrite set can contain Rewrite actions only." }
            return rewriteRules.compactMap(\.rewriteIssue).first
        }
        if isRewriteAction && !(1...5000).contains(rewriteTimeoutMs) { return "Choose a match timeout from 1 to 5000 milliseconds." }
        if !supportsNamePattern && (rewriteNameRegex || !rewriteNewName.isEmpty) { return "Name matching and renaming require Header/Query Replace or Remove." }
        if rewriteMode == "remove" && !rewriteNewName.isEmpty { return "Remove cannot rename a field." }
        if !needsReplacementCount && (rewriteRegex || rewriteWhole || !rewriteCaseSensitive) { return "Value matching options require a text replacement operation." }
        if !rewriteModes.isEmpty && !rewriteModes.contains(rewriteMode) { return "Choose a supported rewrite operation." }
        if (isHeaderRewrite || isQueryRewrite) && rewriteMode != "replace" && (!rewriteFind.isEmpty || rewriteCount != "all") { return "Saved find/count options require Replace. Select an operation to update this draft." }
        if needsLiteralFind && name.isEmpty && !rewriteRegex { return "Enter nonempty text to find." }
        if (isHeaderRewrite || isQueryRewrite) && name.isEmpty && !rewriteNameRegex { return "Enter a field name." }
        if (isHeaderRewrite || isQueryRewrite) && rewriteMode == "replace" && rewriteFind.isEmpty && !rewriteRegex { return "Enter nonempty header value text to find." }
        if needsReplacementCount && !["all", "first"].contains(rewriteCount) { return "Choose First or All replacements." }
        if kind == "rewrite_response_status", !(name.count == 3 && name.utf8.allSatisfy({ (48...57).contains($0) }) && (200...599).contains(Int(name) ?? 0)) { return "Response status must be 200–599." }
        return nil
    }
    // Explicit user changes admit the new operation's draft. Decoding leaves
    // saved/unknown choices intact so opening a sheet never rewrites them.
    mutating func selectKind(_ selected: String) {
        kind = selected
        if selected != "map_remote" { mapDestination = nil }
        if rewriteModes.isEmpty { rewriteMode = "set" }
        if !(isHeaderRewrite || isQueryRewrite) || rewriteMode != "replace" { rewriteFind = "" }
        if !needsReplacementCount { rewriteCount = "all"; rewriteRegex = false; rewriteWhole = false; rewriteCaseSensitive = true }
        if !supportsNamePattern { rewriteNameRegex = false; rewriteNewName = "" }
        if !rewriteModes.isEmpty && rewriteMode == "remove" { value = "" }
    }
    mutating func selectRewriteMode(_ selected: String) {
        rewriteMode = selected
        if selected != "replace" { rewriteFind = ""; rewriteCount = "all"; rewriteRegex = false; rewriteWhole = false; rewriteCaseSensitive = true }
        if !supportsNamePattern { rewriteNameRegex = false; rewriteNewName = "" }
        if selected == "remove" { rewriteNewName = "" }
        if selected == "remove" { value = "" }
    }
}

extension ProxyRule {
    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        id = try values.decode(String.self, forKey: .id)
        enabled = try values.decode(Bool.self, forKey: .enabled)
        kind = try values.decode(String.self, forKey: .kind)
        match = try values.decode(String.self, forKey: .match)
        name = try values.decode(String.self, forKey: .name)
        value = try values.decode(String.self, forKey: .value)
        timeoutSeconds = try values.decodeIfPresent(Int.self, forKey: .timeoutSeconds) ?? 60
        pathMode = try values.decodeIfPresent(String.self, forKey: .pathMode) ?? "append"
        mapDestination = try values.decodeIfPresent(RemoteDestination.self, forKey: .mapDestination)
        rewriteMode = try values.decodeIfPresent(String.self, forKey: .rewriteMode) ?? "set"
        rewriteFind = try values.decodeIfPresent(String.self, forKey: .rewriteFind) ?? ""
        rewriteCount = try values.decodeIfPresent(String.self, forKey: .rewriteCount) ?? "all"
        rewriteRegex = try values.decodeIfPresent(Bool.self, forKey: .rewriteRegex) ?? false
        rewriteNameRegex = try values.decodeIfPresent(Bool.self, forKey: .rewriteNameRegex) ?? false
        rewriteWhole = try values.decodeIfPresent(Bool.self, forKey: .rewriteWhole) ?? false
        rewriteCaseSensitive = try values.decodeIfPresent(Bool.self, forKey: .rewriteCaseSensitive) ?? true
        rewriteNewName = try values.decodeIfPresent(String.self, forKey: .rewriteNewName) ?? ""
        rewriteTimeoutMs = try values.decodeIfPresent(Int.self, forKey: .rewriteTimeoutMs) ?? 250
        locations = try values.decodeIfPresent([String].self, forKey: .locations) ?? []
        rewriteRules = try values.decodeIfPresent([ProxyRule].self, forKey: .rewriteRules) ?? []
    }
}

// Request URL policy is independent from ordered traffic transformations and LAN peers.
struct AccessPolicy: Codable, Equatable {
    var blockEnabled = false
    var allowEnabled = false
    var block: [String] = []
    var allow: [String] = []
    var action = "respond"

    private enum CodingKeys: String, CodingKey {
        case blockEnabled = "block_enabled", allowEnabled = "allow_enabled", block, allow, action
    }
    var issue: String? {
        if !["respond", "close"].contains(action) { return "Choose a supported denial action: HTTP 403 or abort request." }
        for (label, patterns) in [("Block", block), ("Allow", allow)] {
            if patterns.count > 500 { return "\(label) List supports at most 500 URL patterns." }
            for (offset, pattern) in patterns.enumerated() {
                if pattern.isEmpty || pattern.unicodeScalars.count > 4096 || pattern.unicodeScalars.contains(where: { [0, 10, 13].contains($0.value) }) {
                    return "\(label) pattern \(offset + 1) must contain 1–4096 Unicode code points and no NUL or line breaks."
                }
            }
        }
        return nil
    }
    func commandValue() throws -> [String: Any] {
        if let issue { throw NSError(domain: "LensAccessLists", code: 1, userInfo: [NSLocalizedDescriptionKey: issue]) }
        return ["block_enabled": blockEnabled, "allow_enabled": allowEnabled, "block": block, "allow": allow, "action": action]
    }
}

struct AccessDecision: Codable, Equatable {
    let reason: String
    let action: String
    let matchedUrl: String
    let pattern: String?
    var reasonLabel: String { reason == "block_match" ? "Block List match" : reason == "allow_miss" ? "Missing from Allow List" : reason }
    var actionLabel: String { action == "respond" ? "HTTP 403" : action == "close" ? "Request aborted" : action }
}

struct RepeatJob: Decodable, Identifiable, EngineSourced {
    var sourceFacts = EngineSourceFacts()
    let jobId: String
    var sessionId: String?
    var sourceId: String?
    var total: Int
    var completed: Int
    var failed: Int
    var cancelled: Int
    var state: String
    var id: String { jobId }
    var finished: Bool { ["complete", "completed", "cancelled"].contains(state) }
    var finishedCount: Int { completed + failed + cancelled }
    enum CodingKeys: String, CodingKey { case jobId, sessionId, sourceId, total, completed, failed, cancelled, state }

}

// Preferences preserve the user's range; parsed facts own port arithmetic and wire values.
protocol ForwardSelection {
    var listenPort: String { get }
    var listenPortEnd: String? { get }
    var targetHost: String { get }
    var targetPort: String { get }
}

extension ForwardSelection {
    var parsed: Result<ForwardEndpointFacts, ForwardEndpointFailure> {
        ForwardEndpointValidation.parse(listenPort: listenPort, listenPortEnd: listenPortEnd, targetHost: targetHost, targetPort: targetPort)
    }
    var issue: String? {
        if case .failure(let failure) = parsed { return failure.localizedDescription }
        return nil
    }
    func commandValue() throws -> [String: Any] { try parsed.get().commandValue }
}

struct TCPForwardSelection: Codable, Identifiable, ForwardSelection {
    var id = UUID()
    var listenPort = ""
    var listenPortEnd: String? = nil
    var targetHost = ""
    var targetPort = ""
}

struct UDPForwardSelection: Codable, Identifiable, ForwardSelection {
    var id = UUID()
    var listenPort = ""
    var listenPortEnd: String? = nil
    var targetHost = ""
    var targetPort = ""
}

struct ForwardEndpointFailure: LocalizedError {
    let errorDescription: String?
    init(_ reason: String) { errorDescription = reason }
}

struct ForwardEndpointFacts {
    let listenPorts: ClosedRange<Int>
    let explicitEnd: Int?
    let targetHost: String
    let targetPort: Int
    var commandValue: [String: Any] {
        var value: [String: Any] = ["listen_port": listenPorts.lowerBound, "target_host": targetHost, "target_port": targetPort]
        if let explicitEnd { value["listen_port_end"] = explicitEnd }
        return value
    }
}

// TCP and UDP share endpoint syntax, while each transport owns its listener namespace.
enum ForwardEndpointValidation {
    static let maximumPorts = 32
    static func parse(listenPort: String, listenPortEnd: String? = nil, targetHost: String, targetPort: String) -> Result<ForwardEndpointFacts, ForwardEndpointFailure> {
        guard let local = Int(listenPort), (1024...65535).contains(local),
              let remote = Int(targetPort), (1...65535).contains(remote) else {
            return .failure(ForwardEndpointFailure("Enter a local port from 1024–65535 and target port from 1–65535."))
        }
        let explicitEnd: Int?
        if let listenPortEnd, !listenPortEnd.isEmpty {
            guard let end = Int(listenPortEnd), (local...65535).contains(end) else {
                return .failure(ForwardEndpointFailure("Local end port must be an integer from the start port through 65535; leave it blank for one port."))
            }
            explicitEnd = end
        } else { explicitEnd = nil }
        let ports = local...(explicitEnd ?? local)
        guard ports.count <= maximumPorts else {
            return .failure(ForwardEndpointFailure("Use at most 32 listening ports per transport, including all ports in each range."))
        }
        guard remote <= 65535 - (ports.count - 1) else {
            return .failure(ForwardEndpointFailure("The target port range would exceed 65535. Lower the target base port or shorten the local range."))
        }
        if targetHost.isEmpty || targetHost.unicodeScalars.count > 1024 || targetHost.contains(where: { $0.isWhitespace || "/\\%@*?[]".contains($0) }) {
            return .failure(ForwardEndpointFailure("Enter an exact target hostname or IP address, without a URL or port (at most 1024 characters)."))
        }
        return .success(ForwardEndpointFacts(listenPorts: ports, explicitEnd: explicitEnd, targetHost: targetHost, targetPort: remote))
    }
    // Invalid rows still occupy a row, allowing correction or removal without hiding the capacity limit.
    static func configuredPortCount<S: ForwardSelection>(_ selections: [S]) -> Int {
        selections.reduce(0) { $0 + ((try? $1.parsed.get().listenPorts.count) ?? 1) }
    }
}

struct SocketEndpoint: Codable {
    let host: String, port: Int
    init(from decoder: Decoder) throws {
        var values = try decoder.unkeyedContainer()
        host = try values.decode(String.self); port = try values.decode(Int.self)
        guard values.isAtEnd else { throw DecodingError.dataCorruptedError(in: values, debugDescription: "Socket endpoint must have two fields") }
    }
    func encode(to encoder: Encoder) throws {
        var values = encoder.unkeyedContainer()
        try values.encode(host); try values.encode(port)
    }
    var label: String { "\(host.contains(":") ? "[\(host)]" : host):\(port)" }
}

struct ClientConnectionInfo: Codable {
    let version: Int
    let id: String
    let listener: String
    let peer: SocketEndpoint
    let listenerAddress: SocketEndpoint
    let acceptedAt: Double
    var process: ClientProcessInfo?
    var listenerLabel: String {
        switch listener {
        case "proxy_port": return "HTTP proxy"
        case "lan_proxy_port": return "LAN HTTP proxy"
        case "socks_port": return "SOCKS proxy"
        case "reverse_port": return "Reverse proxy"
        default: return listener
        }
    }
}

struct ClientProcessInfo: Codable {
    let version: Int
    let state: String
    let scope: String
    let observedAt: Double
    let reason: String?
    let pid: Int?
    let startIdentity: String?
    let name: String?
    let nameBytesBase64: String?
    let socketDescriptor: Int?
    let method: String?

    var label: String {
        guard state == "identified", let pid else { return "Unknown · \(reasonLabel)" }
        return "\(name ?? "Name bytes unavailable as UTF-8") · PID \(pid)"
    }
    private var reasonLabel: String {
        switch reason {
        case "lookup_deadline": return "Lookup timed out"
        case "lookup_stopped": return "Capture stopped during lookup"
        case "lookup_cleanup_pending": return "Helper cleanup requires Stop"
        case "no_visible_local_owner": return "No visible local socket owner"
        case "ambiguous_local_owner": return "Multiple processes own the socket"
        case "socket_owner_changed", "identity_changed": return "Ownership changed during lookup"
        case "identity_unavailable": return "Process start identity unavailable"
        case "process_name_ambiguous", "process_name_unavailable": return "Process name unavailable"
        case "command_output_limit": return "Lookup exceeded its output limit"
        default: return "Local lookup unavailable"
        }
    }
}

struct TCPStreamSummary: Decodable, Identifiable, EngineSourced {
    var sourceFacts = EngineSourceFacts()
    let id: String, targetHost: String, dialHost: String, state: String
    let listenPort: Int, targetPort: Int, sentBytes: Int64, receivedBytes: Int64, retainedBytes: Int, retainedChunks: Int, observedChunks: Int
    let started: Double
    let ended: Double?
    let sourceState: String?
    let peer: SocketEndpoint?
    let peerScope: Int?
    let peerFlowinfo: Int?
    let error: String?
    let truncated: Bool, imported: Bool
    var target: String { "\(targetHost.contains(":") ? "[\(targetHost)]" : targetHost):\(targetPort)" }
    var peerLabel: String {
        guard let peer else { return "unknown" }
        if peer.host.contains(":"), let scope = peerScope, scope != 0 { return "[\(peer.host)%\(scope)]:\(peer.port)" }
        return peer.label
    }
    enum CodingKeys: String, CodingKey { case id, targetHost, dialHost, state, listenPort, targetPort, sentBytes, receivedBytes, retainedBytes, retainedChunks, observedChunks, started, ended, sourceState, peer, peerScope, peerFlowinfo, error, truncated, imported }

}

struct TCPChunkPage: Decodable, EngineSourced {
    var sourceFacts = EngineSourceFacts()
    struct Chunk: Decodable, Identifiable {
        let sequence: Int, direction: String, timestamp: Double, observedBytes: Int, data: Data
        enum CodingKeys: String, CodingKey { case sequence, direction, timestamp, observedBytes, base64 }
        init(from decoder: Decoder) throws {
            let values = try decoder.container(keyedBy: CodingKeys.self)
            sequence = try values.decode(Int.self, forKey: .sequence)
            direction = try values.decode(String.self, forKey: .direction)
            timestamp = try values.decode(Double.self, forKey: .timestamp)
            observedBytes = try values.decode(Int.self, forKey: .observedBytes)
            let encoded = try values.decode(String.self, forKey: .base64)
            guard let bytes = Data(base64Encoded: encoded), ["send", "receive"].contains(direction),
                  !bytes.isEmpty, bytes.count <= observedBytes else {
                throw DecodingError.dataCorruptedError(forKey: .base64, in: values, debugDescription: "Invalid retained TCP chunk")
            }
            data = bytes
        }
        var id: Int { sequence }
        var hex: String { data.map { String(format: "%02x", $0) }.joined(separator: " ") }
        var text: String { String(decoding: data, as: UTF8.self) }
        var timestampLabel: String {
            guard (-62_135_596_800...253_402_300_799).contains(timestamp) else { return "Unix seconds \(timestamp)" }
            return Date(timeIntervalSince1970: timestamp).formatted()
        }
    }
    let stream: TCPStreamSummary, offset: Int, total: Int, chunks: [Chunk]
    enum CodingKeys: String, CodingKey { case stream, offset, total, chunks }

}

struct UDPAssociationSummary: Decodable, Identifiable, EngineSourced {
    var sourceFacts = EngineSourceFacts()
    let id: String, targetHost: String, dialHost: String, state: String
    let listenPort: Int, targetPort: Int
    let client: SocketEndpoint, listenerAddress: SocketEndpoint
    let peer: SocketEndpoint?
    let peerScope: Int?, peerFlowinfo: Int?
    let started: Double, ended: Double?
    let sourceState: String?, error: String?
    let sentDatagrams: Int, receivedDatagrams: Int, observedDatagrams: Int, retainedDatagrams: Int
    let sentBytes: Int64, receivedBytes: Int64, retainedBytes: Int
    let droppedClientDatagrams: Int, droppedClientBytes: Int64
    let droppedUpstreamDatagrams: Int, droppedUpstreamBytes: Int64
    let truncated: Bool, imported: Bool
    var target: String { "\(targetHost.contains(":") ? "[\(targetHost)]" : targetHost):\(targetPort)" }
    var peerLabel: String {
        guard let peer else { return "unknown" }
        if peer.host.contains(":"), let scope = peerScope, scope != 0 { return "[\(peer.host)%\(scope)]:\(peer.port)" }
        return peer.label
    }
    enum CodingKeys: String, CodingKey { case id, targetHost, dialHost, state, listenPort, targetPort, client, listenerAddress, peer, peerScope, peerFlowinfo, started, ended, sourceState, error, sentDatagrams, receivedDatagrams, observedDatagrams, retainedDatagrams, sentBytes, receivedBytes, retainedBytes, droppedClientDatagrams, droppedClientBytes, droppedUpstreamDatagrams, droppedUpstreamBytes, truncated, imported }

}

struct UDPDatagramPage: Decodable, EngineSourced {
    var sourceFacts = EngineSourceFacts()
    struct Datagram: Decodable, Identifiable {
        let sequence: Int, direction: String, timestamp: Double, observedBytes: Int, data: Data
        enum CodingKeys: String, CodingKey { case sequence, direction, timestamp, observedBytes, base64 }
        init(from decoder: Decoder) throws {
            let values = try decoder.container(keyedBy: CodingKeys.self)
            sequence = try values.decode(Int.self, forKey: .sequence)
            direction = try values.decode(String.self, forKey: .direction)
            timestamp = try values.decode(Double.self, forKey: .timestamp)
            observedBytes = try values.decode(Int.self, forKey: .observedBytes)
            let encoded = try values.decode(String.self, forKey: .base64)
            guard sequence > 0, timestamp.isFinite, timestamp >= 0, ["send", "receive"].contains(direction),
                  (0...65535).contains(observedBytes), encoded.utf8.count <= 87380, let bytes = Data(base64Encoded: encoded), bytes.count == observedBytes else {
                throw DecodingError.dataCorruptedError(forKey: .base64, in: values, debugDescription: "Invalid retained UDP datagram")
            }
            data = bytes
        }
        var id: Int { sequence }
        var hex: String { data.map { String(format: "%02x", $0) }.joined(separator: " ") }
        var text: String { String(decoding: data, as: UTF8.self) }
        var timestampLabel: String {
            guard (-62_135_596_800...253_402_300_799).contains(timestamp) else { return "Unix seconds \(timestamp)" }
            return Date(timeIntervalSince1970: timestamp).formatted()
        }
    }
    let association: UDPAssociationSummary, offset: Int, total: Int, datagrams: [Datagram]
    enum CodingKeys: String, CodingKey { case association, offset, total, datagrams }

}

struct HTTPSessionInfo: Codable, Identifiable, Equatable {
    let id: String
    let number: Int
    let name: String
    static let initial = HTTPSessionInfo(id: "default", number: 1, name: "Untitled Session 1")
}

struct HTTPSessionCatalog: Decodable {
    let captureSessionId: String
    let sessions: [HTTPSessionInfo]
    let viewSessionId: String?
    func validate() throws {
        let ids = Set(sessions.map(\.id))
        guard !sessions.isEmpty, ids.count == sessions.count,
              Set(sessions.map(\.number)).count == sessions.count,
              ids.contains(captureSessionId), viewSessionId.map(ids.contains) ?? true,
              sessions.allSatisfy({ session in
                  (session.id == "default" || (session.id.count == 32 && session.id.allSatisfy { "0123456789abcdef".contains($0) })) &&
                  session.number > 0 && session.number <= 2147483647 && !session.name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && session.name.utf8.count <= 4096 && !session.name.contains(where: { "\0\r\n".contains($0) })
              }) else { throw EngineJSONFailure.invalid("Invalid HTTP session catalog") }
    }
}
