import SwiftUI
import UniformTypeIdentifiers
import Darwin

enum HTTPBytesEncoding: String, CaseIterable { case utf8 = "UTF-8 text", base64 = "Base64" }

struct HTTPHeaderRow: Identifiable {
    let id = UUID()
    var name: String
    var value: String
    var encoding: HTTPBytesEncoding
    private let originalField: HTTPHeaderField
    private let originalDisplayName: String
    private let originalValueText: String
    private let originalEncoding: HTTPBytesEncoding
    init(name: String, value: String) { self.init(field: HTTPHeaderField(name: Data(name.utf8), value: Data(value.utf8))) }
    init(field: HTTPHeaderField) {
        originalField = field; originalDisplayName = field.displayName; name = field.displayName
        if let text = String(data: field.value, encoding: .utf8) { value = text; encoding = .utf8 }
        else { value = field.value.base64EncodedString(); encoding = .base64 }
        originalValueText = value; originalEncoding = encoding
    }
    func field() throws -> HTTPHeaderField {
        let nameBytes = Data(name.utf8) == Data(originalDisplayName.utf8) ? originalField.name : Data(name.utf8)
        let valueBytes = encoding == originalEncoding && Data(value.utf8) == Data(originalValueText.utf8)
            ? originalField.value : try HTTPMessageDraft.valueBytes(value, encoding: encoding, limit: 65536)
        return HTTPHeaderField(name: nameBytes, value: valueBytes)
    }
    mutating func setEncoding(_ next: HTTPBytesEncoding) throws {
        let bytes = try field().value
        guard next != encoding else { return }
        if next == .utf8 { guard let text = String(data: bytes, encoding: .utf8) else { throw EngineJSONFailure.invalid("These bytes are not UTF-8. Keep Base64 or explicitly replace the value.") }; value = text }
        else { value = bytes.base64EncodedString() }
        encoding = next
    }
}

// Both Compose and Breakpoints edit the same message representation. A preview
// supplies context only; replacement bytes require an explicit choice.
struct HTTPMessageDraft {
    let stage: String
    let originalMethod: String
    let originalURL: String
    let originalStatus: String
    let originalReason: Data
    private let originalReasonText: String
    private let originalReasonEncoding: HTTPBytesEncoding
    let originalHeaders: [HTTPHeaderField]
    let bodyNotice: String
    var method: String
    var url: String
    var status: String
    var reason: String
    var headers: [HTTPHeaderRow]
    var replaceBody = false
    var encoding = HTTPBytesEncoding.utf8
    var reasonEncoding = HTTPBytesEncoding.utf8
    var methodIsOpaque = false
    var urlIsOpaque = false
    var replaceMethod = false
    var replaceURL = false
    var body = ""
    var replacementFileName: String?
    var replacementFileData: Data?
    var replacementFileIssue: String?
    static let fileBodyLimit = 32 * 1024 * 1024
    static let managedHeaders: Set<String> = ["host", "content-length", "transfer-encoding"]
    static let bodyLimit = 2 * 1024 * 1024

    init(stage: String = "request", method: String = "GET", url: String = "", status: Int? = nil,
         reason: Data? = nil, headers: [HTTPHeaderField] = [], available: Bool = true,
         binary: Bool = false, truncated: Bool = false, newRequest: Bool = false) {
        self.stage = stage
        originalMethod = method; self.method = method
        originalURL = url; self.url = url
        originalStatus = status.map(String.init) ?? "200"; self.status = originalStatus
        originalReason = reason ?? Data()
        if let text = String(data: originalReason, encoding: .utf8) { self.reason = text }
        else { self.reason = originalReason.base64EncodedString(); reasonEncoding = .base64 }
        originalReasonText = self.reason; originalReasonEncoding = reasonEncoding
        originalHeaders = headers.filter { !$0.managed }
        self.headers = originalHeaders.map { HTTPHeaderRow(field: $0) }
        bodyNotice = newRequest ? "A new request starts with an empty body. Enable Replace body to supply explicit bytes."
            : !available ? "The source body is unavailable. Supply an explicit replacement to compose this request."
            : truncated ? "The inspector has only a preview. Keep preserves the complete source body; replacement must be supplied explicitly."
            : binary ? "Binary body. Keep preserves the original bytes; replacement accepts explicit UTF-8 or Base64."
            : "Keep preserves the original bytes. Enable Replace body to supply an explicit replacement, including an empty body."
    }
    static func token(_ value: String) -> Bool {
        let allowed = Set("!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".utf8)
        return !value.isEmpty && value.utf8.allSatisfy { allowed.contains($0) }
    }
    private func failure(_ message: String) -> NSError { NSError(domain: "LensHTTPMessage", code: 1, userInfo: [NSLocalizedDescriptionKey: message]) }
    func patch() throws -> [String: Any] {
        if replaceBody, let replacementFileIssue { throw failure(replacementFileIssue + " Choose another file or explicitly use the inline editor.") }
        var result: [String: Any] = [:]
        if stage == "request" {
            if (!methodIsOpaque || replaceMethod) && Data(method.utf8) != Data(originalMethod.utf8) {
                guard Self.token(method) else { throw failure("Method must be a nonempty ASCII HTTP token.") }
                result["method"] = method
            }
            if (!urlIsOpaque || replaceURL) && Data(url.utf8) != Data(originalURL.utf8) {
                let authority = url.range(of: "://").map { String(url[$0.upperBound...].prefix { !["/", "?", "#"].contains($0) }) } ?? ""
                guard !authority.hasSuffix(":"), url.unicodeScalars.count <= 65536, !url.contains("\\"),
                      !url.unicodeScalars.contains(where: { $0.value <= 32 || $0.value == 127 }),
                      let parts = URLComponents(string: url), let scheme = parts.scheme?.lowercased(),
                      ["http", "https"].contains(scheme), let host = parts.host, !host.isEmpty,
                      parts.user == nil, parts.password == nil, parts.fragment == nil,
                      parts.port.map({ (1...65535).contains($0) }) ?? true else {
                    throw failure("URL must be absolute HTTP or HTTPS, with a host and no credentials, fragment or control characters.")
                }
                result["url"] = url
            }
        } else {
            if status != originalStatus {
                guard status.utf8.count == 3, status.utf8.allSatisfy({ (48...57).contains($0) }), let code = Int(status), (200...599).contains(code) else { throw failure("Response status must be between 200 and 599.") }
                result["status_code"] = code
            }
            let reasonBytes = try currentReasonBytes()
            if reasonBytes != originalReason {
                guard !reasonBytes.contains(where: { [0, 10, 13].contains($0) }) else { throw failure("Reason must not contain CR, LF or NUL.") }
                result["reason_base64"] = reasonBytes.base64EncodedString()
            }
        }
        let pairs = try headers.map { try $0.field() }
        if pairs != originalHeaders {
            guard pairs.count <= 1024 else { throw failure("Headers are limited to 1024 rows.") }
            var bytes = 0
            for pair in pairs {
                guard let name = pair.nameText, Self.token(name) else { throw failure("Header names must be nonempty ASCII HTTP tokens.") }
                guard !pair.managed else { throw failure("Host, Content-Length and Transfer-Encoding are managed by the engine.") }
                guard !pair.value.contains(where: { [0, 10, 13].contains($0) }) else { throw failure("Header values cannot contain CR, LF or NUL.") }
                bytes += pair.name.count + pair.value.count + 4
                guard bytes <= 65536 else { throw failure("Headers are limited to 64 KiB including names and separators.") }
            }
            result["headers_base64"] = pairs.map(\.base64Pair)
        }

        if replaceBody {
            let data: Data
            if let file = replacementFileData {
                guard file.count <= Self.fileBodyLimit else { throw failure("File replacement is limited to 32 MiB.") }; data = file
            } else { switch encoding {
            case .utf8:
                guard body.utf8.count <= Self.bodyLimit else { throw failure("Body replacement is limited to 2 MiB.") }
                data = Data(body.utf8)
            case .base64:
                guard body.utf8.count <= ((Self.bodyLimit + 2) / 3) * 4,
                      let decoded = Data(base64Encoded: body), decoded.count <= Self.bodyLimit,
                      decoded.base64EncodedString() == body else { throw failure("Enter canonical Base64 (no whitespace), up to 2 MiB decoded.") }
                data = decoded
            }
            }
            result["body_base64"] = data.base64EncodedString()
        }
        return result
    }
    static func valueBytes(_ value: String, encoding: HTTPBytesEncoding, limit: Int) throws -> Data {
        if encoding == .utf8 { guard value.utf8.count <= limit else { throw EngineJSONFailure.invalid("Text exceeds its byte limit") }; return Data(value.utf8) }
        guard value.utf8.count <= 4 * ((limit + 2) / 3), let bytes = Data(base64Encoded: value), bytes.count <= limit, bytes.base64EncodedString() == value else { throw EngineJSONFailure.invalid("Enter canonical Base64 without whitespace, within the byte limit") }
        return bytes
    }
    private func currentReasonBytes() throws -> Data {
        if reasonEncoding == originalReasonEncoding && Data(reason.utf8) == Data(originalReasonText.utf8) { return originalReason }
        return try Self.valueBytes(reason, encoding: reasonEncoding, limit: 65536)
    }
    mutating func setReasonEncoding(_ next: HTTPBytesEncoding) throws {
        let bytes = try currentReasonBytes()
        if next == .utf8 { guard let text = String(data: bytes, encoding: .utf8) else { throw EngineJSONFailure.invalid("Original reason bytes are not UTF-8. Keep Base64 or explicitly replace them.") }; reason = text }
        else { reason = bytes.base64EncodedString() }
        reasonEncoding = next
    }
    static func readReplacement(_ url: URL) throws -> Data {
        let values = try url.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey])
        guard values.isRegularFile == true, let size = values.fileSize, size <= fileBodyLimit else {
            throw NSError(domain: "LensHTTPMessage", code: 1, userInfo: [NSLocalizedDescriptionKey: "Choose a regular file no larger than 32 MiB."])
        }
        // Verify the opened descriptor as well as the path preflight. Nonblocking
        // open prevents a path swapped to a FIFO from hanging the reader.
        let descriptor = url.withUnsafeFileSystemRepresentation { path in
            path.map { Darwin.open($0, O_RDONLY | O_NONBLOCK | O_CLOEXEC) } ?? -1
        }
        guard descriptor >= 0 else { throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno)) }
        let file = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        defer { try? file.close() }
        var info = stat()
        guard fstat(descriptor, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG, info.st_size <= fileBodyLimit else {
            throw NSError(domain: "LensHTTPMessage", code: 1, userInfo: [NSLocalizedDescriptionKey: "The selected file is no longer a regular file within the 32 MiB limit."])
        }
        var data = Data()
        while data.count <= fileBodyLimit {
            guard let chunk = try file.read(upToCount: min(65536, fileBodyLimit + 1 - data.count)), !chunk.isEmpty else { break }
            data.append(chunk)
        }
        guard data.count <= fileBodyLimit else { throw NSError(domain: "LensHTTPMessage", code: 1, userInfo: [NSLocalizedDescriptionKey: "File grew beyond the 32 MiB replacement limit."]) }
        return data
    }
}

struct HTTPMessageFieldsEditor: View {
    @Binding var draft: HTTPMessageDraft
    @Binding var readingFile: Bool
    @Binding var issue: String?
    @State private var choosingFile = false
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            if draft.stage == "request" {
                if draft.methodIsOpaque {
                    Toggle("Replace original method", isOn: $draft.replaceMethod).onChange(of: draft.replaceMethod) { if draft.replaceMethod { draft.method = "" } }
                    if !draft.replaceMethod { Text("Original method: " + draft.originalMethod).font(.caption).textSelection(.enabled) }
                }
                if !draft.methodIsOpaque || draft.replaceMethod { TextField("Method", text: $draft.method).frame(width: 120).textFieldStyle(.roundedBorder) }
                if draft.urlIsOpaque {
                    Toggle("Replace original URL", isOn: $draft.replaceURL).onChange(of: draft.replaceURL) { if draft.replaceURL { draft.url = "" } }
                    if !draft.replaceURL { Text("Original URL (display): " + draft.originalURL).font(.caption).textSelection(.enabled) }
                }
                if !draft.urlIsOpaque || draft.replaceURL { TextField("Absolute HTTP(S) URL", text: $draft.url).textFieldStyle(.roundedBorder) }
            } else {
                HStack { TextField("Status", text: $draft.status).frame(width: 100); TextField("Reason", text: $draft.reason) }.textFieldStyle(.roundedBorder)
                if draft.reasonEncoding == .base64 { Button("Replace reason as UTF-8 text") { draft.reason = ""; draft.reasonEncoding = .utf8 } }
                Picker("Reason encoding", selection: Binding(get: { draft.reasonEncoding }, set: { next in do { try draft.setReasonEncoding(next) } catch { issue = error.localizedDescription } })) { ForEach(HTTPBytesEncoding.allCases, id: \.self) { Text($0.rawValue).tag($0) } }
            }
            Text("Headers · duplicate names and row order are preserved").font(.subheadline.weight(.semibold))
            Text("Host, Content-Length and Transfer-Encoding are managed by the engine. Editing sends a complete replacement of the other headers. Limit: 1024 rows / 64 KiB.").font(.caption).foregroundStyle(.secondary)
            ForEach($draft.headers) { $row in
                HStack {
                    TextField("Name", text: $row.name).frame(width: 190)
                    TextField(row.encoding == .base64 ? "Canonical Base64 value" : "Value", text: $row.value)
                    if row.encoding == .base64 { Button("Replace as text") { row.value = ""; row.encoding = .utf8 }.font(.caption) }
                    Picker("Value encoding", selection: Binding(get: { row.encoding }, set: { next in do { try row.setEncoding(next) } catch { issue = error.localizedDescription } })) { ForEach(HTTPBytesEncoding.allCases, id: \.self) { Text($0.rawValue).tag($0) } }.labelsHidden().frame(width: 115)
                    Button { draft.headers.removeAll { $0.id == row.id } } label: { Image(systemName: "minus.circle") }.buttonStyle(.borderless).accessibilityLabel("Remove header")
                }.textFieldStyle(.roundedBorder)
            }
            Button("Add header") { draft.headers.append(HTTPHeaderRow(name: "", value: "")) }.disabled(draft.headers.count >= 1024)
            Divider()
            Text(draft.bodyNotice).font(.caption).foregroundStyle(.secondary)
            Toggle("Replace body", isOn: $draft.replaceBody)
            Text("Inline replacements are limited to 2 MiB; a selected regular file can replace up to 32 MiB without displaying its full contents.").font(.caption).foregroundStyle(.secondary)
            if draft.replaceBody {
                HStack {
                    Button(readingFile ? "Reading file…" : "Replace from file…") { choosingFile = true }.disabled(readingFile)
                    if let name = draft.replacementFileName, let data = draft.replacementFileData {
                        Text("\(name) · \(data.count) bytes").font(.caption).textSelection(.enabled)
                    }
                    if draft.replacementFileData != nil || draft.replacementFileIssue != nil {
                        Button("Use inline editor") { draft.replacementFileName = nil; draft.replacementFileData = nil; draft.replacementFileIssue = nil; issue = nil }
                    }
                }
                if draft.replacementFileData == nil {
                    Picker("Replacement encoding", selection: $draft.encoding) { ForEach(HTTPBytesEncoding.allCases, id: \.self) { Text($0.rawValue).tag($0) } }.pickerStyle(.segmented)
                    Text("Explicit replacement · maximum 2 MiB decoded. An empty editor sends an empty body.").font(.caption).foregroundStyle(.secondary)
                    TextEditor(text: $draft.body).font(.system(.caption, design: .monospaced)).frame(minHeight: 180).border(.secondary.opacity(0.3)).accessibilityLabel("Explicit body replacement")
                }
            }
        }
        .fileImporter(isPresented: $choosingFile, allowedContentTypes: [.data]) { result in
            switch result {
            case .failure(let error): issue = error.localizedDescription
            case .success(let url):
                readingFile = true
                Task {
                    do {
                        let bytes = try await Task.detached {
                            let scoped = url.startAccessingSecurityScopedResource()
                            defer { if scoped { url.stopAccessingSecurityScopedResource() } }
                            return try HTTPMessageDraft.readReplacement(url)
                        }.value
                        draft.replacementFileName = url.lastPathComponent; draft.replacementFileData = bytes; issue = nil; draft.replacementFileIssue = nil
                    } catch { issue = error.localizedDescription; draft.replacementFileIssue = error.localizedDescription }
                    readingFile = false
                }
            }
        }
    }
}
