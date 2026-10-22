import Foundation
import CoreFoundation

enum EngineJSONFailure: Error, LocalizedError {
    case invalid(String)
    var errorDescription: String? { if case .invalid(let text) = self { return text }; return nil }
}

enum EnginePathPart: Codable, Hashable {
    case key(String), index(Int)
    init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if let index = try? c.decode(Int.self), index >= 0 { self = .index(index) }
        else { self = .key(try c.decode(String.self)) }
    }
    func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self { case .key(let value): try c.encode(value); case .index(let value): try c.encode(value) }
    }
}

struct EngineSourceText: Codable, Equatable {
    let path: [EnginePathPart]
    let kind: String
    let utf8SurrogatepassBase64: String
    enum CodingKeys: String, CodingKey { case path, kind; case utf8SurrogatepassBase64 = "utf8_surrogatepass_base64" }
}

struct EngineSourceFacts: Codable, Equatable {
    var text: [EngineSourceText] = []
    func containsPrefix(_ field: String) -> Bool { text.contains { $0.path.first == .key(field) } }
    func contains(_ field: String) -> Bool { text.contains { $0.kind == "value" && $0.path == [.key(field)] } }
}

protocol EngineSourced {
    var sourceFacts: EngineSourceFacts { get set }
    mutating func attachSourceFacts(_ facts: EngineSourceFacts) throws
}
extension EngineSourced { mutating func attachSourceFacts(_ facts: EngineSourceFacts) throws { sourceFacts = facts } }

// Projection is presentation. An EngineValue always retains the sparse original
// Python-string bytes, including source object-key identity, across slicing.
struct EngineValue {
    let projection: Any
    let sourceFacts: EngineSourceFacts
    init(_ projection: Any, sourceFacts: EngineSourceFacts = EngineSourceFacts()) { self.projection = projection; self.sourceFacts = sourceFacts }
    static func message(from line: Data) throws -> EngineValue {
        guard let envelope = try JSONSerialization.jsonObject(with: line) as? [String: Any],
              let version = envelope["native_json"] as? NSNumber,
              CFGetTypeID(version) != CFBooleanGetTypeID(), version.doubleValue == 1,
              let message = envelope["message"], let annotations = envelope["source_text"] else {
            throw EngineJSONFailure.invalid("Invalid native JSON envelope")
        }
        let texts = try JSONDecoder().decode([EngineSourceText].self, from: JSONSerialization.data(withJSONObject: annotations))
        var seen = Set<String>()
        for item in texts {
            guard ["key", "value"].contains(item.kind), let bytes = Data(base64Encoded: item.utf8SurrogatepassBase64), bytes.base64EncodedString() == item.utf8SurrogatepassBase64 else { throw EngineJSONFailure.invalid("Invalid source-text encoding") }
            _ = try sourceScalars(bytes)
            var node = message
            for (offset, part) in item.path.enumerated() {
                switch part {
                case .key(let key):
                    guard let object = node as? [String: Any], let value = object[key] else { throw EngineJSONFailure.invalid("Source-text path does not exist") }
                    if item.kind == "key" && offset == item.path.count - 1 { node = key } else { node = value }
                case .index(let index):
                    guard item.kind != "key" || offset < item.path.count - 1, let array = node as? [Any], array.indices.contains(index) else { throw EngineJSONFailure.invalid("Invalid source-text array path") }
                    node = array[index]
                }
            }
            guard node is String, item.kind != "key" || !item.path.isEmpty else { throw EngineJSONFailure.invalid("Source-text annotation must address a string") }
            let identity = item.kind + ":" + (try JSONEncoder().encode(item.path).base64EncodedString())
            guard seen.insert(identity).inserted else { throw EngineJSONFailure.invalid("Duplicate source-text annotation") }
        }
        return EngineValue(message, sourceFacts: EngineSourceFacts(text: texts))
    }
    subscript(_ key: String) -> EngineValue? {
        let prefix: [EnginePathPart] = [.key(key)]
        guard !sourceFacts.text.contains(where: { $0.kind == "key" && $0.path == prefix }), let object = projection as? [String: Any], let value = object[key] else { return nil }
        return slice(value, prefix: prefix)
    }
    subscript(_ index: Int) -> EngineValue? {
        guard let array = projection as? [Any], array.indices.contains(index) else { return nil }
        return slice(array[index], prefix: [.index(index)])
    }
    private func slice(_ value: Any, prefix: [EnginePathPart]) -> EngineValue {
        EngineValue(value, sourceFacts: EngineSourceFacts(text: sourceFacts.text.compactMap { item in
            guard item.path.starts(with: prefix), !(item.kind == "key" && item.path == prefix) else { return nil }
            return EngineSourceText(path: Array(item.path.dropFirst(prefix.count)), kind: item.kind, utf8SurrogatepassBase64: item.utf8SurrogatepassBase64)
        }))
    }
    func elements() throws -> [EngineValue] {
        guard let array = projection as? [Any] else { throw EngineJSONFailure.invalid("Expected array") }
        return array.indices.map { self[$0]! }
    }
    var unicodeString: String? { try? strictString() }
    var displayString: String? { projection as? String }
    func strictString() throws -> String {
        guard !sourceFacts.text.contains(where: { $0.kind == "value" && $0.path.isEmpty }), let value = projection as? String else { throw EngineJSONFailure.invalid("Original text cannot be represented as a Unicode string") }
        return value
    }
    var bool: Bool? { guard let value = projection as? NSNumber, CFGetTypeID(value) == CFBooleanGetTypeID() else { return nil }; return value.boolValue }
    var integer: Int? { guard let value = projection as? NSNumber, CFGetTypeID(value) != CFBooleanGetTypeID(), value.doubleValue == Double(value.intValue) else { return nil }; return value.intValue }
    func decode<T: Decodable>(_ type: T.Type, decoder: JSONDecoder? = nil) throws -> T {
        let d = decoder ?? { let result = JSONDecoder(); result.keyDecodingStrategy = .convertFromSnakeCase; return result }()
        let bytes = try JSONSerialization.data(withJSONObject: projection, options: [.fragmentsAllowed])
        var value = try d.decode(type, from: bytes)
        if var sourced = value as? EngineSourced { try sourced.attachSourceFacts(sourceFacts); value = sourced as! T }
        else if !sourceFacts.text.isEmpty { throw EngineJSONFailure.invalid("This value requires a source-aware decoder") }
        return value
    }
    // Restores legacy JSON text; raw annotations remain authoritative where JSON
    // itself cannot distinguish a literal surrogate pair from one astral scalar.
    func serializedSourceJSON() throws -> Data {
        func encode(_ node: Any, _ path: [EnginePathPart]) throws -> Data {
            if let item = sourceFacts.text.first(where: { $0.kind == "value" && $0.path == path }) { return try Self.sourceJSONString(Data(base64Encoded: item.utf8SurrogatepassBase64)!) }
            if let array = node as? [Any] {
                var out = Data("[".utf8)
                for (index, value) in array.enumerated() { if index > 0 { out.append(44) }; out.append(try encode(value, path + [.index(index)])) }
                out.append(93); return out
            }
            if let object = node as? [String: Any] {
                var out = Data("{".utf8)
                for (index, key) in object.keys.sorted().enumerated() {
                    if index > 0 { out.append(44) }; let child = path + [.key(key)]
                    if let item = sourceFacts.text.first(where: { $0.kind == "key" && $0.path == child }) { out.append(try Self.sourceJSONString(Data(base64Encoded: item.utf8SurrogatepassBase64)!)) }
                    else { out.append(try JSONSerialization.data(withJSONObject: key, options: [.fragmentsAllowed])) }
                    out.append(58); out.append(try encode(object[key]!, child))
                }
                out.append(125); return out
            }
            return try JSONSerialization.data(withJSONObject: node, options: [.fragmentsAllowed])
        }
        return try encode(projection, [])
    }
    private static func sourceJSONString(_ data: Data) throws -> Data {
        var text = "\""
        for scalar in try sourceScalars(data) {
            if scalar <= 0xffff { text += String(format: "\\u%04x", scalar) }
            else { let number = scalar - 0x10000; text += String(format: "\\u%04x\\u%04x", 0xd800 + (number >> 10), 0xdc00 + (number & 1023)) }
        }
        text += "\""; return Data(text.utf8)
    }
    private static func sourceScalars(_ data: Data) throws -> [UInt32] {
        let bytes = Array(data); var result: [UInt32] = []; var index = 0
        while index < bytes.count {
            let first = bytes[index]; let count: Int; var value: UInt32
            if first < 128 { count = 1; value = UInt32(first) }
            else if (0xc2...0xdf).contains(first) { count = 2; value = UInt32(first & 31) }
            else if (0xe0...0xef).contains(first) { count = 3; value = UInt32(first & 15) }
            else if (0xf0...0xf4).contains(first) { count = 4; value = UInt32(first & 7) }
            else { throw EngineJSONFailure.invalid("Invalid UTF-8 surrogatepass source") }
            guard index + count <= bytes.count else { throw EngineJSONFailure.invalid("Truncated source text") }
            for offset in 1..<count { let next = bytes[index + offset]; guard (0x80...0xbf).contains(next) else { throw EngineJSONFailure.invalid("Invalid source continuation") }; value = (value << 6) | UInt32(next & 63) }
            guard (count != 2 || value >= 0x80) && (count != 3 || value >= 0x800) && (count != 4 || value >= 0x10000) && value <= 0x10ffff else { throw EngineJSONFailure.invalid("Noncanonical source text") }
            result.append(value); index += count
        }
        return result
    }
}

struct HTTPHeaderField: Equatable {
    let name: Data
    let value: Data
    var nameText: String? { String(data: name, encoding: .ascii) }
    var displayName: String { nameText ?? "Base64(\(name.base64EncodedString()))" }
    var displayValue: String { String(data: value, encoding: .utf8) ?? "Base64(\(value.base64EncodedString()))" }
    var managed: Bool { nameText.map { ["host", "content-length", "transfer-encoding"].contains($0.lowercased()) } ?? false }
    var base64Pair: [String] { [name.base64EncodedString(), value.base64EncodedString()] }
    static func decode(_ bytes: [[String]]?, legacy: [[String]], legacyHasSourceText: Bool) throws -> [HTTPHeaderField] {
        if let bytes {
            return try bytes.map { pair in
                guard pair.count == 2, let name = Data(base64Encoded: pair[0]), let value = Data(base64Encoded: pair[1]),
                      name.base64EncodedString() == pair[0], value.base64EncodedString() == pair[1] else { throw EngineJSONFailure.invalid("Invalid canonical header byte pair") }
                return HTTPHeaderField(name: name, value: value)
            }
        }
        guard !legacyHasSourceText else { throw EngineJSONFailure.invalid("Original header bytes are missing; display text cannot be sent") }
        return try legacy.map { pair in guard pair.count == 2 else { throw EngineJSONFailure.invalid("Malformed header pair") }; return HTTPHeaderField(name: Data(pair[0].utf8), value: Data(pair[1].utf8)) }
    }
}
