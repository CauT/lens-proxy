// Actual WS/WSS details -> production native model and bounded renderer.
import Foundation

private struct WSDetailFailure: Error { let reason: String }
private func require(_ value: @autoclosure () throws -> Bool, _ reason: String) throws {
    if try !value() { throw WSDetailFailure(reason: reason) }
}
private func rejects(_ fields: [String: Any], page: Bool = false) throws {
    do {
        if page { try EngineValue(fields).decode(WebSocketMessagePage.self).validate() }
        else { _ = try EngineValue(fields).decode(SocketMessage.self) }
    } catch { return }
    throw WSDetailFailure(reason: "Malformed WebSocket facts were accepted")
}

@main private struct WebSocketDetailSmoke {
    static func main() async throws {
        guard CommandLine.arguments.count == 2 else { throw WSDetailFailure(reason: "Pass real wire fixture directory") }
        let folder = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
        var originalLarge: [Data] = []
        for name in ["plain", "wss", "fragmented", "large", "reopened", "paged", "stopped", "historical"] {
            let file = folder.appendingPathComponent(name + ".json"), source = try Data(contentsOf: file)
            let detail = try EngineValue(JSONSerialization.jsonObject(with: source)).decode(FlowDetail.self)
            guard let page = try detail.firstWebSocketPage() else { throw WSDetailFailure(reason: "Actual capture omitted page facts") }
            let har = try JSONSerialization.jsonObject(with: Data(contentsOf: folder.appendingPathComponent(name + ".har"))) as! [String: Any]
            let entries = (har["log"] as! [String: Any])["entries"] as! [[String: Any]]
            let recorded = entries[0]["_webSocketMessages"] as! [[String: Any]]
            try require(page.total == recorded.count && page.messages.count == min(50, recorded.count), "Actual page coverage changed")
            var previews: [Data] = []
            for (index, message) in page.messages.enumerated() {
                let item = recorded[index], raw: Data
                if item["encoding"] as? String == "base64" { raw = Data(base64Encoded: item["data"] as! String)! }
                else { raw = Data((item["data"] as! String).utf8) }
                try require(message.index == index && message.previewBytes == Data(raw.prefix(4096)), "Actual preview bytes or position changed")
                try require(message.contentBytes == raw.count && message.previewTruncated == (raw.count > 4096), "Actual length or completeness changed")
                try require(message.opcode == item["opcode"] as? Int && message.direction == item["type"] as? String, "Type or direction changed")
                try require(message.timestamp == (item["time"] as! NSNumber).doubleValue, "Timestamp changed")
                if message.opcode == 2 { try require(message.preferredHex, "UTF-8 binary message was reclassified as text") }
                let input = BodyRenderInput(format: .hex, text: "not authoritative", base64: message.contentBase64, truncated: false)
                guard let rendered = await BodyRenderWorker.shared.render(input) else { throw WSDetailFailure(reason: "Render cancelled") }
                let hex = raw.prefix(6).map { String(format: "%02x", $0) }.joined(separator: " ")
                try require(rendered.utf8.count <= 32768 && (raw.isEmpty || rendered.contains(hex)), "Bounded actual byte rendering lost its prefix")
                previews.append(message.previewBytes!)
            }
            if name == "large" { originalLarge = previews }
            if name == "reopened" { try require(originalLarge == previews, "HAR reopen changed native large-message bytes") }
            if name == "paged" { try require(page.total == 122 && page.nextOffset == 50, "Actual later pages were hidden") }
            if name == "historical" {
                try require(page.messages[0].timestamp == 0 && page.messages[1].timestamp == 0 && page.messages[0].index != page.messages[1].index, "Equal historical timestamps collapsed identity")
                try require(page.messages[1].opcode == nil && page.messages[1].dropped == nil && page.messages[1].injected == nil, "Legacy source facts were invented")
            }
            try require(Data(contentsOf: file) == source, "Rendering changed source evidence")
            print("PASS: \(name) actual WS bytes/type/time/coverage survive native decoding and bounded rendering")
        }

        let legacy = try EngineValue(["direction": "send", "text": "old preview", "timestamp": 0]).decode(SocketMessage.self)
        try require(legacy.previewBytes == nil && legacy.opcode == nil && legacy.previewTruncated == nil && !legacy.preferredHex, "Legacy display text became captured bytes or a guessed type")
        print("PASS: legacy display-only previews retain unknown bytes/type/completeness")
        let valid: [String: Any] = ["direction": "receive", "text": "display", "timestamp": 0, "index": 0, "opcode": 2,
            "content_base64": "AP8=", "content_bytes": 2, "preview_truncated": false, "dropped": false, "injected": false]
        for (key, bad): (String, Any) in [("content_base64", "AB=="), ("content_base64", String(repeating: "A", count: 6000)),
                ("content_bytes", 1), ("content_bytes", 33554433), ("preview_truncated", true), ("opcode", true), ("opcode", 9), ("index", -1), ("direction", "unknown") ] {
            var fields = valid; fields[key] = bad; try rejects(fields)
        }
        print("PASS: malformed bytes, excessive allocations, inconsistent completeness and invalid message facts reject")
        let validPage: [String: Any] = ["id": "flow", "messages": [valid], "total": 1, "offset": 0, "limit": 50,
            "next_offset": NSNull(), "generation": 0, "preview_limit": 4096, "retention_truncated": NSNull()]
        let unknown = try EngineValue(validPage).decode(WebSocketMessagePage.self)
        try unknown.validate(); try require(unknown.retentionTruncated == nil, "Unknown capture completeness became false")
        for (key, bad): (String, Any) in [("total", 2001), ("total", 2), ("offset", 1), ("limit", 51), ("next_offset", 1), ("generation", -1), ("preview_limit", 8192)] {
            var fields = validPage; fields[key] = bad; try rejects(fields, page: true)
        }
        print("PASS: page count/index/continuation/generation admission preserves unknown retention facts")
    }
}
