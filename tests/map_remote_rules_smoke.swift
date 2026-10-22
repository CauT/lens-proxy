import Foundation

@main struct MapRemoteRuleSmoke {
    static func main() throws {
        let decoder = JSONDecoder(), encoder = JSONEncoder()
        let legacy = Data(#"{"id":"old","enabled":true,"kind":"map_remote","match":"*","name":"","value":"http://localhost/base"}"#.utf8)
        let old = try decoder.decode(ProxyRule.self, from: legacy)
        precondition(old.pathMode == "append", "Saved rules must retain their original path behavior")
        let fresh = ProxyRule(kind: "map_remote", value: "http://localhost/dev/")
        precondition(fresh.pathMode == "relative")
        let value = try JSONSerialization.jsonObject(with: encoder.encode(fresh)) as! [String: Any]
        precondition(value["path_mode"] as? String == "relative")
        var unknown = fresh
        unknown.pathMode = "future-mode"
        let reopened = try decoder.decode(ProxyRule.self, from: encoder.encode(unknown))
        precondition(reopened.pathMode == "future-mode")
        precondition(old.mapDestination == nil && fresh.mapDestination == nil)
        var fields = RemoteDestination(); fields.host = "localhost"; fields.port = "8443"; fields.path = "/dev/"
        fields.queryMode = "replace"; fields.query = "k=%2F&k="
        var partial = fresh; partial.mapDestination = fields
        let roundtrip = try decoder.decode(ProxyRule.self, from: encoder.encode(partial))
        precondition(roundtrip.mapDestination == fields && roundtrip.remoteIssue == nil)
        var encoded = try JSONSerialization.jsonObject(with: encoder.encode(partial)) as! [String: Any]
        encoded["map_destination"] = ["port": 8443]
        let integerPort = try decoder.decode(ProxyRule.self, from: JSONSerialization.data(withJSONObject: encoded))
        precondition(integerPort.mapDestination?.port == "8443" && integerPort.remoteIssue == nil)
        var invalid = partial; invalid.mapDestination?.scheme = "future"
        let reopenedInvalid = try decoder.decode(ProxyRule.self, from: encoder.encode(invalid))
        precondition(reopenedInvalid.mapDestination?.scheme == "future" && reopenedInvalid.remoteIssue != nil)
        invalid.selectKind("rewrite_response_body")
        precondition(invalid.mapDestination == nil)
        print("PASS legacy URL defaults, new relative mode, selected fields/numeric port roundtrip, invalid-choice feedback and explicit kind transitions")
    }
}
