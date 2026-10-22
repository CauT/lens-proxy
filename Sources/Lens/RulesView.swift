import SwiftUI

struct LensRulesView: View {
    @ObservedObject var store: LensStore
    @Environment(\.dismiss) private var dismiss
    @State private var rules: [ProxyRule] = []
    @State private var failure: String?
    private var rowCount: Int { rules.reduce(0) { $0 + $1.configurationRowCount } }
    private var invalid: Bool {
        rowCount > 500 || rules.contains { rule in
            rule.rewriteIssue != nil || (rule.kind.hasPrefix("breakpoint_") && !ProxyRule.breakpointTimeoutRange.contains(rule.timeoutSeconds)) ||
            rule.remoteIssue != nil
        }
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Text("Traffic rules").font(.title2.weight(.semibold)); Spacer()
                Button("Add Rewrite set") { rules.append(.rewriteSet()) }
                Button { rules.append(ProxyRule()) } label: { Label("Add rule", systemImage: "plus") }
            }
            Text("Request rules select the original client URL; response rules select the effective URL. Rules and sets run in list order. Active requests keep their accepted configuration. Rewrite sets have their own enable switch and locations.").font(.callout).foregroundStyle(.secondary)
            if let issue = store.rulesPreferencesIssue { Label(issue, systemImage: "exclamationmark.triangle").font(.caption).foregroundStyle(.orange) }
            ScrollView {
                LazyVStack(spacing: 12) {
                    ForEach(Array(rules.enumerated()), id: \.element.id) { index, snapshot in
                        if snapshot.isRewriteSet {
                            LensRewriteSetEditor(rule: binding(snapshot.id), canMoveUp: index > 0, canMoveDown: index + 1 < rules.count,
                                moveUp: { move(snapshot.id, by: -1) }, moveDown: { move(snapshot.id, by: 1) }, remove: { rules.removeAll { $0.id == snapshot.id } })
                        } else {
                            LensTrafficRuleEditor(rule: binding(snapshot.id), canMoveUp: index > 0, canMoveDown: index + 1 < rules.count,
                                moveUp: { move(snapshot.id, by: -1) }, moveDown: { move(snapshot.id, by: 1) }, remove: { rules.removeAll { $0.id == snapshot.id } })
                        }
                    }
                    if rules.isEmpty { ContentUnavailableView("No rules yet", systemImage: "slider.horizontal.3", description: Text("Add rewrites, mappings, blocks, delays, or breakpoints.")) }
                }
            }.frame(minHeight: 280, maxHeight: 490)
            if let failure { Label(failure, systemImage: "exclamationmark.triangle").font(.callout).foregroundStyle(.orange).textSelection(.enabled) }
            if rowCount > 500 { Text("Use at most 500 rule, set and location rows in total.").foregroundStyle(.orange) }
            HStack {
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction); Spacer()
                Button(store.settingsSaving ? "Saving…" : "Save rules") { store.applyRules(rules) { success in
                    if success { dismiss() }
                    else { failure = store.errorMessage ?? "Rules could not be saved."; store.errorMessage = nil }
                } }
                    .buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction).disabled(invalid)
            }
        }.padding(24).frame(width: 800).disabled(store.settingsSaving)
         .onAppear { rules = store.rules }
    }
    private func binding(_ id: String) -> Binding<ProxyRule> {
        Binding(get: { rules.first { $0.id == id } ?? ProxyRule() }, set: { value in
            if let index = rules.firstIndex(where: { $0.id == id }) { rules[index] = value }
        })
    }
    private func move(_ id: String, by delta: Int) {
        guard let index = rules.firstIndex(where: { $0.id == id }), rules.indices.contains(index + delta) else { return }
        rules.swapAt(index, index + delta)
    }
}

private struct LensRewriteSetEditor: View {
    @Binding var rule: ProxyRule
    let canMoveUp: Bool, canMoveDown: Bool
    let moveUp: () -> Void, moveDown: () -> Void, remove: () -> Void
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Toggle("Enabled", isOn: $rule.enabled).toggleStyle(.checkbox)
                TextField("Rewrite set name", text: $rule.name).textFieldStyle(.roundedBorder)
                Button(action: moveUp) { Image(systemName: "arrow.up") }.disabled(!canMoveUp).help("Move set earlier")
                Button(action: moveDown) { Image(systemName: "arrow.down") }.disabled(!canMoveDown).help("Move set later")
                Button(role: .destructive, action: remove) { Image(systemName: "trash") }.help("Delete Rewrite set")
            }
            Text("Locations · any matching full-URL glob selects this set. * matches any characters; ? matches one. An empty location list selects no traffic.").font(.caption).foregroundStyle(.secondary)
            TextEditor(text: Binding(get: { rule.locations.joined(separator: "\n") }, set: { text in rule.locations = text.isEmpty ? [] : text.components(separatedBy: .newlines) }))
                .font(.system(.caption, design: .monospaced)).frame(height: 55).border(Color.secondary.opacity(0.2)).accessibilityLabel("Rewrite set locations")
            ForEach(Array(rule.rewriteRules.enumerated()), id: \.element.id) { index, snapshot in
                LensTrafficRuleEditor(rule: child(snapshot.id), canMoveUp: index > 0, canMoveDown: index + 1 < rule.rewriteRules.count,
                    moveUp: { move(snapshot.id, by: -1) }, moveDown: { move(snapshot.id, by: 1) }, remove: { rule.rewriteRules.removeAll { $0.id == snapshot.id } }, rewriteOnly: true)
            }
            Button("Add Rewrite rule") { rule.rewriteRules.append(ProxyRule()) }
            if let issue = rule.rewriteIssue { Label(issue, systemImage: "exclamationmark.triangle").font(.caption).foregroundStyle(.orange) }
        }.padding(12).background(Color.accentColor.opacity(0.06), in: RoundedRectangle(cornerRadius: 10))
    }
    private func child(_ id: String) -> Binding<ProxyRule> {
        Binding(get: { rule.rewriteRules.first { $0.id == id } ?? ProxyRule() }, set: { value in
            if let index = rule.rewriteRules.firstIndex(where: { $0.id == id }) { rule.rewriteRules[index] = value }
        })
    }
    private func move(_ id: String, by delta: Int) {
        guard let index = rule.rewriteRules.firstIndex(where: { $0.id == id }), rule.rewriteRules.indices.contains(index + delta) else { return }
        rule.rewriteRules.swapAt(index, index + delta)
    }
}

private struct LensTrafficRuleEditor: View {
    @Binding var rule: ProxyRule
    let canMoveUp: Bool, canMoveDown: Bool
    let moveUp: () -> Void, moveDown: () -> Void, remove: () -> Void
    var rewriteOnly = false
    private var choices: [(String, String)] { rewriteOnly ? ProxyRule.kinds.filter { $0.0.hasPrefix("rewrite_") } : ProxyRule.kinds }
    var body: some View {
        let snapshot = rule
        let rule = $rule
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Toggle("Enabled", isOn: rule.enabled).toggleStyle(.checkbox)
                Picker("Action", selection: Binding(get: { rule.wrappedValue.kind }, set: { selected in var updated = rule.wrappedValue; updated.selectKind(selected); rule.wrappedValue = updated })) { ForEach(choices, id: \.0) { kind in Text(kind.1).tag(kind.0) } }.labelsHidden().frame(width: 220)
                Spacer()
                Button { moveUp() } label: { Image(systemName: "arrow.up") }
                    .buttonStyle(.borderless).help("Move rule earlier").disabled(!canMoveUp)
                Button { moveDown() } label: { Image(systemName: "arrow.down") }
                    .buttonStyle(.borderless).help("Move rule later").disabled(!canMoveDown)
                Button(role: .destructive) { remove() } label: { Image(systemName: "trash") }.buttonStyle(.borderless).help("Delete rule")
            }
            TextField("URL glob, e.g. https://example.com/api/*", text: rule.match).textFieldStyle(.roundedBorder)
            if snapshot.kind.hasPrefix("breakpoint_") {
                HStack {
                    Text("Abort after")
                    TextField("60", value: rule.timeoutSeconds, format: .number).frame(width: 85)
                        .accessibilityLabel("Breakpoint timeout in seconds")
                    Text("seconds").foregroundStyle(.secondary)
                }
                Text("1–3600 seconds; default 60. Expiration aborts the request, never silently continues.").font(.caption).foregroundStyle(.secondary)
                if !ProxyRule.breakpointTimeoutRange.contains(snapshot.timeoutSeconds) { Text("Choose a timeout between 1 and 3600 seconds.").font(.caption).foregroundStyle(.orange) }
            }
            if ["no_cache", "block_cookies"].contains(snapshot.kind) {
                Text(snapshot.kind == "no_cache"
                     ? "Requests ask for fresh content. Responses tell clients not to store them."
                     : "Removes all cookies sent with the request and all cookies set by the response.")
                    .font(.caption).foregroundStyle(.secondary)
                Text("Matches the original client URL for both request and response, on HTTP traffic visible to Lens. Later rules can override this rule. Existing browser cache and cookies are not cleared.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            if !snapshot.rewriteModes.isEmpty {
                Picker("Operation", selection: Binding(get: { rule.wrappedValue.rewriteMode }, set: { selected in var updated = rule.wrappedValue; updated.selectRewriteMode(selected); rule.wrappedValue = updated })) {
                    ForEach(snapshot.rewriteModes, id: \.self) { mode in Text(mode.capitalized).tag(mode) }
                }.pickerStyle(.segmented)
                TextField(snapshot.isHeaderRewrite ? "Header name" : "Decoded query parameter name", text: rule.name).textFieldStyle(.roundedBorder)
                if snapshot.isHeaderRewrite {
                    Text("Set replaces matching fields with one value; Add appends; Remove deletes matching fields; Replace changes matching text within existing values. Other fields retain their bytes and order. Host and message framing are managed automatically.")
                        .font(.caption).foregroundStyle(.secondary)
                    if snapshot.rewriteMode == "replace" { TextField("Find text in header values", text: rule.rewriteFind).textFieldStyle(.roundedBorder) }
                } else {
                    if snapshot.rewriteMode == "replace" { TextField("Find text in decoded parameter values", text: rule.rewriteFind).textFieldStyle(.roundedBorder) }
                    Text("Names match decoded UTF-8 exactly. Set replaces matching duplicates at the first position; Add appends; Remove deletes matching parameters. Other query segments and the path keep their original bytes. New values use percent encoding.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            if snapshot.supportsNamePattern {
                HStack {
                    Toggle("Name regex", isOn: rule.rewriteNameRegex).toggleStyle(.checkbox)
                    if snapshot.rewriteMode == "replace" { TextField("New name (blank keeps name)", text: rule.rewriteNewName).textFieldStyle(.roundedBorder) }
                }
                if snapshot.rewriteNameRegex && !snapshot.needsReplacementCount {
                    HStack { Text("Match timeout"); TextField("250", value: rule.rewriteTimeoutMs, format: .number).frame(width: 80); Text("ms · 1–5000") }.font(.caption)
                }
                Text("Name regex ignores case and may match part of a name. Name replacements use the first match; $1 and ${name} refer to that name pattern's captures.").font(.caption).foregroundStyle(.secondary)
            }
            if snapshot.needsLiteralFind {
                TextField(snapshot.rewriteRegex ? "Find regex (blank matches whole value)" : "Find text (required)", text: rule.name).textFieldStyle(.roundedBorder)
            }
            if snapshot.needsReplacementCount {
                HStack {
                    Toggle("Regex", isOn: rule.rewriteRegex).toggleStyle(.checkbox)
                    Toggle("Case sensitive", isOn: rule.rewriteCaseSensitive).toggleStyle(.checkbox)
                    Toggle("Match whole value", isOn: rule.rewriteWhole).toggleStyle(.checkbox)
                }
                if snapshot.hasPatternOptions || !(1...5000).contains(snapshot.rewriteTimeoutMs) {
                    HStack { Text("Match timeout"); TextField("250", value: rule.rewriteTimeoutMs, format: .number).frame(width: 80); Text("ms · 1–5000") }.font(.caption)
                    Text("A timeout aborts this transaction and shows a Rewrite error. Regex replacement supports $1, $2 and ${name}; backslash quotes the next character. A blank regex match selects the whole value once. A blank replacement removes matched text.").font(.caption).foregroundStyle(.secondary)
                }
                Picker("Occurrences", selection: rule.rewriteCount) { Text("First").tag("first"); Text("All").tag("all") }.pickerStyle(.segmented)
            }
            if snapshot.kind == "rewrite_request_url" {
                Text("Text replacement in the current effective absolute URL. The result must be HTTP(S), with no credentials or fragment. Encode non-ASCII paths explicitly. Host and TLS destination follow the result; access policy is checked again.").font(.caption).foregroundStyle(.secondary)
            }
            if snapshot.kind == "rewrite_response_status" {
                TextField("Status code, 200–599", text: rule.name).textFieldStyle(.roundedBorder)
                Text("Reason below replaces the response reason, including an explicit empty value. A nonempty body cannot become a 204/304 response; remove its body first.").font(.caption).foregroundStyle(.secondary)
            }
            if let issue = snapshot.rewriteIssue { Label(issue, systemImage: "exclamationmark.triangle").font(.caption).foregroundStyle(.orange) }
            if snapshot.kind == "map_remote" {
                LensRemoteMappingEditor(rule: rule)
            } else if !["block", "breakpoint_request", "breakpoint_response", "no_cache", "block_cookies"].contains(snapshot.kind) && !(!snapshot.rewriteModes.isEmpty && snapshot.rewriteMode == "remove") {
                Text(snapshot.kind == "delay" ? "Delay (milliseconds)" : snapshot.kind == "map_local" ? "Absolute local file or directory path" : snapshot.kind == "dns_spoof" ? "Destination IP address (IPv4 or IPv6; original port is preserved)" : snapshot.kind == "rewrite_response_status" ? "Response reason" : "Replacement value").font(.caption).foregroundStyle(.secondary)
                TextEditor(text: rule.value).font(.system(.caption, design: .monospaced)).frame(height: snapshot.kind.contains("body") ? 100 : 45).border(Color.secondary.opacity(0.2))
                if snapshot.kind == "map_local" {
                    Text("Directory example: https://example.com/assets/* → /Users/me/site maps /assets/css/app.css to site/css/app.css. The directory before the first path wildcard is removed. Query parameters are ignored. Missing files use the original server; directory links are not followed.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
        }.padding(12).background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 8))
    }
}


private struct LensRemoteMappingEditor: View {
    @Binding var rule: ProxyRule
    private var destination: Binding<RemoteDestination> {
        Binding(get: { rule.mapDestination ?? RemoteDestination() }, set: { value in
            if rule.mapDestination != nil { rule.mapDestination = value }
        })
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Picker("Destination input", selection: Binding(get: { rule.mapDestination == nil ? "url" : "fields" }, set: { value in
                if value == "url" { rule.mapDestination = nil }
                else if rule.mapDestination == nil { rule.mapDestination = RemoteDestination() }
            })) {
                Text("Full URL").tag("url")
                Text("Individual fields").tag("fields")
            }.pickerStyle(.segmented)
            if rule.mapDestination != nil {
                Picker("Protocol", selection: destination.scheme) {
                    Text("Original").tag(""); Text("HTTP").tag("http"); Text("HTTPS").tag("https")
                }.accessibilityLabel("Map Remote protocol")
                HStack {
                    TextField("Original host", text: destination.host).textFieldStyle(.roundedBorder).accessibilityLabel("Map Remote host")
                    TextField("Original port", text: destination.port).textFieldStyle(.roundedBorder).frame(width: 150).accessibilityLabel("Map Remote port")
                }
                TextField("Original path (or /destination/)", text: destination.path).textFieldStyle(.roundedBorder).accessibilityLabel("Map Remote path")
                Picker("Query", selection: destination.queryMode) { Text("Preserve query").tag("preserve"); Text("Replace query").tag("replace") }.pickerStyle(.segmented)
                if rule.mapDestination?.queryMode == "replace" {
                    TextField("Query without ? (blank clears it)", text: destination.query).textFieldStyle(.roundedBorder).accessibilityLabel("Map Remote query")
                }
                Text("Blank fields preserve the current request, including its port when the protocol changes. IPv6 hosts use ::1 without brackets. Percent-encode non-ASCII paths and queries.").font(.caption).foregroundStyle(.secondary)
            } else {
                TextField("Absolute destination URL, e.g. https://localhost:8443/dev/", text: $rule.value).textFieldStyle(.roundedBorder).accessibilityLabel("Map Remote destination URL")
                Text("The URL chooses protocol, host and port together. Without a destination path, the request path is retained. A final ? clears the original query; without ?, it is preserved.").font(.caption).foregroundStyle(.secondary)
            }
            Picker("Path mapping", selection: $rule.pathMode) {
                Text("Relative directory / exact file").tag("relative")
                Text("Append full path (legacy)").tag("append")
            }
            Text(rule.pathMode == "relative"
                 ? "A destination ending / maps the source directory: /api/* → /dev/ sends /api/x to /dev/x. A file path replaces the whole path. Blank preserves the path."
                 : "Appends the complete request path to the destination base. Existing saved rules retain this behavior.")
                .font(.caption).foregroundStyle(.secondary)
            Text("Host and upstream TLS identity follow the resulting destination. Redirects are returned to the client.").font(.caption).foregroundStyle(.secondary)
            if let issue = rule.remoteIssue { Label(issue, systemImage: "exclamationmark.triangle").font(.caption).foregroundStyle(.orange) }
        }
    }
}
