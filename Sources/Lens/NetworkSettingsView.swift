import Foundation
import SwiftUI
import AppKit
import Darwin

struct LensClientCertificatesView: View {
    @ObservedObject var store: LensStore
    @Environment(\.dismiss) private var dismiss
    @State private var selections: [ClientCertificateSelection] = []
    @State private var upstreamCA = ""
    private var locked: Bool { store.isRunning || store.isStarting }
    private var issue: String? {
        if !upstreamCA.isEmpty && (!NSString(string: upstreamCA).expandingTildeInPath.hasPrefix("/") || upstreamCA.contains("\0")) { return "The upstream CA bundle must be an absolute PEM file path." }
        return selections.compactMap(\.issue).first
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Text("TLS client certificates").font(.title2.weight(.semibold))
                Spacer()
                Button("Add identity") { selections.append(ClientCertificateSelection()) }.disabled(locked || selections.count >= 32)
            }
            Text("Select a certificate and matching private key for an exact upstream host and port. PKCS#12 (.p12/.pfx) and combined PEM files are supported.")
                .foregroundStyle(.secondary)
            Text("Passwords and private keys stay in memory. Selections are kept until you remove them or quit Lens; no password, key or identity selection is saved in preferences or captures. Certificates are checked before listeners open on the next Start.")
                .font(.caption).foregroundStyle(.secondary)
            if locked { Label("Stop Lens before editing identities. Existing TLS connections keep their original identity until Stop.", systemImage: "lock").font(.caption) }
            VStack(alignment: .leading, spacing: 6) {
                TextField("Optional absolute upstream CA bundle path (PEM)", text: $upstreamCA)
                    .textFieldStyle(.roundedBorder).accessibilityLabel("Upstream CA bundle path")
                Text("Leave blank for the default public roots. An explicit bundle replaces those roots for Lens's upstream connections. Chain and hostname verification stay enabled; system trust is unchanged.")
                    .font(.caption).foregroundStyle(.secondary)
            }.disabled(locked)
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    ForEach($selections) { $selection in
                        VStack(alignment: .leading, spacing: 8) {
                            HStack {
                                TextField("Exact hostname or IP", text: $selection.host).accessibilityLabel("Client certificate host")
                                TextField("443", text: $selection.port).frame(width: 75).accessibilityLabel("Client certificate target port")
                                Button(role: .destructive) { selections.removeAll { $0.id == selection.id } } label: { Image(systemName: "trash") }.help("Remove identity")
                            }
                            HStack {
                                TextField("Absolute certificate file path", text: $selection.path).accessibilityLabel("Client certificate file path")
                                Button("Choose file…") { chooseFile(for: selection.id) }
                            }
                            SecureField("Certificate password (if encrypted)", text: $selection.password).accessibilityLabel("Client certificate password")
                            if let issue = selection.issue { Text(issue).font(.caption).foregroundStyle(.orange) }
                        }.textFieldStyle(.roundedBorder).padding(12).background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 8))
                    }
                    if selections.isEmpty { Text("No client identities selected. HTTPS inspection does not automatically forward a client's own certificate.").foregroundStyle(.secondary).padding(.vertical, 20) }
                }.disabled(locked)
                if !store.activeClientCertificates.isEmpty {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Loaded for the running proxy").font(.headline)
                        ForEach(store.activeClientCertificates) { identity in
                            Text("\(identity.endpointLabel) · \(identity.subject)\n\(identity.path)\nSHA-256 \(identity.sha256)\nExpires \(identity.expires)")
                                .font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                        }
                    }.frame(maxWidth: .infinity, alignment: .leading).padding(.top, 12)
                }
            }.frame(minHeight: 180, maxHeight: 380)
            HStack {
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Spacer()
                Button(locked ? "Done" : "Use on next Start") {
                    if !locked { store.clientCertificates = selections; store.upstreamCA = upstreamCA }
                    dismiss()
                }.buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction).disabled(!locked && issue != nil)
            }
        }.padding(24).frame(width: 730)
        .onAppear { selections = store.clientCertificates; upstreamCA = store.upstreamCA }
        .onDisappear { selections.removeAll() }
    }

    private func chooseFile(for id: UUID) {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true; panel.canChooseDirectories = false; panel.allowsMultipleSelection = false
        panel.begin { response in
            if response == .OK, let path = panel.url?.path, let index = selections.firstIndex(where: { $0.id == id }) {
                selections[index].path = path
            }
        }
    }
}

// Shared validation keeps the two settings sheets consistent. Startup must validate independently as well.
enum LensNetworkSettingsValidation {
    static func upstreamProxyIssue(_ value: String, socks: String = "0", reverse: String = "0", tcpCount: Int = 0, udpCount: Int = 0) -> String? {
        if value.isEmpty { return nil }
        guard value.utf8.count <= 2048, !value.unicodeScalars.contains(where: { CharacterSet.whitespacesAndNewlines.contains($0) || $0.value < 32 }),
              let url = URLComponents(string: value), url.scheme?.lowercased() == "http", let host = url.host, !host.isEmpty,
              url.user == nil, url.password == nil, let port = url.port, (1...65535).contains(port),
              ["", "/"].contains(url.percentEncodedPath), url.query == nil, url.fragment == nil,
              !host.contains("%"), url.url != nil else {
            return "Enter http://host:port with no credentials, path, query or fragment; leave blank for direct connections."
        }
        let endpointHost = host.hasPrefix("[") && host.hasSuffix("]") ? String(host.dropFirst().dropLast()) : host
        if endpointHost.contains(":") {
            var address = in6_addr()
            guard inet_pton(AF_INET6, endpointHost, &address) == 1 else { return "Enter a valid IPv6 upstream address." }
        } else {
            var normalized = (url.url?.host ?? endpointHost).lowercased()
            if normalized.hasSuffix(".") { normalized.removeLast() }
            guard normalized.utf8.count <= 253, !normalized.isEmpty,
                  normalized.split(separator: ".", omittingEmptySubsequences: false).allSatisfy({ label in
                      label.utf8.count <= 63 && label.range(of: "^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$", options: .regularExpression) != nil
                  }) else { return "Enter an exact upstream hostname or IP address." }
        }
        if socks != "0" || reverse != "0" || tcpCount != 0 || udpCount != 0 {
            return "HTTP upstream proxy supports the HTTP/HTTPS listener only. Disable additional SOCKS, reverse, TCP and UDP listeners before Start."
        }
        return nil
    }
    static func connectTimeout(_ value: String) -> Int? {
        guard !value.isEmpty, value.utf8.allSatisfy({ (48...57).contains($0) }),
              value.count <= 3, let seconds = Int(value), (1...600).contains(seconds) else { return nil }
        return seconds
    }
    static func listenerIssue(httpPort: String, socksPort: String, reversePort: String, reverseURL: String, tcpForwards: [TCPForwardSelection] = [], udpForwards: [UDPForwardSelection] = []) -> String? {
        guard let http = Int(httpPort), (1024...65535).contains(http) else { return "HTTP port must be between 1024 and 65535." }
        guard let socks = Int(socksPort), socks == 0 || (1024...65535).contains(socks),
              let reverse = Int(reversePort), reverse == 0 || (1024...65535).contains(reverse) else {
            return "Additional listener ports must be 0 (off) or between 1024 and 65535."
        }
        if tcpForwards.count > ForwardEndpointValidation.maximumPorts { return "Use at most 32 TCP listening ports, including all ports in each range." }
        if udpForwards.count > ForwardEndpointValidation.maximumPorts { return "Use at most 32 UDP listening ports, including all ports in each range." }
        let tcp: [ForwardEndpointFacts], udp: [ForwardEndpointFacts]
        do {
            tcp = try tcpForwards.map { try $0.parsed.get() }
            udp = try udpForwards.map { try $0.parsed.get() }
        } catch { return error.localizedDescription }
        if tcp.reduce(0, { $0 + $1.listenPorts.count }) > ForwardEndpointValidation.maximumPorts { return "Use at most 32 TCP listening ports, including all ports in each range." }
        if udp.reduce(0, { $0 + $1.listenPorts.count }) > ForwardEndpointValidation.maximumPorts { return "Use at most 32 UDP listening ports, including all ports in each range." }
        let tcpPorts = tcp.flatMap { Array($0.listenPorts) }, udpPorts = udp.flatMap { Array($0.listenPorts) }
        guard Set(udpPorts).count == udpPorts.count else { return "UDP forwarding endpoints must use different UDP ports. TCP and UDP may share a port." }
        let active = [http, socks, reverse].filter { $0 != 0 } + tcpPorts
        guard Set(active).count == active.count else { return "HTTP, SOCKS, reverse proxy and TCP forwarding listeners must use different ports." }
        if reverse != 0 || !reverseURL.isEmpty {
            guard let url = URLComponents(string: reverseURL),
                  ["http", "https"].contains(url.scheme?.lowercased() ?? ""),
                  let host = url.host, !host.isEmpty,
                  url.user == nil, url.password == nil, url.url != nil else {
                return "Reverse target must be an HTTP or HTTPS URL with a host and no credentials."
            }
            if reverse != 0 && (!["", "/"].contains(url.percentEncodedPath) || url.query != nil || url.fragment != nil) {
                return "Enabled reverse proxy target must be an origin URL: no path other than /, query, or fragment."
            }
        }
        return nil
    }

    static func rate(_ value: String) -> Int? {
        guard let number = Int(value), number >= 0 else { return nil }
        return number
    }
}

struct LensNetworkSettingsView: View {
    @ObservedObject var store: LensStore
    @Environment(\.dismiss) private var dismiss
    @State private var upload = "0"
    @State private var download = "0"
    @State private var socksPort = "0"
    @State private var reversePort = "0"
    @State private var reverseURL = ""
    @State private var identifyClientProcesses = false
    @State private var connectTimeout = "10"
    @State private var connectionMessage: String?
    @State private var appliedMessage: String?
    @State private var upstreamProxy = ""
    @State private var upstreamMessage: String?
    private var upstreamIssue: String? {
        LensNetworkSettingsValidation.upstreamProxyIssue(upstreamProxy, socks: store.socksPort, reverse: store.reversePort,
                                                        tcpCount: store.tcpForwards.count, udpCount: store.udpForwards.count)
    }
    private var locked: Bool { store.isRunning || store.isStarting }
    private var listenerIssue: String? {
        LensNetworkSettingsValidation.listenerIssue(httpPort: store.port, socksPort: socksPort, reversePort: reversePort, reverseURL: reverseURL, tcpForwards: store.tcpForwards, udpForwards: store.udpForwards)
    }
    private var ratesValid: Bool { LensNetworkSettingsValidation.rate(upload) != nil && LensNetworkSettingsValidation.rate(download) != nil }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Network settings").font(.title2.weight(.semibold))
            Text("Shape captured traffic and configure additional local listeners.").foregroundStyle(.secondary)
            Form {
                Section("HTTP upstream proxy") {
                    TextField("Blank = direct, e.g. http://127.0.0.1:7897", text: $upstreamProxy)
                        .accessibilityLabel("HTTP upstream proxy URL")
                        .disabled(locked || store.settingsSaving)
                    Text("Route Lens HTTP/HTTPS traffic through an existing HTTP proxy. HTTPS uses CONNECT with normal certificate verification. An unavailable upstream fails the request; Lens never falls back to a direct connection. This does not change Mac system proxies.")
                        .font(.caption).foregroundStyle(.secondary)
                    Text("One unauthenticated HTTP endpoint for both protocols. Other upstream types, authentication and bypass lists are not available yet.").font(.caption).foregroundStyle(.secondary)
                    if locked { Label("Stop Lens before changing its upstream proxy.", systemImage: "lock").font(.caption) }
                    if let upstreamIssue { Text(upstreamIssue).font(.caption).foregroundStyle(.orange) }
                    if let upstreamMessage { Text(upstreamMessage).font(.caption).foregroundStyle(.secondary) }
                    HStack { Spacer(); Button("Save upstream proxy") {
                        store.saveHTTPUpstreamProxy(upstreamProxy) { success in
                            upstreamMessage = success ? "Upstream proxy saved for next Start." : (store.errorMessage ?? "Upstream proxy was not saved.")
                            if !success { store.errorMessage = nil }
                        }
                    }.disabled(locked || store.settingsSaving || upstreamIssue != nil) }
                }
                Section("Upstream connections") {
                    HStack {
                        Text("DNS / TCP timeout")
                        Spacer()
                        TextField("10", text: $connectTimeout).multilineTextAlignment(.trailing).frame(width: 85)
                            .accessibilityLabel("Connection timeout in seconds")
                        Text("seconds").foregroundStyle(.secondary)
                    }
                    Text("1–600 seconds; default 10. Limits new upstream DNS/TCP connection attempts across HTTP, HTTPS, SOCKS, reverse proxy and TCP forwarding. Established connections, TLS handshakes and server response waits keep their existing behavior.").font(.caption).foregroundStyle(.secondary)
                    if LensNetworkSettingsValidation.connectTimeout(connectTimeout) == nil {
                        Label("Enter a whole number from 1 to 600.", systemImage: "exclamationmark.triangle").font(.caption).foregroundStyle(.orange)
                    }
                    if let issue = store.connectionTimeoutPreferencesIssue { Text(issue).font(.caption).foregroundStyle(.orange) }
                    if let connectionMessage { Text(connectionMessage).font(.caption).foregroundStyle(.secondary).textSelection(.enabled) }
                    HStack { Spacer(); Button("Apply connection timeout") {
                        connectionMessage = "Applying…"
                        store.applyRules(connectTimeout: connectTimeout) { success in
                            connectionMessage = success ? "Connection timeout saved for new attempts." : (store.errorMessage ?? "Connection timeout was not applied.")
                            if !success { store.errorMessage = nil }
                        }
                    }.disabled(LensNetworkSettingsValidation.connectTimeout(connectTimeout) == nil || store.settingsSaving) }
                }
                Section("Bandwidth · shared across all enabled listeners") {
                    HStack {
                        Text("Upload")
                        Spacer()
                        TextField("0", text: $upload).multilineTextAlignment(.trailing).frame(width: 110)
                            .accessibilityLabel("Upload kilobytes per second")
                        Text("kB/s").foregroundStyle(.secondary)
                    }
                    HStack {
                        Text("Download")
                        Spacer()
                        TextField("0", text: $download).multilineTextAlignment(.trailing).frame(width: 110)
                            .accessibilityLabel("Download kilobytes per second")
                        Text("kB/s").foregroundStyle(.secondary)
                    }
                    Text("1 kB/s = 1,000 bytes per second. 0 means unlimited. Upload and download budgets are shared across all enabled HTTP, SOCKS, and reverse listeners; no restart is needed.").font(.caption).foregroundStyle(.secondary)
                    if !ratesValid { Label("Enter a whole number greater than or equal to 0.", systemImage: "exclamationmark.triangle").font(.caption).foregroundStyle(.orange) }
                    HStack {
                        if let message = appliedMessage { Text(message).font(.caption).foregroundStyle(.secondary) }
                        Spacer()
                        Button("Apply bandwidth now") { applyBandwidth() }.disabled(!ratesValid || store.settingsSaving)
                    }
                }
                Section("Additional listeners · loopback only") {
                    HStack { Text("SOCKS port"); Spacer(); TextField("0 = off", text: $socksPort).frame(width: 140) }
                    HStack { Text("Reverse proxy port"); Spacer(); TextField("0 = off", text: $reversePort).frame(width: 140) }
                    TextField("Reverse origin, e.g. https://example.com", text: $reverseURL)
                        .accessibilityLabel("Reverse proxy target URL")
                    Text("Both listeners are off by default and bind only to 127.0.0.1. Use separate ports from the main HTTP proxy (\(store.port)).").font(.caption).foregroundStyle(.secondary)
                    if locked { Label("Stop Lens before changing listener ports or the reverse target.", systemImage: "lock").font(.caption).foregroundStyle(.secondary) }
                    if let issue = listenerIssue { Label(issue, systemImage: "exclamationmark.triangle").font(.caption).foregroundStyle(.orange) }
                    HStack { Spacer(); Button("Save listener settings") { saveListeners() }.disabled(locked || listenerIssue != nil || store.settingsSaving) }
                }
                .disabled(locked)
                Section("Host client processes") {
                    Toggle("Identify local client processes", isOn: $identifyClientProcesses)
                    Text("Off by default. New HTTP, HTTPS, SOCKS and reverse connections briefly wait for a bounded host socket lookup. The Overview retains a process name and PID, or an explicit unknown reason. The lookup does not identify remote Android/iOS apps or raw TCP/UDP traffic.").font(.caption).foregroundStyle(.secondary)
                    if locked { Label("Stop Lens before changing process identification.", systemImage: "lock").font(.caption) }
                    HStack { Spacer(); Button("Save process setting") {
                        guard !locked else { return }
                        store.identifyClientProcesses = identifyClientProcesses
                        store.applyRules { success in appliedMessage = success ? "Process setting saved for the next Start." : "Could not save process setting." }
                    }.disabled(locked || store.settingsSaving) }
                }.disabled(locked)
            }
            .formStyle(.grouped)
            HStack {
                Text("Listener and process changes take effect on the next Start.").font(.caption).foregroundStyle(.secondary)
                Spacer()
                Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(22).frame(width: 620, height: 680)
        .onAppear {
            upload = String(store.uploadKbps); download = String(store.downloadKbps)
            socksPort = store.socksPort; reversePort = store.reversePort; reverseURL = store.reverseURL
            identifyClientProcesses = store.identifyClientProcesses
            connectTimeout = store.connectTimeoutSeconds
            upstreamProxy = store.httpUpstreamProxy
        }
    }

    private func applyBandwidth() {
        guard let upload = LensNetworkSettingsValidation.rate(upload), let download = LensNetworkSettingsValidation.rate(download) else { return }
        store.uploadKbps = upload; store.downloadKbps = download
        appliedMessage = "Applying…"
        store.applyRules { success in
            appliedMessage = success ? (store.isRunning ? "Bandwidth settings applied." : "Bandwidth saved for the next Start.") : "Bandwidth was not applied. See the error message."
        }
    }

    private func saveListeners() {
        guard !locked, listenerIssue == nil else { return }
        store.socksPort = socksPort; store.reversePort = reversePort; store.reverseURL = reverseURL
        store.applyRules { success in appliedMessage = success ? "Listener settings saved." : "Could not save listener settings." }
    }
}
