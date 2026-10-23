import AppKit
import SwiftUI

enum LensConnectionPage: String, CaseIterable {
    case welcome = "Get Started"
    case system = "This Mac"
    case android = "Android"
    case ios = "iPhone & iPad"
    case client = "Client connection"

    var isDevice: Bool { self == .android || self == .ios }
}

struct LensConnectionView: View {
    @ObservedObject var store: LensStore
    @ObservedObject private var systemProxy: SystemProxyController
    @Environment(\.dismiss) private var dismiss
    @State private var page: LensConnectionPage
    @State private var port = ""
    @State private var sslHosts = ""
    @State private var lanEnabled = false
    @State private var lanAddress = ""
    @State private var lanAddresses: [LensLANAccess.Address] = []
    @State private var showClientCertificates = false
    @State private var baselineFlowIDs = Set<String>()
    @State private var guideOpenedAt = Date().timeIntervalSince1970
    @StateObject private var deviceSetup: LensDeviceSetup

    init(store: LensStore, page: LensConnectionPage = .client) {
        self.store = store; self.systemProxy = store.systemProxy; self._page = State(initialValue: page)
        self._deviceSetup = StateObject(wrappedValue: LensDeviceSetup(store: store))
    }

    private var configurationIssue: String? {
        LensNetworkSettingsValidation.listenerIssue(httpPort: port, socksPort: store.socksPort, reversePort: store.reversePort, reverseURL: store.reverseURL, tcpForwards: store.tcpForwards, udpForwards: store.udpForwards) ?? LensLANAccess.issue(enabled: lanEnabled, address: lanAddress)
    }
    private var proxyURL: String { "http://127.0.0.1:\(port)" }
    private var certificatePath: String { store.caCert.isEmpty ? store.dataDirectory.appendingPathComponent("mitmproxy-ca-cert.pem").path : store.caCert }
    private var curlExample: String { "curl --proxy \(proxyURL) --cacert '\(certificatePath.replacingOccurrences(of: "'", with: "'\\''"))' https://example.com" }
    private var guideProgress: LensGuideProgress {
        LensGuideProgress(flows: store.flows(in: store.captureSessionID), excluding: baselineFlowIDs, since: guideOpenedAt, lanOnly: page.isDevice)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Get Started with Lens").font(.title2.weight(.semibold))
            Picker("Connection page", selection: $page) {
                ForEach(LensConnectionPage.allCases, id: \.self) { Text($0.rawValue).tag($0) }
            }.pickerStyle(.segmented).labelsHidden()
            Form {
                if page == .welcome { welcomeSections }
                else if page == .client { clientSections }
                else if page == .android { androidSections }
                else if page == .ios { iosSections }
                else { systemSections }
            }.formStyle(.grouped)
            if page.isDevice, let error = deviceSetup.error ?? store.startupIssue?.message {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .font(.caption).foregroundStyle(.red).fixedSize(horizontal: false, vertical: true).textSelection(.enabled)
            }
            HStack {
                Button(page == .welcome ? "Set Up Later" : "Close Guide") { dismiss() }.keyboardShortcut(.cancelAction)
                Spacer()
                if page.isDevice { devicePrimaryAction }
                else if page != .welcome {
                    Button("Done") { saveAndDismiss() }.buttonStyle(.borderedProminent)
                        .keyboardShortcut(.defaultAction).disabled(configurationIssue != nil || store.settingsSaving)
                }
            }
        }
        .padding(22).frame(width: 740, height: 680)
        .sheet(isPresented: $showClientCertificates) { LensClientCertificatesView(store: store) }
        .onAppear {
            port = store.port; sslHosts = store.sslHosts
            lanEnabled = store.lanEnabled; lanAddress = store.lanAddress
            lanAddresses = LensLANAccess.addresses()
            if lanAddress.isEmpty && lanAddresses.count == 1 { lanAddress = lanAddresses[0].ip }
            if page.isDevice { lanEnabled = true }
            guideOpenedAt = Date().timeIntervalSince1970
            baselineFlowIDs = Set(store.sessions.flatMap { store.flows(in: $0.id).map(\.id) })
            if page == .system { systemProxy.refresh() }
        }
        .onChange(of: page) {
            if page == .system { systemProxy.refresh() }
            if page.isDevice { lanEnabled = true }
        }
    }

    @ViewBuilder private var welcomeSections: some View {
        Section("Choose a device to inspect") {
            destination("Android phone / tablet", detail: "Enable LAN access → Set the Wi-Fi proxy → Install the CA → Inspect requests", icon: "smartphone", page: .android)
            destination("iPhone / iPad", detail: "Set the Wi-Fi proxy → Install the profile → Enable full certificate trust", icon: "ipad.and.iphone", page: .ios)
            destination("This Mac", detail: "Review existing proxies, then choose whether to route Mac traffic through Lens", icon: "desktopcomputer", page: .system)
        }
        Section("Your first capture in four steps") {
            Text("1. Start the proxy. 2. Connect your device. 3. Set up HTTPS trust. 4. Select a request and inspect Request and Response.")
            Text("A running proxy does not mean your device is connected. The guide tracks proxy readiness, HTTP requests and decrypted HTTPS responses separately.")
                .font(.callout).foregroundStyle(.secondary)
            Text("Device capture needs no Mac system proxy changes or device IP registration. Choosing a device does not change network settings.")
                .font(.callout).foregroundStyle(.secondary)
        }
    }

    private func destination(_ title: String, detail: String, icon: String, page selected: LensConnectionPage) -> some View {
        Button { page = selected } label: {
            HStack(spacing: 14) {
                Image(systemName: icon).font(.title2).frame(width: 30)
                VStack(alignment: .leading, spacing: 5) {
                    Text(title).font(.headline)
                    Text(detail).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
                Spacer()
                Image(systemName: "chevron.right")
            }.padding(.vertical, 9).contentShape(Rectangle())
        }.buttonStyle(.plain)
    }

    @ViewBuilder private var devicePrimaryAction: some View {
        if deviceSetup.busy || store.isStarting {
            ProgressView().controlSize(.small)
            Text("Working, please wait…").font(.caption)
        } else if store.isRunning, store.activeLANAddress == nil {
            Button("Stop and Set Up Device Proxy", action: deviceSetup.stop).buttonStyle(.borderedProminent)
        } else if store.isRunning {
            Button("Back to Traffic") { dismiss() }.buttonStyle(.borderedProminent)
        } else if lanEnabled {
            Button("Save and Start Device Proxy") { deviceSetup.start(port: port, address: lanAddress, sslHosts: sslHosts) }
                .buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction)
                .disabled(configurationIssue != nil || store.settingsSaving)
        } else {
            Button("Save for Local Clients Only") { saveAndDismiss() }.buttonStyle(.borderedProminent)
                .disabled(configurationIssue != nil || store.settingsSaving)
        }
    }

    private var lanSection: some View {
        Section("1 · Enable the device proxy") {
            if deviceSetup.stopping {
                Label("Stopping the proxy and keeping your session, please wait…", systemImage: "hourglass")
            } else if store.isStarting {
                Label("Starting the proxy. Device connection has not been confirmed yet.", systemImage: "hourglass")
                Button("Cancel Start", action: deviceSetup.stop)
            } else if deviceSetup.busy {
                Label("Saving settings or changing the proxy, please wait…", systemImage: "hourglass")
            } else if store.isRunning, let active = store.activeLANAddress {
                Label("LAN proxy ready: \(active):\(store.port)", systemImage: "checkmark.circle.fill").foregroundStyle(.green)
                if !store.recording {
                    Label("Recording is paused. Resume to see new requests.", systemImage: "pause.circle").foregroundStyle(.orange)
                    Button("Resume Recording", action: store.toggleRecording)
                }
                Button("Stop Capture to Change Settings", action: deviceSetup.stop).disabled(deviceSetup.busy)
            } else if store.isRunning {
                Text("Lens is listening on loopback only, so devices cannot connect. Choose Stop and Set Up Device Proxy below, then save and start.")
                    .foregroundStyle(.orange)
            } else {
                Text("Choose the Mac LAN address and port, then choose Save and Start Device Proxy below. Enable LAN access again each time you open Lens.")
            }
            Group {
            Toggle("Enable LAN proxy for this launch", isOn: $lanEnabled)
            TextField("HTTP & HTTPS port", text: $port).accessibilityLabel("LAN HTTP and HTTPS proxy port")
            TextField("Mac LAN IPv4 address", text: $lanAddress).accessibilityLabel("Mac LAN IPv4 address")
            ForEach(lanAddresses) { value in
                Button("Use \(value.interface): \(value.ip)") { lanAddress = value.ip }
            }
            }.disabled(store.isRunning || store.isStarting || deviceSetup.busy)
            Text("Any device that can reach this LAN address can connect; no device allowlist is required. Device capture does not take over the Mac system proxy.")
                .font(.caption).foregroundStyle(.secondary)
            if lanAddresses.isEmpty { Text("No Mac LAN IPv4 address found. Connect to Wi-Fi or Ethernet first.") .font(.caption).foregroundStyle(.orange) }
            if let issue = configurationIssue {
                Label(issue, systemImage: "exclamationmark.triangle").font(.caption).foregroundStyle(.orange)
            }
        }
    }

    @ViewBuilder private var androidSections: some View {
        lanSection
        deviceProxySection
        Section("3 · Install the Android HTTPS certificate") {
            TextField("SSL hosts, comma-separated; * for all", text: $sslHosts)
                .accessibilityLabel("Android HTTPS hosts to decrypt")
            Text("On the device test page, choose Download Lens CA. In Android Settings, find Install a certificate / CA certificate and install the file. Menus vary by device; the certificate may be named mitmproxy. Check the fingerprint below before installing.")
                .font(.caption).textSelection(.enabled)
            certificateIdentity
            Text("The target browser or app must trust this CA. Modern Android apps may require a debug Network Security Configuration; installing a user CA alone does not make every app trust it. Certificate-pinned apps may reject inspection.").font(.caption).foregroundStyle(.secondary)
            Link("Android app CA trust configuration", destination: URL(string: "https://developer.android.com/privacy-and-security/security-config#TrustingDebugCa")!).font(.caption)
        }
        deviceResultSection
    }

    @ViewBuilder private var iosSections: some View {
        lanSection
        deviceProxySection
        Section("3 · Install and trust the iPhone / iPad HTTPS certificate") {
            TextField("SSL hosts, comma-separated; * for all", text: $sslHosts)
            Text("Open the device test page in Safari and download Lens CA. Install the profile in Settings → General → VPN & Device Management. Then enable full trust for the root in General → About → Certificate Trust Settings. Installing the profile alone is not enough.")
                .font(.caption).textSelection(.enabled)
            certificateIdentity
            Link("Apple: Enable SSL trust for a manually installed certificate", destination: URL(string: "https://support.apple.com/en-us/102390")!).font(.caption)
        }
        deviceResultSection
    }

    private var deviceProxySection: some View {
        Section("2 · Set the device Wi-Fi proxy and open the test page") {
            Text(page == .android ? "Android: Connected Wi-Fi network → Edit network / Advanced options → Proxy → Manual." : "iPhone / iPad: Settings → Wi-Fi → ⓘ beside the current network → Configure Proxy → Manual. Turn Authentication off.")
                .font(.caption)
            LabeledContent("Proxy server", value: lanAddress.isEmpty ? "Choose a Mac LAN address first" : lanAddress).textSelection(.enabled)
            LabeledContent("Proxy port", value: port).textSelection(.enabled)
            HStack {
                Button("Copy Server Address") { lensCopy(lanAddress) }.disabled(lanAddress.isEmpty)
                Button("Copy Port") { lensCopy(port) }
            }
            Text("Connect the device and Mac to the same network. Enter only the IP address as the server, without http://. Do not use 127.0.0.1.")
                .font(.caption).foregroundStyle(.secondary)
            Text("Open in the device browser: http://lens.invalid/").font(.callout.monospaced()).textSelection(.enabled)
            Button("Copy Device Test URL") { lensCopy("http://lens.invalid/") }
            Label(guideProgress.httpCount > 0 ? "\(guideProgress.httpCount) new LAN HTTP requests received during this setup" : "Waiting for device requests. The test page should say Connected to Lens.", systemImage: guideProgress.httpCount > 0 ? "checkmark.circle.fill" : "circle")
                .font(.caption).foregroundStyle(guideProgress.httpCount > 0 ? Color.green : Color.secondary)
        }
    }

    private var deviceResultSection: some View {
        Section("4 · Verify decrypted HTTPS and inspect Request / Response") {
            Label(guideProgress.httpsCount > 0 ? "\(guideProgress.httpsCount) decrypted HTTPS responses received during this setup" : "Waiting for decrypted HTTPS traffic. The Mac cannot directly confirm whether the device has installed the CA.", systemImage: guideProgress.httpsCount > 0 ? "checkmark.circle.fill" : "circle")
                .font(.caption).foregroundStyle(guideProgress.httpsCount > 0 ? Color.green : Color.secondary)
            Text("Open an HTTPS page or target app on your device. In Lens, select the request and open Request and Response to inspect headers and bodies. A CONNECT tunnel alone does not prove HTTPS decryption.")
                .font(.caption)
            if let latest = guideProgress.latest {
                Button("Open Latest Request") {
                    store.selectSession(store.captureSessionID); store.search = ""; store.selectedHost = nil
                    store.selection = latest.id; dismiss()
                }
            }
            DisclosureGroup("Still no traffic? Troubleshoot by symptom") {
                Text("No HTTP: Check that the LAN proxy is ready, the device proxy address and port are correct, and both devices share a network. Guest Wi-Fi or AP isolation may block access. If the Mac firewall asks about incoming connections, allow Lens.")
                Text("HTTP works but HTTPS fails: Check the CA fingerprint, certificate trust and whether SSL hosts includes the target. Some Android apps do not trust user CAs; certificate-pinned apps may reject inspection.")
                Text("Still an empty list: Check that recording is active and switch from an old session to the recording session. When finished, set the device Wi-Fi proxy back to None / Off.")
            }.font(.caption).foregroundStyle(.secondary)
        }
    }

    @ViewBuilder private var certificateIdentity: some View {
        Text(store.caSHA256.isEmpty ? "Start Lens to display the CA SHA-256 fingerprint." : "CA SHA-256: " + store.caSHA256)
            .font(.system(.caption, design: .monospaced)).textSelection(.enabled)
        Text("The generated certificate can be named mitmproxy. Compare the downloaded CA's SHA-256 fingerprint before trusting it.").font(.caption).foregroundStyle(.secondary)
    }

    @ViewBuilder private var clientSections: some View {
        Section("HTTP & HTTPS proxy") {
            HStack {
                Text("127.0.0.1").font(.system(.body, design: .monospaced))
                Spacer()
                TextField("Port", text: $port).frame(width: 100).disabled(store.isRunning || store.isStarting)
                    .accessibilityLabel("Main HTTP proxy port")
            }
            Text("Configure both HTTP and HTTPS in your client to use this loopback address and port. Stop Lens before changing the port.").font(.caption).foregroundStyle(.secondary)
            if let issue = configurationIssue { Label(issue, systemImage: "exclamationmark.triangle").font(.caption).foregroundStyle(.orange) }
        }
        Section("HTTPS inspection") {
            TextField("SSL hosts, comma-separated; * for all", text: $sslHosts)
            Text("Host globs to decrypt. Start Lens once to generate your local CA certificate.").font(.caption).foregroundStyle(.secondary)
            HStack {
                Button("Reveal CA certificate", action: store.revealCertificate).disabled(store.caCert.isEmpty)
                Button("Open certificate…") { NSWorkspace.shared.open(URL(fileURLWithPath: store.caCert)) }.disabled(store.caCert.isEmpty)
            }
            Text("Import and review trust settings in Keychain Access yourself. Lens does not change certificate trust.").font(.caption).foregroundStyle(.secondary)
        }
        Section("TLS client certificates") {
            HStack {
                Text("\(store.activeClientCertificates.count) active · \(store.clientCertificates.count) selected for next Start")
                    .font(.caption).foregroundStyle(.secondary)
                Spacer()
                Button("Client certificates…") { showClientCertificates = true }
            }
            Text("Use PKCS#12 or combined PEM identities for servers requiring mutual TLS. Each identity applies to one exact host and port.")
                .font(.caption).foregroundStyle(.secondary)
        }
        Section("Test a client") {
            Text(curlExample).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
            HStack { Button("Copy cURL command") { lensCopy(curlExample) }; Spacer(); Button("Open Network settings") { openNetworkSettings() } }
            Text("Manual system setup: Network → your connection → Details → Proxies. Enable HTTP and HTTPS, set both to 127.0.0.1 and this port, then turn them off when Lens stops.").font(.caption).foregroundStyle(.secondary)
            Text("Capture limits: 2,000 requests / 256 MiB retained; 32 MiB per body; 2 MiB preview.").font(.caption).foregroundStyle(.secondary)
        }
    }

    @ViewBuilder private var systemSections: some View {
        Section("This Mac · Start with your browser") {
            Text("1. Start the local proxy. 2. Review the existing proxy and network service below, then choose Use Lens for this service. 3. Set up HTTPS certificate trust. 4. Browse normally, select a request and inspect Request / Response.")
                .font(.caption)
            if !store.isRunning && !store.isStarting { Button("Start Local Proxy", action: store.start) }
            Button("Review HTTPS Certificate Setup") { page = .client }
            Text("Using the Mac system proxy changes this service’s HTTP/HTTPS route. If you depend on an existing proxy such as Clash, review upstream settings first. For device capture, choose Android or iPhone; Mac traffic does not need to be routed here.")
                .font(.caption).foregroundStyle(.secondary)
        }
        Section("Capture status") {
            Text(store.status).font(.caption)
            if let issue = store.startupIssue {
                Text(issue.message).font(.caption).foregroundStyle(.red).textSelection(.enabled)
                if issue.isCaptureSetup { Button("Review proxy port and certificates") { page = .client } }
            }
        }
        Section("Network service") {
            LabeledContent("Active service", value: systemProxy.primaryService ?? "Unknown — choose and verify the service manually").font(.caption)
            if let active = systemProxy.primaryService, !systemProxy.selectedService.isEmpty, systemProxy.selectedService != active {
                Text("The selected service is not the active service (\(active)). Ordinary browser traffic may use the active service instead.").font(.caption).foregroundStyle(.orange)
            }
            HStack {
                Picker("Service", selection: Binding(get: {
                    systemProxy.services.contains(systemProxy.selectedService) ? systemProxy.selectedService : ""
                }, set: { systemProxy.selectService($0) })) {
                    // Keep this tag present while loading, on failure, and after service list updates.
                    Text("Choose a service").tag("")
                    ForEach(systemProxy.services, id: \.self) { Text($0).tag($0) }
                }.disabled(systemProxy.isBusy)
                Button { systemProxy.refresh() } label: { Image(systemName: "arrow.clockwise") }
                    .disabled(systemProxy.isBusy).help("Refresh proxy settings")
                if systemProxy.isBusy { ProgressView().controlSize(.small) }
            }
            if let current = systemProxy.snapshot, current.service == systemProxy.selectedService {
                LabeledContent("HTTP", value: current.http.summary).font(.caption)
                LabeledContent("HTTPS", value: current.https.summary).font(.caption)
                if let issue = current.automaticConfigurationIssue { Label(issue, systemImage: "exclamationmark.triangle").font(.caption).foregroundStyle(.orange) }
            }
        }
        Section("Use the local capture proxy") {
            Text("For HTTPS content, first open Client connection, review the Lens CA and configure trust in Keychain Access, then choose SSL hosts. Without trusted certificates, inspected HTTPS connections may fail. Lens never changes trust automatically.")
                .font(.caption).foregroundStyle(.secondary)
            Toggle("Reconnect this service when Lens opens", isOn: Binding(get: { systemProxy.rememberOnLaunch }, set: { systemProxy.setRememberOnLaunch($0) }))
                .disabled(systemProxy.isBusy)
            Text("Saved after successful setup. Reconnection waits for Lens to listen and refuses changed network locations or previous proxy settings.").font(.caption).foregroundStyle(.secondary)
            if let current = systemProxy.snapshot, current.http.enabled || current.https.enabled {
                Text("Existing proxy: HTTP \(current.http.summary); HTTPS \(current.https.summary). Applying Lens replaces these routes for this service. If apps require an existing HTTP proxy, configure and verify Lens's HTTP upstream proxy first. Settings are not copied automatically. Stop/Quit restores the saved settings.")
                    .font(.caption).foregroundStyle(.orange).textSelection(.enabled)
            }
            HStack {
                Button("Use Lens for this service") { store.connectMacCapture() }
                    .disabled(!store.isRunning || systemProxy.isBusy || systemProxy.hasBackup || systemProxy.snapshot == nil || systemProxy.snapshot?.automaticConfigurationIssue != nil)
                Button("Restore previous settings") { systemProxy.restore() }.disabled(!systemProxy.hasBackup || systemProxy.isBusy)
            }
            Text("These buttons may request macOS administrator permission. Only HTTP and HTTPS are changed. Previous settings are saved for Stop, Quit, and crash recovery; external changes are never overwritten.").font(.caption).foregroundStyle(.secondary)
            if !store.isRunning { Text("Start Lens before applying the system proxy.").font(.caption).foregroundStyle(.secondary) }
            if systemProxy.hasBackup { Label("Recovery saved for \(systemProxy.backupService ?? "a network service").", systemImage: "arrow.uturn.backward.circle").font(.caption) }
            if let message = systemProxy.message { Text(message).font(.caption).foregroundStyle(.secondary).textSelection(.enabled) }
            if let error = systemProxy.error { Text(error).font(.caption).foregroundStyle(.red).textSelection(.enabled).lineLimit(5).help(error) }
            Button("Open Network settings") { openNetworkSettings() }
            Button("Use manual clients only") {
                systemProxy.chooseManualClients()
                if systemProxy.error == nil { dismiss() }
            }.disabled(systemProxy.isBusy || systemProxy.hasBackup)
        }
    }

    private func openNetworkSettings() {
        if let url = URL(string: "x-apple.systempreferences:com.apple.Network-Settings.extension") { NSWorkspace.shared.open(url) }
    }
    private func saveAndDismiss() {
        guard configurationIssue == nil else { return }
        store.port = port; store.sslHosts = sslHosts
        store.lanEnabled = lanEnabled; store.lanAddress = lanAddress
        store.applyRules { if $0 { dismiss() } }
    }
}
