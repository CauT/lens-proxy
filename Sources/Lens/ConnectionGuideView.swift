import AppKit
import SwiftUI

enum LensConnectionPage: String, CaseIterable {
    case welcome = "新手引导"
    case system = "这台 Mac"
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
            Text("开始使用 Lens").font(.title2.weight(.semibold))
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
                Button(page == .welcome ? "稍后再设置" : "关闭引导") { dismiss() }.keyboardShortcut(.cancelAction)
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
        Section("先选择要抓包的设备") {
            destination("Android 手机 / 平板", detail: "开启局域网代理 → 设置手机 Wi-Fi 代理 → 安装证书 → 查看请求", icon: "smartphone", page: .android)
            destination("iPhone / iPad", detail: "设置 Wi-Fi 代理 → 安装描述文件 → 开启证书完全信任", icon: "ipad.and.iphone", page: .ios)
            destination("这台 Mac", detail: "检查现有代理，再由你选择是否接入 Mac 系统流量", icon: "desktopcomputer", page: .system)
        }
        Section("第一次抓包，只需完成这四步") {
            Text("1. 开启代理。2. 让设备使用代理。3. 配置 HTTPS 证书。4. 选择请求，查看 Request 和 Response。")
            Text("代理正在运行，并不代表手机已经连接。引导会分别显示代理、HTTP 请求和 HTTPS 明文请求的状态。")
                .font(.callout).foregroundStyle(.secondary)
            Text("手机抓包无需修改 Mac 系统代理，也不需要登记设备 IP。选择设备不会立即改变任何网络设置。")
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
            Text("正在处理，请稍候…").font(.caption)
        } else if store.isRunning, store.activeLANAddress == nil {
            Button("停止，配置手机代理", action: deviceSetup.stop).buttonStyle(.borderedProminent)
        } else if store.isRunning {
            Button("返回抓包列表") { dismiss() }.buttonStyle(.borderedProminent)
        } else if lanEnabled {
            Button("保存并启动手机代理") { deviceSetup.start(port: port, address: lanAddress, sslHosts: sslHosts) }
                .buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction)
                .disabled(configurationIssue != nil || store.settingsSaving)
        } else {
            Button("保存为仅本机连接") { saveAndDismiss() }.buttonStyle(.borderedProminent)
                .disabled(configurationIssue != nil || store.settingsSaving)
        }
    }

    private var lanSection: some View {
        Section("1 · 开启手机代理入口") {
            if deviceSetup.stopping {
                Label("正在停止代理并保留会话，请稍候…", systemImage: "hourglass")
            } else if store.isStarting {
                Label("代理正在启动，尚未确认手机连接。", systemImage: "hourglass")
                Button("取消启动", action: deviceSetup.stop)
            } else if deviceSetup.busy {
                Label("正在保存设置或切换代理，请稍候…", systemImage: "hourglass")
            } else if store.isRunning, let active = store.activeLANAddress {
                Label("局域网代理已就绪：\(active):\(store.port)", systemImage: "checkmark.circle.fill").foregroundStyle(.green)
                if !store.recording {
                    Label("录制已暂停，恢复后才会显示新请求。", systemImage: "pause.circle").foregroundStyle(.orange)
                    Button("恢复录制", action: store.toggleRecording)
                }
                Button("停止抓包以修改连接设置", action: deviceSetup.stop).disabled(deviceSetup.busy)
            } else if store.isRunning {
                Text("当前只监听本机，手机暂时连不上。先点击下方“停止，配置手机代理”，再保存并启动。")
                    .foregroundStyle(.orange)
            } else {
                Text("选择 Mac 的局域网地址和端口，然后点击下方“保存并启动手机代理”。每次重新打开 Lens 后需重新开启。")
            }
            Group {
            Toggle("Enable LAN proxy for this launch", isOn: $lanEnabled)
            TextField("HTTP & HTTPS port", text: $port).accessibilityLabel("LAN HTTP and HTTPS proxy port")
            TextField("Mac LAN IPv4 address", text: $lanAddress).accessibilityLabel("Mac LAN IPv4 address")
            ForEach(lanAddresses) { value in
                Button("Use \(value.interface): \(value.ip)") { lanAddress = value.ip }
            }
            }.disabled(store.isRunning || store.isStarting || deviceSetup.busy)
            Text("所有能访问该局域网地址的设备均可连接，无需设备白名单。手机抓包不会主动接管 Mac 系统代理。")
                .font(.caption).foregroundStyle(.secondary)
            if lanAddresses.isEmpty { Text("未找到 Mac 的局域网 IPv4 地址，请先连接 Wi-Fi 或以太网。") .font(.caption).foregroundStyle(.orange) }
            if let issue = configurationIssue {
                Label(issue, systemImage: "exclamationmark.triangle").font(.caption).foregroundStyle(.orange)
            }
        }
    }

    @ViewBuilder private var androidSections: some View {
        lanSection
        deviceProxySection
        Section("3 · 安装 Android HTTPS 证书") {
            TextField("SSL hosts, comma-separated; * for all", text: $sslHosts)
                .accessibilityLabel("Android HTTPS hosts to decrypt")
            Text("在手机测试页点“下载 Lens CA”，到 Android 设置中的“安装证书 / CA 证书”安装下载文件。菜单因品牌而异，证书名称可能是 mitmproxy；安装前核对下方指纹。")
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
        Section("3 · 安装并信任 iPhone / iPad HTTPS 证书") {
            TextField("SSL hosts, comma-separated; * for all", text: $sslHosts)
            Text("用 Safari 打开手机测试页，下载 Lens CA。到“设置 → 通用 → VPN 与设备管理”安装下载的描述文件，再到“通用 → 关于本机 → 证书信任设置”开启该根证书的完全信任。只安装描述文件还不够。")
                .font(.caption).textSelection(.enabled)
            certificateIdentity
            Link("Apple：手动安装证书后开启 SSL 信任", destination: URL(string: "https://support.apple.com/zh-cn/102390")!).font(.caption)
        }
        deviceResultSection
    }

    private var deviceProxySection: some View {
        Section("2 · 设置手机 Wi-Fi 代理，并打开测试页") {
            Text(page == .android ? "Android：已连接的 Wi-Fi → 修改网络 / 高级选项 → 代理 → 手动。" : "iPhone / iPad：设置 → Wi-Fi → 当前网络右侧 ⓘ → 配置代理 → 手动，关闭认证。")
                .font(.caption)
            LabeledContent("代理服务器", value: lanAddress.isEmpty ? "先选择 Mac 局域网地址" : lanAddress).textSelection(.enabled)
            LabeledContent("代理端口", value: port).textSelection(.enabled)
            HStack {
                Button("复制服务器地址") { lensCopy(lanAddress) }.disabled(lanAddress.isEmpty)
                Button("复制端口") { lensCopy(port) }
            }
            Text("手机与 Mac 连接同一网络。服务器只填 IP，不加 http://，也不填 127.0.0.1。")
                .font(.caption).foregroundStyle(.secondary)
            Text("手机浏览器打开：http://lens.invalid/").font(.callout.monospaced()).textSelection(.enabled)
            Button("复制手机测试页地址") { lensCopy("http://lens.invalid/") }
            Label(guideProgress.httpCount > 0 ? "本次引导已收到 \(guideProgress.httpCount) 个新的局域网 HTTP 请求" : "等待手机请求；测试页应显示“已连接 Lens”", systemImage: guideProgress.httpCount > 0 ? "checkmark.circle.fill" : "circle")
                .font(.caption).foregroundStyle(guideProgress.httpCount > 0 ? Color.green : Color.secondary)
        }
    }

    private var deviceResultSection: some View {
        Section("4 · 确认 HTTPS 明文，并查看请求 / 响应") {
            Label(guideProgress.httpsCount > 0 ? "本次已收到 \(guideProgress.httpsCount) 个 HTTPS 明文响应" : "等待 HTTPS 明文请求；Mac 无法直接确认手机是否已安装证书", systemImage: guideProgress.httpsCount > 0 ? "checkmark.circle.fill" : "circle")
                .font(.caption).foregroundStyle(guideProgress.httpsCount > 0 ? Color.green : Color.secondary)
            Text("在手机打开一个 HTTPS 网页或目标 App。回到 Lens，选择请求行，分别点击右侧 Request 和 Response，查看请求头和正文。仅出现 CONNECT 隧道不算 HTTPS 明文抓包成功。")
                .font(.caption)
            if let latest = guideProgress.latest {
                Button("打开本次最新请求") {
                    store.selectSession(store.captureSessionID); store.search = ""; store.selectedHost = nil
                    store.selection = latest.id; dismiss()
                }
            }
            DisclosureGroup("仍然没有流量？按现象排查") {
                Text("HTTP 也没有：确认上方显示“局域网代理已就绪”、手机代理 IP/端口正确、两端同一网络。访客 Wi-Fi / AP 隔离可能阻止设备互访；若 Mac 防火墙询问传入连接，请允许 Lens。")
                Text("HTTP 有、HTTPS 失败：核对证书指纹与信任、SSL hosts 是否包含目标域名。部分 Android App 不信任用户 CA；证书固定的 App 可能拒绝抓包。")
                Text("列表仍为空：确认录制未暂停；若正在查看旧会话，切换到录制会话。结束测试后，将手机 Wi-Fi 代理改回“无 / 关闭”。")
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
        Section("这台 Mac · 从普通浏览器请求开始") {
            Text("1. 启动本地代理。2. 检查下方已有代理与网络服务，再由你选择“Use Lens for this service”。3. 配置 HTTPS 证书信任。4. 正常浏览后，在列表选择请求，查看 Request / Response。")
                .font(.caption)
            if !store.isRunning && !store.isStarting { Button("启动本地代理", action: store.start) }
            Button("查看 HTTPS 证书设置") { page = .client }
            Text("接入 Mac 系统代理会改变此服务的 HTTP/HTTPS 路由；若依赖 Clash 等现有代理，先核对上游设置。手机抓包请选择 Android / iPhone，无须在这里接管 Mac 流量。")
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
