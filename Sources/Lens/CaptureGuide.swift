import Foundation
import SwiftUI
import Combine

struct LensGuideProgress {
    private(set) var httpCount = 0
    private(set) var httpsCount = 0
    private(set) var latest: TrafficFlow?

    init(flows: [TrafficFlow], excluding baseline: Set<String>, since openedAt: TimeInterval, lanOnly: Bool) {
        for flow in flows where flow.started >= openedAt && !baseline.contains(flow.id) && flow.imported != true && !flow.replayed {
            guard !lanOnly || flow.clientConnection?.listener == "lan_proxy_port",
                  flow.method != "CONNECT", flow.error == nil, flow.status != nil,
                  flow.state == "complete" else { continue }
            if flow.scheme == "https" { httpsCount += 1 }
            else if flow.scheme == "http" { httpCount += 1 }
            else { continue }
            if let previous = latest {
                if flow.started > previous.started { latest = flow }
            } else { latest = flow }
        }
    }
}

@MainActor
final class LensDeviceSetup: ObservableObject {
    @Published private(set) var busy = false
    @Published private(set) var stopping = false
    @Published private(set) var error: String?
    private let store: LensStore
    private var startupObservation: AnyCancellable?
    private var expectedAddress: String?

    init(store: LensStore) { self.store = store }

    func stop() {
        guard !busy || (startupObservation != nil && store.isStarting) else { return }
        startupObservation = nil
        busy = true; stopping = true; error = nil
        store.stop { [weak self] success in
            guard let self else { return }
            self.busy = false; self.stopping = false
            if !success { self.takeFailure("未能停止代理，请检查当前状态后重试。") }
        }
    }

    func start(port: String, address: String, sslHosts: String) {
        guard !busy else { return }
        error = nil
        guard !store.isRunning, !store.isStarting, !store.systemProxy.isBusy,
              !store.systemProxy.hasBackup else {
            error = "先停止当前抓包，再启动手机代理。"; return
        }
        if let issue = LensNetworkSettingsValidation.listenerIssue(httpPort: port, socksPort: store.socksPort,
            reversePort: store.reversePort, reverseURL: store.reverseURL, tcpForwards: store.tcpForwards,
            udpForwards: store.udpForwards) ?? LensLANAccess.issue(enabled: true, address: address) {
            error = issue; return
        }
        store.systemProxy.chooseManualClients()
        if let reason = store.systemProxy.error { error = reason; return }
        store.port = port; store.lanAddress = address; store.lanEnabled = true; store.sslHosts = sslHosts
        busy = true
        store.applyRules { [weak self] success in
            guard let self else { return }
            guard success else { self.busy = false; self.takeFailure("设置未能保存，请检查后重试。"); return }
            self.expectedAddress = address
            self.startupObservation = self.store.objectWillChange.sink { [weak self] _ in
                Task { @MainActor in self?.completeStartIfSettled() }
            }
            self.store.start()
            self.completeStartIfSettled()
        }
    }

    private func completeStartIfSettled() {
        guard startupObservation != nil, !store.captureChanging else { return }
        startupObservation = nil; busy = false
        if !store.isRunning || store.activeLANAddress != expectedAddress {
            takeFailure("代理未能确认局域网入口，请查看错误后重试。")
        }
    }

    private func takeFailure(_ fallback: String) {
        error = store.errorMessage ?? fallback
        store.errorMessage = nil
    }
}
