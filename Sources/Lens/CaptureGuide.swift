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
            if !success { self.takeFailure("Could not stop the proxy. Check its current status and try again.") }
        }
    }

    func start(port: String, address: String, sslHosts: String) {
        guard !busy else { return }
        error = nil
        guard !store.isRunning, !store.isStarting, !store.systemProxy.isBusy,
              !store.systemProxy.hasBackup else {
            error = "Stop the current capture before starting the device proxy."; return
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
            guard success else { self.busy = false; self.takeFailure("Could not save settings. Review them and try again."); return }
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
            takeFailure("Could not confirm the LAN listener. Review the error and try again.")
        }
    }

    private func takeFailure(_ fallback: String) {
        error = store.errorMessage ?? fallback
        store.errorMessage = nil
    }
}
