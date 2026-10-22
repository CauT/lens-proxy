// Shared Foundation/Network request probe. macOS is exercised by the CLI lane;
// compiling this source against an iOS SDK is a separate required acceptance.
import Foundation
import Network
import Security
import CryptoKit

struct AppleProxyProbeConfiguration: Decodable {
    let proxyHost: String
    let proxyPort: UInt16
    let url: String
    let method: String
    let bodyBase64: String
    let headers: [String: String]
    let anchorDERBase64: String?
}

struct AppleProxyProbeResult: Encodable {
    let platform: String
    let os: String
    let url: String
    let proxyHost: String
    let proxyPort: UInt16
    let proxyFailover: Bool
    let status: Int?
    let bodyBase64: String?
    let errorDomain: String?
    let errorCode: Int?
    let errorDescription: String?
    let trustMode: String
    let acceptedChallenges: Int
    let rejectedChallenges: Int
    let leafSHA256: String?
}

private struct AppleProbeInvalid: Error { let reason: String }

private final class AppleProbeTrust: NSObject, URLSessionDelegate, @unchecked Sendable {
    let anchor: SecCertificate?
    private let lock = NSLock()
    private var accepted = 0
    private var rejected = 0
    private var leaf: String?

    init(anchor: SecCertificate?) { self.anchor = anchor }

    func observation() -> (Int, Int, String?) {
        lock.lock(); defer { lock.unlock() }
        return (accepted, rejected, leaf)
    }

    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust else {
            completionHandler(.performDefaultHandling, nil); return
        }
        guard let anchor else { completionHandler(.performDefaultHandling, nil); return }
        // Test-client-only trust, preserving hostname, chain, date and usage checks.
        // No keychain write, blanket credential acceptance or SSL bypass is used.
        let policy = SecPolicyCreateSSL(true, challenge.protectionSpace.host as CFString)
        let setup = SecTrustSetPolicies(trust, policy) == errSecSuccess &&
            SecTrustSetAnchorCertificates(trust, [anchor] as CFArray) == errSecSuccess &&
            SecTrustSetAnchorCertificatesOnly(trust, true) == errSecSuccess &&
            SecTrustSetNetworkFetchAllowed(trust, false) == errSecSuccess
        var error: CFError?
        let valid = setup && SecTrustEvaluateWithError(trust, &error)
        let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate]
        let digest = chain?.first.map { SHA256.hash(data: SecCertificateCopyData($0) as Data).map { String(format: "%02x", $0) }.joined() }
        lock.lock()
        if valid { accepted += 1 } else { rejected += 1 }
        leaf = digest
        lock.unlock()
        completionHandler(valid ? .useCredential : .cancelAuthenticationChallenge,
                          valid ? URLCredential(trust: trust) : nil)
    }
}

@available(macOS 14.0, iOS 17.0, *)
enum AppleProxyProbe {
    static func run(_ input: AppleProxyProbeConfiguration) async throws -> AppleProxyProbeResult {
        guard input.proxyPort != 0, !input.proxyHost.isEmpty,
              let url = URL(string: input.url), ["http", "https"].contains(url.scheme),
              url.host != nil, url.user == nil, url.password == nil,
              let body = Data(base64Encoded: input.bodyBase64) else {
            throw AppleProbeInvalid(reason: "Invalid explicit proxy, HTTP(S) URL or request body")
        }
        let anchor: SecCertificate?
        if let value = input.anchorDERBase64 {
            guard let bytes = Data(base64Encoded: value), let parsed = SecCertificateCreateWithData(nil, bytes as CFData) else {
                throw AppleProbeInvalid(reason: "Anchor must be a public DER certificate")
            }
            anchor = parsed
        } else { anchor = nil }
        let configuration = URLSessionConfiguration.ephemeral
        var proxy = ProxyConfiguration(httpCONNECTProxy: .hostPort(host: .init(input.proxyHost), port: .init(rawValue: input.proxyPort)!))
        proxy.allowFailover = false
        proxy.matchDomains = []
        proxy.excludedDomains = []
        configuration.proxyConfigurations = [proxy]
        configuration.urlCache = nil
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.timeoutIntervalForRequest = 5
        configuration.timeoutIntervalForResource = 8
        let delegate = AppleProbeTrust(anchor: anchor)
        let session = URLSession(configuration: configuration, delegate: delegate, delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        var request = URLRequest(url: url)
        request.httpMethod = input.method
        request.httpBody = body.isEmpty ? nil : body
        for (key, value) in input.headers { request.setValue(value, forHTTPHeaderField: key) }
        var status: Int?, data: Data?, failure: NSError?
        do {
            let (bytes, response) = try await session.data(for: request)
            data = bytes; status = (response as? HTTPURLResponse)?.statusCode
        } catch { failure = error as NSError }
        let (accepted, rejected, leaf) = delegate.observation()
        #if os(iOS)
        let platform = "iOS"
        #else
        let platform = "macOS"
        #endif
        return AppleProxyProbeResult(platform: platform, os: ProcessInfo.processInfo.operatingSystemVersionString,
            url: input.url, proxyHost: input.proxyHost, proxyPort: input.proxyPort, proxyFailover: proxy.allowFailover,
            status: status, bodyBase64: data?.base64EncodedString(), errorDomain: failure?.domain,
            errorCode: failure?.code, errorDescription: failure?.localizedDescription,
            trustMode: anchor == nil ? "system-default" : "session-only-anchor-with-hostname-validation",
            acceptedChallenges: accepted, rejectedChallenges: rejected, leafSHA256: leaf)
    }
}
