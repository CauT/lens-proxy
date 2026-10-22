import Foundation
import Darwin

struct LensLANConfiguration {
    let address: String
}

enum LensLANAccess {
    struct Address: Identifiable {
        let interface: String
        let ip: String
        var id: String { interface + ":" + ip }
    }
    private struct Invalid: Error, LocalizedError {
        let message: String
        var errorDescription: String? { message }
    }
    private static func octets(_ value: String) -> [UInt8]? {
        var address = in_addr()
        guard value.withCString({ inet_pton(AF_INET, $0, &address) }) == 1 else { return nil }
        return withUnsafeBytes(of: address.s_addr) { Array($0) }
    }
    private static func isLocal(_ ip: String) -> Bool {
        guard let value = octets(ip) else { return false }
        return value[0] == 10 || value[0] == 172 && (16...31).contains(value[1]) ||
            value[0] == 192 && value[1] == 168 || value[0] == 169 && value[1] == 254
    }
    static func configuration(enabled: Bool, address: String) throws -> LensLANConfiguration? {
        guard enabled else { return nil }
        guard isLocal(address) else { throw Invalid(message: "Choose a specific private IPv4 address assigned to this Mac.") }
        return LensLANConfiguration(address: address)
    }
    static func issue(enabled: Bool, address: String) -> String? {
        do { _ = try configuration(enabled: enabled, address: address); return nil }
        catch { return error.localizedDescription }
    }
    static func addresses() -> [Address] {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else { return [] }
        defer { freeifaddrs(head) }
        var result: [Address] = []
        var current: UnsafeMutablePointer<ifaddrs>? = first
        while let item = current {
            defer { current = item.pointee.ifa_next }
            guard let socket = item.pointee.ifa_addr, socket.pointee.sa_family == UInt8(AF_INET),
                  item.pointee.ifa_flags & UInt32(IFF_UP) != 0 else { continue }
            let name = String(cString: item.pointee.ifa_name)
            guard name.hasPrefix("en") || name.hasPrefix("bridge") else { continue }
            var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            var address = UnsafeRawPointer(socket).assumingMemoryBound(to: sockaddr_in.self).pointee.sin_addr
            guard inet_ntop(AF_INET, &address, &buffer, socklen_t(buffer.count)) != nil else { continue }
            let ip = String(cString: buffer)
            if isLocal(ip) { result.append(Address(interface: name, ip: ip)) }
        }
        return result.sorted { $0.id < $1.id }
    }
}
