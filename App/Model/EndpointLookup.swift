import Darwin
import Foundation

/// getaddrinfo off the main thread, with a deadline: a slow resolver must not hold up connecting.
/// getaddrinfo can't be canceled, so the lookup runs on its own thread and the caller simply
/// stops waiting at the deadline (a task group would wait for it; audit Q2-M1). At most four
/// lookups run at once, so a config with many hostnames can't spawn a thread per peer.
enum EndpointLookup {
    private static let slots = DispatchSemaphore(value: 4)

    static func addresses(for host: String, timeout: Duration = .seconds(4)) async -> [String] {
        await withCheckedContinuation { continuation in
            let once = ResumeOnce(continuation)
            DispatchQueue.global(qos: .userInitiated).async {
                guard slots.wait(timeout: .now() + .seconds(4)) == .success else { return once.resume([]) }
                defer { slots.signal() }
                once.resume(lookup(host))
            }
            DispatchQueue.global().asyncAfter(deadline: .now() + Double(timeout.components.seconds)) {
                once.resume([])
            }
        }
    }

    private final class ResumeOnce: @unchecked Sendable {
        private let lock = NSLock()
        private var continuation: CheckedContinuation<[String], Never>?
        init(_ continuation: CheckedContinuation<[String], Never>) { self.continuation = continuation }
        func resume(_ value: [String]) {
            lock.lock()
            let c = continuation
            continuation = nil
            lock.unlock()
            c?.resume(returning: value)
        }
    }

    /// Numeric IPv4 and IPv6 addresses, IPv4 first (what WireGuardKit's own resolver prefers).
    private static func lookup(_ host: String) -> [String] {
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_DGRAM
        hints.ai_protocol = IPPROTO_UDP
        var list: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &list) == 0, let list else { return [] }
        defer { freeaddrinfo(list) }
        var v4: [String] = [], v6: [String] = []
        var node: UnsafeMutablePointer<addrinfo>? = list
        while let info = node?.pointee {
            var buffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if getnameinfo(info.ai_addr, info.ai_addrlen, &buffer, socklen_t(buffer.count), nil, 0, NI_NUMERICHOST) == 0 {
                let text = String(cString: buffer)
                if info.ai_family == AF_INET { v4.append(text) } else if info.ai_family == AF_INET6, !text.contains("%") { v6.append(text) }
            }
            node = info.ai_next
        }
        return Array((NSOrderedSet(array: v4 + v6).array as? [String] ?? []).prefix(8))
    }
}
