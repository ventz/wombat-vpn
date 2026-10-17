// The utun lookup is WireGuardKit's (MIT, © 2018-2023 WireGuard LLC), with Wombat's claims.

import Foundation

/// The packet tunnel's utun socket. NetworkExtension doesn't hand its descriptor out, so it is
/// found among the process's descriptors. One extension process serves every tunnel, so each
/// tunnel claims the one it found and others skip it (the same rule as the WireGuard engine,
/// audit WOM-02). libopenconnect works on a dup() of it; the provider releases the claim on
/// NetworkExtension's descriptor when the tunnel has stopped.
enum TunnelDevice {
    private static let lock = NSLock()
    nonisolated(unsafe) private static var claimed = Set<Int32>()

    static func claim() -> Int32? {
        lock.withLock {
            guard let fd = find(excluding: claimed) else { return nil }
            claimed.insert(fd)
            return fd
        }
    }

    /// Claims a descriptor this process made itself (the engine's dup of a utun socket).
    static func claimExisting(_ fd: Int32) {
        _ = lock.withLock { claimed.insert(fd) }
    }

    /// Closes such a descriptor and drops its claim in one step, so its number can't be reused
    /// by a new utun and skipped, or the stale socket claimed, in between.
    static func closeAndRelease(_ fd: Int32) {
        lock.withLock {
            close(fd)
            claimed.remove(fd)
        }
    }

    static func release(_ fd: Int32) {
        _ = lock.withLock { claimed.remove(fd) }
    }

    /// "utunN" for a claimed descriptor.
    static func name(_ fd: Int32) -> String? {
        var buffer = [CChar](repeating: 0, count: Int(IFNAMSIZ))
        var size = socklen_t(IFNAMSIZ)
        guard getsockopt(fd, 2 /* SYSPROTO_CONTROL */, 2 /* UTUN_OPT_IFNAME */, &buffer, &size) == 0 else { return nil }
        return String(cString: buffer)
    }

    private static func find(excluding claimed: Set<Int32>) -> Int32? {
        var info = ctl_info()
        withUnsafeMutablePointer(to: &info.ctl_name) {
            $0.withMemoryRebound(to: CChar.self, capacity: MemoryLayout.size(ofValue: $0.pointee)) {
                _ = strcpy($0, "com.apple.net.utun_control")
            }
        }
        for fd: Int32 in 0...1024 where !claimed.contains(fd) {
            var addr = sockaddr_ctl()
            var length = socklen_t(MemoryLayout.size(ofValue: addr))
            let named = withUnsafeMutablePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getpeername(fd, $0, &length) }
            }
            guard named == 0, addr.sc_family == AF_SYSTEM else { continue }
            if info.ctl_id == 0, ioctl(fd, CTLIOCGINFO, &info) != 0 { continue }
            if addr.sc_id == info.ctl_id { return fd }
        }
        return nil
    }
}
