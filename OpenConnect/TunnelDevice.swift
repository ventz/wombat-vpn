// The utun lookup is WireGuardKit's (MIT, © 2018-2023 WireGuard LLC), with Wombat's claims.

import Darwin
import Foundation
import TunnelCore

/// The packet tunnel's utun socket. NetworkExtension doesn't hand its descriptor out, so it is
/// found among the process's descriptors. One extension process serves every tunnel, so each
/// tunnel claims the one it found and others skip it (the same rule as the WireGuard engine,
/// audit WOM-02). The engines work on a dup() of it; the provider releases its claim on
/// NetworkExtension's descriptor when the tunnel ends.
///
/// Claims record the kernel socket too (`UtunClaims`): a claim that outlived its tunnel no
/// longer hides a new utun that reused its number (1.4.6 report, 2026-11-18).
enum TunnelDevice {
    private static let lock = NSLock()
    nonisolated(unsafe) private static var claims = UtunClaims()

    /// What a failed lookup saw, for the Log tab: counts only, nothing identifying.
    struct Lookup: Error, CustomStringConvertible {
        var scanned: Int32 = 0
        var utuns = 0
        var claimedSkipped = 0
        var claimsHeld = 0
        var unknownIdentity = 0
        var staleDroppedInProcess = 0
        var processAge: Int?
        var description: String {
            "scanned \(scanned) descriptors, \(utuns) utun, \(claimedSkipped) claimed, \(claimsHeld) claim(s) held"
                + " (\(unknownIdentity) without socket identity), \(staleDroppedInProcess) stale claim(s) dropped by this process"
                + (processAge.map { ", process running \($0 / 60) min" } ?? "")
        }
    }

    static func claim() -> Result<UtunClaim, Lookup> {
        lock.withLock {
            claims.dropClosed { fcntl($0, F_GETFD) == -1 && errno == EBADF }
            var lookup = Lookup()
            if let fd = find(&lookup) {
                let claim = UtunClaim(fd: fd, socket: socketID(fd))
                claims.insert(claim)
                return .success(claim)
            }
            lookup.claimsHeld = claims.count
            lookup.unknownIdentity = claims.unknownIdentity
            lookup.staleDroppedInProcess = claims.staleDropped
            lookup.processAge = processAge()
            return .failure(lookup)
        }
    }

    /// Duplicates a claimed utun socket for an engine and claims the copy in one step, under
    /// the lock `claim()` takes: another tunnel's lookup in between would otherwise find the
    /// unclaimed copy and take this tunnel's traffic (review NEW-10). With `below`, a copy at or
    /// above it is refused: libopenconnect's main loop uses select(), whose fd_set holds
    /// FD_SETSIZE (1024) descriptors, so a higher one would write past it (review 2026-11-18).
    static func duplicateAndClaim(_ original: UtunClaim, below: Int32? = nil) -> UtunClaim? {
        lock.withLock {
            let copy = fcntl(original.fd, F_DUPFD, 0)
            guard copy >= 0 else { return nil }
            if let below, copy >= below {
                close(copy)
                return nil
            }
            // Same socket as the original (a dup), so the identity is the original's.
            let claim = UtunClaim(fd: copy, socket: original.socket)
            claims.insert(claim)
            return claim
        }
    }

    /// Closes such a copy and drops its claim in one step, so its number can't be reused by a
    /// new utun and skipped, or the stale socket claimed, in between.
    static func closeAndRelease(_ claim: UtunClaim) {
        lock.withLock {
            close(claim.fd)
            claims.release(claim)
        }
    }

    /// Drops a claim (only if it is still this one: a late release can't free a newer tunnel's).
    static func release(_ claim: UtunClaim) {
        lock.withLock { _ = claims.release(claim) }
    }

    /// "utunN" for a claimed descriptor.
    static func name(_ fd: Int32) -> String? {
        var buffer = [CChar](repeating: 0, count: Int(IFNAMSIZ))
        var size = socklen_t(IFNAMSIZ)
        guard getsockopt(fd, 2 /* SYSPROTO_CONTROL */, 2 /* UTUN_OPT_IFNAME */, &buffer, &size) == 0 else { return nil }
        return String(cString: buffer)
    }

    /// The kernel socket behind a descriptor (`soi_so`, an opaque per-socket value that a reused
    /// descriptor number doesn't keep). 0 when it can't be read: claims then hold as before.
    private static func socketID(_ fd: Int32) -> UInt64 {
        var info = socket_fdinfo()
        let size = Int32(MemoryLayout<socket_fdinfo>.size)
        guard proc_pidfdinfo(getpid(), fd, PROC_PIDFDSOCKETINFO, &info, size) == size else { return 0 }
        return info.psi.soi_so
    }

    /// Seconds since this process started, for the diagnostics.
    private static func processAge() -> Int? {
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.size
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        guard sysctl(&mib, 4, &info, &size, nil, 0) == 0 else { return nil }
        let start = info.kp_proc.p_un.__p_starttime
        return Int(Date().timeIntervalSince1970) - start.tv_sec
    }

    /// Every descriptor up to the process limit (capped), not just 0...1024: a long-lived
    /// process can hold more. About 7 ms for 65536 (measured, review 2026-11-18).
    private static func find(_ lookup: inout Lookup) -> Int32? {
        var info = ctl_info()
        withUnsafeMutablePointer(to: &info.ctl_name) {
            $0.withMemoryRebound(to: CChar.self, capacity: MemoryLayout.size(ofValue: $0.pointee)) {
                _ = strcpy($0, "com.apple.net.utun_control")
            }
        }
        let limit = min(max(getdtablesize(), 1025), 1 << 16)
        lookup.scanned = limit
        for fd: Int32 in 0..<limit {
            var addr = sockaddr_ctl()
            var length = socklen_t(MemoryLayout.size(ofValue: addr))
            let named = withUnsafeMutablePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getpeername(fd, $0, &length) }
            }
            guard named == 0, addr.sc_family == AF_SYSTEM else { continue }
            if info.ctl_id == 0, ioctl(fd, CTLIOCGINFO, &info) != 0 { continue }
            guard addr.sc_id == info.ctl_id else { continue }
            lookup.utuns += 1
            if claims.holds(fd, current: socketID(fd)) {
                lookup.claimedSkipped += 1
                continue
            }
            return fd
        }
        return nil
    }
}
