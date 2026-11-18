import Foundation

/// One claim on a utun descriptor: its number and the kernel socket behind it at claim time.
public struct UtunClaim: Hashable, Sendable {
    public let fd: Int32
    /// Opaque per-socket identity (`proc_pidfdinfo`'s `soi_so`), 0 when it couldn't be read.
    public let socket: UInt64

    public init(fd: Int32, socket: UInt64) {
        self.fd = fd
        self.socket = socket
    }
}

/// Which utun descriptors a tunnel in this extension process has claimed, so another tunnel's
/// lookup skips them (audit WOM-02). Keyed by descriptor number AND the kernel socket behind it:
/// a number alone goes stale. If a tunnel ends without its claim being released (macOS ends a
/// session without the cleanup that releases it), NetworkExtension closes that utun and the next
/// tunnel's utun often gets the same lowest-free number. A number-only claim then hid the new
/// device, and every start failed with "Could not find the tunnel device" until the process
/// exited (1.4.6 report, 2026-11-18).
///
/// Rules (reviews 2026-11-18, Fable 5.2 + GPT-6.2 Astra):
/// - A descriptor whose socket is claimed under ANY number is skipped: dup()s share the socket,
///   so an engine's copy (WireGuard's Go bridge dups without telling Swift) is never handed out.
/// - A claim on a number that now holds a different socket is stale and dropped.
/// - A release removes only the claim it made (same number and socket), so a late release of an
///   ended tunnel can't free a newer tunnel's claim on a reused number.
/// - Unknown identity (0) on either side keeps the claim: fail closed.
public struct UtunClaims: Sendable {
    private var claims: [Int32: UInt64] = [:]
    /// Claims found stale and dropped since the process started, for diagnostics.
    public private(set) var staleDropped = 0

    public init() {}

    public var count: Int { claims.count }
    /// Claims whose socket couldn't be identified (they hold by number only).
    public var unknownIdentity: Int { claims.values.filter { $0 == 0 }.count }

    public mutating func insert(_ claim: UtunClaim) { claims[claim.fd] = claim.socket }

    /// Removes `claim` if it is still the claim on its number. Returns whether it was.
    @discardableResult
    public mutating func release(_ claim: UtunClaim) -> Bool {
        guard let recorded = claims[claim.fd] else { return false }
        // Same socket, or identity unknown on either side (then the number is all there is).
        guard recorded == claim.socket || recorded == 0 || claim.socket == 0 else { return false }
        claims[claim.fd] = nil
        return true
    }

    /// Whether a lookup must skip `fd`, which now holds the socket `current`.
    public mutating func holds(_ fd: Int32, current: UInt64) -> Bool {
        if current != 0, claims.contains(where: { $0.key != fd && $0.value == current }) { return true }
        guard let recorded = claims[fd] else { return false }
        if recorded == 0 || current == 0 || recorded == current { return true }
        claims[fd] = nil
        staleDropped += 1
        return false
    }

    /// Drops claims whose descriptor is closed (`isClosed` true), so a closed number never
    /// shadows a device opened under it later.
    public mutating func dropClosed(isClosed: (Int32) -> Bool) {
        for fd in claims.keys where isClosed(fd) {
            claims[fd] = nil
            staleDropped += 1
        }
    }
}
