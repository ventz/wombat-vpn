import Foundation

/// How much of the IPv4 / IPv6 address space a set of routes covers, computed on merged
/// intervals. "Full tunnel" must mean "routes (nearly) everything", not "contains a literal /0":
/// 0.0.0.0/1 + 128.0.0.0/1 routes all traffic too, and must be labeled as such.
public struct RouteCoverage: Equatable, Sendable {
    /// 0...1 of the IPv4 space.
    public let ipv4: Double
    /// 0...1 of the IPv6 space.
    public let ipv6: Double

    public init(_ ranges: [IPAddressRange]) {
        ipv4 = Self.fraction(ranges.filter { $0.family == .v4 }, bits: 32)
        ipv6 = Self.fraction(ranges.filter { $0.family == .v6 }, bits: 128)
    }

    /// Routes at least half of the family's space: treated as a full tunnel for warnings.
    /// (Typical "everything except my LAN" configs cover ~99%.)
    public var routesMostIPv4: Bool { ipv4 >= 0.5 }
    public var routesMostIPv6: Bool { ipv6 >= 0.5 }
    public var isFullTunnel: Bool { routesMostIPv4 || routesMostIPv6 }

    /// "all", "99.6%", "none".
    public static func describe(_ fraction: Double) -> String {
        if fraction >= 1 { return "all" }
        if fraction <= 0 { return "none" }
        let percent = fraction * 100
        return percent < 0.1 ? "<0.1%" : String(format: "%.1f%%", min(percent, 99.9))
    }

    private static func fraction(_ ranges: [IPAddressRange], bits: Int) -> Double {
        guard !ranges.isEmpty else { return 0 }
        // Intervals as [start, end) in UInt128; the IPv6 space end (2^128) doesn't fit, so use
        // inclusive ends.
        var intervals: [(UInt128, UInt128)] = ranges.map { r in
            let start = Self.value(r.network.address)
            let hostBits = bits - Int(r.prefixLength)
            let size: UInt128 = hostBits >= 128 ? UInt128.max : (UInt128(1) << UInt128(hostBits)) - 1
            return (start, start &+ size)
        }
        intervals.sort { $0.0 < $1.0 }
        var covered: Double = 0
        var current = intervals[0]
        for next in intervals.dropFirst() {
            if next.0 <= current.1 || current.1 &+ 1 == next.0 {
                current.1 = max(current.1, next.1)
            } else {
                covered += Double(current.1 - current.0) + 1
                current = next
            }
        }
        covered += Double(current.1 - current.0) + 1
        return min(1, covered / pow(2, Double(bits)))
    }

    static func value(_ bytes: Data) -> UInt128 {
        bytes.reduce(UInt128(0)) { ($0 << 8) | UInt128($1) }
    }
}

extension TunnelConfiguration {
    /// The share of each address family every peer actually receives, computed the way
    /// WireGuard routes: the longest matching prefix wins, and an identical prefix listed again
    /// replaces the earlier one, so the later peer gets it. Prefixes are either nested or
    /// disjoint, so one sorted pass with a stack credits each route its block minus the more
    /// specific routes inside it. Exact for every address, unlike sampling destinations, which
    /// a decoy holding just the sample addresses could fool (audit S4e L1).
    ///
    /// Counts are exact integers (addresses, saturating at UInt128.max for the one value that
    /// doesn't fit, all of IPv6): Doubles drifted below one half for a peer tiling half of IPv6
    /// out of many small routes (S4f L1). Doubles are only for sorting and display.
    public func routeShares() -> [(peer: PeerConfiguration, ipv4: Double, ipv6: Double)] {
        routeCounts().map { ($0.peer, Double($0.ipv4) / 0x1p32, Double($0.ipv6) / 0x1p128) }
    }

    /// Addresses of each family every peer receives (see routeShares).
    func routeCounts() -> [(peer: PeerConfiguration, ipv4: UInt128, ipv6: UInt128)] {
        struct Prefix: Hashable { let address: Data; let length: UInt8 }
        var counts = Array(repeating: (ipv4: UInt128(0), ipv6: UInt128(0)), count: peers.count)
        for family in [IPAddressRange.Family.v4, .v6] {
            let bits = family == .v4 ? 32 : 128
            // The engine's table: one owner per exact prefix, the last peer that lists it.
            var owner: [Prefix: (peer: Int, route: IPAddressRange)] = [:]
            for (i, peer) in peers.enumerated() {
                for route in peer.allowedIPs where route.family == family {
                    let network = route.network
                    owner[Prefix(address: network.address, length: network.prefixLength)] = (i, network)
                }
            }
            func start(_ r: IPAddressRange) -> UInt128 { RouteCoverage.value(r.address) }
            // The last address of a block (no overflow: all of IPv6 ends at UInt128.max).
            func end(_ r: IPAddressRange) -> UInt128 {
                let hostBits = bits - Int(r.prefixLength)
                return start(r) | (hostBits == 128 ? UInt128.max : (UInt128(1) << hostBits) - 1)
            }
            // Wider blocks before the ones they contain.
            let routes = owner.values.sorted { start($0.route) != start($1.route) ? start($0.route) < start($1.route) : $0.route.prefixLength < $1.route.prefixLength }
            // Each block's size minus its direct children's: the addresses it actually gets.
            // The size of all of IPv6 (2^128) wraps to 0, so it takes 0 &- children, exact
            // unless nothing is inside it, which saturates to UInt128.max.
            var own = routes.map { r -> UInt128 in
                let hostBits = bits - Int(r.route.prefixLength)
                return hostBits == 128 ? 0 : UInt128(1) << hostBits
            }
            var hasChildren = Array(repeating: false, count: routes.count)
            var stack: [Int] = []
            for (k, entry) in routes.enumerated() {
                while let top = stack.last, end(routes[top].route) < start(entry.route) { stack.removeLast() }
                if let parent = stack.last {
                    let hostBits = bits - Int(entry.route.prefixLength)
                    own[parent] &-= UInt128(1) << hostBits  // a child is never all of IPv6
                    hasChildren[parent] = true
                }
                stack.append(k)
            }
            for (k, entry) in routes.enumerated() {
                let count = (bits - Int(entry.route.prefixLength) == 128 && !hasChildren[k]) ? UInt128.max : own[k]
                if family == .v4 {
                    counts[entry.peer].ipv4 += count
                } else {
                    let (sum, overflow) = counts[entry.peer].ipv6.addingReportingOverflow(count)
                    counts[entry.peer].ipv6 = overflow ? .max : sum
                }
            }
        }
        return peers.indices.map { (peers[$0], counts[$0].ipv4, counts[$0].ipv6) }
    }

    /// The peers that receive most of IPv4 or IPv6 (at least half of either), the biggest first.
    /// At most one peer per family can, so this lists the real destination of internet traffic.
    public var internetPeers: [PeerConfiguration] {
        routeCounts()
            .filter { $0.ipv4 >= UInt128(1) << 31 || $0.ipv6 >= UInt128(1) << 127 }
            .map { ($0.peer, max(Double($0.ipv4) / 0x1p32, Double($0.ipv6) / 0x1p128)) }
            .sorted { $0.1 > $1.1 }
            .map(\.0)
    }
}
