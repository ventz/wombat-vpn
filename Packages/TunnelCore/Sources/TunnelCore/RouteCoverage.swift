import Foundation

/// How much of the IPv4 / IPv6 address space a set of routes covers, computed on merged
/// intervals. "Full tunnel" must mean "routes (nearly) everything", not "contains a literal /0":
/// 0.0.0.0/1 + 128.0.0.0/1 routes all traffic too, and must be labeled as such.
public struct RouteCoverage: Equatable, Sendable {
    /// 0...1 of the IPv4 space.
    public let ipv4: Double
    /// 0...1 of internet IPv6: global unicast, 2000::/3. Measured against the whole IPv6 space,
    /// `8000::/1` counted as half while routing no internet address, and the common `2000::/3`
    /// as 12.5% (review SEC-5).
    public let ipv6: Double
    /// 0...1 of the whole IPv6 space, ULA, link-local and NAT64 (64:ff9b::/96) included.
    public let ipv6Space: Double
    /// 0...1 of NAT64's 64:ff9b::/96, where IPv4 sites are reached over IPv6.
    public let nat64: Double

    public init(_ ranges: [IPAddressRange]) {
        ipv4 = Self.fraction(ranges.filter { $0.family == .v4 }, bits: 32)
        ipv6 = Self.fraction(ranges.filter { $0.family == .v6 }, bits: 128, within: Self.globalUnicast)
        ipv6Space = Self.fraction(ranges.filter { $0.family == .v6 }, bits: 128)
        nat64 = Self.fraction(ranges.filter { $0.family == .v6 }, bits: 128, within: Self.nat64Prefix)
    }

    /// Whether the IPv6 the tunnel doesn't route should be blocked (routed into the tunnel, where
    /// wireguard-go drops it) because IPv4 is a full tunnel. Only when IPv6 is mostly routed by
    /// BOTH measures is it left alone: `2000::/3` covers all internet IPv6 but not NAT64's
    /// `64:ff9b::/96` (IPv4 sites reached over IPv6), which would then leave outside the tunnel
    /// (security-6 L2); `8000::/1` covers half the space and no internet address (SEC-5).
    /// NAT64 must be routed too: `0.0.0.0/0, 2000::/3, 8000::/1` passes both measures yet
    /// leaves 64:ff9b::/96 neither routed nor blocked, and so does an IPv6 full tunnel of
    /// `2000::/3` alone, whose IPv4 is blocked (review NEW-10).
    public var blocksUncoveredIPv6: Bool { isFullTunnel && !(routesMostIPv6 && ipv6Space >= 0.5 && nat64 >= 1) }
    /// The other way round: an IPv6 full tunnel blocks the IPv4 it doesn't route.
    public var blocksUncoveredIPv4: Bool { routesMostIPv6 && !routesMostIPv4 }

    /// 2000::/3 as an inclusive interval.
    static let globalUnicast: (UInt128, UInt128) = (UInt128(0x2000) << 112, (UInt128(0x4000) << 112) - 1)
    /// 64:ff9b::/96 as an inclusive interval.
    static let nat64Prefix: (UInt128, UInt128) = ((UInt128(0x64) << 112) | (UInt128(0xff9b) << 96), ((UInt128(0x64) << 112) | (UInt128(0xff9b) << 96)) + (UInt128(1) << 32) - 1)

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

    /// The covered share of `within` (inclusive bounds; default: the whole space).
    private static func fraction(_ ranges: [IPAddressRange], bits: Int, within: (UInt128, UInt128)? = nil) -> Double {
        // Intervals with inclusive ends: the IPv6 space end (2^128) doesn't fit in UInt128.
        var intervals: [(UInt128, UInt128)] = ranges.compactMap { r in
            let start = Self.value(r.network.address)
            let hostBits = bits - Int(r.prefixLength)
            let size: UInt128 = hostBits >= 128 ? UInt128.max : (UInt128(1) << UInt128(hostBits)) - 1
            guard let within else { return (start, start &+ size) }
            let clipped = (max(start, within.0), min(start &+ size, within.1))
            return clipped.0 <= clipped.1 ? clipped : nil
        }
        guard !intervals.isEmpty else { return 0 }
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
        let space = within.map { Double($0.1 - $0.0) + 1 } ?? pow(2, Double(bits))
        return min(1, covered / space)
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
    /// `internetIPv6`: count only IPv6 addresses inside 2000::/3 (security-6 L1).
    func routeCounts(internetIPv6: Bool = false) -> [(peer: PeerConfiguration, ipv4: UInt128, ipv6: UInt128)] {
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
            // Prefixes are nested or disjoint, and 2000::/3 is one too, so a block's addresses
            // inside it are all of the block, all of 2000::/3, or none.
            let window = family == .v6 && internetIPv6 ? RouteCoverage.globalUnicast : nil
            func size(_ r: IPAddressRange) -> UInt128 {
                let hostBits = bits - Int(r.prefixLength)
                guard let window else { return hostBits == 128 ? 0 : UInt128(1) << hostBits }
                if start(r) >= window.0 && end(r) <= window.1 { return UInt128(1) << hostBits }
                if start(r) <= window.0 && end(r) >= window.1 { return window.1 - window.0 + 1 }
                return 0
            }
            var own = routes.map { size($0.route) }
            var hasChildren = Array(repeating: false, count: routes.count)
            var stack: [Int] = []
            for (k, entry) in routes.enumerated() {
                while let top = stack.last, end(routes[top].route) < start(entry.route) { stack.removeLast() }
                if let parent = stack.last {
                    own[parent] &-= size(entry.route)  // a child is never all of IPv6
                    hasChildren[parent] = true
                }
                stack.append(k)
            }
            for (k, entry) in routes.enumerated() {
                let count = (window == nil && bits - Int(entry.route.prefixLength) == 128 && !hasChildren[k]) ? UInt128.max : own[k]
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

    /// Every peer that receives part of a family this config routes most of, the biggest share
    /// first. Naming only a peer with at least half let four peers splitting the default route
    /// (/2 each) hide behind an empty list (review SEC-4); a peer whose routes are all shadowed
    /// gets nothing and isn't named.
    public var internetPeers: [PeerConfiguration] {
        let coverage = self.coverage
        guard coverage.isFullTunnel else { return [] }
        var ranked: [(peer: PeerConfiguration, share: Double)] = []
        // IPv6 shares of internet IPv6 only, like the coverage: a decoy with 8000::/2 gets none
        // and can't outrank the real recipient (security-6 L1).
        for entry in routeCounts(internetIPv6: true) {
            let v4: Double = coverage.routesMostIPv4 ? Double(entry.ipv4) / 0x1p32 : 0
            let v6: Double = coverage.routesMostIPv6 ? Double(entry.ipv6) / 0x1p125 : 0
            if v4 > 0 || v6 > 0 { ranked.append((entry.peer, max(v4, v6))) }
        }
        // Stable: equal shares keep config order.
        return ranked.enumerated()
            .sorted { $0.element.share != $1.element.share ? $0.element.share > $1.element.share : $0.offset < $1.offset }
            .map(\.element.peer)
    }
}
