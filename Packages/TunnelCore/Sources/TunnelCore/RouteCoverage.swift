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
