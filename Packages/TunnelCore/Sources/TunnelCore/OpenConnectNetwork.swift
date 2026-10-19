import Foundation

/// The network settings an AnyConnect gateway pushes when the tunnel connects (CSTP headers,
/// as libopenconnect reports them in `struct oc_ip_info`). All of it comes from the server.
public struct OpenConnectIPInfo: Equatable, Sendable {
    public var address: String?
    /// Dotted quad ("255.255.255.0").
    public var netmask: String?
    public var address6: String?
    /// IPv6 address with prefix ("2001:db8::5/64"), as OpenConnect gives it.
    public var netmask6: String?
    public var dns: [String] = []
    /// The default domain; may hold several, separated by spaces or commas.
    public var domain: String?
    public var splitDNS: [String] = []
    public var splitIncludes: [String] = []
    public var splitExcludes: [String] = []
    public var mtu: Int = 0
    /// The gateway sent more split routes, or split-DNS entries, than `maxRoutes`; the engine
    /// kept the first ones it found.
    public var routesTruncated = false
    public var splitDNSTruncated = false

    public init() {}
}

/// What the extension applies, after validation. Plain strings, so it is testable without
/// NetworkExtension; the extension turns it into NEPacketTunnelNetworkSettings.
public struct OpenConnectNetworkPlan: Equatable, Sendable {
    public struct Route: Equatable, Sendable {
        public let address: String
        /// Dotted mask for IPv4, prefix length for IPv6.
        public let mask: String
        public let prefixLength: UInt8

        var range: IPAddressRange? { IPAddressRange("\(address)/\(prefixLength)") }
    }
    public var ipv4Address: Route?
    public var ipv6Address: Route?
    public var ipv4Included: [Route] = []
    public var ipv4Excluded: [Route] = []
    public var ipv6Included: [Route] = []
    public var ipv6Excluded: [Route] = []
    public var dnsServers: [String] = []
    public var searchDomains: [String] = []
    /// nil: the tunnel's DNS answers every query. Otherwise only these domains (split DNS).
    public var matchDomains: [String]?
    public var mtu: Int?
    /// The gateway routes all IPv4 (or IPv6) but gave no address of the other family: that
    /// family is routed into the tunnel too, so it can't leave outside it (CLAUDE.md, leak
    /// protection), with a reserved placeholder address.
    public var blockedIPv6 = false
    public var blockedIPv4 = false
    /// Gateway settings left out at the caps, each with what it means, for the Log tab
    /// (review NEW-10).
    public var dropped: [String] = []

    /// "Full" the way the WireGuard engine counts it (CLAUDE.md #10): routes covering at least
    /// half the family, so 0.0.0.0/1 + 128.0.0.0/1 counts, not only a literal /0.
    /// Excludes count against it (S5B-L3): including everything and excluding both halves
    /// carries nothing.
    /// The share of the address space that really goes into the tunnel: the included set minus
    /// the excluded set, as address ranges (not a difference of percentages; S5C-M4).
    /// IPv6 is measured like RouteCoverage measures it for WireGuard (review NEW-7): against
    /// internet IPv6 (2000::/3), so `8000::/1` (half the space, no internet address) is not
    /// full and `2000::/3` is.
    public var isFullTunnelIPv4: Bool { Self.netShare(ipv4Included, minus: ipv4Excluded, bits: 32) >= 0.5 }
    public var isFullTunnelIPv6: Bool {
        Self.netShare(ipv6Included, minus: ipv6Excluded, bits: 128, within: RouteCoverage.globalUnicast) >= 0.5
    }
    /// Most of the whole IPv6 space, NAT64's 64:ff9b::/96 and ULAs included.
    var routesMostIPv6Space: Bool { Self.netShare(ipv6Included, minus: ipv6Excluded, bits: 128) >= 0.5 }

    /// The IPv6 to route into the tunnel because IPv4 is a full tunnel: unless IPv6 is mostly
    /// routed by BOTH measures, as RouteCoverage.blocksUncoveredIPv6 decides for WireGuard.
    /// `2000::/3` alone would leave NAT64 (IPv4 sites over IPv6) outside (security-6 L2).
    /// Also for an IPv6 full tunnel that leaves NAT64 out (review NEW-10).
    var blocksUncoveredIPv6: Bool {
        (isFullTunnelIPv4 || isFullTunnelIPv6) && !(isFullTunnelIPv6 && routesMostIPv6Space
            && Self.netShare(ipv6Included, minus: ipv6Excluded, bits: 128, within: RouteCoverage.nat64Prefix) >= 1)
    }
    var blocksUncoveredIPv4: Bool { isFullTunnelIPv6 && !isFullTunnelIPv4 }

    /// The share of `within` (inclusive bounds; default the whole family) that the included
    /// routes minus the excluded ones cover.
    static func netShare(_ included: [Route], minus excluded: [Route], bits: Int, within: (UInt128, UInt128)? = nil) -> Double {
        func intervals(_ routes: [Route]) -> [(UInt128, UInt128)] {
            routes.compactMap(\.range).compactMap { r in
                let start = RouteCoverage.value(r.network.address)
                let hostBits = bits - Int(r.prefixLength)
                let span: UInt128 = hostBits >= 128 ? UInt128.max : (UInt128(1) << hostBits) - 1
                guard let within else { return (start, start + span) }
                let clipped = (max(start, within.0), min(start + span, within.1))
                return clipped.0 <= clipped.1 ? clipped : nil
            }.sorted { $0.0 < $1.0 }
        }
        // Merge the included ranges, then cut every excluded range out of them.
        var merged: [(UInt128, UInt128)] = []
        for (start, end) in intervals(included) {
            if let last = merged.last, start <= last.1 || (last.1 < UInt128.max && start == last.1 + 1) {
                merged[merged.count - 1].1 = max(last.1, end)
            } else {
                merged.append((start, end))
            }
        }
        for (cutStart, cutEnd) in intervals(excluded) {
            var next: [(UInt128, UInt128)] = []
            for (start, end) in merged {
                if cutEnd < start || cutStart > end { next.append((start, end)); continue }
                if cutStart > start { next.append((start, cutStart - 1)) }
                if cutEnd < end { next.append((cutEnd + 1, end)) }
            }
            merged = next
        }
        let total = merged.reduce(0.0) { $0 + Double($1.1 - $1.0) + 1 }
        let space = within.map { Double($0.1 - $0.0) + 1 } ?? pow(2.0, Double(bits))
        return min(1, total / space)
    }

    /// Placeholders for leak blocking, the same as the WireGuard engine's (RFC 7600 dummy IPv4,
    /// a fixed ULA).
    public static let placeholderIPv4 = "192.0.0.8"
    public static let placeholderIPv6 = "fd77:6f6d:6261:7400::1"

    public static let maxRoutes = 2048
    public static let maxDNS = 16
    public static let maxDomains = 64

    public struct Failure: Error, Equatable, Sendable, CustomStringConvertible { public let description: String }

    public static func make(_ info: OpenConnectIPInfo) throws -> OpenConnectNetworkPlan {
        var plan = OpenConnectNetworkPlan()
        if let address = info.address {
            guard let range = IPAddressRange(address), range.family == .v4, range.prefixLength == 32 else {
                throw Failure(description: "The gateway assigned an invalid IPv4 address")
            }
            let prefix = info.netmask.flatMap(prefixLength(ofMask:)) ?? 32
            plan.ipv4Address = Route(address: range.addressString, mask: maskString(prefix), prefixLength: prefix)
        }
        if let address6 = info.address6 ?? info.netmask6.map({ String($0.split(separator: "/").first ?? "") }) {
            let withPrefix = info.netmask6 ?? address6
            guard let range = IPAddressRange(withPrefix), range.family == .v6 else {
                throw Failure(description: "The gateway assigned an invalid IPv6 address")
            }
            // Below /120 has no effect on Apple's stack (WireGuardKit clamps the same way).
            let prefix = min(range.prefixLength, 120)
            plan.ipv6Address = Route(address: range.addressString, mask: "\(prefix)", prefixLength: prefix)
        }
        guard plan.ipv4Address != nil || plan.ipv6Address != nil else {
            throw Failure(description: "The gateway assigned no address to the tunnel")
        }

        var includes4: [Route] = [], includes6: [Route] = []
        for text in info.splitIncludes.prefix(maxRoutes) {
            guard let route = parseRoute(text) else { continue }
            if route.address.contains(":") { includes6.append(route) } else { includes4.append(route) }
        }
        var excludes4: [Route] = [], excludes6: [Route] = []
        for text in info.splitExcludes.prefix(maxRoutes) {
            guard let route = parseRoute(text) else { continue }
            // Excluding everything would turn the VPN off while it reports connected.
            guard route.prefixLength > 0 else { continue }
            if route.address.contains(":") { excludes6.append(route) } else { excludes4.append(route) }
        }

        // No split includes for a family: the gateway takes all of it (vpnc-script's rule).
        if plan.ipv4Address != nil {
            plan.ipv4Included = includes4.isEmpty ? [Route(address: "0.0.0.0", mask: "0.0.0.0", prefixLength: 0)] : includes4
            plan.ipv4Excluded = excludes4
        }
        if plan.ipv6Address != nil {
            plan.ipv6Included = includes6.isEmpty ? [Route(address: "::", mask: "0", prefixLength: 0)] : includes6
            plan.ipv6Excluded = excludes6
        }
        // One family full and the other not (no address, or only partial routes): the other
        // goes into the tunnel too, as the WireGuard engine does (CLAUDE.md #10, S5B-M2).
        let blocks6 = plan.blocksUncoveredIPv6, blocks4 = plan.blocksUncoveredIPv4
        if blocks6 {
            if plan.ipv6Address == nil {
                plan.blockedIPv6 = true
                plan.ipv6Address = Route(address: placeholderIPv6, mask: "128", prefixLength: 128)
            }
            // All of IPv6 goes in; the gateway's IPv6 excludes go too, on purpose: they would
            // leave exactly the uncovered IPv6 this blocks outside (fails closed).
            plan.ipv6Included = [Route(address: "::", mask: "0", prefixLength: 0)]
            plan.ipv6Excluded = []
        }
        if blocks4 {
            if plan.ipv4Address == nil {
                plan.blockedIPv4 = true
                plan.ipv4Address = Route(address: placeholderIPv4, mask: "255.255.255.255", prefixLength: 32)
            }
            plan.ipv4Included = [Route(address: "0.0.0.0", mask: "0.0.0.0", prefixLength: 0)]
            plan.ipv4Excluded = []
        }

        // Only servers of a family the tunnel really carries (a placeholder address carries
        // nothing): another family's would be reached outside the tunnel (S5B-M1).
        plan.dnsServers = Array(info.dns.filter { text in
            guard let host = IPAddressRange(text), host.prefixLength == host.maxPrefix else { return false }
            return host.family == .v4 ? (plan.ipv4Address != nil && !plan.blockedIPv4) : (plan.ipv6Address != nil && !plan.blockedIPv6)
        }.prefix(maxDNS))
        // The tunnel's DNS servers are reached through the tunnel even when the split routes
        // leave them out; otherwise every query would cross the open network in plaintext.
        for server in plan.dnsServers {
            guard let host = IPAddressRange(server) else { continue }
            // Covered means included and not excluded; an excluded server is the gateway's choice
            // (a server on the local network) and stays outside.
            func covered(_ included: [Route], _ excluded: [Route]) -> Bool {
                included.contains { $0.range?.contains(host) == true } || excluded.contains { $0.range?.contains(host) == true }
            }
            if host.family == .v4, !covered(plan.ipv4Included, plan.ipv4Excluded) {
                plan.ipv4Included.append(Route(address: host.addressString, mask: "255.255.255.255", prefixLength: 32))
            }
            if host.family == .v6, !covered(plan.ipv6Included, plan.ipv6Excluded) {
                plan.ipv6Included.append(Route(address: host.addressString, mask: "128", prefixLength: 128))
            }
        }
        let domains = (info.domain ?? "").split(whereSeparator: { $0 == " " || $0 == "," }).map(String.init)
        let validDomains = domains.compactMap(validDomain)
        plan.searchDomains = Array(validDomains.prefix(maxDomains))
        let split = info.splitDNS.flatMap { $0.split(whereSeparator: { $0 == " " || $0 == "," }).map(String.init) }.compactMap(validDomain)
        // Split DNS only means something for a split tunnel: a full tunnel's DNS answers all.
        if !split.isEmpty && !plan.isFullTunnelIPv4 && !plan.isFullTunnelIPv6 {
            plan.matchDomains = Array(split.prefix(maxDomains))
            if split.count > maxDomains || info.splitDNSTruncated {
                plan.dropped.append("split-DNS domains beyond \(maxDomains) (looked up outside the tunnel)")
            }
        }
        if validDomains.count > maxDomains { plan.dropped.append("search domains beyond \(maxDomains)") }
        // Extra includes would have carried traffic into the tunnel; extra excludes would have
        // kept it out, so dropping those only sends more through the tunnel.
        if info.routesTruncated || info.splitIncludes.count > maxRoutes {
            plan.dropped.append("routes beyond \(maxRoutes) (that traffic goes outside the tunnel unless the kill switch is on)")
        }
        if info.splitExcludes.count > maxRoutes { plan.dropped.append("excluded routes beyond \(maxRoutes) (that traffic goes through the tunnel)") }
        if info.mtu > 0 { plan.mtu = min(max(info.mtu, 576), 9000) }
        return plan
    }

    /// "10.0.0.0/255.0.0.0", "10.0.0.0/8" or "fd00::/64".
    static func parseRoute(_ text: String) -> Route? {
        let parts = text.trimmingCharacters(in: .whitespaces).split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2 else { return nil }
        let address = String(parts[0]), mask = String(parts[1])
        if address.contains(":") {
            guard let range = IPAddressRange("\(address)/\(mask)"), range.family == .v6 else { return nil }
            let network = range.network
            return Route(address: network.addressString, mask: "\(range.prefixLength)", prefixLength: range.prefixLength)
        }
        let prefix: UInt8
        if mask.contains(".") {
            guard let p = prefixLength(ofMask: mask) else { return nil }
            prefix = p
        } else {
            guard let p = UInt8(mask), p <= 32 else { return nil }
            prefix = p
        }
        guard let range = IPAddressRange("\(address)/\(prefix)"), range.family == .v4 else { return nil }
        let network = range.network
        return Route(address: network.addressString, mask: maskString(prefix), prefixLength: prefix)
    }

    /// "255.255.240.0" → 20; nil for a mask with holes.
    static func prefixLength(ofMask mask: String) -> UInt8? {
        let parts = mask.split(separator: ".", omittingEmptySubsequences: false).compactMap { UInt8($0) }
        guard parts.count == 4 else { return nil }
        let value = parts.reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
        let ones = value.leadingZeroBitCount == 0 ? (~value).leadingZeroBitCount : 0
        guard value == (ones == 0 ? 0 : UInt32.max << (32 - UInt32(ones))) else { return nil }
        return UInt8(ones)
    }

    static func maskString(_ prefix: UInt8) -> String {
        let value: UInt32 = prefix == 0 ? 0 : UInt32.max << (32 - UInt32(prefix))
        return [24, 16, 8, 0].map { String((value >> $0) & 0xFF) }.joined(separator: ".")
    }

    static func validDomain(_ raw: String) -> String? {
        let d = raw.trimmingCharacters(in: CharacterSet(charactersIn: ". ")).lowercased()
        guard !d.isEmpty, d.count <= 253,
              d.unicodeScalars.allSatisfy({ CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyz0123456789-.").contains($0) }),
              !d.split(separator: ".").contains(where: { $0.isEmpty || $0.count > 63 || $0.hasPrefix("-") || $0.hasSuffix("-") }) else { return nil }
        return d
    }
}

/// Live state of an OpenConnect tunnel, from the extension to the app (JSON, no secrets).
public struct OpenConnectStatus: Codable, Equatable, Sendable {
    public var rxBytes: UInt64 = 0
    public var txBytes: UInt64 = 0
    public var ipv4: String?
    public var ipv6: String?
    public var dnsServers: [String] = []
    public var routes: [String] = []
    public var fullTunnel = false
    public var gateway: String?
    /// "TLS" or "DTLS": which carries packets right now.
    public var transport: String?
    public var cipher: String?
    public var connectedSince: Date?

    public init() {}
}
