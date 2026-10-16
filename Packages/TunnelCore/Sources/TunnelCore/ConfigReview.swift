import Foundation

/// Security and correctness findings about a parsed tunnel, shown before import and in the editor.
public struct Finding: Equatable, Sendable, Codable {
    public enum Level: String, Sendable, Codable { case risk, warning, info }
    public let level: Level
    public let code: String
    public let message: String
}

public enum ConfigReview {
    /// Repeated findings of one kind are summarized after this many, so a hostile file with
    /// thousands of peers can't produce millions of lines (and freeze the UI rendering them).
    public static let maxPerCode = 5

    public static func review(_ c: TunnelConfiguration) -> [Finding] {
        var out: [Finding] = []
        var counts: [String: Int] = [:]
        func add(_ level: Finding.Level, _ code: String, _ message: String) {
            counts[code, default: 0] += 1
            if counts[code]! <= maxPerCode { out.append(Finding(level: level, code: code, message: message)) }
        }

        if c.interface.privateKey.isZero {
            add(.risk, "zero-private-key", "The private key is all zeros")
        }
        let ownPublic = c.interface.publicKey
        if c.peers.contains(where: { $0.publicKey == ownPublic }) {
            add(.risk, "peer-is-self", "A peer has this interface's own public key")
        }
        if c.peers.isEmpty {
            add(.warning, "no-peers", "The tunnel has no peers, so no traffic can flow")
        }
        if c.interface.addresses.isEmpty {
            add(.warning, "no-address", "The interface has no Address")
        }

        // Overlapping AllowedIPs: WireGuard sends each destination to exactly one peer, so one
        // of the overlapping entries silently loses. Sorted sweep: O(n log n).
        for family in [IPAddressRange.Family.v4, .v6] {
            let routes = c.peers.flatMap { p in p.allowedIPs.filter { $0.family == family }.map { (p.publicKey, $0.network) } }
                .sorted { RouteCoverage.value($0.1.address) < RouteCoverage.value($1.1.address) || (RouteCoverage.value($0.1.address) == RouteCoverage.value($1.1.address) && $0.1.prefixLength < $1.1.prefixLength) }
            var widest: (WireGuardKey, IPAddressRange)?
            for route in routes {
                if let w = widest, w.1.contains(route.1) || w.1.overlaps(route.1) {
                    if w.0 != route.0 {
                        add(.warning, "overlapping-allowed-ips",
                            "Peers \(w.0.abbreviated) and \(route.0.abbreviated) have overlapping AllowedIPs (\(w.1) and \(route.1))")
                    }
                    continue
                }
                widest = route
            }
        }

        let allRoutes = c.peers.flatMap(\.allowedIPs)
        let coverage = RouteCoverage(allRoutes)
        if coverage.isFullTunnel {
            let what = coverage.routesMostIPv4 && coverage.routesMostIPv6 ? "IPv4 and IPv6"
                : coverage.routesMostIPv4 ? "IPv4" : "IPv6"
            add(.info, "full-tunnel", "Routes \(RouteCoverage.describe(max(coverage.ipv4, coverage.ipv6))) of \(what) traffic through this tunnel")
            if c.interface.dnsServers.isEmpty {
                add(.risk, "dns-leak", "Routes most traffic but sets no DNS: name lookups still go to the local network's resolver")
            }
            if coverage.routesMostIPv4 != coverage.routesMostIPv6 {
                let other = coverage.routesMostIPv4 ? "IPv6" : "IPv4"
                // Wombat blocks the uncovered family while connected (blockUncoveredIPv4/6), so it
                // doesn't leak here; other WireGuard apps may leak it, and it won't work at all.
                add(.warning, "ip-family-leak",
                    "\(other) traffic is blocked while connected, because the tunnel only carries \(other == "IPv6" ? "IPv4" : "IPv6"). Add \(coverage.routesMostIPv4 ? "::/0" : "0.0.0.0/0") to AllowedIPs to route it; other WireGuard apps may send it outside the tunnel")
            }
        }

        // A DNS server no peer routes is queried outside the tunnel, for every lookup.
        for server in c.interface.dnsServers {
            guard let ip = IPAddressRange(server) else { continue }
            if !allRoutes.contains(where: { $0.contains(ip) }) {
                add(coverage.isFullTunnel ? .risk : .warning, "dns-outside-tunnel",
                    "DNS server \(server) is not inside AllowedIPs, so lookups to it leave outside the tunnel")
            }
        }

        let hostnamePeers = c.peers.filter { $0.endpoint?.isHostname == true }
        for p in hostnamePeers.prefix(maxPerCode) {
            add(.info, "endpoint-hostname", "Peer \(p.publicKey.abbreviated)'s endpoint \(p.endpoint!.hostString) is resolved outside the tunnel")
        }
        let noPSK = c.peers.filter { $0.presharedKey == nil }
        if noPSK.count == 1 {
            add(.info, "no-preshared-key", "Peer \(noPSK[0].publicKey.abbreviated) has no PresharedKey (an extra layer against future quantum attacks)")
        } else if noPSK.count > 1 {
            add(.info, "no-preshared-key", "\(noPSK.count) peers have no PresharedKey (an extra layer against future quantum attacks)")
        }
        for p in c.peers where p.allowedIPs.isEmpty {
            add(.warning, "no-allowed-ips", "Peer \(p.publicKey.abbreviated) has no AllowedIPs, so no traffic is routed to it")
        }
        if c.isAmnezia, let amnezia = c.interface.amnezia {
            add(.info, "amneziawg", "Speaks AmneziaWG, so it only connects to an AmneziaWG server")
            let signatures = amnezia.signaturePackets.compactMap { $0 }.count
            if signatures > 0 {
                // The file decides these bytes, and they go to whatever endpoint it names, LAN
                // devices included (audit S4-L4).
                add(.warning, "amneziawg-signature-packets",
                    "Sends \(signatures) packet\(signatures == 1 ? "" : "s") of bytes chosen by this file (I1-I5) to the endpoint before each handshake")
            }
            // A cookie reply larger than the initiation that triggers it lets anyone who knows
            // this tunnel's public key bounce more traffic at a spoofed address while the
            // tunnel is under load (audit S4 M2). A warning: real servers may need it.
            // Either handshake message can trigger a cookie reply (S4b M1), and an initiation
            // triggers a response (S4c L2). The engine caps replies larger than their
            // trigger at 20 a second (amneziawg-go patch 9); this tells the user why.
            let s = amnezia.paddings.map { Int($0 ?? 0) }
            let initiation = s[0] + 148, response = s[1] + 92, cookie = s[2] + 64
            if cookie > min(initiation, response) || response > initiation {
                add(.warning, "amneziawg-amplification",
                    "S1-S3 make some replies larger than their trigger, a possible traffic amplifier (capped at 20/s); keep S2 ≤ S1 + 56 and S3 ≤ S2 + 28")
            }
        }
        for item in c.interface.ignored where ["preup", "postup", "predown", "postdown"].contains(item.key.lowercased()) {
            add(.risk, "script-hook", "\(item.key) asks to run a shell command; it is ignored")
        }

        for (code, count) in counts where count > maxPerCode {
            let level = out.first { $0.code == code }?.level ?? .warning
            out.append(Finding(level: level, code: code, message: "…and \(count - maxPerCode) more like this"))
        }
        // Risks first, so a long list never pushes them out of view.
        let order: [Finding.Level: Int] = [.risk: 0, .warning: 1, .info: 2]
        return out.enumerated().sorted { (order[$0.element.level]!, $0.offset) < (order[$1.element.level]!, $1.offset) }.map(\.element)
    }
}
