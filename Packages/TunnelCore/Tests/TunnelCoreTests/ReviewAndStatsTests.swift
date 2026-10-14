import Foundation
import Testing
@testable import TunnelCore

private func config(_ body: String) throws -> TunnelConfiguration {
    let r = WgQuick.parse("[Interface]\nPrivateKey = \(privA)\nAddress = 10.0.0.2/32\n" + body)
    return try #require(r.configuration, "\(r.diagnostics)")
}

private func codes(_ c: TunnelConfiguration) -> Set<String> { Set(ConfigReview.review(c).map(\.code)) }

@Suite struct ConfigReviewTests {
    @Test func fullTunnelWithoutDNSIsALeak() throws {
        let c = try config("[Peer]\nPublicKey = \(pubB)\nAllowedIPs = 0.0.0.0/0, ::/0")
        #expect(codes(c).isSuperset(of: ["full-tunnel", "dns-leak"]))
        #expect(!codes(c).contains("ip-family-leak"))
    }

    @Test func ipv4OnlyFullTunnelLeaksIPv6() throws {
        let c = try config("DNS = 1.1.1.1\n[Peer]\nPublicKey = \(pubB)\nAllowedIPs = 0.0.0.0/0")
        #expect(codes(c).contains("ip-family-leak"))
        #expect(!codes(c).contains("dns-leak"))
    }

    @Test func splitTunnelIsQuiet() throws {
        let c = try config("[Peer]\nPublicKey = \(pubB)\nPresharedKey = \(psk)\nAllowedIPs = 10.0.0.0/24\nEndpoint = 1.2.3.4:51820")
        #expect(codes(c).isEmpty)
    }

    @Test func peerWithOwnKey() throws {
        let c = try config("[Peer]\nPublicKey = \(pubA)\nAllowedIPs = 10.1.0.0/24")
        #expect(codes(c).contains("peer-is-self"))
    }

    // WireGuardKit calls fatalError on duplicate peers, which would take down the extension.
    @Test func duplicatePeersAreAParseError() {
        let r = WgQuick.parse("[Interface]\nPrivateKey = \(privA)\n[Peer]\nPublicKey = \(pubB)\n[Peer]\nPublicKey = \(pubB)")
        #expect(r.configuration == nil)
        #expect(r.errors.contains { $0.line == 6 })
    }

    @Test func byteOrderMarkIsAccepted() {
        #expect(WgQuick.parse("\u{FEFF}[Interface]\nPrivateKey = \(privA)").configuration != nil)
    }

    @Test func lowMTUWithIPv6Warns() {
        let r = WgQuick.parse("[Interface]\nPrivateKey = \(privA)\nAddress = fd00::2/128\nMTU = 1200")
        #expect(r.warnings.contains { $0.message.contains("1280") })
    }

    @Test func overlappingAllowedIPs() throws {
        let c = try config("[Peer]\nPublicKey = \(pubA)\nAllowedIPs = 10.0.0.0/8\n[Peer]\nPublicKey = \(pubB)\nAllowedIPs = 10.5.0.0/16")
        #expect(codes(c).contains("overlapping-allowed-ips"))
    }

    @Test func scriptHooksAreRisks() throws {
        let c = try config("PostUp = iptables -A FORWARD\n[Peer]\nPublicKey = \(pubB)\nAllowedIPs = 10.0.0.0/24")
        #expect(ConfigReview.review(c).contains { $0.code == "script-hook" && $0.level == .risk })
    }

    @Test func hostnameEndpointIsNoted() throws {
        let c = try config("[Peer]\nPublicKey = \(pubB)\nAllowedIPs = 10.0.0.0/24\nEndpoint = vpn.example.com:51820")
        #expect(codes(c).contains("endpoint-hostname"))
    }
}

@Suite struct RuntimeStatsTests {
    @Test func parsesPeersAndSkipsSecrets() throws {
        let pubHex = try #require(WireGuardKey(base64: pubB)).hex
        let text = """
        private_key=e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a
        listen_port=51820
        public_key=\(pubHex)
        preshared_key=0000000000000000000000000000000000000000000000000000000000000000
        endpoint=192.0.2.1:51820
        last_handshake_time_sec=1700000000
        last_handshake_time_nsec=500000000
        tx_bytes=1000
        rx_bytes=2000
        persistent_keepalive_interval=25
        allowed_ip=0.0.0.0/0
        allowed_ip=::/0
        public_key=\(pubHex.replacingOccurrences(of: "c", with: "d"))
        rx_bytes=5
        persistent_keepalive_interval=0
        errno=0
        """
        let s = RuntimeStats.parse(uapi: text)
        #expect(s.listenPort == 51820)
        #expect(s.peers.count == 2)
        #expect(s.peers[0].publicKey == pubB)
        #expect(s.peers[0].endpoint == "192.0.2.1:51820")
        #expect(s.peers[0].lastHandshake == Date(timeIntervalSince1970: 1_700_000_000.5))
        #expect(s.peers[0].allowedIPs == ["0.0.0.0/0", "::/0"])
        #expect(s.peers[0].persistentKeepalive == 25)
        #expect(s.peers[1].lastHandshake == nil)
        #expect(s.peers[1].persistentKeepalive == nil)
        #expect(s.rxBytes == 2005 && s.txBytes == 1000)
        let encoded = String(decoding: try Control.encode(s), as: UTF8.self)
        #expect(!encoded.contains("e84b5a6d"))
    }

    @Test(arguments: [(0.5, "Now"), (42, "42 s ago"), (180, "3 min ago"), (7200, "2 h ago"), (172_800, "2 d ago")])
    func handshakeAge(seconds: Double, expected: String) {
        let now = Date()
        #expect(Format.handshakeAge(now.addingTimeInterval(-seconds), now: now) == expected)
    }

    @Test func staleAfterThreeMinutes() {
        let now = Date()
        #expect(!Format.isHandshakeStale(now.addingTimeInterval(-179), now: now))
        #expect(Format.isHandshakeStale(now.addingTimeInterval(-181), now: now))
        #expect(Format.isHandshakeStale(nil))
    }
}

@Suite struct NameTests {
    @Test func fromFileName() {
        #expect(TunnelName.from(fileName: "home.conf") == "home")
        #expect(TunnelName.from(fileName: "My\u{202E}VPN\n.CONF") == "MyVPN")
        #expect(TunnelName.from(fileName: ".conf") == "Tunnel")
        #expect(TunnelName.from(fileName: String(repeating: "x", count: 200) + ".conf").count == TunnelName.maxLength)
    }

    @Test func unique() {
        #expect(TunnelName.unique("Home", existing: ["home", "Home 2"]) == "Home 3")
        #expect(TunnelName.unique("Work", existing: ["home"]) == "Work")
    }
}

@Suite struct ControlTests {
    @Test func requestRoundTrip() throws {
        let r = Control.Request(.import, name: "x", config: "[Interface]")
        #expect(try Control.decode(Control.Request.self, from: Control.encode(r)) == r)
    }
}

@Suite struct AuditRegressionTests {
    // M-2: halves of the address space are a full tunnel too.
    @Test func splitDefaultRouteIsFullTunnel() throws {
        let c = try config("[Peer]\nPublicKey = \(pubB)\nAllowedIPs = 0.0.0.0/1, 128.0.0.0/1")
        #expect(c.isFullTunnel)
        #expect(c.coverage.ipv4 == 1)
        #expect(codes(c).isSuperset(of: ["full-tunnel", "dns-leak", "ip-family-leak"]))
    }

    @Test func coverageOfCommonShapes() throws {
        #expect(RouteCoverage([IPAddressRange("10.0.0.0/8")!]).ipv4 == 1.0 / 256)
        #expect(RouteCoverage([IPAddressRange("0.0.0.0/0")!, IPAddressRange("10.0.0.0/8")!]).ipv4 == 1)
        #expect(RouteCoverage([IPAddressRange("::/0")!]).ipv6 == 1)
        #expect(RouteCoverage([IPAddressRange("10.0.0.0/8")!, IPAddressRange("11.0.0.0/8")!]).ipv4 == 2.0 / 256)
        #expect(!RouteCoverage([IPAddressRange("10.0.0.0/8")!]).isFullTunnel)
        #expect(RouteCoverage.describe(1) == "all")
    }

    // M-4: thousands of overlapping peers must stay fast and bounded.
    @Test func hostileOverlapIsBoundedAndFast() throws {
        var body = "DNS = 1.1.1.1\n"
        for _ in 0..<2000 {
            body += "[Peer]\nPublicKey = \(KeyPair.publicKey(for: KeyPair.generatePrivateKey()).base64)\nAllowedIPs = 0.0.0.0/0\n"
        }
        let c = try config(body)
        let start = Date()
        let findings = ConfigReview.review(c)
        #expect(Date().timeIntervalSince(start) < 1)
        #expect(findings.count < 30)
        #expect(findings.contains { $0.message.hasPrefix("…and") })
    }

    @Test func risksComeFirst() throws {
        let c = try config("PostUp = x\n[Peer]\nPublicKey = \(pubB)\nAllowedIPs = 0.0.0.0/0")
        #expect(ConfigReview.review(c).first?.level == .risk)
    }

    // L-5
    @Test func dnsOutsideTunnel() throws {
        let c = try config("DNS = 192.168.1.1\n[Peer]\nPublicKey = \(pubB)\nAllowedIPs = 10.0.0.0/24")
        #expect(codes(c).contains("dns-outside-tunnel"))
        let inside = try config("DNS = 10.0.0.53\n[Peer]\nPublicKey = \(pubB)\nAllowedIPs = 10.0.0.0/24")
        #expect(!codes(inside).contains("dns-outside-tunnel"))
    }

    // L-6
    @Test(arguments: ["2130706433:51820", "10.1:51820", "host.123:1"])
    func numericHostnamesRejected(text: String) { #expect(Endpoint(text) == nil) }

    @Test func multiByteHexDoesNotCrash() {
        #expect(WireGuardKey(hex: String(repeating: "é", count: 32)) == nil)
    }

    @Test func bidiOverrideIsRejected() {
        #expect(WgQuick.parse("[Interface]\nPrivateKey = \(privA)\nAddress = 10.0.0.1/32\u{202E}").configuration == nil)
    }
}

@Suite struct AuditRound2Tests {
    // WOM-16: numeric forms inet_aton accepts are not hostnames.
    @Test func hexAndOctalEndpointsAreNotHostnames() {
        for host in ["0x7f000001", "127.0.0.0x1", "0177.1", "10.1", "2130706433"] {
            #expect(Endpoint("\(host):51820") == nil, "\(host) must be rejected")
        }
        #expect(Endpoint("vpn.example.com:51820") != nil)
        #expect(Endpoint("0xdeadbeef.example.com:51820") != nil)  // a real name with a hex-looking label
    }

    // C1 control characters (U+0080-U+009F) are rejected like C0 ones.
    @Test func c1ControlCharactersAreRejected() {
        let text = "[Interface]\nPrivateKey = \(privA)\nAddress = 10.0.0.2/32\u{90}\n"
        #expect(WgQuick.parse(text).configuration == nil)
    }

    // WOM-10: the DNS list is bounded, so the server-vs-route review stays cheap.
    @Test func dnsEntriesAreCapped() {
        let servers = (0..<(WgQuick.maxDNSEntries + 5)).map { "10.0.\($0 / 250).\($0 % 250 + 1)" }.joined(separator: ", ")
        let result = WgQuick.parse("[Interface]\nPrivateKey = \(privA)\nDNS = \(servers)\n")
        #expect(result.configuration == nil)
    }

    // The uncovered address family is blocked, not leaked: the review must not say it leaks.
    @Test func ipFamilyMessageSaysBlocked() throws {
        let c = try config("[Peer]\nPublicKey = \(pubB)\nAllowedIPs = 0.0.0.0/0")
        let message = ConfigReview.review(c).first { $0.code == "ip-family-leak" }?.message ?? ""
        #expect(message.contains("blocked"))
        #expect(!message.contains("reveal your real address"))
    }
}
