import Foundation
import Testing
@testable import TunnelCore

/// The shape of a real AmneziaWG 2.0 export (S1-S4, H ranges, no I-packets). The keys are the
/// wg(8) examples and the endpoint is made up.
let awg2 = """
[Interface]
PrivateKey = \(privA)
Jc = 4
Jmin = 8
Jmax = 80
S1 = 97
S2 = 24
S3 = 136
S4 = 8
H1 = 52817304-98112577
H2 = 203946611-260118845
H3 = 811402277-1390655104
H4 = 1602337918-1849120473
Address = 10.190.136.153/32
DNS = 1.1.1.1
MTU = 1380

[Peer]
PublicKey = \(pubB)
AllowedIPs = 192.168.0.0/24, 10.190.136.0/24
Endpoint = vpn.example.com:37777
"""

private func interface(_ lines: String) -> String {
    "[Interface]\nPrivateKey = \(privA)\nAddress = 10.0.0.2/32\n\(lines)\n\n[Peer]\nPublicKey = \(pubB)\nAllowedIPs = 10.0.0.0/24\n"
}

private func errors(_ lines: String) -> [String] {
    WgQuick.parse(interface(lines)).errors.map(\.message)
}

@Suite struct AmneziaTests {
    @Test func parsesAmneziaWG2Export() throws {
        let result = WgQuick.parse(awg2)
        #expect(result.errors.isEmpty, "\(result.errors)")
        let c = try #require(result.configuration)
        #expect(c.isAmnezia)
        let a = try #require(c.interface.amnezia)
        #expect(a.junkCount == 4 && a.junkMin == 8 && a.junkMax == 80)
        #expect(a.paddings == [97, 24, 136, 8])
        #expect(a.headers.map { $0?.description } == ["52817304-98112577", "203946611-260118845", "811402277-1390655104", "1602337918-1849120473"])
        #expect(a.signaturePackets == [nil, nil, nil, nil, nil])
    }

    @Test func uapiCarriesEverySetting() throws {
        let a = try #require(WgQuick.parse(awg2).configuration?.interface.amnezia)
        let text = a.uapiPairs.map { "\($0.key)=\($0.value)" }.joined(separator: "\n")
        #expect(text == """
        jc=4
        jmin=8
        jmax=80
        s1=97
        s2=24
        s3=136
        s4=8
        h1=52817304-98112577
        h2=203946611-260118845
        h3=811402277-1390655104
        h4=1602337918-1849120473
        """)
    }

    @Test func roundTrips() throws {
        let c = try #require(WgQuick.parse(awg2).configuration)
        let text = WgQuick.serialize(c)
        #expect(text.contains("Jc = 4\nJmin = 8\nJmax = 80\nS1 = 97"))
        #expect(text.contains("H4 = 1602337918-1849120473\n"))
        let again = try #require(WgQuick.parse(text).configuration)
        #expect(again == c)
    }

    @Test func plainWireGuardIsUntouched() throws {
        let c = try #require(WgQuick.parse(sample).configuration)
        #expect(c.interface.amnezia == nil)
        #expect(!c.isAmnezia)
        #expect(!WgQuick.serialize(c).contains("Jc"))
    }

    @Test func allDefaultSettingsArePlainWireGuard() throws {
        let c = try #require(WgQuick.parse(interface("Jc = 0\nS1 = 0\nS2 = 0\nH1 = 1\nH2 = 2\nH3 = 3\nH4 = 4")).configuration)
        #expect(c.interface.amnezia != nil)
        #expect(!c.isAmnezia)
    }

    @Test func eachSettingAloneActivates() throws {
        for line in ["Jc = 3\nJmin = 10\nJmax = 50", "S1 = 1", "S4 = 32", "H1 = 5", "I1 = <r 10>"] {
            let c = try #require(WgQuick.parse(interface(line)).configuration, "\(line)")
            #expect(c.isAmnezia, "\(line)")
        }
    }

    @Test func keysAreCaseInsensitive() throws {
        let c = try #require(WgQuick.parse(interface("jc = 2\nJMIN = 10\njMax = 20")).configuration)
        #expect(c.interface.amnezia?.junkCount == 2)
    }

    @Test func rejectsBadNumbers() {
        #expect(errors("Jc = 129\nJmin = 1\nJmax = 2").contains { $0.contains("Jc must be a number from 0 to 128") })
        #expect(errors("Jc = -1").contains { $0.contains("Jc must be") })
        #expect(errors("Jc = ４").contains { $0.contains("Jc must be") })  // fullwidth digit
        #expect(errors("Jmax = 1501").contains { $0.contains("Jmax must be a number from 0 to 1500") })
        #expect(errors("S1 = 1133").contains { $0.contains("S1 must be a number from 0 to 1132") })
        #expect(errors("S2 = 1189").contains { $0.contains("S2 must be") })
        #expect(errors("S3 = 1217").contains { $0.contains("S3 must be") })
        #expect(errors("S4 = 33").contains { $0.contains("S4 must be a number from 0 to 32") })
        #expect(errors("S1 = 99999999999999999999").contains { $0.contains("S1 must be") })
    }

    @Test func rejectsInconsistentJunk() {
        #expect(errors("Jc = 4\nJmin = 80\nJmax = 8").contains { $0 == "Jmax is smaller than Jmin" })
        #expect(errors("Jc = 4").contains { $0.contains("Jmin and Jmax must give their size") })
        #expect(errors("Jc = 4\nJmin = 0\nJmax = 0").contains { $0.contains("Jmin and Jmax") })
        #expect(errors("Jc = 0\nJmin = 0\nJmax = 0").isEmpty)
    }

    @Test func warnsWhenJunkMayFragment() {
        let result = WgQuick.parse(interface("MTU = 1280\nJc = 2\nJmin = 10\nJmax = 1300"))
        #expect(result.errors.isEmpty)
        #expect(result.warnings.contains { $0.message.contains("may be fragmented") })
    }

    @Test func rejectsBadHeaders() {
        #expect(errors("H1 = abc").contains { $0.contains("H1 must be a number or a range") })
        #expect(errors("H1 = 200-100").contains { $0.contains("H1 must be") })
        #expect(errors("H1 = 1-2-3").contains { $0.contains("H1 must be") })
        #expect(errors("H1 = -5").contains { $0.contains("H1 must be") })
        #expect(errors("H1 = 4294967296").contains { $0.contains("H1 must be") })
        #expect(errors("H1 = 4294967295").isEmpty)
    }

    @Test func rejectsOverlappingHeaders() {
        #expect(errors("H1 = 100-200\nH2 = 150-300\nH3 = 400\nH4 = 500").contains { $0.contains("H1 and H2 overlap") })
        #expect(errors("H1 = 100\nH2 = 100\nH3 = 400\nH4 = 500").contains { $0.contains("H1 and H2 overlap") })
        // An unset H keeps WireGuard's value, which a set one must not reuse.
        #expect(errors("H1 = 2").contains { $0.contains("H1 and H2 (unset, so 2) overlap") })
        #expect(errors("H1 = 1-10").contains { $0.contains("overlap") })
        #expect(errors("H1 = 5\nH2 = 6\nH3 = 7\nH4 = 8").isEmpty)
    }

    @Test func parsesSignaturePackets() throws {
        let c = try #require(WgQuick.parse(interface("I1 = <b 0xc0ffee><t><r 16>\nI2 = <rc 8> <rd 4>\nI3 =")).configuration)
        let a = try #require(c.interface.amnezia)
        #expect(a.signaturePackets[0] == "<b 0xc0ffee><t><r 16>")
        #expect(a.signaturePackets[1] == "<rc 8> <rd 4>")
        #expect(a.signaturePackets[2] == nil)  // empty means no packet
        #expect(SignaturePacket.length(of: "<b 0xc0ffee><t><r 16>") == .success(3 + 4 + 16))
    }

    @Test func rejectsBadSignaturePackets() {
        #expect(errors("I1 = <b 0xabc>").contains { $0.contains("even number of hex digits") })
        #expect(errors("I1 = <b 0x>").contains { $0.contains("even number") })
        #expect(errors("I1 = <b 0xＡＢ>").contains { $0.contains("only ASCII") })  // fullwidth
        #expect(errors("I1 = <r>").contains { $0.contains("<r> needs a length") })
        #expect(errors("I1 = <r -1>").contains { $0.contains("<r> needs a length") })
        #expect(errors("I1 = <rc 123456>").contains { $0.contains("<rc> needs a length") })
        #expect(errors("I1 = <t 5>").contains { $0.contains("<t> takes no value") })
        #expect(errors("I1 = <d>").contains { $0.contains("not one of the supported tags") })
        #expect(errors("I1 = <r 4097>").contains { $0.contains("I1 is longer than 4096 bytes") })
        #expect(errors("I1 = <r 4000><r 4000>").contains { $0.contains("longer than 4096 bytes") })
        #expect(errors("I1 = hello <r 4>").contains { $0.contains("text outside a <tag>") })
        #expect(errors("I1 = <r 4").contains { $0.contains("missing its closing >") })
        #expect(errors("I1 = <>").contains { $0.contains("malformed") })
        #expect(errors("I1 = <r 4 5>").contains { $0.contains("malformed") })
    }

    @Test func refusesUnsupportedAmneziaKeys() {
        for key in ["HeaderProtectionKey", "RejectAfterTime", "RekeyAfterTime", "J1", "Itime", "DisableCookies"] {
            #expect(errors("\(key) = 1").contains { $0.contains("\(key) is an AmneziaWG setting this app doesn't support yet") }, "\(key)")
        }
        let device = WgQuick.parse("[Device]\nHeaderProtectionKey = x\n" + interface(""))
        #expect(device.errors.contains { $0.message.contains("[Device] is an AmneziaWG 3 section") })
    }

    @Test func rejectsDuplicates() {
        #expect(errors("Jc = 1\nJc = 2\nJmin = 1\nJmax = 2").contains { $0.contains("Duplicate key") })
    }

    @Test func amneziaKeysOnlyInInterface() {
        let text = "[Interface]\nPrivateKey = \(privA)\n\n[Peer]\nPublicKey = \(pubB)\nJc = 4\n"
        #expect(WgQuick.parse(text).errors.contains { $0.message.contains("Unknown key \"Jc\" in [Peer]") })
    }

    /// Every value that reaches the UAPI is one line: no "\n" can be smuggled into a device key.
    @Test func uapiValuesAreSingleLine() throws {
        let a = try #require(WgQuick.parse(interface("I1 = <b 0x00><r 4>\nH1 = 5-9\nS1 = 3")).configuration?.interface.amnezia)
        for (key, value) in a.uapiPairs {
            let keyIsClean = !key.contains { $0.isNewline } && !key.contains("=")
            let valueIsClean = !value.contains { $0.isNewline }
            #expect(keyIsClean && valueIsClean)
        }
    }
}

@Suite struct AmneziaAuditFixTests {
    @Test func jminWithoutJmaxIsRefused() {
        #expect(errors4("Jmin = 50").contains { $0.contains("Jmin is set but Jmax isn't") })
        #expect(errors4("Jmin = 0").isEmpty)
    }

    @Test func emptyPacketHasItsOwnMessage() {
        #expect(errors4("I1 = <r 0>").contains { $0.contains("the packet would be empty") })
        #expect(errors4("I1 = <r 0><r 1>").isEmpty)
    }

    @Test func longSpecsAreRefused() {
        let padded = "<r 4>" + String(repeating: " ", count: 10_000)
        #expect(errors4("I1 = \(padded)x").contains { $0.contains("longer than 10000 bytes") })
        // Few characters, many bytes: whitespace with combining marks is one grapheme each.
        let dense = "<r 4>" + String(repeating: " \u{0301}\u{0301}\u{0301}", count: 2_000)
        #expect(errors4("I1 = \(dense)").contains { $0.contains("longer than 10000 bytes") })
    }

    @Test func warnsWhenInitiationAndResponseMatch() {
        let result = WgQuick.parse(iface4("S1 = 10\nS2 = 66"))
        #expect(result.errors.isEmpty)
        #expect(result.warnings.contains { $0.message.contains("same size") })
    }

    @Test func reviewFlagsSignaturePackets() throws {
        let c = try #require(WgQuick.parse(iface4("I1 = <b 0x00>\nI2 = <r 4>")).configuration)
        let findings = ConfigReview.review(c)
        #expect(findings.contains { $0.code == "amneziawg" && $0.level == .info })
        #expect(findings.contains { $0.code == "amneziawg-signature-packets" && $0.level == .warning && $0.message.contains("Sends 2 packets") })
        let plain = try #require(WgQuick.parse(sample).configuration)
        #expect(!ConfigReview.review(plain).contains { $0.code.hasPrefix("amneziawg") })
    }
}

private func iface4(_ lines: String) -> String {
    "[Interface]\nPrivateKey = \(privA)\nAddress = 10.0.0.2/32\n\(lines)\n\n[Peer]\nPublicKey = \(pubB)\nAllowedIPs = 10.0.0.0/24\n"
}

private func errors4(_ lines: String) -> [String] {
    WgQuick.parse(iface4(lines)).errors.map(\.message)
}

@Suite struct AmneziaRound2Tests {
    private func config(peers: Int, _ lines: String) -> String {
        var text = "[Interface]\nPrivateKey = \(privA)\nAddress = 10.0.0.2/32\n\(lines)\n"
        for i in 0..<peers {
            // Vary middle bytes: X25519 clamping clears bits of the first and last ones.
            let seed = [UInt8](repeating: 7, count: 10) + [UInt8(i % 256), UInt8(i / 256)] + [UInt8](repeating: 7, count: 20)
            let key = KeyPair.publicKey(for: WireGuardKey(rawValue: Data(seed))!)
            text += "\n[Peer]\nPublicKey = \(key.base64)\nAllowedIPs = 10.\(i / 250).\(i % 250).0/24\n"
        }
        return text
    }

    @Test func burstIsLimitedAcrossPeers() {
        let heavy = "Jc = 128\nJmin = 1000\nJmax = 1500"
        #expect(WgQuick.parse(config(peers: 1, heavy)).errors.isEmpty)
        #expect(WgQuick.parse(config(peers: 6, heavy)).errors.contains { $0.message.contains("Junk and signature packets for 6 peers") })
        // Many peers with light settings: the packet count is the limit.
        #expect(WgQuick.parse(config(peers: 300, "Jc = 4\nJmin = 8\nJmax = 16")).errors.contains { $0.message.contains("1024 packets") })
        #expect(WgQuick.parse(config(peers: 200, "Jc = 4\nJmin = 8\nJmax = 16")).errors.isEmpty)
    }

    @Test func messagesNeverQuoteValues() {
        let text = config(peers: 1, "Jc = 4\nJmin = 777\nJmax = 555\nMTU = 1280\nI1 = <r 4321>\nS1 = 1999")
        let messages = WgQuick.parse(text).diagnostics.map(\.message)
        #expect(!messages.isEmpty)
        for spec in ["<secretword 8>", "<cafe>"] {
            let tag = WgQuick.parse(config(peers: 1, "I1 = \(spec)")).errors.map(\.message)
            #expect(tag.contains { $0.contains("not one of the supported tags") }, "\(spec)")
            #expect(!tag.contains { $0.contains("secretword") || $0.contains("cafe") }, "\(spec)")
        }
        for value in ["777", "555", "4321", "1999"] {
            #expect(!messages.contains { $0.contains(value) }, "\(value)")
        }
    }

    @Test func warnsAboutCookieAmplification() throws {
        let risky = try #require(WgQuick.parse(config(peers: 1, "S1 = 0\nS3 = 200")).configuration)
        #expect(ConfigReview.review(risky).contains { $0.code == "amneziawg-amplification" })
        // A real 2.0 shape (values changed): S2 24, S3 136, so a 116-byte response-shaped packet
        // gets a 200-byte cookie reply.
        let user = try #require(WgQuick.parse(awg2).configuration)
        #expect(ConfigReview.review(user).contains { $0.code == "amneziawg-amplification" })
        let response = try #require(WgQuick.parse(config(peers: 1, "S1 = 0\nS2 = 1188")).configuration)
        #expect(ConfigReview.review(response).contains { $0.code == "amneziawg-amplification" })
        let safe = try #require(WgQuick.parse(config(peers: 1, "S1 = 100\nS2 = 50\nS3 = 70")).configuration)
        #expect(!ConfigReview.review(safe).contains { $0.code == "amneziawg-amplification" })
    }
}

@Suite struct AmneziaRound3Tests {
    @Test func signatureSpecsAreASCII() {
        #expect(errors4("I1 = <r \u{0301} 16>").contains { $0.contains("only ASCII characters") })
        #expect(errors4("I1 = <r\u{00A0}16>").contains { $0.contains("only ASCII characters") })
        #expect(errors4("I1 = <r 16>\t<t>").isEmpty)
    }

    @Test func equalSizeWarningCountsOmittedS1() {
        #expect(WgQuick.parse(iface4("S2 = 56")).warnings.contains { $0.message.contains("same size") })
        #expect(!WgQuick.parse(iface4("S2 = 57")).warnings.contains { $0.message.contains("same size") })
    }
}

@Suite struct InternetPeersTests {
    private func peer(_ n: UInt8, _ routes: String) -> String {
        let seed = [UInt8](repeating: 9, count: 10) + [n] + [UInt8](repeating: 9, count: 21)
        let key = KeyPair.publicKey(for: WireGuardKey(rawValue: Data(seed))!)
        return "\n[Peer]\nPublicKey = \(key.base64)\nAllowedIPs = \(routes)\nEndpoint = peer\(n).example:51820\n"
    }

    /// The real recipient listed first with /1 routes beats six later /0 decoys (S4d L1).
    @Test func longestPrefixWinsOverOrder() throws {
        var text = "[Interface]\nPrivateKey = \(privA)\n" + peer(1, "0.0.0.0/1, 128.0.0.0/1, ::/1, 8000::/1")
        for n in 2...7 { text += peer(UInt8(n), "0.0.0.0/0, ::/0") }
        let c = try #require(WgQuick.parse(text).configuration)
        #expect(c.internetPeers.map { $0.endpoint!.hostString } == ["peer1.example"])
    }

    /// A winner in the middle of many /0 decoys still comes first (S4d L1).
    @Test func middlePeerWinsAmongDecoys() throws {
        var text = "[Interface]\nPrivateKey = \(privA)\n"
        for n in 1...13 {
            text += peer(UInt8(n), n == 7 ? "0.0.0.0/1, 128.0.0.0/1, ::/1, 8000::/1" : "0.0.0.0/0, ::/0")
        }
        let c = try #require(WgQuick.parse(text).configuration)
        #expect(c.internetPeers.first?.endpoint?.hostString == "peer7.example")
    }

    /// Equal prefixes: the peer listed last wins, as in WireGuard.
    @Test func lastPeerWinsATie() throws {
        let text = "[Interface]\nPrivateKey = \(privA)\n" + peer(1, "0.0.0.0/0") + peer(2, "0.0.0.0/0")
        let c = try #require(WgQuick.parse(text).configuration)
        #expect(c.internetPeers.map { $0.endpoint!.hostString } == ["peer2.example"])
    }

    /// A decoy holding exactly the addresses a sampler would test can't hide the last /0 peer,
    /// which really gets the internet (S4e L1).
    @Test func hostRouteDecoyDoesNotHideTheRealPeer() throws {
        let hosts = "1.1.1.1/32, 8.8.8.8/32, 142.250.80.46/32, 208.67.222.222/32, 2606:4700:4700::1111/128, 2001:4860:4860::8888/128, 8000::1/128, fd00::1/128"
        var text = "[Interface]\nPrivateKey = \(privA)\n" + peer(1, hosts)
        for n in 2...8 { text += peer(UInt8(n), "0.0.0.0/0, ::/0") }
        let c = try #require(WgQuick.parse(text).configuration)
        // The decoy is named too (it does get those addresses), after the real recipient.
        #expect(c.internetPeers.map { $0.endpoint!.hostString } == ["peer8.example", "peer1.example"])
    }

    /// Four peers splitting the default route into /2s are all named (review SEC-4).
    @Test func splitDefaultRouteNamesEveryPeer() throws {
        var text = "[Interface]\nPrivateKey = \(privA)\n"
        for (n, route) in ["0.0.0.0/2", "64.0.0.0/2", "128.0.0.0/2", "192.0.0.0/2"].enumerated() { text += peer(UInt8(n + 1), route) }
        let c = try #require(WgQuick.parse(text).configuration)
        #expect(c.internetPeers.count == 4)
    }

    /// Small decoys listed first come after the peer that gets most traffic (SEC-4).
    @Test func biggestShareComesFirst() throws {
        var text = "[Interface]\nPrivateKey = \(privA)\n"
        for n in 1...6 { text += peer(UInt8(n), "10.\(n).0.0/16") }
        text += peer(7, "0.0.0.0/0")
        let c = try #require(WgQuick.parse(text).configuration)
        #expect(c.internetPeers.first?.endpoint?.hostString == "peer7.example")
        #expect(c.internetPeers.count == 7)
    }

    /// IPv6 decoys outside 2000::/3 can't outrank the real internet recipient (security-6 L1).
    @Test func ipv6DecoysOutsideInternetDontRankFirst() throws {
        var text = "[Interface]\nPrivateKey = \(privA)\n"
        for n in 1...6 { text += peer(UInt8(n), "8000::/\(n + 1)") }
        text += peer(7, "2000::/3")
        let c = try #require(WgQuick.parse(text).configuration)
        #expect(c.internetPeers.map { $0.endpoint!.hostString } == ["peer7.example"])
    }

    /// 0.0.0.0/0 + 2000::/3 still blocks the rest of IPv6 (NAT64), ::/0 doesn't need to, and
    /// 8000::/1 (no internet IPv6) does (security-6 L2, SEC-5).
    @Test func uncoveredIPv6Blocking() {
        func cov(_ s: String...) -> RouteCoverage { RouteCoverage(s.map { IPAddressRange($0)! }) }
        #expect(cov("0.0.0.0/0", "2000::/3").blocksUncoveredIPv6)
        #expect(cov("0.0.0.0/0", "8000::/1").blocksUncoveredIPv6)
        #expect(cov("0.0.0.0/0").blocksUncoveredIPv6)
        #expect(!cov("0.0.0.0/0", "::/0").blocksUncoveredIPv6)
        #expect(!cov("0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1").blocksUncoveredIPv6)
        #expect(cov("2000::/3").blocksUncoveredIPv4)
        #expect(!cov("10.0.0.0/8").blocksUncoveredIPv6)
    }

    /// Internet IPv6 is 2000::/3: 8000::/1 routes none of it, 2000::/3 all of it (SEC-5).
    @Test func ipv6CoverageMeansInternetIPv6() {
        #expect(RouteCoverage([IPAddressRange("8000::/1")!]).ipv6 == 0)
        #expect(RouteCoverage([IPAddressRange("2000::/3")!]).ipv6 == 1)
        #expect(RouteCoverage([IPAddressRange("::/1")!]).ipv6 == 1)
        #expect(RouteCoverage([IPAddressRange("fd00::/8")!]).ipv6 == 0)
        #expect(RouteCoverage([IPAddressRange("0.0.0.0/0")!, IPAddressRange("8000::/1")!]).routesMostIPv6 == false)
    }

    @Test func sharesSplitBetweenNestedRoutes() throws {
        let text = "[Interface]\nPrivateKey = \(privA)\n" + peer(1, "0.0.0.0/0") + peer(2, "0.0.0.0/1, 10.0.0.0/8")
        let c = try #require(WgQuick.parse(text).configuration)
        let shares = c.routeShares()
        #expect(shares[0].ipv4 == 0.5 && shares[1].ipv4 == 0.5)
        #expect(c.internetPeers.count == 2)
    }

    /// Exactly half of IPv6, tiled from 57 routes whose sizes don't add up exactly in a Double
    /// (::/2, 4000::/3, ... 0x...::/54, then four /56s), still counts as half (S4f L1).
    @Test func tiledHalfOfIPv6IsExact() throws {
        var routes: [String] = []
        var start = UInt128(0)
        for prefix in 2...54 {
            routes.append(Self.v6(start) + "/\(prefix)")
            start += UInt128(1) << (128 - prefix)
        }
        for _ in 0..<4 {
            routes.append(Self.v6(start) + "/56")
            start += UInt128(1) << 72
        }
        #expect(start == UInt128(1) << 127)  // the tiles cover ::/1 exactly
        let text = "[Interface]\nPrivateKey = \(privA)\n" + peer(1, routes.joined(separator: ", ")) + peer(2, "0.0.0.0/0, 8000::/1")
        let c = try #require(WgQuick.parse(text).configuration)
        #expect(Set(c.internetPeers.map { $0.endpoint!.hostString }) == ["peer1.example", "peer2.example"])
    }

    private static func v6(_ value: UInt128) -> String {
        (0..<8).map { String(UInt16(truncatingIfNeeded: value >> (112 - 16 * $0)), radix: 16) }.joined(separator: ":")
    }

    /// A DNS-only tunnel routes two addresses: nobody gets "all traffic".
    @Test func hostRoutesAreNotInternet() throws {
        let c = try #require(WgQuick.parse("[Interface]\nPrivateKey = \(privA)\n" + peer(1, "1.1.1.1/32, 8.8.8.8/32")).configuration)
        #expect(c.internetPeers.isEmpty)
    }

    @Test func splitTunnelHasNoInternetPeer() throws {
        let c = try #require(WgQuick.parse(awg2).configuration)
        #expect(c.internetPeers.isEmpty)
    }
}
