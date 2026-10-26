import Foundation
import Testing
@testable import TunnelCore

/// The cases live in the Go engine's `node/testdata/control-urls.json`: the engine and the app
/// apply the same rules, so they run the same list (quality-9 L1). "DEFAULT" is Tailscale's server.
private struct URLFixture: Decodable {
    let canonical: [String: String]
    let refused: [String]
    let login: [LoginCase]

    struct LoginCase: Decodable {
        let login: String, control: String, valid: Bool
        init(from decoder: Decoder) throws {
            var c = try decoder.unkeyedContainer()
            login = try c.decode(String.self)
            control = try c.decode(String.self)
            valid = try c.decode(Bool.self)
        }
    }

    static let shared: URLFixture = {
        let url = URL(fileURLWithPath: #filePath)  // Packages/TunnelCore/Tests/TunnelCoreTests/
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Vendor/tailscale-bridge/node/testdata/control-urls.json")
        return try! JSONDecoder().decode(URLFixture.self, from: Data(contentsOf: url))
    }()

    static func resolve(_ s: String) -> String { s == "DEFAULT" ? TailnetControl.defaultURL : s }
}

@Suite struct TailnetControlTests {
    @Test func fixtureIsShared() {
        let f = URLFixture.shared
        #expect(!f.canonical.isEmpty && f.refused.count > 30 && !f.login.isEmpty)
    }

    @Test func canonicalForms() throws {
        for (input, want) in URLFixture.shared.canonical {
            #expect(try TailnetControl.canonical(input).get() == URLFixture.resolve(want), "\(input)")
        }
    }

    @Test func refused() {
        for input in URLFixture.shared.refused {
            if case .success(let url) = TailnetControl.canonical(input) { Issue.record("accepted \(input) as \(url)") }
        }
    }

    @Test func keyPerServer() {
        let a = TailnetControl.key("https://hs.example.com")
        #expect(a.count == 16 && a != TailnetControl.key("https://hs2.example.com"))
    }

    @Test func loginURLs() {
        for c in URLFixture.shared.login {
            #expect(TailnetControl.isValidLoginURL(c.login, control: URLFixture.resolve(c.control)) == c.valid, "\(c.login) for \(c.control)")
        }
    }
}

@Suite struct TailnetFileTests {
    @Test func parsesAndRoundTrips() throws {
        let text = "[Tailnet]\nControlURL = https://HS.example.com/\nHostname = laptop-1\nAcceptDNS = no\n"
        let profile = try #require(TailnetFile.parse(text).profile)
        #expect(profile == TailnetProfile(controlURL: "https://hs.example.com", hostname: "laptop-1", acceptDNS: false))
        #expect(TailnetFile.parse(TailnetFile.serialize(profile)).profile == profile)
        #expect(TailnetFile.looksLikeProfile(text))
        #expect(try #require(TailnetFile.parse("[Tailnet]\n").profile).controlURL == TailnetControl.defaultURL)
    }

    @Test(arguments: [
        "[Tailnet]\nExitNode = 100.64.0.1\n", "[Tailnet]\nAuthKey = tskey-abc\n", "[Tailnet]\nControlURL = http://hs.example.com\n",
        "[Tailnet]\nHostname = bad name\n", "[Tailnet]\nAcceptDNS = maybe\n", "[Interface]\nPrivateKey = x\n",
        "[Tailnet]\nControlURL = https://a.com\nControlURL = https://b.com\n", "ControlURL = https://a.com\n",
        "[Tailnet]\nPostUp = echo hi\n",
    ])
    func refused(_ text: String) {
        #expect(TailnetFile.parse(text).profile == nil, "\(text)")
    }
}

@Suite struct TailnetNetworkPlanTests {
    let hs = "https://hs.example.com"
    func proposal(addresses: [String] = ["100.64.0.2/32", "fd7a:115c:a1e0::2/128"],
                  routes: [String] = ["100.64.0.1/32", "fd7a:115c:a1e0::/48", "100.100.100.100/32", "fd7a:115c:a1e0::53/128"],
                  dns: [String] = ["100.100.100.100", "fd7a:115c:a1e0::53"],
                  match: [String] = ["wombat-test.internal", "64.100.in-addr.arpa"]) -> TailnetNetworkPlan.Proposal {
        var p = TailnetNetworkPlan.Proposal()
        p.addresses = addresses
        p.routes = routes
        p.dnsServers = dns
        p.matchDomains = match
        p.searchDomains = ["wombat-test.internal", "evil.com"]
        return p
    }

    @Test func probeShapedPlanPasses() throws {
        let plan = try TailnetNetworkPlan.make(proposal(), acceptDNS: true, control: hs)
        #expect(plan.ipv4Address?.description == "100.64.0.2/32")
        #expect(plan.ipv4Routes.map(\.description) == ["100.64.0.1/32", "100.100.100.100/32"])
        #expect(plan.ipv6Routes.count == 2)
        #expect(plan.dnsServers == ["100.100.100.100", "fd7a:115c:a1e0::53"])
        #expect(plan.matchDomains == ["wombat-test.internal", "64.100.in-addr.arpa"])
        #expect(plan.searchDomains.isEmpty)  // security-9 fable L1: no search domains on macOS
        #expect(plan.magicDNSSuffix == "wombat-test.internal")
        #expect(plan.dropped.isEmpty)
        #expect(plan.mtu == 1280)
    }

    @Test(arguments: ["0.0.0.0/0", "10.0.0.0/8", "::/0", "192.168.1.0/24", "100.0.0.0/8", "8.8.8.8/32", "2000::/3"])
    func foreignRoutesDropped(_ route: String) throws {
        let plan = try TailnetNetworkPlan.make(proposal(routes: [route, "100.64.0.1/32"]), acceptDNS: true, control: hs)
        #expect(plan.dropped.filter { $0.hasPrefix("route") } == ["route \(IPAddressRange(route)!)"])
        #expect(!(plan.ipv4Routes + plan.ipv6Routes).contains { $0.isDefaultRoute || !$0.description.hasPrefix("100.") && !$0.description.hasPrefix("fd7a") })
    }

    @Test func noAddressIsAnEmptyPlan() throws {
        // Before sign-in the engine sends a plan with nothing in it; that must not end the tunnel.
        let empty = try TailnetNetworkPlan.make(TailnetNetworkPlan.Proposal(), acceptDNS: true, control: hs)
        #expect(empty.ipv4Address == nil && empty.ipv6Address == nil && empty.ipv4Routes.isEmpty && empty.dnsServers.isEmpty)
        let stray = try TailnetNetworkPlan.make(proposal(addresses: []), acceptDNS: true, control: hs)
        #expect(stray.ipv4Routes.isEmpty && stray.ipv6Routes.isEmpty && stray.dnsServers.isEmpty && !stray.dropped.isEmpty)
    }

    @Test(arguments: [["10.0.0.2/32"], ["100.64.0.2/24"], ["100.64.0.2/32", "100.64.0.3/32"], ["2001:db8::1/128"], ["junk"]])
    func foreignAddressRefused(_ addresses: [String]) {
        #expect(throws: TailnetNetworkPlan.Failure.self) { try TailnetNetworkPlan.make(proposal(addresses: addresses), acceptDNS: true, control: hs) }
    }

    @Test func foreignResolverDropsDNS() throws {
        let plan = try TailnetNetworkPlan.make(proposal(dns: ["100.100.100.100", "8.8.8.8"]), acceptDNS: true, control: hs)
        #expect(plan.dnsServers.isEmpty && plan.matchDomains.isEmpty)
        #expect(plan.dropped.first?.contains("8.8.8.8") == true)
    }

    @Test func neverAllDomains() throws {
        // No match domains would make quad100 the only resolver: refused, never [""].
        for match in [[], [""], ["."]] {
            let plan = try TailnetNetworkPlan.make(proposal(match: match), acceptDNS: true, control: hs)
            #expect(plan.dnsServers.isEmpty && plan.matchDomains.isEmpty, "\(match)")
        }
        #expect(try TailnetNetworkPlan.make(proposal(), acceptDNS: false, control: hs).dnsServers.isEmpty)
    }

    @Test func onlyTailnetDomainsReachQuad100() throws {
        // security-7 M1: a server can't take over DNS for other names.
        let plan = try TailnetNetworkPlan.make(proposal(match: ["wombat-test.internal", "com", "github.com", "in-addr.arpa", "8.100.in-addr.arpa", "64.100.in-addr.arpa", "0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa"]), acceptDNS: true, control: hs)
        #expect(plan.matchDomains == ["wombat-test.internal", "64.100.in-addr.arpa", "0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa"])
        #expect(plan.dropped.contains("DNS domain com") && plan.dropped.contains("DNS domain github.com") && plan.dropped.contains("DNS domain in-addr.arpa"))
        // A top-level suffix is never MagicDNS, and Tailscale's own server only names under ts.net.
        var p = proposal(match: ["internal"])
        p.searchDomains = ["internal"]
        #expect(try TailnetNetworkPlan.make(p, acceptDNS: true, control: hs).dnsServers.isEmpty)
        var t = proposal(match: ["tail1234.ts.net", "example.com"])
        t.searchDomains = ["example.com", "tail1234.ts.net"]
        let official = try TailnetNetworkPlan.make(t, acceptDNS: true, control: TailnetControl.defaultURL)
        #expect(official.matchDomains == ["tail1234.ts.net"] && official.searchDomains.isEmpty && official.magicDNSSuffix == "tail1234.ts.net")
    }

    @Test func pinnedSuffixHolds() throws {
        // security-9 astra S9-1: a server can't move the Mac's lookups to a new name later.
        let same = try TailnetNetworkPlan.make(proposal(), acceptDNS: true, control: hs, pinnedSuffix: "wombat-test.internal")
        #expect(same.matchDomains.contains("wombat-test.internal"))
        let moved = try TailnetNetworkPlan.make(proposal(), acceptDNS: true, control: hs, pinnedSuffix: "first.internal")
        #expect(!moved.matchDomains.contains("wombat-test.internal") && moved.magicDNSSuffix == nil)
        #expect(moved.matchDomains == ["64.100.in-addr.arpa"])  // reverse lookups stay
        #expect(moved.dropped.contains { $0.contains("first used first.internal") })
    }

    @Test func resolverMustBeRouted() throws {
        // quality-9 L3: quad100 without a route into the tunnel would be asked in clear text.
        let plan = try TailnetNetworkPlan.make(proposal(routes: ["100.64.0.1/32"]), acceptDNS: true, control: hs)
        #expect(plan.dnsServers.isEmpty && plan.matchDomains.isEmpty)
        #expect(plan.dropped.contains { $0.contains("isn't routed") })
        let covered = try TailnetNetworkPlan.make(proposal(routes: ["100.64.0.0/10"]), acceptDNS: true, control: hs)
        #expect(covered.dnsServers == ["100.100.100.100"])
    }

    @Test func decodesEngineJSON() throws {
        let json = #"{"addresses":["100.64.0.2/32"],"routes":["100.64.0.1/32","100.100.100.100/32"],"mtu":0,"dnsServers":["100.100.100.100"],"matchDomains":["x.internal"],"searchDomains":["x.internal"]}"#
        let plan = try TailnetNetworkPlan.make(try TailnetNetworkPlan.decode(Data(json.utf8)), acceptDNS: true, control: hs)
        #expect(plan.ipv4Routes.count == 2 && plan.ipv6Routes.isEmpty && plan.matchDomains == ["x.internal"])
    }
}

@Suite struct TailnetStatusTests {
    @Test func decodesGoStatus() throws {
        let json = #"{"state":"Running","authURL":"https://evil.com/a/x","control":"https://hs.example.com","self":{"name":"mac","addresses":["100.64.0.2"],"online":true,"active":false,"direct":false,"rxBytes":0,"txBytes":0},"health":[],"peers":[{"name":"peer","dnsName":"peer.x.internal","addresses":["100.64.0.1"],"online":true,"active":true,"relay":"nyc","direct":false,"rxBytes":10,"txBytes":20,"lastSeen":"2026-10-26T19:04:57.090359115Z"}]}"#
        let status = try #require(TailnetStatus.decode(Data(json.utf8)))
        #expect(status.peers.first?.lastSeen != nil)
        #expect(status.validAuthURL(control: "https://hs.example.com") == nil)  // wrong host for this server
        var good = status
        good.authURL = "https://hs.example.com/register/abc"
        #expect(good.validAuthURL(control: "https://hs.example.com") != nil)
        #expect(good.validAuthURL(control: "https://other.example.com") == nil)  // not this profile's server
    }
}
