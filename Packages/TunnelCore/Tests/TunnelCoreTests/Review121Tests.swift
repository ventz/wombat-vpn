import Foundation
import Testing
@testable import TunnelCore

/// Fixes from the external 1.2.1 review (NEW-n) and the checks that followed it.
@Suite struct Review121Tests {
    @Test func appVersionsCompareNumerically() {
        #expect(AppVersion.isOlder("1.2.0", than: "1.10.0"))
        #expect(!AppVersion.isOlder("1.10.0", than: "1.2.0"))
        #expect(!AppVersion.isOlder("1.2", than: "1.2.0"))
        #expect(!AppVersion.isOlder("1.3.0-beta", than: "1.3.0"))  // a pre-release isn't refused
        #expect(AppVersion.isOlder("", than: "1.2.1"))              // unparsable counts as oldest
        #expect(!AppVersion.isOlder("1.2.1", than: "garbage"))
    }

    @Test func declineBackoffDoublesToItsCap() {
        #expect((1...7).map(DeclineBackoff.wait(afterDeclines:)) == [10, 20, 40, 80, 160, 320, 320])
        #expect(DeclineBackoff.wait(afterDeclines: 0) == 10)
    }

    @Test func aConfigurationStartsWithInterface() {
        #expect(WgQuick.startsWithInterface("\u{FEFF}# exported\n\n[Interface]\nPrivateKey = x"))
        #expect(WgQuick.startsWithInterface("  [interface]  "))
        #expect(!WgQuick.startsWithInterface("[Peer]\n[Interface]"))
        #expect(!WgQuick.startsWithInterface("[AnyConnect]\n# [Interface]\nServer = https://x"))
        #expect(!WgQuick.startsWithInterface("Server = [Interface]"))
    }

    private func cov(_ s: String...) -> RouteCoverage { RouteCoverage(s.map { IPAddressRange($0)! }) }

    /// NAT64 must be routed in full before uncovered IPv6 is left alone, IPv6-only tunnels too.
    @Test func nat64MustBeRoutedInFull() {
        #expect(cov("0.0.0.0/0", "::/0", "64:ff9b::/97").blocksUncoveredIPv6 == false)  // ::/0 covers it
        #expect(cov("0.0.0.0/0", "2000::/3", "8000::/1", "64:ff9b::/97").blocksUncoveredIPv6)  // half isn't enough
        #expect(cov("2000::/3").blocksUncoveredIPv6)            // IPv6-only full tunnel
        #expect(cov("2000::/3").blocksUncoveredIPv4)
        #expect(!cov("::/0").blocksUncoveredIPv6)
        #expect(!cov("10.0.0.0/8", "fd00::/8").blocksUncoveredIPv6)  // split tunnels are left alone
    }

    @Test func fullTunnelLineNamesEachFamily() throws {
        func message(_ allowed: String) throws -> String? {
            let c = try #require(WgQuick.parse("[Interface]\nPrivateKey = \(privA)\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = \(pubB)\nAllowedIPs = \(allowed)").configuration)
            return ConfigReview.review(c).first { $0.code == "full-tunnel" }?.message
        }
        #expect(try message("0.0.0.0/0, ::/0") == "Routes all of IPv4 and all of internet IPv6 traffic through this tunnel")
        #expect(try message("0.0.0.0/1, 128.0.0.0/1, 8000::/1") == "Routes all of IPv4 traffic through this tunnel")
        #expect(try message("2000::/3") == "Routes all of internet IPv6 traffic through this tunnel")
    }

    private func r(_ a: String, _ p: UInt8) -> OpenConnectNetworkPlan.Route {
        .init(address: a, mask: OpenConnectNetworkPlan.maskString(p), prefixLength: p)
    }

    @Test func netShareClipsToTheMeasuredRange() {
        let inet = RouteCoverage.globalUnicast
        // ::/2 holds 2000::/3 whole; 2000::/4 is half of it; 8000::/1 none of it.
        #expect(OpenConnectNetworkPlan.netShare([r("::", 2)], minus: [], bits: 128, within: inet) == 1)
        #expect(OpenConnectNetworkPlan.netShare([r("2000::", 4)], minus: [], bits: 128, within: inet) == 0.5)
        #expect(OpenConnectNetworkPlan.netShare([r("8000::", 1)], minus: [], bits: 128, within: inet) == 0)
        #expect(OpenConnectNetworkPlan.netShare([r("::", 0)], minus: [r("2000::", 4)], bits: 128, within: inet) == 0.5)
    }

    @Test func anyConnectLeavesIPv6AloneOnlyWithNAT64Routed() throws {
        var info = OpenConnectIPInfo()
        info.address = "10.8.0.5"
        info.netmask6 = "fd00:8::5/64"
        info.splitIncludes = ["0.0.0.0/0.0.0.0", "2000::/3", "8000::/1", "64:ff9b::/96"]
        var plan = try OpenConnectNetworkPlan.make(info)
        #expect(!plan.blockedIPv6)
        #expect(plan.ipv6Included.map(\.prefixLength).sorted() == [1, 3, 96])  // the gateway's routes kept
        info.splitIncludes = ["2000::/3"]
        info.address = nil
        plan = try OpenConnectNetworkPlan.make(info)
        #expect(plan.ipv6Included.first?.prefixLength == 0)  // IPv6-only: NAT64 kept inside too
        #expect(plan.blockedIPv4)
    }

    @Test func droppedSettingsAreNamed() throws {
        var info = OpenConnectIPInfo()
        info.address = "10.8.0.5"
        info.splitIncludes = ["10.0.0.0/255.0.0.0"]
        info.domain = (0...64).map { "d\($0).example.edu" }.joined(separator: " ")
        info.splitDNS = (0...64).map { "s\($0).example.edu" }
        info.routesTruncated = true
        let plan = try OpenConnectNetworkPlan.make(info)
        #expect(plan.dropped.contains { $0.hasPrefix("split-DNS domains beyond 64") })
        #expect(plan.dropped.contains("search domains beyond 64"))
        #expect(plan.dropped.contains { $0.hasPrefix("routes beyond 2048") })
        #expect(!plan.dropped.contains { $0.hasPrefix("excluded routes") })
        var quiet = OpenConnectIPInfo()
        quiet.address = "10.8.0.5"
        #expect(try OpenConnectNetworkPlan.make(quiet).dropped.isEmpty)
    }
}
