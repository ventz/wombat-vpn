import Foundation
import Testing
@testable import TunnelCore

/// 1.4.6 report (2026-11-18): turning the OpenConnect extension off and on removed the VPN, and
/// the user had to set it up again although Wombat's keychain copy was still there.
@Suite struct RemovedConfigsTests {
    let now = Date(timeIntervalSince1970: 2_000_000)
    let a = UUID(uuidString: "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA")!
    let b = UUID(uuidString: "BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB")!

    func item(_ id: UUID, _ ref: Int, label: String? = "Wombat VPN: Work", kind: RemovedConfigs.Kind = .openConnect,
              age: TimeInterval = 3600) -> RemovedConfigs.Item<Int> {
        .init(reference: ref, account: "\(id.uuidString)/\(UUID().uuidString)", label: label, kind: kind,
              created: now.addingTimeInterval(-age))
    }

    @Test func aTunnelWithoutConfigurationIsOffered() {
        let found = RemovedConfigs.find([item(a, 1), item(b, 2, label: "Wombat tunnel: Home", kind: .wireGuard)],
                                        existing: [b], now: now)
        #expect(found.count == 1)
        #expect(found.first?.id == a)
        #expect(found.first?.name == "Work")
        #expect(found.first?.kind == .openConnect)
    }

    @Test func existingTunnelsAreNeverOffered() {
        #expect(RemovedConfigs.find([item(a, 1)], existing: [a], now: now).isEmpty)
    }

    @Test func aRecentItemMayBeAnAddInProgress() {
        #expect(RemovedConfigs.find([item(a, 1, age: 10)], existing: [], now: now).isEmpty)
        // An edit in progress: a fresh item next to an old one also waits.
        #expect(RemovedConfigs.find([item(a, 1), item(a, 2, age: 5)], existing: [], now: now).isEmpty)
        #expect(RemovedConfigs.find([item(a, 1, age: RemovedConfigs.grace + 1)], existing: [], now: now).count == 1)
    }

    @Test func theNewestItemIsRestoredAndAllGo() {
        let found = RemovedConfigs.find([item(a, 1, age: 9000), item(a, 2, label: "Wombat VPN: Work 2", age: 4000)],
                                        existing: [], now: now)
        #expect(found.count == 1)
        #expect(found.first?.newest == 2)
        #expect(found.first?.name == "Work 2")
        #expect(Set(found.first?.references ?? []) == [1, 2])
    }

    @Test func foreignAccountsAreIgnored() {
        let odd = RemovedConfigs.Item(reference: 9, account: "not-a-uuid/x", label: nil, kind: .wireGuard, created: nil)
        #expect(RemovedConfigs.find([odd], existing: [], now: now).isEmpty)
    }

    @Test func labelsBecomeNames() {
        #expect(RemovedConfigs.name("Wombat tunnel: Home") == "Home")
        #expect(RemovedConfigs.name("Wombat VPN: Work") == "Work")
        #expect(RemovedConfigs.name("Something else") == "Unnamed VPN")
        #expect(RemovedConfigs.name(nil) == "Unnamed VPN")
        #expect(RemovedConfigs.name("Wombat VPN:  ") == "Unnamed VPN")
    }

    @Test func sortedByName() {
        let found = RemovedConfigs.find([item(a, 1, label: "Wombat VPN: b"), item(b, 2, label: "Wombat VPN: A")],
                                        existing: [], now: now)
        #expect(found.map(\.name) == ["A", "b"])
    }
}
