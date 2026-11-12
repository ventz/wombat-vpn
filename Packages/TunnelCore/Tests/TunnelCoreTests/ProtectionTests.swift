import Foundation
import Testing
@testable import TunnelCore

/// Kill switch exception for Bonjour discovery (GitHub issue #2).
struct ProtectionTests {
    @Test func discoveryOnlyAppliesWithKillSwitchAndLAN() {
        #expect(Control.Protection(killSwitch: true, allowLAN: true, allowDiscovery: true).effective.allowDiscovery)
        #expect(!Control.Protection(killSwitch: true, allowLAN: false, allowDiscovery: true).effective.allowDiscovery)
        #expect(!Control.Protection(killSwitch: false, allowLAN: true, allowDiscovery: true).effective.allowDiscovery)
        #expect(!Control.Protection(killSwitch: true, allowLAN: true).effective.allowDiscovery)
    }

    @Test func effectiveKeepsKillSwitchAndLAN() {
        let p = Control.Protection(killSwitch: true, allowLAN: false, allowDiscovery: true).effective
        #expect(p.killSwitch && !p.allowLAN)
    }

    @Test func olderPeerWithoutDiscoveryDecodesAsOff() throws {
        let json = Data(#"{"killSwitch":true,"allowLAN":true}"#.utf8)
        let p = try JSONDecoder().decode(Control.Protection.self, from: json)
        #expect(p.killSwitch && p.allowLAN && !p.allowDiscovery)
    }

    @Test func roundTrips() throws {
        let p = Control.Protection(killSwitch: true, allowLAN: true, allowDiscovery: true)
        #expect(try JSONDecoder().decode(Control.Protection.self, from: JSONEncoder().encode(p)) == p)
    }

    @Test func missingKillSwitchStillFails() {
        #expect(throws: (any Error).self) { try JSONDecoder().decode(Control.Protection.self, from: Data(#"{"allowLAN":true}"#.utf8)) }
    }
}
