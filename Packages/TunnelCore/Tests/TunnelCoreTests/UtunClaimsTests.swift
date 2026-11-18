import Testing
@testable import TunnelCore

/// 1.4.6 report (2026-11-18): every AnyConnect start failed with "Could not find the tunnel
/// device" until the extension process was killed. A claim kept by descriptor number alone
/// outlived its tunnel and hid the next utun, which reused the number.
@Suite struct UtunClaimsTests {
    func claim(_ fd: Int32, _ socket: UInt64) -> UtunClaim { UtunClaim(fd: fd, socket: socket) }

    @Test func aClaimOnTheSameSocketHolds() {
        var c = UtunClaims()
        c.insert(claim(7, 0xAAAA))
        let held = c.holds(7, current: 0xAAAA)
        #expect(held)
        #expect(c.count == 1)
    }

    @Test func aReusedNumberWithANewSocketIsFree() {
        var c = UtunClaims()
        c.insert(claim(7, 0xAAAA))
        let held = c.holds(7, current: 0xBBBB)
        #expect(!held)
        #expect(c.count == 0)
        #expect(c.staleDropped == 1)
        c.insert(claim(7, 0xBBBB))
        let heldNew = c.holds(7, current: 0xBBBB)
        #expect(heldNew)
    }

    /// Reviews: a late release of the ended tunnel must not free the newer tunnel's claim.
    @Test func aLateReleaseLeavesTheNewerClaim() {
        var c = UtunClaims()
        let old = claim(7, 0xAAAA)
        c.insert(old)
        _ = c.holds(7, current: 0xBBBB)  // stale, dropped
        let new = claim(7, 0xBBBB)
        c.insert(new)
        let released = c.release(old)
        #expect(!released)
        let held = c.holds(7, current: 0xBBBB)
        #expect(held)
        let releasedNew = c.release(new)
        #expect(releasedNew)
        #expect(c.count == 0)
    }

    /// Reviews: a dup() shares the socket, so an engine's unrecorded copy is never handed out.
    @Test func anAliasOfAClaimedSocketIsSkipped() {
        var c = UtunClaims()
        c.insert(claim(7, 0xAAAA))
        let alias = c.holds(12, current: 0xAAAA)
        #expect(alias)
        let other = c.holds(13, current: 0xCCCC)
        #expect(!other)
        #expect(c.count == 1)
    }

    @Test func unknownIdentityFailsClosed() {
        var c = UtunClaims()
        c.insert(claim(7, 0))
        let a = c.holds(7, current: 0xBBBB)
        #expect(a)
        c.insert(claim(8, 0xAAAA))
        let b = c.holds(8, current: 0)
        #expect(b)
        #expect(c.staleDropped == 0)
        #expect(c.unknownIdentity == 1)
        // A release with unknown identity falls back to the number.
        let released = c.release(claim(7, 0xDDDD))
        #expect(released)
    }

    @Test func unclaimedIsNeverHeld() {
        var c = UtunClaims()
        let held = c.holds(3, current: 0xAAAA)
        #expect(!held)
    }

    @Test func closedDescriptorsAreDropped() {
        var c = UtunClaims()
        c.insert(claim(5, 1))
        c.insert(claim(6, 2))
        c.dropClosed { $0 == 5 }
        #expect(c.count == 1)
        let six = c.holds(6, current: 2)
        #expect(six)
        let five = c.holds(5, current: 1)
        #expect(!five)
        #expect(c.staleDropped == 1)
    }
}
