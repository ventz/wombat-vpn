import Foundation
import Testing
@testable import TunnelCore

/// The backup hand-off route (2026-11-18): macOS can leave a replaced extension's launchd job
/// without its Mach service, and every AnyConnect connect then failed until a reboot.
@Suite struct ProviderHandOffTests {
    let id = "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA"
    let rev = "11111111-1111-1111-1111-111111111111"
    let profile = "[AnyConnect]\nServer = vpn.example.edu"

    func handOff(nonce: String?, id: String? = nil, revision: String? = nil, profile: String? = nil) -> ProviderHandOff {
        var s = AnyConnectSession(cookie: "ABC", host: "vpn.example.edu", port: 443, address: "192.0.2.1",
                                  serverCertificateSHA256: String(repeating: "a", count: 64))
        s.startNonce = nonce
        return ProviderHandOff(id: id ?? self.id, revision: revision ?? rev, profile: profile ?? self.profile, session: s)
    }

    @Test func theWaitingStartWithItsNonceAccepts() throws {
        let nonce = try #require(StartNonce.generate())
        let h = handOff(nonce: nonce)
        #expect(h.refusal(waiting: true, tunnelID: id.lowercased(), revision: rev, nonce: nonce) == nil)
    }

    @Test func roundTripsAsAProviderMessage() throws {
        let nonce = try #require(StartNonce.generate())
        let message = try #require(handOff(nonce: nonce).message())
        #expect(message.first == ProviderHandOff.messageTag)
        let back = try #require(ProviderHandOff.parse(message))
        #expect(back.session.cookie == "ABC")
        #expect(back.session.startNonce == nonce)
        // A one-byte status request is never mistaken for a hand-off.
        #expect(ProviderHandOff.parse(Data([ProviderHandOff.messageTag])) == nil)
        #expect(ProviderHandOff.parse(Data([2]) + message.dropFirst()) == nil)
    }

    @Test func oversizeIsRefused() throws {
        let nonce = try #require(StartNonce.generate())
        let huge = handOff(nonce: nonce, profile: profile + "\n#" + String(repeating: "x", count: ProviderHandOff.maxBytes))
        #expect(huge.message() == nil)
        var raw = Data([ProviderHandOff.messageTag])
        raw.append(Data(repeating: 0x20, count: ProviderHandOff.maxBytes + 1))
        #expect(ProviderHandOff.parse(raw) == nil)
    }

    @Test func refusals() throws {
        let nonce = try #require(StartNonce.generate())
        let other = try #require(StartNonce.generate())
        let h = handOff(nonce: nonce)
        #expect(h.refusal(waiting: false, tunnelID: id, revision: rev, nonce: nonce) == .notWaiting)
        // A start without a nonce (System Settings, on-demand) never takes one from this route.
        #expect(h.refusal(waiting: true, tunnelID: id, revision: rev, nonce: nil) == .noNonce)
        #expect(handOff(nonce: nil).refusal(waiting: true, tunnelID: id, revision: rev, nonce: nonce) == .nonce)
        #expect(h.refusal(waiting: true, tunnelID: id, revision: rev, nonce: other) == .nonce)
        #expect(h.refusal(waiting: true, tunnelID: "BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB", revision: rev, nonce: nonce) == .tunnel)
        #expect(h.refusal(waiting: true, tunnelID: nil, revision: rev, nonce: nonce) == .tunnel)
        #expect(h.refusal(waiting: true, tunnelID: id, revision: "22222222-2222-2222-2222-222222222222", nonce: nonce) == .revision)
        #expect(h.refusal(waiting: true, tunnelID: id, revision: nil, nonce: nonce) == .revision)
        #expect(handOff(nonce: nonce, profile: "not a profile").refusal(waiting: true, tunnelID: id, revision: rev, nonce: nonce) == .invalid)
    }

    @Test func replyRoundTrips() {
        let r = ProviderHandOffReply(error: nil, serviceMissing: true)
        #expect(ProviderHandOffReply.decode(r.encoded()) == r)
        #expect(ProviderHandOffReply.decode(nil) == nil)
        #expect(ProviderHandOffReply.decode(Data("junk".utf8)) == nil)
    }
}
