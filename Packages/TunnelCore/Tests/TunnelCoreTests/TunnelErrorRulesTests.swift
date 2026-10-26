import Foundation
import Testing
@testable import TunnelCore

/// The 2026-10-23 report: "Connected" with "The network extension didn't start" under it, and
/// "Another sign-in is in progress" left on an AnyConnect VPN.
@Suite struct TunnelErrorRulesTests {
    private struct Unreachable: Error {}
    private struct Refused: LocalizedError { var errorDescription: String? { "Invalid configuration" } }
    private let notRunning = "The network extension didn't start."
    private var extensionErrors: Set<String> { [notRunning, "The OpenConnect extension didn't start."] }

    /// security-8 L2: a slow deliver (XPC retries) must not stretch the wait to attempts × its
    /// duration; the deadline ends it.
    @MainActor @Test func slowDeliveriesStopAtTheDeadline() async {
        var tries = 0
        let started = ContinuousClock.now
        let outcome = await LaunchHandOff.run(attempts: 48, interval: .zero, deadline: .milliseconds(300), deliver: {
            tries += 1
            try await Task.sleep(for: .milliseconds(100))
            throw Unreachable()
        }, isUnreachable: { $0 is Unreachable }, isCurrent: { true }, tunnelIsUp: { false })
        #expect(outcome == .extensionNotRunning)
        #expect(tries <= 4)
        #expect(ContinuousClock.now - started < .seconds(2))
    }

    @MainActor @Test func unreachableExtensionWithTunnelUpIsNoError() async {
        var tries = 0
        let outcome = await LaunchHandOff.run(attempts: 36, interval: .zero, deliver: {
            tries += 1
            throw Unreachable()
        }, isUnreachable: { $0 is Unreachable }, isCurrent: { true }, tunnelIsUp: { true })
        #expect(outcome == .unreachableWhileUp)
        #expect(tries == 36)
    }

    @MainActor @Test func unreachableExtensionWithTunnelDownIsReported() async {
        let outcome = await LaunchHandOff.run(attempts: 3, interval: .zero, deliver: { throw Unreachable() },
                                              isUnreachable: { $0 is Unreachable }, isCurrent: { true }, tunnelIsUp: { false })
        #expect(outcome == .extensionNotRunning)
    }

    @MainActor @Test func handOffStopsAtTheFirstAnswer() async {
        var tries = 0
        let delivered = await LaunchHandOff.run(attempts: 36, interval: .zero, deliver: {
            tries += 1
            if tries < 3 { throw Unreachable() }
        }, isUnreachable: { $0 is Unreachable }, isCurrent: { true }, tunnelIsUp: { false })
        #expect(delivered == .delivered)
        #expect(tries == 3)
        let refused = await LaunchHandOff.run(attempts: 36, interval: .zero, deliver: { throw Refused() },
                                              isUnreachable: { $0 is Unreachable }, isCurrent: { true }, tunnelIsUp: { false })
        #expect(refused == .failed("Invalid configuration"))
        // A refusal is shown even with the tunnel up: it can be a peer that isn't the real
        // extension (review round 1, security M1).
        let refusedUp = await LaunchHandOff.run(attempts: 36, interval: .zero, deliver: { throw Refused() },
                                                isUnreachable: { $0 is Unreachable }, isCurrent: { true }, tunnelIsUp: { true })
        #expect(refusedUp == .failed("Invalid configuration"))
    }

    @MainActor @Test func upIsAskedWhenTheHandOffGivesUp() async {
        var tries = 0
        // Down for the first attempts, up by the end: what the user saw ("Connected" + error).
        let outcome = await LaunchHandOff.run(attempts: 5, interval: .zero, deliver: {
            tries += 1
            throw Unreachable()
        }, isUnreachable: { $0 is Unreachable }, isCurrent: { true }, tunnelIsUp: { tries >= 5 })
        #expect(outcome == .unreachableWhileUp)
    }

    @MainActor @Test func unreachableThenARealErrorIsShown() async {
        var tries = 0
        let outcome = await LaunchHandOff.run(attempts: 36, interval: .zero, deliver: {
            tries += 1
            if tries < 4 { throw Unreachable() }
            throw Refused()
        }, isUnreachable: { $0 is Unreachable }, isCurrent: { true }, tunnelIsUp: { true })
        #expect(outcome == .failed("Invalid configuration"))
        #expect(tries == 4)
    }

    @MainActor @Test func aLaterStartOrADisconnectSupersedesTheHandOff() async {
        var tries = 0, current = true
        let outcome = await LaunchHandOff.run(attempts: 36, interval: .zero, deliver: {
            tries += 1
            if tries == 2 { current = false }  // the user turned it off during the wait
            throw Unreachable()
        }, isUnreachable: { $0 is Unreachable }, isCurrent: { current }, tunnelIsUp: { false })
        #expect(outcome == .superseded)
        #expect(tries == 2)  // stops trying, too
        // A refusal that arrives after the user moved on isn't shown either.
        current = true
        var refusedTries = 0
        let refused = await LaunchHandOff.run(attempts: 36, interval: .zero, deliver: {
            refusedTries += 1
            current = refusedTries < 1
            throw Refused()
        }, isUnreachable: { $0 is Unreachable }, isCurrent: { current }, tunnelIsUp: { false })
        #expect(refused == .superseded)
        #expect(refusedTries == 1)
    }

    @Test func aTunnelThatIsUpDropsOnlyTheExtensionError() {
        #expect(TunnelErrorRules.error(notRunning, tunnelIsUp: true, extensionErrors: extensionErrors) == nil)
        #expect(TunnelErrorRules.error(notRunning, tunnelIsUp: false, extensionErrors: extensionErrors) == notRunning)
        #expect(TunnelErrorRules.error("Handshake failed", tunnelIsUp: true, extensionErrors: extensionErrors) == "Handshake failed")
        #expect(TunnelErrorRules.error(nil, tunnelIsUp: true, extensionErrors: extensionErrors) == nil)
    }

    @Test func anAnsweringExtensionDropsOnlyTheExtensionError() {
        #expect(TunnelErrorRules.errorAfterExtensionAnswered(notRunning, extensionErrors: extensionErrors) == nil)
        #expect(TunnelErrorRules.errorAfterExtensionAnswered("Other", extensionErrors: extensionErrors) == "Other")
        #expect(TunnelErrorRules.errorAfterExtensionAnswered(nil, extensionErrors: extensionErrors) == nil)
    }

    @MainActor @Test func supersededAfterTheLastAttemptNeverAsksIfUp() async {
        var tries = 0, askedUp = false
        let outcome = await LaunchHandOff.run(attempts: 3, interval: .zero, deliver: {
            tries += 1
            throw Unreachable()
        }, isUnreachable: { $0 is Unreachable }, isCurrent: { tries < 3 }, tunnelIsUp: { askedUp = true; return true })
        #expect(outcome == .superseded)
        #expect(!askedUp)
        let none = await LaunchHandOff.run(attempts: 0, interval: .zero, deliver: {}, isUnreachable: { _ in true },
                                           isCurrent: { true }, tunnelIsUp: { false })
        #expect(none == .extensionNotRunning)
    }

    @Test func onlyASessionFromThisStartCountsAsUp() {
        let start = Date(timeIntervalSince1970: 1_000)
        #expect(TunnelErrorRules.isUp(since: start, connected: true, connectedDate: start.addingTimeInterval(2)))
        #expect(TunnelErrorRules.isUp(since: start, connected: true, connectedDate: start))
        // Reconnect whose stop stalled: the old session is still connected, from before the start.
        #expect(!TunnelErrorRules.isUp(since: start, connected: true, connectedDate: start.addingTimeInterval(-300)))
        #expect(!TunnelErrorRules.isUp(since: start, connected: true, connectedDate: nil))
        #expect(!TunnelErrorRules.isUp(since: start, connected: false, connectedDate: start.addingTimeInterval(2)))
        // No start in this run of the app (connected at launch): connected is enough.
        #expect(TunnelErrorRules.isUp(since: nil, connected: true, connectedDate: nil))
        #expect(!TunnelErrorRules.isUp(since: nil, connected: false, connectedDate: nil))
    }

    @Test func givingUpKeepsAnErrorSetDuringTheWait() {
        #expect(TunnelErrorRules.errorAfterGivingUp(nil, notRunning: notRunning) == notRunning)
        #expect(TunnelErrorRules.errorAfterGivingUp("Could not resolve endpoint", notRunning: notRunning) == "Could not resolve endpoint")
    }

    @Test func busyAndCanceledSignInsLeaveNoError() {
        #expect(TunnelErrorRules.shownError(for: SignInBusy()) == nil)
        #expect(TunnelErrorRules.shownError(for: AnyConnectSignInError.canceled) == nil)
        #expect(TunnelErrorRules.shownError(for: Refused()) == "Invalid configuration")
        #expect(TunnelErrorRules.shownError(for: AnyConnectSignInError.server("Denied")) == AnyConnectSignInError.server("Denied").localizedDescription)
    }
}
