import Foundation
import Testing
@testable import TunnelCore

/// The OpenConnect extension's in-memory sessions and the hand-off diagnosis (1.4.5 reports:
/// "didn't deliver this VPN's sign-in ... in time", GitHub issue #4).
@Suite struct OpenConnectHandOffTests {
    let rev = "11111111-1111-1111-1111-111111111111"
    let id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    let t0 = Date(timeIntervalSince1970: 1_000_000)

    // MARK: Sessions

    /// The race: the previous start's stop (up to 10 s of goodbye) or its main loop's exit ran
    /// after the app handed over the next start's session, and dropped it by tunnel id.
    @Test func lateCleanupOfAnOlderStartKeepsTheNewSession() {
        var s = HeldSessions<String>(lifetime: 600)
        let old = s.put(id, owner: 501, revision: rev, value: "old")
        let new = s.put(id, owner: 501, revision: rev, value: "new")
        #expect(old != new)
        let droppedOld = s.drop(id, generation: old)
        #expect(!droppedOld)
        let held = s.session(id, owner: 501, revision: rev)?.value
        #expect(held == "new")
        let droppedNew = s.drop(id, generation: new)
        #expect(droppedNew)
        #expect(s.count == 0)
    }

    /// A start that never got a session cleans up only while it is the newest start.
    @Test func startWithoutSessionDropsOnlyWhileNewest() {
        var s = HeldSessions<String>(lifetime: 600)
        let first = s.beginStart(id, now: t0)
        s.put(id, owner: 501, revision: rev, value: "for the second start", now: t0)
        let second = s.beginStart(id, now: t0)
        let byFirst = s.drop(id, ifLatestStart: first, receivedBy: t0.addingTimeInterval(5))
        #expect(!byFirst)
        #expect(s.count == 1)
        let bySecond = s.drop(id, ifLatestStart: second, receivedBy: t0.addingTimeInterval(5))
        #expect(bySecond)
        #expect(s.count == 0)
    }

    /// With the extension already running, the app hands the session over BEFORE it starts the
    /// next connection, so the stopped start is still the newest when the session arrives. Its
    /// cleanup must not take a session received after its stop began (review S5/L1).
    @Test func sessionArrivingAfterTheStopSurvivesTheCleanup() {
        var s = HeldSessions<String>(lifetime: 600)
        let stopped = s.beginStart(id, now: t0)
        let stopAt = t0.addingTimeInterval(1)
        s.put(id, owner: 501, revision: rev, value: "next start", now: t0.addingTimeInterval(2))
        let dropped = s.drop(id, ifLatestStart: stopped, receivedBy: stopAt)
        #expect(!dropped)
        #expect(s.count == 1)
    }

    /// A refused start (the newest one) still drops the session it was handed (review NEW-10).
    @Test func refusedNewestStartDropsItsSession() {
        var s = HeldSessions<String>(lifetime: 600)
        let token = s.beginStart(id, now: t0)
        s.put(id, owner: 501, revision: rev, value: "x", now: t0)
        let dropped = s.drop(id, ifLatestStart: token, receivedBy: t0.addingTimeInterval(1))
        #expect(dropped)
        let held = s.session(id, owner: 501, revision: rev, now: t0)
        #expect(held == nil)
    }

    /// Unchanged, fail-closed rules: another owner, another revision, an unknown owner or an old
    /// token gets nothing, and the mismatched session is dropped.
    @Test func mismatchesStayClosed() {
        var s = HeldSessions<String>(lifetime: 600)
        s.put(id, owner: 501, revision: rev, value: "x", now: t0)
        let otherOwner = s.session(id, owner: 502, revision: rev, now: t0)
        #expect(otherOwner == nil)
        #expect(s.count == 0)
        s.put(id, owner: 501, revision: rev, value: "x", now: t0)
        let otherRevision = s.session(id, owner: 501, revision: "22222222-2222-2222-2222-222222222222", now: t0)
        #expect(otherRevision == nil)
        #expect(s.count == 0)
        s.put(id, owner: 501, revision: rev, value: "x", now: t0)
        let noOwner = s.session(id, owner: nil, revision: rev, now: t0)
        #expect(noOwner == nil)
        s.put(id, owner: 501, revision: rev, value: "x", now: t0)
        let tooOld = s.session(id, owner: 501, revision: rev, now: t0.addingTimeInterval(601))
        #expect(tooOld == nil)
        #expect(s.count == 0)
    }

    @Test func expiredSessionsArePrunedOnPutAndOnStart() {
        var s = HeldSessions<String>(lifetime: 600)
        s.put(id, owner: 501, revision: rev, value: "old", now: t0)
        s.put("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", owner: 501, revision: rev, value: "new", now: t0.addingTimeInterval(700))
        #expect(s.count == 1)
        _ = s.beginStart(id, now: t0.addingTimeInterval(1400))
        #expect(s.count == 0)
    }

    @Test func removeDropsWhateverIsHeld() {
        var s = HeldSessions<String>(lifetime: 600)
        s.put(id, owner: 501, revision: rev, value: "x")
        s.drop(id)
        #expect(s.count == 0)
    }

    // MARK: Activity

    /// A request that landed before the provider's start was called still counts (review M1):
    /// the listener is up before the start, and the app retries every 250 ms.
    @Test func requestsJustBeforeTheStartCount() {
        var a = HandOffActivity()
        a.noteRequest(id, at: t0.addingTimeInterval(-1))
        a.noteRefusal(id, "save", at: t0.addingTimeInterval(-0.5))
        a.noteRequest("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", at: t0)  // another tunnel
        a.noteRequest(id, at: t0.addingTimeInterval(-60))  // long before: an earlier connect
        let seen = a.summary(id, since: t0.addingTimeInterval(-HandOffDiagnosis.lookback))
        #expect(seen.requests == 1)
        #expect(seen.refusals == ["save": 1])
    }

    @Test func activityIsBounded() {
        var a = HandOffActivity()
        for i in 0..<(HandOffActivity.capacity + 50) { a.noteRequest(id, at: t0.addingTimeInterval(Double(i))) }
        #expect(a.events.count == HandOffActivity.capacity)
        #expect(a.events.first?.at == t0.addingTimeInterval(50))
    }

    // MARK: Diagnosis

    @Test func nothingForThisTunnelMeansTheAppNeverReachedTheExtension() {
        let d = HandOffDiagnosis(requests: 0, profile: .current)
        #expect(d.appNeverReachedExtension)
        #expect(d.line == "hand-off: 0 request(s) from Wombat, profile current, refused: none")
        #expect(HandOffDiagnosis.unreachableMessage.contains("Wombat OpenConnect"))
    }

    /// A refusal is an answer: the extension was reached, so "turn it off and on" is wrong.
    @Test func aRefusalCountsAsReached() {
        let d = HandOffDiagnosis(requests: 0, profile: .older, refusals: ["save": 2, "revision": 1])
        #expect(!d.appNeverReachedExtension)
        #expect(d.line.hasSuffix("profile older, refused: revision ×1, save ×2"))
    }

    /// The line is fixed words and counts: nothing a scrubber would have to remove.
    @Test func diagnosisLineSurvivesTheScrubberUnchanged() {
        let d = HandOffDiagnosis(requests: 2, profile: .missing, refusals: ["owner": 1])
        #expect(LogScrubber.scrub(d.line) == d.line)
        let text = HandOffTimeoutText.openConnect(d)
        #expect(LogScrubber.scrub(text) == text)
    }

    // MARK: Report

    @Test func appCauseIsAddedToTheTimeoutText() {
        let timeout = HandOffTimeoutText.openConnect(HandOffDiagnosis(requests: 3, profile: .current))
        #expect(timeout.hasPrefix(HandOffTimeoutText.openConnect))
        #expect(HandOffReport.isHandOffTimeout(timeout))
        #expect(HandOffReport.reason(extensionReason: timeout, appNote: .cause("Could not save: EPERM"))
            == timeout + " (Wombat: Could not save: EPERM)")
        #expect(HandOffReport.reason(extensionReason: timeout, appNote: nil) == timeout)
        // Any other end reason stays as the extension wrote it.
        #expect(HandOffReport.reason(extensionReason: "The gateway ended the session", appNote: .cause("x")) == "The gateway ended the session")
    }

    /// The app knows why it never got through: its cause replaces the "turn it off and on"
    /// advice, which would be wrong then (review M1).
    @Test func appCauseReplacesTheUnreachableAdvice() {
        let reason = HandOffReport.reason(extensionReason: HandOffDiagnosis.unreachableMessage,
                                          appNote: .cause("The keychain item for this tunnel is missing"))
        #expect(reason == "Wombat couldn't hand over this VPN's sign-in: The keychain item for this tunnel is missing")
        #expect(HandOffReport.reason(extensionReason: HandOffDiagnosis.unreachableMessage, appNote: nil) == HandOffDiagnosis.unreachableMessage)
    }

    @Test func everyExtensionsTimeoutTextIsRecognized() {
        for text in HandOffTimeoutText.all { #expect(HandOffReport.isHandOffTimeout(text)) }
        #expect(!HandOffReport.isHandOffTimeout("Sign in from Wombat to connect this VPN"))
    }

    // MARK: App log lines

    @Test func appLinesArePutBackAfterACopy() {
        let fresh = ["2026-11-16T14:36:27.100Z Starting tunnel, requested by the app", "2026-11-16T14:36:37.200Z Cannot start: x"]
        let app = ["2026-11-16T14:36:27.400Z Hand-off: the hand-off failed: y", "2026-11-16T14:36:37.300Z Tunnel ended: x"]
        #expect(AppLogMerge.merge(fresh: fresh, appLines: app) == fresh + app)
        // Already there: not twice.
        #expect(AppLogMerge.merge(fresh: fresh + app, appLines: app) == fresh + app)
        // Nothing fetched: nothing to merge into.
        #expect(AppLogMerge.merge(fresh: [], appLines: app).isEmpty)
    }

    /// A later session macOS started itself must not end with an earlier run's lines.
    @Test func olderAppLinesStayOut() {
        let fresh = ["2026-11-16T15:00:00.000Z Starting tunnel, requested by the system"]
        let app = ["2026-11-16T14:36:37.300Z Tunnel ended: x"]
        #expect(AppLogMerge.merge(fresh: fresh, appLines: app) == fresh)
    }
}

/// Decision 2-B: each AnyConnect session is bound to one connect attempt.
@Suite struct StartNonceTests {
    let rev = "11111111-1111-1111-1111-111111111111"
    let id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"

    @Test func generatedNoncesAreValidAndDistinct() throws {
        let a = try #require(StartNonce.generate())
        let b = try #require(StartNonce.generate())
        #expect(StartNonce.isValid(a) && StartNonce.isValid(b))
        #expect(a != b)
        #expect(Data(base64Encoded: a)?.count == 32)
    }

    @Test func matchingRules() throws {
        let a = try #require(StartNonce.generate())
        let b = try #require(StartNonce.generate())
        #expect(StartNonce.matches(nil, nil))
        #expect(StartNonce.matches(a, a))
        #expect(!StartNonce.matches(a, b))
        #expect(!StartNonce.matches(a, nil))
        #expect(!StartNonce.matches(nil, a))
        // Malformed values never match, not even themselves.
        #expect(!StartNonce.matches("x", "x"))
        #expect(!StartNonce.matches(Data(count: 16).base64EncodedString(), Data(count: 16).base64EncodedString()))
        #expect(!StartNonce.isValid(Data(count: 33).base64EncodedString()))
        #expect(!StartNonce.isValid(String(repeating: "A", count: 100)))
    }

    /// The four app/extension version pairings, modeled with the store and the start's options.
    /// Old app: no nonce in the session or the options. Old extension: ignores both (it neither
    /// stores nor compares one), which is today's behavior.
    @Test func versionSkew() throws {
        let nonce = try #require(StartNonce.generate())
        // Old app + new extension: no nonce either side, works as before.
        var s = HeldSessions<String>(lifetime: 600)
        s.put(id, owner: 501, revision: rev, value: "old-app", nonce: nil)
        let oldApp = s.session(id, owner: 501, revision: rev, nonce: nil)
        #expect(oldApp?.value == "old-app")
        // New app + new extension: same nonce, works.
        s.put(id, owner: 501, revision: rev, value: "new-app", nonce: nonce)
        let sameAttempt = s.session(id, owner: 501, revision: rev, nonce: nonce)
        #expect(sameAttempt?.value == "new-app")
        // New app + old extension: the old extension decodes the session without the field
        // (shown by the JSON test below) and starts as today.
        // A start nobody signed in for (System Settings, no options) can't use the app's session,
        // and doesn't destroy it either: its own attempt may still be on its way.
        let systemStart = s.session(id, owner: 501, revision: rev, nonce: nil)
        #expect(systemStart == nil)
        #expect(s.count == 1)
        // Another attempt's start can't use it.
        let other = s.session(id, owner: 501, revision: rev, nonce: try #require(StartNonce.generate()))
        #expect(other == nil)
    }

    /// The wire format: an extension from before 1.4.6 decodes a new app's session (it ignores
    /// the extra key), and a new extension decodes an old app's (no key: nil).
    @Test func sessionJSONStaysCompatible() throws {
        struct OldSession: Codable { var cookie: String; var host: String; var port: Int; var address: String?
            var serverCertificateSHA256: String; var issued: Date; var strapKey: String? }
        var new = AnyConnectSession(cookie: "ABC", host: "vpn.example.edu", port: 443, address: "192.0.2.1",
                                    serverCertificateSHA256: String(repeating: "a", count: 64))
        new.startNonce = StartNonce.generate()
        let data = try JSONEncoder().encode(new)
        let seenByOld = try JSONDecoder().decode(OldSession.self, from: data)
        #expect(seenByOld.cookie == "ABC")
        let oldData = try JSONEncoder().encode(seenByOld)
        let seenByNew = try JSONDecoder().decode(AnyConnectSession.self, from: oldData)
        #expect(seenByNew.startNonce == nil)
    }

    @Test func malformedNonceIsRefusedByValidate() {
        var s = AnyConnectSession(cookie: "ABC", host: "vpn.example.edu", port: 443, address: "192.0.2.1",
                                  serverCertificateSHA256: String(repeating: "a", count: 64))
        s.startNonce = "not-a-nonce"
        #expect(s.validate() == "Invalid start nonce")
        s.startNonce = StartNonce.generate()
        #expect(s.validate() != "Invalid start nonce")
    }

    /// With nonces, a sessionless cleanup drops exactly its own attempt's session, whatever the
    /// order of starts and hand-offs (closes review L1 fully for apps from 1.4.6).
    @Test func cleanupWithNonceDropsOnlyItsOwnAttempt() throws {
        let mine = try #require(StartNonce.generate())
        let next = try #require(StartNonce.generate())
        let t0 = Date(timeIntervalSince1970: 1_000_000)
        var s = HeldSessions<String>(lifetime: 600)
        let token = s.beginStart(id, now: t0)
        s.put(id, owner: 501, revision: rev, value: "next", nonce: next, now: t0.addingTimeInterval(1))
        // Still the newest start, and the session came "before" a late cutoff: no matter.
        let dropped = s.drop(id, ifLatestStart: token, nonce: mine, receivedBy: t0.addingTimeInterval(5))
        #expect(!dropped)
        s.put(id, owner: 501, revision: rev, value: "mine", nonce: mine, now: t0.addingTimeInterval(2))
        let droppedMine = s.drop(id, ifLatestStart: 999, nonce: mine, receivedBy: t0)
        #expect(droppedMine)
        // A start without a nonce never drops a nonce-bound session.
        s.put(id, owner: 501, revision: rev, value: "bound", nonce: next, now: t0)
        let t2 = s.beginStart(id, now: t0)
        let byOld = s.drop(id, ifLatestStart: t2, nonce: nil, receivedBy: t0.addingTimeInterval(5))
        #expect(!byOld)
    }

    @Test func runningStartsAreCounted() {
        var s = HeldSessions<String>(lifetime: 600)
        let a = s.beginStart(id)
        let b = s.beginStart("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
        #expect(s.runningStarts(excluding: a) == 1)
        s.finishStart(b)
        s.finishStart(b)
        #expect(s.runningStarts(excluding: a) == 0)
        #expect(s.runningStarts(excluding: nil) == 1)
    }
}

/// Decision 1-B: the OpenConnect extension quits itself only when nothing lives in it.
@Suite struct ExtensionSelfRestartTests {
    let now = Date(timeIntervalSince1970: 2_000_000)
    func input(_ change: (inout ExtensionSelfRestart.Input) -> Void = { _ in }) -> ExtensionSelfRestart.Input {
        var i = ExtensionSelfRestart.Input(appNeverReached: true, otherRunningStarts: 0, heldSessions: 0, recentRequests: 0, lastRestart: nil, now: now)
        change(&i)
        return i
    }

    @Test func restartsOnlyWhenNothingElseLivesInIt() {
        #expect(ExtensionSelfRestart.decide(input()) == .restart)
        #expect(ExtensionSelfRestart.decide(input { $0.appNeverReached = false }) == .stay("the app reached the extension"))
        #expect(ExtensionSelfRestart.decide(input { $0.otherRunningStarts = 1 }) == .stay("another tunnel is running in the extension"))
        #expect(ExtensionSelfRestart.decide(input { $0.heldSessions = 1 }) == .stay("a sign-in is still held"))
        #expect(ExtensionSelfRestart.decide(input { $0.recentRequests = 1 }) == .stay("the app sent a request meanwhile"))
    }

    /// No loop: a second restart within the interval is refused (the user gets the toggle advice).
    @Test func notTwiceWithinTheInterval() {
        let recent = now.addingTimeInterval(-60)
        let old = now.addingTimeInterval(-ExtensionSelfRestart.minimumInterval - 1)
        #expect(ExtensionSelfRestart.decide(input { $0.lastRestart = recent }) == .stay("already restarted recently"))
        #expect(ExtensionSelfRestart.decide(input { $0.lastRestart = old }) == .restart)
        // A time in the future (clock set back) doesn't block forever.
        #expect(ExtensionSelfRestart.decide(input { $0.lastRestart = now.addingTimeInterval(3600) }) == .restart)
    }

    @Test func logLineAndMessageAreFixedText() {
        #expect(LogScrubber.scrub(ExtensionSelfRestart.logLine) == ExtensionSelfRestart.logLine)
        #expect(HandOffReport.isHandOffTimeout(ExtensionSelfRestart.message))
        // The app knows a cause of its own: that wins over "restarted, connect again".
        #expect(HandOffReport.reason(extensionReason: ExtensionSelfRestart.message, appNote: .cause("keychain"))
            == "Wombat couldn't hand over this VPN's sign-in: keychain")
    }
}

/// Requests for any tunnel count against a restart.
@Suite struct HandOffActivityTotalTests {
    @Test func totalCountsEveryTunnel() {
        var a = HandOffActivity()
        let t0 = Date(timeIntervalSince1970: 3_000_000)
        a.noteRequest("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", at: t0)
        a.noteRefusal("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "save", at: t0.addingTimeInterval(1))
        a.noteRequest("cccccccc-cccc-cccc-cccc-cccccccccccc", at: t0.addingTimeInterval(-100))
        #expect(a.total(since: t0.addingTimeInterval(-15)) == 2)
    }
}

/// Review round 2: the app's 12 s "didn't answer" note is the extension's own finding seen from
/// the other side; it must not replace the extension's advice (M1), while a real cause does.
@Suite struct AppHandOffNoteTests {
    let unreachable = AppHandOffNote.unreachable("the OpenConnect extension's service didn't answer Wombat for 12 s")

    @Test func adviceSurvivesTheAppsUnreachableNote() {
        for advice in HandOffReport.adviceTexts {
            let shown = HandOffReport.reason(extensionReason: advice, appNote: unreachable)
            #expect(shown == advice)
            // So the Fix It button (matched by prefix) still shows.
            #expect(HandOffReport.adviceTexts.contains { shown.hasPrefix($0) })
        }
    }

    @Test func aCauseStillReplacesTheAdvice() {
        let shown = HandOffReport.reason(extensionReason: ExtensionSelfRestart.message, appNote: .cause("Could not save: EPERM"))
        #expect(shown == "Wombat couldn't hand over this VPN's sign-in: Could not save: EPERM")
    }

    @Test func theGenericTimeoutGetsEitherNote() {
        let timeout = HandOffTimeoutText.openConnect
        #expect(HandOffReport.reason(extensionReason: timeout, appNote: unreachable) == timeout + " (Wombat: \(unreachable.text))")
    }
}

/// The restart marker's format (security-2 N1, review S6).
@Suite struct RestartMarkerTests {
    @Test func roundTrips() {
        let date = Date(timeIntervalSince1970: 1_800_000_000.5)
        #expect(ExtensionSelfRestart.parseMarker(ExtensionSelfRestart.marker(for: date)) == date)
    }

    @Test func rejectsAnythingElse() {
        for text in ["", "garbage", "nan", "inf", "-inf", "-5", "0", String(repeating: "1", count: 40)] {
            #expect(ExtensionSelfRestart.parseMarker(Data(text.utf8)) == nil, "\(text)")
        }
        #expect(ExtensionSelfRestart.parseMarker(Data([0xff, 0xfe])) == nil)
        #expect(ExtensionSelfRestart.parseMarker(Data(" 1800000000\n".utf8)) == Date(timeIntervalSince1970: 1_800_000_000))
    }
}

/// A start's life on the store, as the provider drives it (review S6).
@Suite struct StartLifecycleTests {
    let a = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    let b = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
    let rev = "11111111-1111-1111-1111-111111111111"

    func restart(_ s: HeldSessions<String>, excluding token: UInt64?) -> ExtensionSelfRestart.Decision {
        ExtensionSelfRestart.decide(.init(appNeverReached: true, otherRunningStarts: s.runningStarts(excluding: token),
                                          heldSessions: s.count, recentRequests: 0, lastRestart: nil))
    }

    @Test func failedStartAloneMayRestart() {
        var s = HeldSessions<String>(lifetime: 600)
        let t = s.beginStart(a)
        #expect(restart(s, excluding: t) == .restart)
        s.finishStart(t)  // the completion wrapper
        #expect(restart(s, excluding: t) == .restart)
    }

    @Test func aTunnelUpElsewhereBlocksIt() {
        var s = HeldSessions<String>(lifetime: 600)
        let up = s.beginStart(b)
        let g = s.put(b, owner: 501, revision: rev, value: "b")
        _ = s.session(b, owner: 501, revision: rev)
        let failing = s.beginStart(a)
        #expect(restart(s, excluding: failing) == .stay("another tunnel is running in the extension"))
        // The tunnel ends on its own: its session goes by generation and its start finishes.
        s.drop(b, generation: g)
        s.finishStart(up)
        #expect(restart(s, excluding: failing) == .restart)
    }

    @Test func anUnclaimedSessionBlocksItUntilPruned() {
        var s = HeldSessions<String>(lifetime: 600)
        let t0 = Date(timeIntervalSince1970: 1_000_000)
        s.put(b, owner: 501, revision: rev, value: "late", nonce: StartNonce.generate(), now: t0)
        let failing = s.beginStart(a, now: t0)
        #expect(restart(s, excluding: failing) == .stay("a sign-in is still held"))
        s.pruneExpired(t0.addingTimeInterval(601))
        #expect(restart(s, excluding: failing) == .restart)
    }
}
