import Foundation
import Security

/// A random value the app makes for one connect attempt and sends both in the start's options
/// and with the session it hands over, so a start uses only the session signed in for it (review
/// round 2, decision 2-B). Without it, a session delivered after its start had been stopped (from
/// System Settings, say) stayed usable for 10 minutes by any later start of that VPN, including
/// one nobody signed in for. Not a credential by itself (the token is), but never logged anyway.
public enum StartNonce {
    public static let byteCount = 32

    /// 32 bytes from the system CSPRNG, base64. nil only if the CSPRNG fails (then the connect
    /// fails rather than going ahead unbound).
    public static func generate() -> String? {
        var bytes = [UInt8](repeating: 0, count: byteCount)
        guard SecRandomCopyBytes(kSecRandomDefault, byteCount, &bytes) == errSecSuccess else { return nil }
        return Data(bytes).base64EncodedString()
    }

    /// The form a nonce must have on the wire.
    public static func isValid(_ nonce: String) -> Bool {
        nonce.utf8.count <= 64 && Data(base64Encoded: nonce)?.count == byteCount
    }

    /// Both absent (an app from before 1.4.6), or both present and equal. Equal is checked over
    /// every byte whatever the content, so the time taken says nothing about how much matched.
    public static func matches(_ a: String?, _ b: String?) -> Bool {
        switch (a, b) {
        case (nil, nil): return true
        case let (a?, b?):
            guard let x = Data(base64Encoded: a), let y = Data(base64Encoded: b),
                  x.count == byteCount, y.count == byteCount else { return false }
            var difference: UInt8 = 0
            for i in 0..<byteCount { difference |= x[i] ^ y[i] }
            return difference == 0
        default: return false
        }
    }
}

/// The sign-in sessions the OpenConnect extension holds in memory, one per tunnel id, and the
/// starts it is running.
///
/// One extension process serves every start of a tunnel, and a previous start's cleanup can run
/// late: `stopTunnel` waits up to 10 s for the gateway's goodbye, and the main loop's exit
/// handler fires whenever the loop ends. Those cleanups used to drop "the session for this id",
/// which could be the session the app had just handed over for the NEXT start; that start then
/// waited for nothing. Each session now carries a generation, and a cleanup drops only the
/// session it used. A start that never got one drops only a session carrying its own nonce, or
/// (no nonce: an app from before 1.4.6) one received before its stop while it is the newest start.
///
/// Not thread-safe: the extension's store wraps it in a lock.
public struct HeldSessions<Value> {
    public struct Held {
        public let owner: UInt32
        public let revision: String
        public let value: Value
        public let received: Date
        public let generation: UInt64
        /// The connect attempt it was signed in for (nil: an app from before 1.4.6).
        public let nonce: String?
    }

    public let lifetime: TimeInterval
    private var held: [String: Held] = [:]
    private var latestStart: [String: UInt64] = [:]
    /// Starts that began and haven't finished (failed, or stopped), any tunnel.
    private var running: Set<UInt64> = []
    private var counter: UInt64 = 0

    public init(lifetime: TimeInterval) {
        self.lifetime = lifetime
    }

    private mutating func next() -> UInt64 {
        counter &+= 1
        return counter
    }

    /// Forgets sessions too old to start (also run on a timer after each hand-off, so an unclaimed
    /// token doesn't sit in memory until the next start; security-2 L4).
    public mutating func pruneExpired(_ now: Date = Date()) {
        held = held.filter { now.timeIntervalSince($0.value.received) <= lifetime }
    }

    /// Stores (or replaces) the session for `key`, and forgets sessions too old to start.
    /// Returns its generation.
    @discardableResult
    public mutating func put(_ key: String, owner: UInt32, revision: String, value: Value, nonce: String? = nil, now: Date = Date()) -> UInt64 {
        pruneExpired(now)
        let generation = next()
        held[key] = Held(owner: owner, revision: revision, value: value, received: now, generation: generation, nonce: nonce)
        return generation
    }

    /// The session for a start: same owner and revision as the profile, recent, and signed in
    /// for this start (`nonce`). A session that doesn't match the profile is dropped (fails
    /// closed). One for another connect attempt is left alone (that start may be on its way) and
    /// never returned here.
    public mutating func session(_ key: String, owner: UInt32?, revision: String?, nonce: String? = nil, now: Date = Date()) -> Held? {
        guard let entry = held[key] else { return nil }
        guard entry.owner == owner, revision == nil || entry.revision == revision,
              now.timeIntervalSince(entry.received) <= lifetime else {
            held[key] = nil
            return nil
        }
        guard StartNonce.matches(entry.nonce, nonce) else { return nil }
        return entry
    }

    /// Unconditional: a removed or pruned tunnel's session goes with it.
    public mutating func drop(_ key: String) {
        held[key] = nil
    }

    /// Drops the session only if it is still the one with this generation: a newer hand-off
    /// stays. Returns whether something went.
    @discardableResult
    public mutating func drop(_ key: String, generation: UInt64) -> Bool {
        guard held[key]?.generation == generation else { return false }
        held[key] = nil
        return true
    }

    /// A provider's start for `key` began; returns its token. A later start replaces it as the
    /// newest. Also forgets expired sessions, so one never outlives its lifetime by much.
    public mutating func beginStart(_ key: String, now: Date = Date()) -> UInt64 {
        pruneExpired(now)
        let token = next()
        latestStart[key] = token
        running.insert(token)
        return token
    }

    /// The start failed or stopped. Idempotent.
    public mutating func finishStart(_ token: UInt64) {
        running.remove(token)
    }

    /// Starts still running, other than `token`.
    public func runningStarts(excluding token: UInt64?) -> Int {
        running.subtracting(token.map { [$0] } ?? []).count
    }

    /// For a start that never got a session (stopped or refused before using one). With a nonce:
    /// only the session signed in for it. Without one (an app from before 1.4.6): only while this
    /// start is still the newest one for the tunnel AND the session came before `cutoff` (when
    /// the stop or refusal happened); the app hands a session over before it starts the next
    /// connection when the extension is already running (review S5/L1).
    @discardableResult
    public mutating func drop(_ key: String, ifLatestStart token: UInt64, nonce: String? = nil, receivedBy cutoff: Date) -> Bool {
        guard let entry = held[key] else { return false }
        if let nonce {
            guard let mine = entry.nonce, StartNonce.matches(mine, nonce) else { return false }
        } else {
            guard entry.nonce == nil, latestStart[key] == token, entry.received <= cutoff else { return false }
        }
        held[key] = nil
        return true
    }

    public var count: Int { held.count }
}

/// Requests and refusals the extension's store saw, per tunnel, with times: what a start that
/// waited in vain for its hand-off checks to say which stage failed. Counts and fixed labels
/// only, never request data. Bounded. Not thread-safe: the store wraps it in a lock.
public struct HandOffActivity {
    public struct Event: Equatable {
        public let key: String
        /// nil for a request that was accepted (or not yet judged); else the refusal label.
        public let refusal: String?
        public let at: Date
    }

    public static let capacity = 256
    public private(set) var events: [Event] = []

    public init() {}

    private mutating func add(_ event: Event) {
        events.append(event)
        if events.count > Self.capacity { events.removeFirst(events.count - Self.capacity) }
    }

    /// The app asked about or handed over something for this tunnel.
    public mutating func noteRequest(_ key: String, at: Date = Date()) {
        add(Event(key: key, refusal: nil, at: at))
    }

    /// `label` is a fixed word ("owner", "revision", "save"...), never text from the request.
    public mutating func noteRefusal(_ key: String, _ label: String, at: Date = Date()) {
        add(Event(key: key, refusal: label, at: at))
    }

    /// Requests and refusals for any tunnel from `since` on.
    public func total(since: Date) -> Int {
        events.filter { $0.at >= since }.count
    }

    /// What happened for `key` from `since` on.
    public func summary(_ key: String, since: Date) -> (requests: Int, refusals: [String: Int]) {
        var requests = 0
        var refusals: [String: Int] = [:]
        for e in events where e.key == key && e.at >= since {
            if let label = e.refusal { refusals[label, default: 0] += 1 } else { requests += 1 }
        }
        return (requests, refusals)
    }
}

/// What the OpenConnect extension knows when its wait for the app's hand-off ends without a
/// session, so the next report says which stage failed instead of "try connecting again".
public struct HandOffDiagnosis: Equatable, Sendable {
    public enum Profile: String, Sendable { case current, older, missing }

    /// How far before the start a request still counts as this start's: the app's last check
    /// ran just before it asked macOS to start the tunnel, and the extension's listener is up
    /// before the provider's start is called (review M1).
    public static let lookback: TimeInterval = 15

    /// Requests from the app for this tunnel since shortly before the start.
    public var requests: Int
    public var profile: Profile
    /// Requests for this tunnel the store turned down, by fixed label.
    public var refusals: [String: Int]

    public init(requests: Int, profile: Profile, refusals: [String: Int] = [:]) {
        self.requests = requests
        self.profile = profile
        self.refusals = refusals
    }

    /// Fixed words and counts only: safe for the error text, the Log tab and the system log.
    public var line: String {
        let refused = refusals.isEmpty ? "none"
            : refusals.sorted { $0.key < $1.key }.map { "\($0.key) ×\($0.value)" }.joined(separator: ", ")
        return "hand-off: \(requests) request(s) from Wombat, profile \(profile.rawValue), refused: \(refused)"
    }

    /// Nothing from the app for this tunnel reached this process: the app couldn't find the
    /// extension's service, though macOS started the tunnel in it (the suspected state after the
    /// 1.4.5 update and in GitHub issue #4). Trying again doesn't help; restarting the extension
    /// should. A refusal counts as reaching it.
    public var appNeverReachedExtension: Bool { requests == 0 && refusals.isEmpty }

    /// The extension found its own XPC service missing from launchd: macOS replaced the extension
    /// while the old one was still exiting, and the new one never got its service (ProviderHandOff
    /// has the story). Restarting the extension can't fix that; restarting the Mac does, and
    /// turning the extension off and on would also remove its VPNs.
    public static let serviceMissingMessage = "macOS didn't finish updating the Wombat OpenConnect extension, so Wombat can't reach it to hand over this VPN's sign-in. Restart the Mac to fix it."

    public static let unreachableMessage = "Wombat couldn't reach the OpenConnect extension to hand over this VPN's sign-in. Turn “Wombat OpenConnect” off and on in System Settings › General › Login Items & Extensions › Extensions › Network Extensions (ⓘ), then connect again. If that doesn't help, restart the Mac."
}

/// The extensions' texts for a start whose hand-off didn't arrive in time, kept here so the
/// app's matching can't drift from them (review S4).
public enum HandOffTimeoutText {
    public static let openConnect = "Wombat didn't deliver this VPN's sign-in to the OpenConnect extension in time; try connecting again"
    public static let wireGuard = "Wombat didn't deliver this tunnel's configuration to the network extension in time; try connecting again"
    public static let tailnet = "Wombat didn't deliver this tailnet to the Tailnet extension in time; try connecting again"
    public static let all = [openConnect, wireGuard, tailnet, HandOffDiagnosis.unreachableMessage, ExtensionSelfRestart.message,
                             HandOffDiagnosis.serviceMissingMessage]

    /// The OpenConnect timeout with what the extension saw (its log lines may never reach the
    /// app once the session is stopping; the error text does, review S1).
    public static func openConnect(_ diagnosis: HandOffDiagnosis?) -> String {
        diagnosis.map { "\(openConnect) (\($0.line))" } ?? openConnect
    }
}

/// What the app's launch hand-off ran into for a start.
public enum AppHandOffNote: Equatable, Sendable {
    /// The app knows why it didn't get through: it failed before reaching the extension (a
    /// missing keychain item) or the extension answered and refused ("Could not save: …").
    case cause(String)
    /// The extension's service never answered for the whole wait: the same fact the extension
    /// reports from its side, not a cause, so it must not replace the extension's advice
    /// (review round 2, M1).
    case unreachable(String)

    public var text: String {
        switch self { case .cause(let t), .unreachable(let t): t }
    }
}

/// The app's side of a failed launch hand-off, joined with the extension's reason when the
/// tunnel ends, so the app's real cause ("Could not save: …", a missing keychain item) isn't
/// replaced by the extension's generic timeout text.
public enum HandOffReport {
    public static func isHandOffTimeout(_ reason: String) -> Bool {
        HandOffTimeoutText.all.contains { reason.hasPrefix($0) }
    }

    /// The extension's texts that carry advice of their own ("turn it off and on", "is restarting").
    public static let adviceTexts = [HandOffDiagnosis.unreachableMessage, ExtensionSelfRestart.message, HandOffDiagnosis.serviceMissingMessage]

    public static func reason(extensionReason: String, appNote: AppHandOffNote?) -> String {
        guard let appNote, !appNote.text.isEmpty, isHandOffTimeout(extensionReason) else { return extensionReason }
        if adviceTexts.contains(where: { extensionReason.hasPrefix($0) }) {
            switch appNote {
            // The app knows why it never got through: "turn the extension off and on" or "it is
            // restarting" would be the wrong advice (review M1).
            case .cause(let cause): return "Wombat couldn't hand over this VPN's sign-in: \(cause)"
            // The same silence seen from the app's side: the extension's advice stands.
            case .unreachable: return extensionReason
            }
        }
        return "\(extensionReason) (Wombat: \(appNote.text))"
    }
}

/// Puts the lines the app wrote itself (the end reason, hand-off problems) back into a fresh copy
/// of an extension's log, which never has them. Only lines no older than the copy's first line:
/// a session that macOS started on its own must not end with an earlier run's lines. Both sides
/// start with the same fixed-width UTC ISO 8601 timestamp, so text order is time order.
public enum AppLogMerge {
    public static func merge(fresh: [String], appLines: [String]) -> [String] {
        guard let first = fresh.first, !appLines.isEmpty else { return fresh }
        let since = first.first?.isNumber == true ? timestamp(first) : ""
        let missing = appLines.filter { line in
            !fresh.contains(line) && (since.isEmpty || timestamp(line) >= since)
        }
        return fresh + missing
    }

    private static func timestamp(_ line: String) -> Substring {
        line.prefix { $0 != " " }
    }
}

/// Decision 1-B (Ventz, 2026-11-16): when nothing from the app reached the OpenConnect extension
/// during a start's hand-off wait, the extension quits itself after failing that start, so macOS
/// starts a fresh copy on the next connect. Meant to do automatically what killing "the
/// openconnect processes" by hand did in GitHub issue #4; whether this process was the deaf one
/// there is not known (if a different, older process holds the service, this exit doesn't help,
/// and the second failure shows the "turn it off and on" advice). "Nothing reached it" is
/// inferred from silence, so it also fires when the app failed before any XPC call; harmless, the
/// process is idle and starts fresh. The one sanctioned exception to "no exit in the extension"
/// (pitfall 12): one process serves every AnyConnect tunnel and the XPC listener, so it may go
/// only when nothing else lives in it.
///
/// Why it can't loop: it runs only at the end of a start that waited for a hand-off
/// (`StartOption.awaitHandOff`), and every start needs someone to start it; a start whose options
/// lack that flag (System Settings) never gets here. The app is what sets it, but other processes
/// may be able to pass start options too (`SCNetworkConnectionStart`; not verified), so nothing
/// relies on that: a second restart within `minimumInterval` is refused (the time is kept in the
/// extension's root-only container) and the user is told to turn the extension off and on.
///
/// Why another process can't use it for worse than a reconnect: it fires only after a start
/// that already failed (and that start already stopped any other VPN, as any start does); it
/// never exits while another start runs, a session is held, or anything asked about any tunnel
/// since shortly before the start. The final check and the exit happen under the store's locks,
/// so no request is accepted in between (security-2 L1).
public enum ExtensionSelfRestart {
    public static let minimumInterval: TimeInterval = 15 * 60
    /// Between failing the start and exiting: NetworkExtension records the start's error first.
    public static let delay: TimeInterval = 2

    /// The marker file's content: the time of the last restart, as seconds since 1970.
    public static func marker(for date: Date) -> Data { Data(String(date.timeIntervalSince1970).utf8) }

    /// nil for anything that isn't a plain, finite, positive time (security-2 N1).
    public static func parseMarker(_ data: Data) -> Date? {
        guard data.count <= 32, let text = String(data: data, encoding: .utf8),
              let seconds = TimeInterval(text.trimmingCharacters(in: .whitespacesAndNewlines)),
              seconds.isFinite, seconds > 0 else { return nil }
        return Date(timeIntervalSince1970: seconds)
    }

    public struct Input: Equatable, Sendable {
        /// `HandOffDiagnosis.appNeverReachedExtension` for the failing start.
        public var appNeverReached: Bool
        /// Starts in this process still running, the failing one not counted.
        public var otherRunningStarts: Int
        /// Sessions still held in memory, any tunnel.
        public var heldSessions: Int
        /// Requests or refusals for ANY tunnel since shortly before the failing start.
        public var recentRequests: Int
        /// The last self-restart, if any (from the extension's container).
        public var lastRestart: Date?
        public var now: Date

        public init(appNeverReached: Bool, otherRunningStarts: Int, heldSessions: Int, recentRequests: Int, lastRestart: Date?, now: Date = Date()) {
            self.appNeverReached = appNeverReached
            self.otherRunningStarts = otherRunningStarts
            self.heldSessions = heldSessions
            self.recentRequests = recentRequests
            self.lastRestart = lastRestart
            self.now = now
        }
    }

    public enum Decision: Equatable, Sendable {
        case restart
        /// Fixed text, safe for the public log.
        case stay(String)
    }

    public static func decide(_ input: Input) -> Decision {
        guard input.appNeverReached else { return .stay("the app reached the extension") }
        guard input.otherRunningStarts == 0 else { return .stay("another tunnel is running in the extension") }
        guard input.heldSessions == 0 else { return .stay("a sign-in is still held") }
        guard input.recentRequests == 0 else { return .stay("the app sent a request meanwhile") }
        // A time in the future (the clock was set back) doesn't block: each restart still needs a
        // connect from the user, so the worst case is one more restart.
        if let last = input.lastRestart, input.now >= last, input.now.timeIntervalSince(last) < minimumInterval {
            return .stay("already restarted recently")
        }
        return .restart
    }

    /// Shown before the exit, so it says "is restarting", and asks for a short wait: a connect
    /// within the delay keeps the old process (review round 2, S1).
    public static let message = "Wombat couldn't hand over this VPN's sign-in to its OpenConnect extension, so the extension is restarting. Wait a few seconds, then connect again. If this keeps happening, turn “Wombat OpenConnect” off and on in System Settings › General › Login Items & Extensions › Extensions › Network Extensions (ⓘ), or restart the Mac."

    /// The public line logged right before the exit.
    public static let logLine = "Restarting the OpenConnect extension: nothing from Wombat reached it during the hand-off wait, and no tunnel or sign-in is held"
}
