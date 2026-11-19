import Foundation
import TunnelCore

/// The OpenConnect extension's store: profiles on disk like the WireGuard extension's configs
/// (root-only, owner recorded), and session tokens from sign-ins in memory only. A token is a
/// bearer credential for the VPN session, so it never touches a disk and goes when the tunnel
/// stops (the stop also logs it off at the gateway).
final class OpenConnectStore: SecretStore, OpenConnectStoreProtocol, @unchecked Sendable {
    /// A start must follow its sign-in within this time; older tokens are refused.
    static let sessionLifetime: TimeInterval = 10 * 60

    private let sessionLock = NSLock()
    /// Generation-tagged, so a previous start's late cleanup can't drop a newer hand-off.
    private var sessions = HeldSessions<AnyConnectSession>(lifetime: OpenConnectStore.sessionLifetime)

    init() {
        super.init(maxBytes: OpenConnectFile.maxBytes, interface: NSXPCInterface(with: OpenConnectStoreProtocol.self)) { text in
            let parsed = OpenConnectFile.parse(text)
            return parsed.profile == nil ? parsed.errors.map(\.description).joined(separator: "; ") : nil
        }
        // A removed or pruned tunnel's session goes with it.
        onForget = { [weak self] id in self?.dropSession(for: id) }
    }

    private static func key(_ id: String) -> String? { UUID(uuidString: id)?.uuidString.lowercased() }

    func storeSession(id: String, revision: String, session data: Data, reply: @escaping (String?) -> Void) {
        noteRequest(id)
        guard let uid = callerUID() else { noteRefusal(id, "caller"); return reply("Unknown caller") }
        guard let key = Self.key(id), UUID(uuidString: revision) != nil else { noteRefusal(id, "invalid"); return reply("Invalid tunnel id") }
        guard data.count <= AnyConnectSession.maxBytes, let session = try? JSONDecoder().decode(AnyConnectSession.self, from: data) else {
            noteRefusal(id, "invalid")
            return reply("Invalid session")
        }
        if let problem = session.validate() { noteRefusal(id, "invalid"); return reply(problem) }
        reply(hold(session, key: key, id: id, revision: revision, uid: uid))
    }

    /// The backup hand-off route (`ProviderHandOff`): the provider holds its own start's session
    /// for the owner its configuration names, with the same checks as `storeSession`.
    func storeSessionForStart(id: String, revision: String, session: AnyConnectSession, uid: UInt32) -> String? {
        guard let key = Self.key(id), UUID(uuidString: revision) != nil else { return "Invalid tunnel id" }
        if let problem = session.validate() { return problem }
        return hold(session, key: key, id: id, revision: revision, uid: uid)
    }

    /// Holds a session for its owner's tunnel at the profile revision it was signed in for.
    /// nil on success, else the reason.
    private func hold(_ session: AnyConnectSession, key: String, id: String, revision: String, uid: UInt32) -> String? {
        // Only for the caller's own tunnel, and only for the profile revision it signed in with.
        guard let owner = owner(of: id) else { noteRefusal(id, "no-profile"); return "The extension has no profile for this tunnel yet" }
        guard owner == uid else {
            noteRefusal(id, "owner")
            log.error("Refused a session for \(id, privacy: .public): owned by uid \(owner, privacy: .public), caller \(uid, privacy: .public)")
            return "This tunnel belongs to another user of this Mac"
        }
        guard self.revision(of: id) == .some(revision) else { noteRefusal(id, "revision"); return "The extension's copy of this VPN is out of date; try again" }
        // Tokens handed over but never used go once they're too old to start (S5-I6).
        let generation = sessionLock.withLock { sessions.put(key, owner: uid, revision: revision, value: session, nonce: session.startNonce) }
        log.notice("Received a session for \(id, privacy: .public) (generation \(generation, privacy: .public))")
        // An unclaimed token goes at its lifetime, not at the next start (security-2 L4).
        // Wall clock, so sleep counts (review round 3, R3).
        DispatchQueue.global(qos: .utility).asyncAfter(wallDeadline: .now() + Self.sessionLifetime + 1) { [weak self] in
            guard let self else { return }
            self.sessionLock.withLock { self.sessions.pruneExpired() }
        }
        return nil
    }

    /// The session for a start: same owner and revision as the profile, recent, and signed in
    /// for this start (`nonce`, decision 2-B), with the generation a cleanup must name to drop it.
    func session(for id: String, revision: String?, nonce: String?) -> (session: AnyConnectSession, generation: UInt64)? {
        guard let key = Self.key(id) else { return nil }
        let owner = owner(of: id)
        return sessionLock.withLock {
            sessions.session(key, owner: owner, revision: revision, nonce: nonce).map { ($0.value, $0.generation) }
        }
    }

    func hasSession(for id: String, revision: String, nonce: String?) -> Bool { session(for: id, revision: revision, nonce: nonce) != nil }

    /// Every session of the tunnel (it was removed or pruned).
    func dropSession(for id: String) {
        guard let key = Self.key(id) else { return }
        sessionLock.withLock { sessions.drop(key) }
    }

    /// Only the session a start used: a newer hand-off stays.
    func dropSession(for id: String, generation: UInt64) {
        guard let key = Self.key(id) else { return }
        sessionLock.withLock { _ = sessions.drop(key, generation: generation) }
    }

    /// A provider's start began; the token lets a start that never used a session clean up
    /// without touching a later start's, and counts it as running until `finishStart`.
    func beginStart(for id: String) -> UInt64? {
        guard let key = Self.key(id) else { return nil }
        return sessionLock.withLock { sessions.beginStart(key) }
    }

    /// The start failed or stopped (idempotent).
    func finishStart(_ token: UInt64) {
        sessionLock.withLock { sessions.finishStart(token) }
    }

    /// Only the session signed in for this start (its nonce), or, without a nonce, one received
    /// by `cutoff` (when that start stopped or was refused) while no newer start has begun.
    func dropSession(for id: String, ifLatestStart token: UInt64, nonce: String?, receivedBy cutoff: Date) {
        guard let key = Self.key(id) else { return }
        sessionLock.withLock { _ = sessions.drop(key, ifLatestStart: token, nonce: nonce, receivedBy: cutoff) }
    }

    /// No start running and no sign-in waiting for one: quitting would lose a session.
    override func idleForReplacement(exit: Bool = false) -> Bool {
        sessionLock.withLock {
            let idle = sessions.runningStarts(excluding: nil) == 0 && sessions.count == 0
            // Under the session lock: no session can be accepted between the check and the exit.
            if idle, exit { _exit(0) }
            return idle
        }
    }

    // MARK: Self-restart (decision 1-B)

    /// What the self-restart rule sees now, for a start failing with no request from the app.
    func selfRestartInput(excluding token: UInt64?, requestsSince: Date) -> ExtensionSelfRestart.Input {
        let (running, held) = sessionLock.withLock { (sessions.runningStarts(excluding: token), sessions.count) }
        return ExtensionSelfRestart.Input(appNeverReached: true, otherRunningStarts: running, heldSessions: held,
                                          recentRequests: handOffActivityTotal(since: requestsSince), lastRestart: lastSelfRestart())
    }

    /// The final check, the record and the exit as one step: under the session lock (every start
    /// and hand-off takes it) and the activity lock (every request notes itself there first), so
    /// nothing can be accepted between the check and the exit (security-2 L1). A request that
    /// arrives meanwhile waits on a lock and sees the connection end, which the app treats like
    /// any interruption. Returns the reason when it stays. `_exit`: no atexit handlers (OpenSSL
    /// registers one) run while other threads exist (security-2 N4).
    func exitIfIdle(excluding token: UInt64?, requestsSince: Date) -> String {
        sessionLock.withLock {
            withActivityLocked { activity in
                let input = ExtensionSelfRestart.Input(appNeverReached: true, otherRunningStarts: sessions.runningStarts(excluding: token),
                                                       heldSessions: sessions.count, recentRequests: activity.total(since: requestsSince),
                                                       lastRestart: lastSelfRestart())
                if case .stay(let reason) = ExtensionSelfRestart.decide(input) { return reason }
                // No record, no exit: the record is what stops a second restart within 15 min.
                guard recordSelfRestart() else { return "could not record the restart" }
                log.notice("\(ExtensionSelfRestart.logLine, privacy: .public)")
                _exit(0)
            }
        }
    }

    /// In the container's Application Support folder, which belongs to root (0600 file); only the
    /// time, so a restart loop can be refused across processes.
    private var restartMarker: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("last-self-restart")
    }

    func lastSelfRestart() -> Date? {
        guard let handle = try? FileHandle(forReadingFrom: restartMarker) else { return nil }
        defer { try? handle.close() }
        return (try? handle.read(upToCount: 33)).flatMap { ExtensionSelfRestart.parseMarker($0) }
    }

    /// Fails closed: if the time can't be written, the restart doesn't happen (no unguarded loop).
    func recordSelfRestart(_ now: Date = Date()) -> Bool {
        do {
            let folder = restartMarker.deletingLastPathComponent()
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            try ExtensionSelfRestart.marker(for: now).write(to: restartMarker, options: [.atomic])
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: restartMarker.path)
            return true
        } catch {
            log.error("Could not record the self-restart: \(FileErrorDetail.describe(error), privacy: .public)")
            return false
        }
    }
}
