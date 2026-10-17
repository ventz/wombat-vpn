import Foundation
import TunnelCore

/// The OpenConnect extension's store: profiles on disk like the WireGuard extension's configs
/// (root-only, owner recorded), and session tokens from sign-ins in memory only. A token is a
/// bearer credential for the VPN session, so it never touches a disk and goes when the tunnel
/// stops (the stop also logs it off at the gateway).
final class OpenConnectStore: SecretStore, OpenConnectStoreProtocol, @unchecked Sendable {
    /// A start must follow its sign-in within this time; older tokens are refused.
    static let sessionLifetime: TimeInterval = 10 * 60

    private struct Held {
        let owner: UInt32
        let revision: String
        let session: AnyConnectSession
        let received: Date
    }

    private let sessionLock = NSLock()
    private var sessions: [String: Held] = [:]

    init() {
        super.init(maxBytes: OpenConnectFile.maxBytes, interface: NSXPCInterface(with: OpenConnectStoreProtocol.self)) { text in
            let parsed = OpenConnectFile.parse(text)
            return parsed.profile == nil ? parsed.errors.map(\.description).joined(separator: "; ") : nil
        }
        // A removed or pruned tunnel's session goes with it.
        onForget = { [weak self] id in self?.dropSession(for: id) }
    }

    func storeSession(id: String, revision: String, session data: Data, reply: @escaping (String?) -> Void) {
        guard let uid = callerUID() else { return reply("Unknown caller") }
        guard let key = UUID(uuidString: id)?.uuidString.lowercased(), UUID(uuidString: revision) != nil else { return reply("Invalid tunnel id") }
        guard data.count <= AnyConnectSession.maxBytes, let session = try? JSONDecoder().decode(AnyConnectSession.self, from: data) else {
            return reply("Invalid session")
        }
        if let problem = session.validate() { return reply(problem) }
        // Only for the caller's own tunnel, and only for the profile revision it signed in with.
        guard let owner = owner(of: id) else { return reply("The extension has no profile for this tunnel yet") }
        guard owner == uid else {
            log.error("Refused a session for \(id, privacy: .public): owned by uid \(owner, privacy: .public), caller \(uid, privacy: .public)")
            return reply("This tunnel belongs to another user of this Mac")
        }
        guard self.revision(of: id) == .some(revision) else { return reply("The extension's copy of this VPN is out of date; try again") }
        sessionLock.withLock {
            // Tokens handed over but never used go once they're too old to start (S5-I6).
            sessions = sessions.filter { Date().timeIntervalSince($0.value.received) <= Self.sessionLifetime }
            sessions[key] = Held(owner: uid, revision: revision, session: session, received: Date())
        }
        log.notice("Received a session for \(id, privacy: .public)")
        reply(nil)
    }

    /// The session for a start: same owner and revision as the profile, and recent.
    func session(for id: String, revision: String?) -> AnyConnectSession? {
        guard let key = UUID(uuidString: id)?.uuidString.lowercased() else { return nil }
        let owner = owner(of: id)
        return sessionLock.withLock {
            guard let held = sessions[key] else { return nil }
            guard held.owner == owner, revision == nil || held.revision == revision,
                  Date().timeIntervalSince(held.received) <= Self.sessionLifetime else {
                sessions[key] = nil
                return nil
            }
            return held.session
        }
    }

    func hasSession(for id: String, revision: String) -> Bool { session(for: id, revision: revision) != nil }

    func dropSession(for id: String) {
        guard let key = UUID(uuidString: id)?.uuidString.lowercased() else { return }
        sessionLock.withLock { sessions[key] = nil }
    }
}
