import Foundation

/// The backup route for an AnyConnect hand-off: the profile and the sign-in session, sent by the
/// app as a provider message (`NETunnelProviderSession.sendProviderMessage`) to the start that is
/// waiting for them, instead of over the extension's XPC service.
///
/// Why (2026-11-18): when macOS replaces a system extension it SIGKILLs the old process and
/// creates the new launchd job without waiting for the old one to exit. If the old process is
/// still dying (it held a connected VPN), the new job is created WITHOUT its Mach service
/// ("The endpoint ... already exists and is owned by" the old job, then "failed activation ...
/// Operation not permitted" at every launch). From then on the app can't reach the extension,
/// every AnyConnect connect fails with the hand-off error, and only a reboot or turning the
/// extension off and on recreates the job. Seen on this project's own Mac (1.4.6 → 1.4.8),
/// matching a user's 1.4.6 report, issue #4 and the 1.4.5 report.
///
/// Trust: macOS delivers provider messages only from the app that owns the VPN configuration,
/// and the extension accepts one only for its own waiting start, with the start's own nonce
/// (32 random bytes the app put in the start options; another account's Wombat can't know it).
public struct ProviderHandOff: Codable, Sendable {
    /// The provider message's first byte (`ProviderMessage.openConnectHandOff`); the JSON follows.
    public static let messageTag: UInt8 = 6
    public static let maxBytes = OpenConnectFile.maxBytes + AnyConnectSession.maxBytes + 4096

    public var id: String
    public var revision: String
    /// The canonical AnyConnect profile (no secrets), for an extension without a current copy.
    public var profile: String
    public var session: AnyConnectSession

    public init(id: String, revision: String, profile: String, session: AnyConnectSession) {
        self.id = id
        self.revision = revision
        self.profile = profile
        self.session = session
    }

    /// The whole provider message: tag byte, then JSON. nil if it would be too large.
    public func message() -> Data? {
        guard let json = try? JSONEncoder().encode(self), json.count <= Self.maxBytes else { return nil }
        return Data([Self.messageTag]) + json
    }

    /// Parses a provider message; nil unless it is a well-formed hand-off within the size limit.
    public static func parse(_ message: Data) -> ProviderHandOff? {
        guard message.count > 1, message.count <= maxBytes + 1, message.first == messageTag else { return nil }
        return try? JSONDecoder().decode(ProviderHandOff.self, from: message.dropFirst())
    }

    public enum Refusal: String, Sendable, Equatable {
        /// The start isn't waiting for a hand-off (none asked, or its wait is over).
        case notWaiting = "not waiting"
        /// The extension's XPC service works: the hand-off goes that way, never this one
        /// (review security-11 NV1: this route trusts macOS's message delivery and the nonce, the
        /// XPC route the caller's code signature and uid).
        case serviceWorks = "service works"
        /// A start without a nonce (System Settings, on-demand, an app before 1.4.6) never takes
        /// a session from this route.
        case noNonce = "no nonce"
        case nonce
        case tunnel
        case revision
        case invalid
    }

    /// Whether the waiting start (`tunnelID`, `revision` from its configuration, `nonce` from its
    /// options) may take this hand-off. Every check runs; the nonce compare is constant-time.
    public func refusal(waiting: Bool, tunnelID: String?, revision expected: String?, nonce: String?) -> Refusal? {
        guard waiting else { return .notWaiting }
        guard let nonce, StartNonce.isValid(nonce) else { return .noNonce }
        guard let sent = session.startNonce, StartNonce.matches(sent, nonce) else { return .nonce }
        guard let tunnelID, let mine = UUID(uuidString: tunnelID), UUID(uuidString: id) == mine else { return .tunnel }
        guard let expected, UUID(uuidString: expected) != nil, revision == expected else { return .revision }
        guard session.validate() == nil, OpenConnectFile.parse(profile).profile != nil else { return .invalid }
        return nil
    }
}

/// The extension's answer to a `ProviderHandOff`.
public struct ProviderHandOffReply: Codable, Sendable, Equatable {
    /// nil when the start has what it needs.
    public var error: String?
    /// The extension's own XPC service is missing (the launchd race above): Wombat works through
    /// this route, but other changes (edits, new VPNs) can't reach the extension until a restart.
    public var serviceMissing: Bool
    /// The refusal behind `error`, when it was one (`Refusal.rawValue`): the app tries again on
    /// "not waiting", which a message arriving before the start's wait began also gets.
    public var refusal: String?

    public init(error: String? = nil, serviceMissing: Bool = false, refusal: String? = nil) {
        self.error = error
        self.serviceMissing = serviceMissing
        self.refusal = refusal
    }

    public var isWorthRetrying: Bool { refusal == ProviderHandOff.Refusal.notWaiting.rawValue }

    public func encoded() -> Data { (try? JSONEncoder().encode(self)) ?? Data() }
    public static func decode(_ data: Data?) -> ProviderHandOffReply? {
        guard let data, data.count <= 4096 else { return nil }
        return try? JSONDecoder().decode(ProviderHandOffReply.self, from: data)
    }
}
