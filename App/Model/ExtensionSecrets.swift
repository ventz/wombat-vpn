import Foundation
import os
import TunnelCore

/// Hands tunnel configurations to the extension over its Mach service. The extension runs as
/// root and can't read the user's keychain, so it keeps its own root-only copy. The connection
/// only accepts the extension signed by our team.
@MainActor
enum ExtensionSecrets {
    /// Which system extension: each has its own Mach service, signature and store.
    enum Engine: Sendable {
        case wireGuard, openConnect

        var machService: String { self == .wireGuard ? AppIdentity.extensionMachService : AppIdentity.openConnectMachService }
        var requirement: String { self == .wireGuard ? CodeSigning.tunnelExtension : CodeSigning.openConnectExtension }
        var interface: NSXPCInterface {
            NSXPCInterface(with: self == .wireGuard ? TunnelSecretStoreProtocol.self : OpenConnectStoreProtocol.self)
        }
        var name: String { self == .wireGuard ? "network extension" : "OpenConnect extension" }
    }

    struct Failure: LocalizedError {
        let errorDescription: String?
        /// Nothing answered: the extension isn't running. macOS launches it only to run a tunnel,
        /// so this is normal after a reboot or an update, not an error by itself.
        var unreachable = false
        /// The connection broke after the lookup worked (NSXPCConnectionInterrupted): the extension
        /// went away mid-call, as it does while macOS replaces it with a newer version or a stale
        /// process holds the service. Tried again on a fresh connection before anything is decided.
        var interrupted = false
    }

    static let notRunning = "The network extension didn't start. Check that Wombat is turned on in System Settings › General › Login Items & Extensions › Extensions › Network Extensions (ⓘ). If it is, turn it off and on again there."
    static let openConnectNotRunning = "The OpenConnect extension didn't start. Check that “Wombat OpenConnect” is turned on in System Settings › General › Login Items & Extensions › Extensions › Network Extensions (ⓘ). If it is, turn it off and on again there."

    static func notRunningMessage(_ engine: Engine) -> String { engine == .wireGuard ? notRunning : openConnectNotRunning }

    private static let log = Logger(subsystem: AppIdentity.logSubsystem, category: "secrets")

    private static func proxy(_ engine: Engine, _ onError: @escaping (Error) -> Void) -> (NSXPCConnection, TunnelSecretStoreProtocol?) {
        let connection = NSXPCConnection(machServiceName: engine.machService, options: [])
        connection.remoteObjectInterface = engine.interface
        connection.setCodeSigningRequirement(engine.requirement)
        connection.resume()
        let proxy = connection.remoteObjectProxyWithErrorHandler(onError) as? TunnelSecretStoreProtocol
        return (connection, proxy)
    }

    /// `retryInterruptions: false` for callers with their own retry loop (the launch hand-off,
    /// which must stay within its 12 s; security-8 L2).
    static func store(_ engine: Engine = .wireGuard, id: UUID, text: String, revision: String, retryInterruptions: Bool = true) async throws {
        try await call(engine, retryInterruptions: retryInterruptions) { proxy, done in
            proxy.store(id: id.uuidString, config: Data(text.utf8), revision: revision) { done($0) }
        }
    }

    /// Hands a sign-in's session to the OpenConnect extension (memory only there). Never
    /// retried: a retry could land after a disconnect and leave a session nothing drops
    /// (security-8 L2); a lost session only means signing in again.
    static func storeSession(id: UUID, revision: String, session: AnyConnectSession) async throws {
        let data = try JSONEncoder().encode(session)
        try await call(.openConnect, retryInterruptions: false) { proxy, done in
            guard let store = proxy as? OpenConnectStoreProtocol else { return done("The OpenConnect extension can't take sessions") }
            store.storeSession(id: id.uuidString, revision: revision, session: data) { done($0) }
        }
    }

    /// A failed lookup means "not running"; an interruption is retried (`interruptedRetries`) and,
    /// if it persists, treated the same way. Anything else (a code-signing mismatch above all) is a
    /// real failure and must not be quietly queued (audit S3-L4). Every XPC error has the same
    /// text ("Couldn't communicate with a helper application"), so the message names the code.
    private static func failure(_ error: Error, _ engine: Engine) -> Failure {
        let ns = error as NSError
        if ns.domain == NSCocoaErrorDomain, ns.code == NSXPCConnectionInvalid {
            return Failure(errorDescription: "The \(engine.name) is not running", unreachable: true)
        }
        if ns.domain == NSCocoaErrorDomain, ns.code == NSXPCConnectionInterrupted {
            return Failure(errorDescription: "The \(engine.name) stopped answering", interrupted: true)
        }
        if ns.domain == NSCocoaErrorDomain, ns.code == NSXPCConnectionCodeSigningRequirementFailure {
            return Failure(errorDescription: "The \(engine.name) failed Wombat's signature check; nothing was sent. Reinstall Wombat from wombat.vpetkov.net.")
        }
        return Failure(errorDescription: "The \(engine.name) could not be reached: \(error.localizedDescription) (\(ns.domain) \(ns.code))")
    }

    /// Fresh connections after an interruption, 1 s then 2 s apart: long enough for macOS to
    /// finish replacing the extension (seen as the first add of an AnyConnect VPN failing while
    /// the OpenConnect extension was being activated).
    private static let interruptedRetries: [Duration] = [.seconds(1), .seconds(2)]

    /// Runs `attempt` again on an interruption. One that persists counts as "not running": the
    /// hand-off is queued and the next connect starts the extension, which refuses any copy whose
    /// revision isn't current, so nothing runs from a stale configuration (fails closed).
    /// Told when an interruption persists, so it shows instead of passing for "not running"
    /// (TunnelStore.extensionProblem; security-8 L1).
    static var onPersistentInterruption: ((String) -> Void)?

    private static func retryingInterruptions<T>(_ engine: Engine, retry: Bool = true, isInterrupted: (T) -> Bool, _ attempt: () async -> T) async -> (T, persisted: Bool) {
        var result = await attempt()
        for delay in (retry ? interruptedRetries : []) where isInterrupted(result) {
            log.notice("The \(engine.name, privacy: .public) connection was interrupted; trying again")
            try? await Task.sleep(for: delay)
            result = await attempt()
        }
        let persisted = isInterrupted(result)
        if persisted {
            log.error("The \(engine.name, privacy: .public) kept interrupting the connection; treating it as not running")
            onPersistentInterruption?("The \(engine.name) keeps dropping the connection (NSCocoaErrorDomain \(NSXPCConnectionInterrupted)). Changes wait until it answers; if this stays, turn it off and on in System Settings › General › Login Items & Extensions › Extensions › Network Extensions (ⓘ).")
        }
        return (result, persisted)
    }

    enum Presence: Equatable { case yes, no, notRunning, failed(String) }

    static func remove(_ engine: Engine = .wireGuard, id: UUID) async throws {
        try await call(engine) { proxy, done in
            proxy.remove(id: id.uuidString) { done($0) }
        }
    }

    /// Asks the extension to drop this user's records for tunnels that no longer exist.
    static func prune(_ engine: Engine = .wireGuard, keeping ids: [UUID]) async -> Int {
        await withCheckedContinuation { continuation in
            let once = Once()
            let (connection, proxy) = Self.proxy(engine) { _ in once.run { continuation.resume(returning: 0) } }
            guard let proxy else { connection.invalidate(); return once.run { continuation.resume(returning: 0) } }
            proxy.prune(keeping: ids.map(\.uuidString)) { removed in
                // Only the root-owned extension's answer counts (security-8 L3).
                once.run { continuation.resume(returning: connection.effectiveUserIdentifier == 0 ? removed : 0) }
                connection.invalidate()
            }
        }
    }

    /// `.yes` only when the extension's copy has this revision (empty: any).
    static func has(_ engine: Engine = .wireGuard, id: UUID, revision: String = "") async -> Presence {
        let (result, persisted) = await retryingInterruptions(engine, isInterrupted: { $0 == .interrupted }) {
            await hasOnce(engine, id: id, revision: revision)
        }
        if persisted { return .notRunning }
        switch result {
        case .interrupted: return .notRunning
        case .presence(let presence): return presence
        }
    }

    private enum HasResult: Equatable { case presence(Presence), interrupted }

    private static func hasOnce(_ engine: Engine, id: UUID, revision: String) async -> HasResult {
        await withCheckedContinuation { continuation in
            let once = Once()
            let (connection, proxy) = Self.proxy(engine) { error in
                let failure = Self.failure(error, engine)
                let result: HasResult = failure.interrupted ? .interrupted
                    : .presence(failure.unreachable ? .notRunning : .failed(failure.errorDescription ?? ""))
                once.run { continuation.resume(returning: result) }
            }
            guard let proxy else { connection.invalidate(); return once.run { continuation.resume(returning: .presence(.notRunning)) } }
            proxy.has(id: id.uuidString, revision: revision) { result in
                // The real extension binary started as an ordinary user passes the signature
                // check; its "yes" would clear a pending hand-off (security-8 L3).
                let uid = connection.effectiveUserIdentifier
                let presence: Presence = uid == 0 ? (result ? .yes : .no)
                    : .failed("The \(engine.name) did not answer as the system (uid \(uid))")
                once.run { continuation.resume(returning: .presence(presence)) }
                connection.invalidate()
            }
        }
    }

    /// Store, remove and storeSession replace whole records, so sending one again after an
    /// interruption is safe; the root check below runs again on each fresh connection.
    private static func call(_ engine: Engine, retryInterruptions: Bool = true, _ body: @escaping (TunnelSecretStoreProtocol, @escaping (String?) -> Void) -> Void) async throws {
        var (failure, persisted) = await retryingInterruptions(engine, retry: retryInterruptions, isInterrupted: { $0?.interrupted == true }) {
            await callOnce(engine, body)
        }
        if persisted { failure = Failure(errorDescription: "The \(engine.name) is not answering", unreachable: true) }
        if let failure {
            if failure.unreachable {
                log.notice("Extension not running; the hand-off waits for the next start")
            } else {
                log.error("Extension refused: \(failure.errorDescription ?? "", privacy: .public)")
            }
            throw failure
        }
    }

    private static func callOnce(_ engine: Engine, _ body: @escaping (TunnelSecretStoreProtocol, @escaping (String?) -> Void) -> Void) async -> Failure? {
        await withCheckedContinuation { continuation in
            let once = Once()
            let (connection, proxy) = Self.proxy(engine) { error in
                once.run { continuation.resume(returning: Self.failure(error, engine)) }
            }
            guard let proxy else {
                connection.invalidate()
                return once.run { continuation.resume(returning: Failure(errorDescription: "The \(engine.name) is not running", unreachable: true)) }
            }
            // Before any secret is sent, a harmless round trip proves the peer is the real,
            // root-owned extension: the signature check alone would also accept the genuine
            // binary started as an ordinary user under the same Mach service name.
            proxy.has(id: UUID().uuidString, revision: "") { _ in
                guard connection.effectiveUserIdentifier == 0 else {
                    once.run { continuation.resume(returning: Failure(errorDescription: "The \(engine.name) did not answer as the system (uid \(connection.effectiveUserIdentifier)); nothing was sent")) }
                    connection.invalidate()
                    return
                }
                body(proxy) { reply in
                    once.run { continuation.resume(returning: reply.map { Failure(errorDescription: $0) }) }
                    connection.invalidate()
                }
            }
        }
    }
}

/// Resumes a continuation exactly once when both the reply and the error handler may fire.
private final class Once: @unchecked Sendable {
    private let lock = NSLock()
    private var done = false
    func run(_ body: () -> Void) {
        lock.lock()
        let first = !done
        done = true
        lock.unlock()
        if first { body() }
    }
}
