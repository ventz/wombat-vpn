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
    }

    static let notRunning = "The network extension didn't start. Check that Wombat is turned on in System Settings › General › Login Items & Extensions › Extensions › Network Extensions (ⓘ)."
    static let openConnectNotRunning = "The OpenConnect extension didn't start. Check that “Wombat OpenConnect” is turned on in System Settings › General › Login Items & Extensions › Extensions › Network Extensions (ⓘ)."

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

    static func store(_ engine: Engine = .wireGuard, id: UUID, text: String, revision: String) async throws {
        try await call(engine) { proxy, done in
            proxy.store(id: id.uuidString, config: Data(text.utf8), revision: revision) { done($0) }
        }
    }

    /// Hands a sign-in's session to the OpenConnect extension (memory only there).
    static func storeSession(id: UUID, revision: String, session: AnyConnectSession) async throws {
        let data = try JSONEncoder().encode(session)
        try await call(.openConnect) { proxy, done in
            guard let store = proxy as? OpenConnectStoreProtocol else { return done("The OpenConnect extension can't take sessions") }
            store.storeSession(id: id.uuidString, revision: revision, session: data) { done($0) }
        }
    }

    /// Only a failed lookup means "not running". Anything else (a code-signing mismatch above
    /// all) is a real failure and must not be quietly queued (audit S3-L4).
    private static func failure(_ error: Error, _ engine: Engine) -> Failure {
        let ns = error as NSError
        if ns.domain == NSCocoaErrorDomain, ns.code == NSXPCConnectionInvalid {
            return Failure(errorDescription: "The \(engine.name) is not running", unreachable: true)
        }
        return Failure(errorDescription: "The \(engine.name) could not be reached: \(error.localizedDescription)")
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
                once.run { continuation.resume(returning: removed) }
                connection.invalidate()
            }
        }
    }

    /// `.yes` only when the extension's copy has this revision (empty: any).
    static func has(_ engine: Engine = .wireGuard, id: UUID, revision: String = "") async -> Presence {
        await withCheckedContinuation { continuation in
            let once = Once()
            let (connection, proxy) = Self.proxy(engine) { error in
                let failure = Self.failure(error, engine)
                once.run { continuation.resume(returning: failure.unreachable ? .notRunning : .failed(failure.errorDescription ?? "")) }
            }
            guard let proxy else { connection.invalidate(); return once.run { continuation.resume(returning: .notRunning) } }
            proxy.has(id: id.uuidString, revision: revision) { result in
                once.run { continuation.resume(returning: result ? .yes : .no) }
                connection.invalidate()
            }
        }
    }

    private static func call(_ engine: Engine, _ body: @escaping (TunnelSecretStoreProtocol, @escaping (String?) -> Void) -> Void) async throws {
        let failure: Failure? = await withCheckedContinuation { continuation in
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
        if let failure {
            if failure.unreachable {
                log.notice("Extension not running; the hand-off waits for the next start")
            } else {
                log.error("Extension refused: \(failure.errorDescription ?? "", privacy: .public)")
            }
            throw failure
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
