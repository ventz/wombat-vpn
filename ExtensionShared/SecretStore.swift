import Foundation
import os
import TunnelCore

/// Tunnel configurations as an extension sees them: one 0600 file per tunnel in the
/// extension's sandbox container, which belongs to root (system extensions run as root), so no
/// user process can read them. Each record remembers which macOS user stored it, and only that
/// user's app may replace or remove it: VPN configurations are shared by all users of the Mac,
/// so another account must not be able to swap in its own config under your tunnel's id.
///
/// Shared by both system extensions (WireGuard and OpenConnect), each with its own container,
/// validator and XPC interface; `main.swift` of each sets them up before the listener starts.
class SecretStore: NSObject, TunnelSecretStoreProtocol, NSXPCListenerDelegate, @unchecked Sendable {
    /// The extension's store, chosen by its main.swift.
    nonisolated(unsafe) static var shared: SecretStore!

    /// Checks a configuration before it is stored: nil when valid, else the reason.
    let validate: (String) -> String?
    let maxBytes: Int
    /// What the XPC connection exports (a subclass may add methods).
    let interface: NSXPCInterface
    /// Called when a tunnel's record goes, for per-tunnel caches.
    var onForget: (String) -> Void = { _ in }

    let log = Logger(subsystem: AppIdentity.logSubsystem, category: "secrets")
    let lock = NSLock()

    init(maxBytes: Int, interface: NSXPCInterface, validate: @escaping (String) -> String?) {
        self.maxBytes = maxBytes
        self.interface = interface
        self.validate = validate
    }

    private struct Record: Codable {
        var ownerUID: UInt32
        var config: String
        /// nil in records stored before revisions existed.
        var revision: String?
    }

    private var directory: URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return base.appendingPathComponent("Tunnels", isDirectory: true)
    }

    // MARK: Reading (extension only)

    /// The wg-quick text for a tunnel, or nil when the app never handed it over.
    func config(for id: String) -> String? {
        guard UUID(uuidString: id) != nil else { return nil }
        lock.lock(); defer { lock.unlock() }
        guard let data = try? Data(contentsOf: file(id)), let record = try? JSONDecoder().decode(Record.self, from: data) else { return nil }
        return record.config
    }

    // MARK: XPC

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        // The listener's code-signing requirement already restricts clients to our app.
        connection.exportedInterface = interface
        connection.exportedObject = self
        connection.resume()
        return true
    }

    func store(id: String, config: Data, revision: String, reply: @escaping (String?) -> Void) {
        guard let uid = callerUID() else { return reply("Unknown caller") }
        guard UUID(uuidString: id) != nil else { return reply("Invalid tunnel id") }
        guard revision.isEmpty || UUID(uuidString: revision) != nil else { return reply("Invalid revision") }
        guard config.count <= maxBytes, let text = String(data: config, encoding: .utf8) else {
            return reply("Configuration is not UTF-8 text under \(maxBytes / 1024) KB")
        }
        if let problem = validate(text) { return reply("Invalid configuration: \(problem)") }
        lock.lock(); defer { lock.unlock() }
        if let owner = ownerUID(id), owner != uid {
            log.error("Refused store for \(id, privacy: .public): owned by uid \(owner, privacy: .public), caller \(uid, privacy: .public)")
            return reply("This tunnel belongs to another user of this Mac")
        }
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            let data = try JSONEncoder().encode(Record(ownerUID: uid, config: text, revision: revision.isEmpty ? nil : revision))
            let target = file(id)
            try data.write(to: target, options: [.atomic, .completeFileProtection])
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: target.path)
            log.notice("Stored configuration for \(id, privacy: .public)")
            reply(nil)
        } catch {
            reply("Could not save: \(error.localizedDescription)")
        }
    }

    func remove(id: String, reply: @escaping (String?) -> Void) {
        guard let uid = callerUID() else { return reply("Unknown caller") }
        guard UUID(uuidString: id) != nil else { return reply("Invalid tunnel id") }
        lock.lock(); defer { lock.unlock() }
        if let owner = ownerUID(id), owner != uid { return reply("This tunnel belongs to another user of this Mac") }
        do {
            if FileManager.default.fileExists(atPath: file(id).path) { try FileManager.default.removeItem(at: file(id)) }
        } catch {
            return reply("Could not remove the extension's copy: \(error.localizedDescription)")
        }
        onForget(id)
        reply(nil)
    }

    func prune(keeping ids: [String], reply: @escaping (Int) -> Void) {
        guard let uid = callerUID() else { return reply(0) }
        let keep = Set(ids.compactMap(UUID.init(uuidString:)).map { $0.uuidString.lowercased() })
        lock.lock(); defer { lock.unlock() }
        let files = (try? FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)) ?? []
        var removed = 0
        for url in files where url.pathExtension == "json" {
            let id = url.deletingPathExtension().lastPathComponent
            guard !keep.contains(id), UUID(uuidString: id) != nil, ownerUID(id) == uid else { continue }
            if (try? FileManager.default.removeItem(at: url)) != nil {
                onForget(id)
                removed += 1
            }
        }
        if removed > 0 { log.notice("Pruned \(removed, privacy: .public) orphaned configuration(s)") }
        reply(removed)
    }

    /// The macOS user who stored a tunnel (extension-internal; not exposed over XPC).
    /// The revision of the stored copy: `.some(nil)` for a record from before revisions,
    /// nil when there is no record.
    func revision(of id: String) -> String?? {
        guard UUID(uuidString: id) != nil else { return nil }
        lock.lock(); defer { lock.unlock() }
        guard let data = try? Data(contentsOf: file(id)), let record = try? JSONDecoder().decode(Record.self, from: data) else { return nil }
        return .some(record.revision)
    }

    func owner(of id: String) -> UInt32? {
        guard UUID(uuidString: id) != nil else { return nil }
        lock.lock(); defer { lock.unlock() }
        return ownerUID(id)
    }

    func has(id: String, revision: String, reply: @escaping (Bool) -> Void) {
        guard let uid = callerUID(), UUID(uuidString: id) != nil else { return reply(false) }
        lock.lock(); defer { lock.unlock() }
        guard ownerUID(id) == uid else { return reply(false) }
        guard !revision.isEmpty else { return reply(true) }
        guard let data = try? Data(contentsOf: file(id)), let record = try? JSONDecoder().decode(Record.self, from: data) else { return reply(false) }
        reply(record.revision == revision)
    }

    // MARK: Helpers

    func file(_ id: String) -> URL { directory.appendingPathComponent(id.lowercased() + ".json") }

    func ownerUID(_ id: String) -> UInt32? {
        guard let data = try? Data(contentsOf: file(id)) else { return nil }
        return (try? JSONDecoder().decode(Record.self, from: data))?.ownerUID
    }

    func callerUID() -> UInt32? {
        guard let connection = NSXPCConnection.current() else { return nil }
        return UInt32(connection.effectiveUserIdentifier)
    }
}
