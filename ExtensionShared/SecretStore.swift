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
        removeCompleteProtection(id, data: data)
        return record.config
    }

    /// Records written before 1.4.4 carry complete file protection: unreadable while the Mac is
    /// locked, so a locked Mac's start or hand-off failed on them (2026-11-18). Rewritten once,
    /// the same bytes without it, the first time one is read. Under `lock`.
    private func removeCompleteProtection(_ id: String, data: Data) {
        let target = file(id)
        guard let protection = try? FileManager.default.attributesOfItem(atPath: target.path)[.protectionKey] as? FileProtectionType,
              protection == .complete || protection == .completeUnlessOpen else { return }
        do {
            try data.write(to: target, options: [.atomic, .noFileProtection])
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: target.path)
            log.notice("Removed complete file protection from the record for \(id, privacy: .public)")
        } catch {
            log.error("Could not rewrite the record for \(id, privacy: .public): \(FileErrorDetail.describe(error), privacy: .public)")
        }
    }

    // MARK: XPC

    // MARK: Hand-off diagnostics

    /// Per tunnel, with times, counts and fixed labels only (never request data): what a start
    /// that waited in vain for its hand-off checks to say which stage failed.
    private let activityLock = NSLock()
    private var activity = HandOffActivity()

    /// The app sent a request about this tunnel (any valid id; the owner check comes after).
    func noteRequest(_ id: String) {
        guard let key = UUID(uuidString: id)?.uuidString.lowercased() else { return }
        activityLock.withLock { activity.noteRequest(key) }
    }

    /// `label` is a fixed word ("owner", "revision", "save"...), never text from the request.
    func noteRefusal(_ id: String, _ label: String) {
        guard let key = UUID(uuidString: id)?.uuidString.lowercased() else { return }
        activityLock.withLock { activity.noteRefusal(key, label) }
    }

    /// For the OpenConnect extension's last check before it exits (decision 1-B): no request can
    /// be noted while `body` runs.
    func withActivityLocked<T>(_ body: (HandOffActivity) -> T) -> T {
        activityLock.withLock { body(activity) }
    }

    /// A request that names no single tunnel (prune).
    func noteRequestForAnyTunnel() {
        activityLock.withLock { activity.noteRequest("*") }
    }

    /// Requests and refusals for any tunnel since `since`.
    func handOffActivityTotal(since: Date) -> Int {
        activityLock.withLock { activity.total(since: since) }
    }

    func handOffActivity(for id: String, since: Date) -> (requests: Int, refusals: [String: Int]) {
        guard let key = UUID(uuidString: id)?.uuidString.lowercased() else { return (0, [:]) }
        return activityLock.withLock { activity.summary(key, since: since) }
    }

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        // The listener's code-signing requirement already restricts clients to our app.
        connection.exportedInterface = interface
        connection.exportedObject = self
        connection.resume()
        return true
    }

    func store(id: String, config: Data, revision: String, reply: @escaping (String?) -> Void) {
        noteRequest(id)
        guard let uid = callerUID() else { noteRefusal(id, "caller"); return reply("Unknown caller") }
        guard UUID(uuidString: id) != nil else { return reply("Invalid tunnel id") }
        guard revision.isEmpty || UUID(uuidString: revision) != nil else { noteRefusal(id, "invalid"); return reply("Invalid revision") }
        guard config.count <= maxBytes, let text = String(data: config, encoding: .utf8) else {
            noteRefusal(id, "invalid")
            return reply("Configuration is not UTF-8 text under \(maxBytes / 1024) KB")
        }
        if let problem = validate(text) { noteRefusal(id, "invalid"); return reply("Invalid configuration: \(problem)") }
        reply(write(id: id, text: text, revision: revision, uid: uid))
    }

    /// The backup hand-off route (`ProviderHandOff`): the provider stores its own start's profile,
    /// for the owner its configuration names, with the same checks as `store`. nil on success.
    func storeForStart(id: String, text: String, revision: String, uid: UInt32) -> String? {
        guard UUID(uuidString: id) != nil, UUID(uuidString: revision) != nil else { return "Invalid tunnel id" }
        guard text.utf8.count <= maxBytes else { return "Configuration too large" }
        if let problem = validate(text) { return "Invalid configuration: \(problem)" }
        return write(id: id, text: text, revision: revision, uid: uid)
    }

    /// Writes a tunnel's record for `uid`, refusing another user's tunnel or an unreadable record.
    /// nil on success, else the reason.
    private func write(id: String, text: String, revision: String, uid: UInt32) -> String? {
        lock.lock(); defer { lock.unlock() }
        // A record that exists but can't be read has an unknown owner: never replaced by anyone,
        // or another account could take over a damaged tunnel (review 2026-11-18). Its owner
        // deletes the tunnel and adds it again (remove allows that).
        switch ownership(id) {
        case .unavailable(let detail):
            noteRefusal(id, "owner")
            log.error("Refused store for \(id, privacy: .public): the stored record can't be read now: \(detail, privacy: .public)")
            return "The network extension can't read its copy of this tunnel right now (is the Mac locked?). Try again after unlocking it."
        case .damaged:
            noteRefusal(id, "owner")
            log.error("Refused store for \(id, privacy: .public): the stored record is damaged")
            return "The extension's copy of this tunnel is damaged. Delete the tunnel and add it again."
        case .missing, .owned:
            break
        }
        if let owner = ownerUID(id), owner != uid {
            noteRefusal(id, "owner")
            log.error("Refused store for \(id, privacy: .public): owned by uid \(owner, privacy: .public), caller \(uid, privacy: .public)")
            return "This tunnel belongs to another user of this Mac"
        }
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            let data = try JSONEncoder().encode(Record(ownerUID: uid, config: text, revision: revision.isEmpty ? nil : revision))
            let target = file(id)
            // No Data Protection class: the folder is root-only and the file 0600 already, and
            // a class-A write from a root system extension (no user keybag) is refused on some
            // Macs (GitHub issue #3, macOS 26.7.3: "You don't have permission to save").
            try data.write(to: target, options: [.atomic])
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: target.path)
            log.notice("Stored configuration for \(id, privacy: .public)")
            return nil
        } catch {
            let detail = FileErrorDetail.describe(error)
            noteRefusal(id, "save")
            log.error("Could not store \(id, privacy: .public): \(detail, privacy: .public)")
            return "Could not save: \(detail)"
        }
    }

    func remove(id: String, reply: @escaping (String?) -> Void) {
        noteRequest(id)
        guard let uid = callerUID() else { return reply("Unknown caller") }
        guard UUID(uuidString: id) != nil else { return reply("Invalid tunnel id") }
        lock.lock(); defer { lock.unlock() }
        // A record that can't be read right now (a locked Mac) still has its owner: not
        // removable by anyone until it can be read (review 2026-11-18, Fable 5).
        if case .unavailable = ownership(id) {
            return reply("The network extension can't read its copy of this tunnel right now (is the Mac locked?). Try again after unlocking it.")
        }
        if let owner = ownerUID(id), owner != uid { return reply("This tunnel belongs to another user of this Mac") }
        do {
            if FileManager.default.fileExists(atPath: file(id).path) { try FileManager.default.removeItem(at: file(id)) }
        } catch {
            return reply("Could not remove the extension's copy: \(FileErrorDetail.describe(error))")
        }
        onForget(id)
        reply(nil)
    }

    func prune(keeping ids: [String], reply: @escaping (Int) -> Void) {
        noteRequestForAnyTunnel()
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
        noteRequest(id)
        guard let uid = callerUID(), UUID(uuidString: id) != nil else { return reply(false) }
        lock.lock(); defer { lock.unlock() }
        guard ownerUID(id) == uid else { return reply(false) }
        guard !revision.isEmpty else { return reply(true) }
        guard let data = try? Data(contentsOf: file(id)), let record = try? JSONDecoder().decode(Record.self, from: data) else { return reply(false) }
        reply(record.revision == revision)
    }

    // MARK: Quitting before a replacement (1.4.9)

    func quitForReplacement(reply: @escaping (Bool) -> Void) {
        let idle = ProviderLifetime.lock.withLock { ProviderLifetime.liveUnlocked == 0 && idleForReplacement() }
        guard idle else {
            log.notice("Not quitting before the replacement: a VPN is running")
            return reply(false)
        }
        log.notice("Quitting before macOS replaces this extension (no VPN running)")
        reply(true)
        // After the reply has gone out; checked again, since a start may have begun meanwhile.
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.3) { [self] in quitIfStillIdle() }
    }

    /// Whatever else must be idle (the OpenConnect extension: no start or held session). Called
    /// under `ProviderLifetime.lock` (and, for the final check, `lock`); if it takes a lock of its
    /// own it must exit inside it when `exit` is set, so nothing is accepted between check and
    /// exit (security-13 L1).
    func idleForReplacement(exit: Bool = false) -> Bool {
        if exit { _exit(0) }
        return true
    }

    /// The final check and the exit as one step. Lock order: provider lock (no provider can be
    /// made in between), store lock (no record is half written), then the subclass's own (the
    /// OpenConnect session lock; `remove` → `onForget` → `dropSession` takes them in that order
    /// too). `_exit`: no atexit handlers run while other threads exist (security-2 N4). launchd
    /// starts a fresh process on demand.
    private func quitIfStillIdle() {
        ProviderLifetime.lock.withLock {
            guard ProviderLifetime.liveUnlocked == 0 else {
                log.notice("Not quitting before the replacement after all: a VPN started")
                return
            }
            lock.withLock {
                if !idleForReplacement(exit: true) {
                    log.notice("Not quitting before the replacement after all: a VPN started")
                }
            }
        }
    }

    // MARK: Helpers

    func file(_ id: String) -> URL { directory.appendingPathComponent(id.lowercased() + ".json") }

    enum Ownership: Equatable {
        case missing, owned(UInt32)
        /// The file exists but can't be read now. Records from before 1.4.4 carry complete file
        /// protection and can't be read while the Mac is locked (seen 2026-11-18): not damage.
        case unavailable(String)
        /// Read, but not a record: damaged.
        case damaged
    }

    /// "No record" and "a record that can't be read" are different answers: only the first
    /// means nobody owns the tunnel.
    func ownership(_ id: String) -> Ownership {
        let path = file(id).path
        guard FileManager.default.fileExists(atPath: path) else { return .missing }
        let data: Data
        do { data = try Data(contentsOf: file(id)) } catch { return .unavailable(FileErrorDetail.describe(error)) }
        guard let record = try? JSONDecoder().decode(Record.self, from: data) else { return .damaged }
        return .owned(record.ownerUID)
    }

    func ownerUID(_ id: String) -> UInt32? {
        if case .owned(let uid) = ownership(id) { return uid }
        return nil
    }

    func callerUID() -> UInt32? {
        guard let connection = NSXPCConnection.current() else { return nil }
        return UInt32(connection.effectiveUserIdentifier)
    }
}
