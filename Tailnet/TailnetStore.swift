import Foundation
import TunnelCore

/// The tailnet extension's store: profiles like the other extensions' configs (root-only,
/// owner recorded; a profile holds no secret), plus each tunnel's Tailscale state directory,
/// which holds the node and machine keys and never leaves this container.
///
///     <container>/Library/Application Support/Tailnet/<tunnel id>/<server key>/state.json
///
/// One directory per coordination server: a different server is a different node, and keys
/// never move between servers (spike design 2.3).
final class TailnetStore: SecretStore, @unchecked Sendable {
    init() {
        super.init(maxBytes: TailnetFile.maxBytes, interface: NSXPCInterface(with: TunnelSecretStoreProtocol.self)) { text in
            let parsed = TailnetFile.parse(text)
            return parsed.profile == nil ? parsed.errors.map(\.description).joined(separator: "; ") : nil
        }
        // A removed or pruned tunnel's keys go with it. A running node keeps its open files
        // until it stops; nothing reads them again.
        onForget = { [weak self] id in self?.removeState(for: id) }
    }

    private var root: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Tailnet", isDirectory: true)
    }

    /// The state directory for a tunnel and server, created 0700 at each level. Directories of
    /// other servers for this tunnel are removed: the profile moved to another server, and
    /// the old node's keys must not linger (the old server can't be told; spike limitation).
    func stateDirectory(for id: String, control: String) throws -> URL {
        guard let uuid = UUID(uuidString: id) else { throw CocoaError(.fileNoSuchFile) }
        let tunnel = root.appendingPathComponent(uuid.uuidString.lowercased(), isDirectory: true)
        let key = TailnetControl.key(control)
        let dir = tunnel.appendingPathComponent(key, isDirectory: true)
        for url in [root, tunnel, dir] {
            try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: url.path)
        }
        for other in (try? FileManager.default.contentsOfDirectory(at: tunnel, includingPropertiesForKeys: nil)) ?? [] where other.lastPathComponent != key {
            do {
                try FileManager.default.removeItem(at: other)
                log.notice("Removed the node state of a previous coordination server for \(id, privacy: .public)")
            } catch {
                // Keys nobody tracks any more: say so instead of leaving them silently (fable note 2).
                log.error("Could not remove a previous server's node state for \(id, privacy: .public): \(error.localizedDescription, privacy: .public)")
            }
        }
        return dir
    }

    /// The MagicDNS suffix a tunnel accepted first, kept beside its keys (so a server change,
    /// which is a new directory, starts over). nil until the first plan with one.
    func pinnedSuffix(in stateDirectory: URL) -> String? {
        let file = stateDirectory.appendingPathComponent("magicdns-suffix")
        guard let data = try? Data(contentsOf: file), data.count <= 253 else { return nil }
        return TailnetNetworkPlan.dnsName(String(decoding: data, as: UTF8.self))
    }

    func pinSuffix(_ suffix: String, in stateDirectory: URL) {
        let file = stateDirectory.appendingPathComponent("magicdns-suffix")
        do {
            try Data(suffix.utf8).write(to: file, options: [.atomic, .completeFileProtection])
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        } catch {
            log.error("Could not save the tailnet's DNS name: \(error.localizedDescription, privacy: .public)")
        }
    }

    func removeState(for id: String) {
        guard let uuid = UUID(uuidString: id) else { return }
        let tunnel = root.appendingPathComponent(uuid.uuidString.lowercased(), isDirectory: true)
        guard FileManager.default.fileExists(atPath: tunnel.path) else { return }
        do {
            try FileManager.default.removeItem(at: tunnel)
            log.notice("Removed the node state for \(id, privacy: .public)")
        } catch {
            log.error("Could not remove the node state for \(id, privacy: .public): \(error.localizedDescription, privacy: .public)")
        }
    }
}
