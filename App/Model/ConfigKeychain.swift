import Foundation
import Security
import TunnelCore

/// Stores each tunnel's wg-quick text (keys included) as a generic password in the login keychain.
/// The NE configuration only carries a persistent reference to it (`passwordReference`).
enum ConfigKeychain {
    struct Failure: LocalizedError {
        let operation: String
        let status: OSStatus
        var errorDescription: String? {
            "Keychain \(operation) failed: \(SecCopyErrorMessageString(status, nil) as String? ?? "error \(status)")"
        }
    }

    /// Adds a new item and returns its persistent reference. A replaced item is deleted only after
    /// the new one is safely stored.
    static func store(_ text: String, tunnelID: UUID, name: String, kind: Tunnel.Kind = .wireGuard, replacing old: Data? = nil) throws -> Data {
        let item: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: AppIdentity.keychainService,
            kSecAttrAccount: "\(tunnelID.uuidString)/\(UUID().uuidString)",
            kSecAttrLabel: kind == .wireGuard ? "Wombat tunnel: \(name)" : "Wombat VPN: \(name)",
            // An AnyConnect profile holds no secret (server, group, username, certificate
            // fingerprints); it lives here anyway so both kinds are handled the same way.
            kSecAttrDescription: kind == .openConnect ? "AnyConnect profile" : kind == .tailnet ? "Tailnet profile" : "wg-quick(8) configuration",
            kSecAttrSynchronizable: false,
            kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecValueData: Data(text.utf8),
            kSecReturnPersistentRef: true,
        ]
        var result: CFTypeRef?
        let status = SecItemAdd(item as CFDictionary, &result)
        guard status == errSecSuccess, let reference = result as? Data else { throw Failure(operation: "add", status: status) }
        if let old { delete(old) }
        return reference
    }

    static func read(_ reference: Data) throws -> String {
        var result: CFTypeRef?
        let status = SecItemCopyMatching([kSecValuePersistentRef: reference, kSecReturnData: true] as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data, let text = String(data: data, encoding: .utf8) else {
            throw Failure(operation: "read", status: status)
        }
        return text
    }

    static func delete(_ reference: Data) {
        SecItemDelete([kSecValuePersistentRef: reference] as CFDictionary)
    }

    static func exists(_ reference: Data) -> Bool {
        SecItemCopyMatching([kSecValuePersistentRef: reference] as CFDictionary, nil) != errSecItemNotFound
    }

    /// Every Wombat item in this user's keychain, attributes only (no profile text), for
    /// `RemovedConfigs`. Empty on any error: nothing is then offered.
    static func list() -> [RemovedConfigs.Item<Data>] {
        var result: CFTypeRef?
        let status = SecItemCopyMatching([
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: AppIdentity.keychainService,
            kSecMatchLimit: kSecMatchLimitAll,
            kSecReturnAttributes: true,
            kSecReturnPersistentRef: true,
        ] as CFDictionary, &result)
        guard status == errSecSuccess, let rows = result as? [[String: Any]] else { return [] }
        return rows.compactMap { row in
            guard let reference = row[kSecValuePersistentRef as String] as? Data,
                  let account = row[kSecAttrAccount as String] as? String else { return nil }
            let description = row[kSecAttrDescription as String] as? String
            let kind: RemovedConfigs.Kind = description == "AnyConnect profile" ? .openConnect
                : description == "Tailnet profile" ? .tailnet : .wireGuard
            return .init(reference: reference, account: account, label: row[kSecAttrLabel as String] as? String,
                         kind: kind, created: row[kSecAttrCreationDate as String] as? Date)
        }
    }
}
