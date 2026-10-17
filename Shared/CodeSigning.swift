import Foundation
import Security

/// Code-signing requirements used to authenticate the app, the extension and the CLI to each
/// other. All three are signed by the same team (Developer ID for releases, Apple Development
/// for local builds); the team is read from our own signature so forks work unchanged.
enum CodeSigning {
    static let teamIdentifier: String? = {
        var code: SecCode?
        var staticCode: SecStaticCode?
        var info: CFDictionary?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code,
              SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode,
              SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let dict = info as? [String: Any] else { return nil }
        return dict[kSecCodeInfoTeamIdentifier as String] as? String
    }()

    /// `identifier "<id>" and anchor apple generic and certificate leaf[subject.OU] = "<team>"`.
    /// With no team (an unsigned or ad-hoc build) the requirement can never be satisfied.
    static func requirement(identifier: String) -> String {
        let team = teamIdentifier ?? "UNSIGNED-NO-TEAM"
        let base = "identifier \"\(identifier)\" and anchor apple generic and certificate leaf[subject.OU] = \"\(team)\""
        #if DEBUG
        return base
        #else
        // Release builds also require Developer ID (the Developer ID CA and the Developer ID
        // Application leaf extension), so a same-team Apple Development build can't pass for
        // the shipped app, extension or CLI (audit F-11).
        return base + " and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"
        #endif
    }

    static var app: String { requirement(identifier: AppIdentity.appBundleID) }
    static var tunnelExtension: String { requirement(identifier: AppIdentity.extensionBundleID) }
    static var openConnectExtension: String { requirement(identifier: AppIdentity.openConnectExtensionBundleID) }
    static var cli: String { requirement(identifier: AppIdentity.appBundleID + ".cli") }
}

/// The extension's XPC service: it receives tunnel configurations from the app and keeps them
/// where only root can read them. Deliberately write-only: nothing here returns a secret.
@objc protocol TunnelSecretStoreProtocol {
    /// Stores (or replaces) the wg-quick text for a tunnel id, with the revision it belongs to
    /// (`ProviderConfigKey.revision`). Replies nil on success.
    func store(id: String, config: Data, revision: String, reply: @escaping (String?) -> Void)
    func remove(id: String, reply: @escaping (String?) -> Void)
    /// Whether the caller's copy exists with this revision (empty: any revision). The extension
    /// decides, so the app never relies on its own bookkeeping to know a copy is current.
    func has(id: String, revision: String, reply: @escaping (Bool) -> Void)
    /// Removes the caller's records whose ids are not in `ids` (tunnels deleted while the
    /// extension was unreachable, or removed in System Settings). Returns how many went.
    func prune(keeping ids: [String], reply: @escaping (Int) -> Void)
}

/// The OpenConnect extension's service: the same write-only store for profiles (which hold no
/// secret), plus the session token from a sign-in, which it keeps in memory only. Nothing here
/// returns a profile or a token.
@objc protocol OpenConnectStoreProtocol: TunnelSecretStoreProtocol {
    /// Hands over the session from a sign-in (`AnyConnectSession` as JSON) for the tunnel's
    /// current profile revision. Replies nil on success.
    func storeSession(id: String, revision: String, session: Data, reply: @escaping (String?) -> Void)
}

extension AppIdentity {
    /// The extension's Mach service (NEMachServiceName); must start with the app group so the
    /// sandboxed app may look it up.
    static var extensionMachService: String { appGroup + ".tunnel" }
    static var openConnectMachService: String { appGroup + ".openconnect" }
}
