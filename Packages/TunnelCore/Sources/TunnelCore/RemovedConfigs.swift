import Foundation

/// VPNs whose VPN configuration macOS removed while Wombat's keychain copy stayed behind.
///
/// Turning a Wombat extension off in System Settings (the advice for a stuck extension) removes
/// that extension's VPN configurations, and the user had to set the VPN up again (1.4.6 report,
/// 2026-11-18). The app's keychain copy of each profile survives, so the app offers to restore it
/// (or forget it). Only the item's attributes are used here; the profile text is read only for
/// a restore the user asked for.
public enum RemovedConfigs {
    /// A keychain item as listed: `account` is "<tunnel id>/<random>" (ConfigKeychain).
    public struct Item<Reference: Hashable & Sendable>: Sendable {
        public let reference: Reference
        public let account: String
        public let label: String?
        public let kind: Kind
        public let created: Date?

        public init(reference: Reference, account: String, label: String?, kind: Kind, created: Date?) {
            self.reference = reference
            self.account = account
            self.label = label
            self.kind = kind
            self.created = created
        }
    }

    public enum Kind: String, Sendable { case wireGuard, openConnect, tailnet }

    public struct Removed<Reference: Hashable & Sendable>: Identifiable, Sendable {
        public let id: UUID  // the old tunnel id
        public let name: String
        public let kind: Kind
        /// The newest item: the one to restore from.
        public let newest: Reference
        /// Every item of this tunnel (an edit can leave an older one behind): all go after a
        /// restore or forget.
        public let references: [Reference]
    }

    /// Items younger than this are skipped: `add` stores the keychain item before the VPN
    /// configuration, and an add in progress must not look removed.
    public static let grace: TimeInterval = 120

    /// The tunnels with keychain items but no VPN configuration. Call only after a clean load of
    /// the configurations: a failed load must not make every tunnel look removed.
    public static func find<R>(_ items: [Item<R>], existing: Set<UUID>, now: Date) -> [Removed<R>] {
        var byID: [UUID: [Item<R>]] = [:]
        for item in items {
            guard let prefix = item.account.split(separator: "/", maxSplits: 1).first,
                  let id = UUID(uuidString: String(prefix)), !existing.contains(id) else { continue }
            byID[id, default: []].append(item)
        }
        var out: [Removed<R>] = []
        for (id, group) in byID {
            // Any recent item means the tunnel may be mid-add or mid-edit: wait.
            if group.contains(where: { ($0.created ?? .distantPast) > now.addingTimeInterval(-grace) }) { continue }
            let sorted = group.sorted { ($0.created ?? .distantPast) > ($1.created ?? .distantPast) }
            let newest = sorted[0]
            out.append(Removed(id: id, name: name(newest.label), kind: newest.kind,
                               newest: newest.reference, references: sorted.map(\.reference)))
        }
        return out.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
    }

    /// "Wombat tunnel: Home" / "Wombat VPN: Work" → the name; anything else → a generic one.
    static func name(_ label: String?) -> String {
        guard let label else { return "Unnamed VPN" }
        for prefix in ["Wombat tunnel: ", "Wombat VPN: "] where label.hasPrefix(prefix) {
            let name = String(label.dropFirst(prefix.count)).trimmingCharacters(in: .whitespacesAndNewlines)
            return name.isEmpty ? "Unnamed VPN" : name
        }
        return "Unnamed VPN"
    }
}
