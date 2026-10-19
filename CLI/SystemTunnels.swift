import Foundation
import SystemConfiguration

/// Wombat's tunnels as macOS has them, for `wombat _names` when the app isn't running, so Tab
/// can still offer tunnel names without launching it.
///
/// The names come from the Network Extension configuration file, which is world-readable and
/// holds no secrets (the keys stay in the keychain). It has each VPN's real name, the one the
/// app shows and its commands accept. `scutil --nc list` and SCNetworkService are no good here:
/// SystemConfiguration keeps its own copy of the name, made unique across every app's VPNs and
/// not updated on rename (it showed "Harvard 2" for Wombat's "Harvard" next to Cisco's "Harvard").
/// The state comes from SCNetworkConnection, keyed by the configuration's identifier, which is
/// the SystemConfiguration service ID. Neither needs privileges or an entitlement.
enum SystemTunnels {
    struct Entry { let name: String; let status: String }

    static let configurationFile = "/Library/Preferences/com.apple.networkextension.plist"

    /// The same tunnels the app lists: its two extensions, and this user's (or no recorded owner).
    static func list() -> [Entry] {
        guard let data = FileManager.default.contents(atPath: configurationFile),
              let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
              let top = plist["$top"] as? [String: Any],
              let unarchiver = try? NSKeyedUnarchiver(forReadingFrom: data) else { return [] }
        // Only the few keys below are read. Every other class in the file (other apps' VPNs,
        // filters) decodes as an empty placeholder, so nothing else is instantiated.
        let placeholder = Placeholder()
        unarchiver.requiresSecureCoding = false
        unarchiver.decodingFailurePolicy = .setErrorAndReturn
        unarchiver.delegate = placeholder
        unarchiver.setClass(Configuration.self, forClassName: "NEConfiguration")
        unarchiver.setClass(VPN.self, forClassName: "NEVPN")
        unarchiver.setClass(ProviderProtocol.self, forClassName: "NETunnelProviderProtocol")
        defer { unarchiver.finishDecoding() }

        var providers: Set = [AppIdentity.extensionBundleID, AppIdentity.openConnectExtensionBundleID]
        #if DEBUG
        // A Debug build can't run tunnels (development-signed extension), so its wombat
        // completes the installed app's tunnels too.
        providers.formUnion(["net.vpetkov.wombat.tunnel", "net.vpetkov.wombat.openconnect"])
        #endif

        var entries: [Entry] = []
        for key in top.keys where UUID(uuidString: key) != nil {
            guard let config = unarchiver.decodeObject(forKey: key) as? Configuration,
                  let name = config.name, let id = config.identifier,
                  let proto = config.vpn?.proto, providers.contains(proto.provider ?? "") else { continue }
            if let owner = proto.vendor?["uid"] as? NSNumber, owner.uint32Value != getuid() { continue }
            entries.append(Entry(name: name, status: status(ofService: id.uuidString)))
        }
        return entries.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
    }

    /// The control protocol's words: disconnected, connecting, connected, disconnecting, invalid.
    static func status(ofService id: String) -> String {
        guard let connection = SCNetworkConnectionCreateWithServiceID(nil, id as CFString, nil, nil) else { return "invalid" }
        switch SCNetworkConnectionGetStatus(connection) {
        case .connected: return "connected"
        case .connecting: return "connecting"
        case .disconnecting: return "disconnecting"
        case .disconnected: return "disconnected"
        default: return "invalid"
        }
    }

    @objc(WombatNEPlaceholder) private final class Placeholder: NSObject, NSKeyedUnarchiverDelegate, NSCoding {
        override init() {}
        init?(coder: NSCoder) {}
        func encode(with coder: NSCoder) {}
        func unarchiver(_ unarchiver: NSKeyedUnarchiver, cannotDecodeObjectOfClassName name: String,
                        originalClasses classNames: [String]) -> AnyClass? { Placeholder.self }
    }

    @objc(WombatNEConfiguration) private final class Configuration: NSObject, NSCoding {
        let name: String?, identifier: UUID?, vpn: VPN?
        init?(coder: NSCoder) {
            name = coder.decodeObject(forKey: "Name") as? String
            identifier = coder.decodeObject(forKey: "Identifier") as? UUID
            vpn = coder.decodeObject(forKey: "VPN") as? VPN
        }
        func encode(with coder: NSCoder) {}
    }

    @objc(WombatNEVPN) private final class VPN: NSObject, NSCoding {
        let proto: ProviderProtocol?
        init?(coder: NSCoder) { proto = coder.decodeObject(forKey: "Protocol") as? ProviderProtocol }
        func encode(with coder: NSCoder) {}
    }

    /// NETunnelProviderProtocol: the extension, and providerConfiguration (stored as
    /// VendorConfiguration) with the owner's uid.
    @objc(WombatNEProviderProtocol) private final class ProviderProtocol: NSObject, NSCoding {
        let provider: String?, vendor: [String: Any]?
        init?(coder: NSCoder) {
            provider = coder.decodeObject(forKey: "NEProviderBundleIdentifier") as? String
            vendor = coder.decodeObject(forKey: "VendorConfiguration") as? [String: Any]
        }
        func encode(with coder: NSCoder) {}
    }
}
