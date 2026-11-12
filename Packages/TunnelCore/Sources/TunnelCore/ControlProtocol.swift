import Foundation

/// The CLI ↔ app protocol: one JSON request per connection on a Unix socket inside the app group
/// container, answered by one JSON response. The app checks the caller's uid and code signature,
/// and anything that adds a tunnel or reveals keys needs the user's approval in the app.
public enum Control {
    public static let protocolVersion = 1
    public static let socketName = "control.sock"
    public static let maxMessageBytes = 512 * 1024

    public struct Request: Codable, Equatable, Sendable {
        public enum Command: String, Codable, Sendable {
            case version, list, status, up, down, stats, `import`, export, delete, rename, onDemand, protection, log, diagnostics
        }
        public var v: Int = Control.protocolVersion
        public var command: Command
        public var name: String?
        /// wg-quick text for `import`.
        public var config: String?
        /// `export`: include PrivateKey/PresharedKey (asks for Touch ID or the login password).
        public var includeSecrets: Bool?
        /// `rename`: the new name.
        public var newName: String?
        /// `onDemand`: the rules to apply.
        public var onDemand: OnDemand?
        /// `protection`: kill switch settings.
        public var protection: Protection?
        /// `diagnostics`: replace server names, addresses and VPN names with placeholders.
        public var hideServers: Bool?

        public init(_ command: Command, name: String? = nil, config: String? = nil, includeSecrets: Bool? = nil) {
            self.command = command
            self.name = name
            self.config = config
            self.includeSecrets = includeSecrets
        }
    }

    public struct TunnelSummary: Codable, Equatable, Sendable {
        public var name: String
        /// disconnected, connecting, connected, reasserting, disconnecting, invalid
        public var status: String
        public var onDemand: Bool
        public var onDemandRules: OnDemand?
        public var protection: Protection?
        public var endpoint: String?
        public var addresses: [String]
        public var connectedSince: Date?
        /// "wireguard", "amneziawg" or "anyconnect". Optional so an older app's reply still decodes.
        public var `protocol`: String?

        public init(name: String, status: String, onDemand: Bool, endpoint: String?, addresses: [String], connectedSince: Date?) {
            self.name = name
            self.status = status
            self.onDemand = onDemand
            self.endpoint = endpoint
            self.addresses = addresses
            self.connectedSince = connectedSince
        }
    }

    /// Automatic connection, evaluated by macOS even while the app is closed.
    public struct OnDemand: Codable, Equatable, Sendable {
        public var enabled: Bool
        public var onWiFi: Bool
        public var onEthernet: Bool
        /// Wi-Fi networks where the tunnel disconnects instead.
        public var trustedSSIDs: [String]

        public init(enabled: Bool, onWiFi: Bool = true, onEthernet: Bool = true, trustedSSIDs: [String] = []) {
            self.enabled = enabled
            self.onWiFi = onWiFi
            self.onEthernet = onEthernet
            self.trustedSSIDs = trustedSSIDs
        }
    }

    public struct Protection: Codable, Equatable, Sendable {
        /// Kill switch: all traffic goes through the tunnel, and none flows while it is down.
        public var killSwitch: Bool
        /// With the kill switch on, still allow unicast to the local network (a NAS or printer by IP).
        /// macOS keeps holding multicast, so Bonjour discovery needs `allowDiscovery` too (issue #2).
        public var allowLAN: Bool
        /// Kill switch exception for Bonjour (mDNS) so AirPlay and other local devices can be
        /// discovered. Only takes effect with `killSwitch` and `allowLAN` (issue #2).
        public var allowDiscovery: Bool

        public init(killSwitch: Bool, allowLAN: Bool, allowDiscovery: Bool = false) {
            self.killSwitch = killSwitch
            self.allowLAN = allowLAN
            self.allowDiscovery = allowDiscovery
        }

        /// What actually applies: discovery is a sub-setting of kill switch + local network.
        public var effective: Protection {
            Protection(killSwitch: killSwitch, allowLAN: allowLAN, allowDiscovery: killSwitch && allowLAN && allowDiscovery)
        }

        private enum CodingKeys: String, CodingKey { case killSwitch, allowLAN, allowDiscovery }

        // A peer from before 1.4.5 sends no allowDiscovery: that means off (the safer value).
        public init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            killSwitch = try c.decode(Bool.self, forKey: .killSwitch)
            allowLAN = try c.decode(Bool.self, forKey: .allowLAN)
            allowDiscovery = try c.decodeIfPresent(Bool.self, forKey: .allowDiscovery) ?? false
        }
    }

    public struct Response: Codable, Equatable, Sendable {
        public var ok: Bool
        public var error: String?
        public var version: String?
        public var tunnels: [TunnelSummary]?
        public var stats: RuntimeStats?
        public var config: String?
        public var findings: [Finding]?
        public var log: [String]?
        /// `diagnostics`: the report text (no secrets; see the app's Diagnostics).
        public var report: String?
        /// `diagnostics`: names the CLI hides in what it adds (the system's VPN log): server
        /// names, and VPN names in the report's order ("VPN 1", "VPN 2"…). Only with hideServers.
        public var servers: [String]?
        public var vpnNames: [String]?

        public init(ok: Bool, error: String? = nil) {
            self.ok = ok
            self.error = error
        }

        public static func failure(_ message: String) -> Response { Response(ok: false, error: message) }
    }

    public static func encode<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(value)
    }

    public static func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode(type, from: data)
    }
}
