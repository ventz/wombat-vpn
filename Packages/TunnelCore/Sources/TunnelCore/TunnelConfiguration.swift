import Foundation

public struct TunnelConfiguration: Equatable, Sendable {
    public var interface: InterfaceConfiguration
    public var peers: [PeerConfiguration]

    public init(interface: InterfaceConfiguration, peers: [PeerConfiguration] = []) {
        self.interface = interface
        self.peers = peers
    }

    /// How much of each address family the peers route through the tunnel.
    public var coverage: RouteCoverage { RouteCoverage(peers.flatMap(\.allowedIPs)) }

    /// Routes most of IPv4 or IPv6 (not just a literal /0: 0.0.0.0/1 + 128.0.0.0/1 counts too).
    public var isFullTunnel: Bool { coverage.isFullTunnel }

    /// Speaks AmneziaWG rather than WireGuard: runs on the amneziawg-go engine and needs an
    /// AmneziaWG peer. All-default AmneziaWG settings are plain WireGuard.
    public var isAmnezia: Bool { interface.amnezia?.isActive ?? false }

    /// The protocol's name for the CLI's JSON: "wireguard" or "amneziawg".
    public var protocolName: String { isAmnezia ? "amneziawg" : "wireguard" }
}

public struct InterfaceConfiguration: Equatable, Sendable {
    public var privateKey: WireGuardKey
    public var addresses: [IPAddressRange] = []
    /// DNS entries that are IP addresses.
    public var dnsServers: [String] = []
    /// DNS entries that are names: search domains, as in wg-quick.
    public var dnsSearchDomains: [String] = []
    public var listenPort: UInt16?
    public var mtu: UInt16?
    /// wg-quick keys this app parses but never acts on (PostUp, Table, …), kept for warnings and round-trips.
    public var ignored: [IgnoredKey] = []
    /// AmneziaWG settings, nil when the file has none. See `isAmnezia` for whether they matter.
    public var amnezia: AmneziaParameters?

    public init(privateKey: WireGuardKey) { self.privateKey = privateKey }

    public var publicKey: WireGuardKey { KeyPair.publicKey(for: privateKey) }
}

public struct PeerConfiguration: Equatable, Sendable {
    public var publicKey: WireGuardKey
    public var presharedKey: WireGuardKey?
    public var allowedIPs: [IPAddressRange] = []
    public var endpoint: Endpoint?
    public var persistentKeepalive: UInt16?

    public init(publicKey: WireGuardKey) { self.publicKey = publicKey }
}

public struct IgnoredKey: Equatable, Sendable {
    public let key: String
    public let value: String
    public let line: Int
}
