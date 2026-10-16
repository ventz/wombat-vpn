import Foundation
import Network
import TunnelCore

/// Converts the validated TunnelCore model into WireGuardKit's types. WireGuardKit's sources are
/// compiled into this target, so its types are unqualified here and TunnelCore's are qualified.
enum ConfigBridge {
    struct ConversionError: LocalizedError {
        let errorDescription: String?
    }

    /// `addresses` maps endpoint hostnames to an IP literal to use instead (see EndpointAddresses).
    static func wireGuardKit(_ c: TunnelCore.TunnelConfiguration, name: String?, addresses: [String: String] = [:]) throws -> TunnelConfiguration {
        guard let privateKey = PrivateKey(rawValue: c.interface.privateKey.rawValue) else {
            throw ConversionError(errorDescription: "private key")
        }
        var interface = InterfaceConfiguration(privateKey: privateKey)
        interface.addresses = try c.interface.addresses.map(range)
        interface.dns = try c.interface.dnsServers.map { text in
            guard let dns = DNSServer(from: text) else { throw ConversionError(errorDescription: "DNS \(text)") }
            return dns
        }
        interface.dnsSearch = c.interface.dnsSearchDomains
        interface.listenPort = c.interface.listenPort
        interface.mtu = c.interface.mtu
        // All-default AmneziaWG settings are plain WireGuard and stay on wireguard-go.
        if c.isAmnezia, let amnezia = c.interface.amnezia {
            interface.amneziaSettings = try amnezia.uapiPairs.map { pair in
                guard let setting = AmneziaSetting(key: pair.key, value: pair.value) else {
                    throw ConversionError(errorDescription: "AmneziaWG setting \(pair.key)")
                }
                return setting
            }
        }

        let peers: [PeerConfiguration] = try c.peers.map { p in
            guard let publicKey = PublicKey(rawValue: p.publicKey.rawValue) else {
                throw ConversionError(errorDescription: "public key")
            }
            var peer = PeerConfiguration(publicKey: publicKey)
            if let psk = p.presharedKey {
                guard let key = PreSharedKey(rawValue: psk.rawValue) else { throw ConversionError(errorDescription: "preshared key") }
                peer.preSharedKey = key
            }
            peer.allowedIPs = try p.allowedIPs.map(range)
            if let e = p.endpoint {
                var text = e.description
                if e.isHostname, let ip = addresses[e.hostString] {
                    text = ip.contains(":") ? "[\(ip)]:\(e.port)" : "\(ip):\(e.port)"
                }
                guard let endpoint = Endpoint(from: text) else { throw ConversionError(errorDescription: "endpoint \(e)") }
                peer.endpoint = endpoint
            }
            peer.persistentKeepAlive = p.persistentKeepalive
            return peer
        }
        let result = TunnelConfiguration(name: name, interface: interface, peers: peers)
        let coverage = c.coverage
        result.blockUncoveredIPv6 = coverage.routesMostIPv4 && !coverage.routesMostIPv6
        result.blockUncoveredIPv4 = coverage.routesMostIPv6 && !coverage.routesMostIPv4
        return result
    }

    private static func range(_ r: TunnelCore.IPAddressRange) throws -> IPAddressRange {
        guard let converted = IPAddressRange(from: r.description) else {
            throw ConversionError(errorDescription: "address \(r)")
        }
        return converted
    }
}
