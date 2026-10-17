import Foundation

/// Live per-peer counters, parsed from the WireGuard UAPI text that `wgGetConfig` returns.
public struct PeerStats: Equatable, Sendable, Codable {
    public var publicKey: String          // base64
    public var endpoint: String?
    public var lastHandshake: Date?
    public var rxBytes: UInt64 = 0
    public var txBytes: UInt64 = 0
    public var persistentKeepalive: UInt16?
    public var allowedIPs: [String] = []

    public init(publicKey: String, endpoint: String? = nil, lastHandshake: Date? = nil, rxBytes: UInt64 = 0,
                txBytes: UInt64 = 0, persistentKeepalive: UInt16? = nil, allowedIPs: [String] = []) {
        self.publicKey = publicKey
        self.endpoint = endpoint
        self.lastHandshake = lastHandshake
        self.rxBytes = rxBytes
        self.txBytes = txBytes
        self.persistentKeepalive = persistentKeepalive
        self.allowedIPs = allowedIPs
    }
}

public struct RuntimeStats: Equatable, Sendable, Codable {
    public var listenPort: UInt16?
    public var peers: [PeerStats] = []
    /// Set for an OpenConnect (AnyConnect) tunnel instead of peers.
    public var openConnect: OpenConnectStatus?

    public init(listenPort: UInt16? = nil, peers: [PeerStats] = [], openConnect: OpenConnectStatus? = nil) {
        self.listenPort = listenPort
        self.peers = peers
        self.openConnect = openConnect
    }
    public var rxBytes: UInt64 { openConnect?.rxBytes ?? peers.reduce(0) { $0 &+ $1.rxBytes } }
    public var txBytes: UInt64 { openConnect?.txBytes ?? peers.reduce(0) { $0 &+ $1.txBytes } }
    public var latestHandshake: Date? { peers.compactMap(\.lastHandshake).max() }

    /// Parses `key=value` lines. Secret fields (private_key, preshared_key) are skipped, never stored.
    public static func parse(uapi: String) -> RuntimeStats {
        var stats = RuntimeStats()
        var current: PeerStats?
        var handshakeSec: Int64 = 0
        var handshakeNsec: Int64 = 0

        func finishPeer() {
            guard var p = current else { return }
            if handshakeSec > 0 || handshakeNsec > 0 {
                p.lastHandshake = Date(timeIntervalSince1970: TimeInterval(handshakeSec) + TimeInterval(handshakeNsec) / 1e9)
            }
            stats.peers.append(p)
            current = nil
            handshakeSec = 0
            handshakeNsec = 0
        }

        for line in uapi.split(whereSeparator: \.isNewline) {
            guard let eq = line.firstIndex(of: "=") else { continue }
            let key = line[..<eq]
            let value = String(line[line.index(after: eq)...])
            switch key {
            case "listen_port": stats.listenPort = UInt16(value)
            case "public_key":
                finishPeer()
                current = PeerStats(publicKey: WireGuardKey(hex: value)?.base64 ?? value)
            case "endpoint": current?.endpoint = value
            case "last_handshake_time_sec": handshakeSec = Int64(value) ?? 0
            case "last_handshake_time_nsec": handshakeNsec = Int64(value) ?? 0
            case "rx_bytes": current?.rxBytes = UInt64(value) ?? 0
            case "tx_bytes": current?.txBytes = UInt64(value) ?? 0
            case "persistent_keepalive_interval":
                let v = UInt16(value) ?? 0
                current?.persistentKeepalive = v == 0 ? nil : v
            case "allowed_ip": current?.allowedIPs.append(value)
            default: continue   // private_key, preshared_key, protocol_version, errno, …
            }
        }
        finishPeer()
        return stats
    }
}

public enum Format {
    /// "1.2 MB", base 1000 like Finder.
    public static func bytes(_ n: UInt64) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(clamping: n), countStyle: .file)
    }

    /// "Now", "42 s ago", "3 min ago", "2 h ago", "Never".
    public static func handshakeAge(_ date: Date?, now: Date = Date()) -> String {
        guard let date else { return "Never" }
        let s = max(0, Int(now.timeIntervalSince(date)))
        switch s {
        case ..<2: return "Now"
        case ..<60: return "\(s) s ago"
        case ..<3600: return "\(s / 60) min ago"
        case ..<86400: return "\(s / 3600) h ago"
        default: return "\(s / 86400) d ago"
        }
    }

    /// WireGuard rekeys every 2 minutes while traffic flows, and session keys expire after 3
    /// (REJECT_AFTER_TIME). An older handshake means no current session: either the tunnel is idle
    /// (no traffic and no keepalive) or the peer is not answering. Only traffic tells them apart.
    public static func isHandshakeStale(_ date: Date?, now: Date = Date()) -> Bool {
        guard let date else { return true }
        return now.timeIntervalSince(date) > 180
    }
}
