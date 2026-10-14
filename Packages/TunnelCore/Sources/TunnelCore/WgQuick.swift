import Foundation

public struct Diagnostic: Equatable, Sendable, CustomStringConvertible {
    public enum Severity: String, Sendable, Codable { case error, warning }
    public let severity: Severity
    /// 1-based line number, or nil for problems with the file as a whole.
    public let line: Int?
    public let message: String

    public init(_ severity: Severity, line: Int?, _ message: String) {
        self.severity = severity
        self.line = line
        self.message = message
    }

    public var description: String {
        let place = line.map { "line \($0): " } ?? ""
        return "\(severity.rawValue): \(place)\(message)"
    }
}

/// Parses and writes the wg-quick(8) file format.
public enum WgQuick {
    public struct ParseResult: Sendable {
        public let configuration: TunnelConfiguration?
        public let diagnostics: [Diagnostic]
        public var errors: [Diagnostic] { diagnostics.filter { $0.severity == .error } }
        public var warnings: [Diagnostic] { diagnostics.filter { $0.severity == .warning } }
    }

    /// Larger files are refused before parsing: real configs are a few KB, and the input may come
    /// from anywhere (a dropped file, a zip, the CLI).
    public static let maxBytes = 256 * 1024
    public static let maxPeers = 2048
    /// DNS entries (servers plus search domains). The review checks each server against every
    /// route, so an unbounded list would make opening a file quadratic (audit WOM-10).
    public static let maxDNSEntries = 64

    /// Keys wg-quick understands that only make sense for its shell implementation. Parsed so a
    /// valid file still imports, but never acted on: running PostUp from a downloaded config
    /// would execute arbitrary commands.
    public static let ignoredInterfaceKeys: Set<String> = [
        "table", "preup", "postup", "predown", "postdown", "saveconfig", "fwmark",
    ]

    public static func parse(_ text: String) -> ParseResult {
        var diagnostics: [Diagnostic] = []
        func error(_ line: Int?, _ message: String) { diagnostics.append(Diagnostic(.error, line: line, message)) }
        func warning(_ line: Int?, _ message: String) { diagnostics.append(Diagnostic(.warning, line: line, message)) }

        guard text.utf8.count <= maxBytes else {
            error(nil, "File is larger than \(maxBytes / 1024) KB")
            return ParseResult(configuration: nil, diagnostics: diagnostics)
        }

        enum Section { case none, interface, peer }
        struct Pending { var values: [String: (value: String, line: Int)] = [:]; var multi: [String: [(String, Int)]] = [:]; var line: Int }

        var section = Section.none
        var interface: Pending?
        var interfaceCount = 0
        var peers: [Pending] = []
        var ignored: [IgnoredKey] = []

        let multiKeys: Set<String> = ["address", "dns", "allowedips"]
        let interfaceKeys: Set<String> = ["privatekey", "address", "dns", "listenport", "mtu"]
        let peerKeys: Set<String> = ["publickey", "presharedkey", "allowedips", "endpoint", "persistentkeepalive"]

        // A UTF-8 byte order mark (Windows editors add one) is not part of the first line.
        let text = text.hasPrefix("\u{FEFF}") ? String(text.dropFirst()) : text
        // isNewline, not "\n": in Swift "\r\n" is one Character, so splitting on "\n" misses CRLF files.
        let lines = text.split(omittingEmptySubsequences: false, whereSeparator: \.isNewline)
        for (index, rawLine) in lines.enumerated() {
            let lineNumber = index + 1
            var line = Substring(rawLine)
            if let hash = line.firstIndex(of: "#") { line = line[..<hash] }
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty { continue }
            // Control characters and invisible format characters (bidi overrides, zero-width)
            // could make a line display differently from what it says.
            if trimmed.unicodeScalars.contains(where: { ($0.value < 0x20 && $0 != "\t") || (0x7F...0x9F).contains($0.value) || $0.properties.generalCategory == .format }) {
                error(lineNumber, "Line contains control or invisible formatting characters")
                continue
            }

            if trimmed.hasPrefix("[") {
                switch trimmed.lowercased() {
                case "[interface]":
                    section = .interface
                    interfaceCount += 1
                    if interfaceCount > 1 { error(lineNumber, "Only one [Interface] section is allowed") }
                    else { interface = Pending(line: lineNumber) }
                case "[peer]":
                    section = .peer
                    if peers.count >= maxPeers { error(lineNumber, "More than \(maxPeers) peers"); return ParseResult(configuration: nil, diagnostics: diagnostics) }
                    peers.append(Pending(line: lineNumber))
                default:
                    error(lineNumber, "Unknown section \(trimmed)")
                    section = .none
                }
                continue
            }

            guard let equals = trimmed.firstIndex(of: "=") else {
                error(lineNumber, "Expected \"Key = Value\"")
                continue
            }
            let key = trimmed[..<equals].trimmingCharacters(in: .whitespaces)
            let value = trimmed[trimmed.index(after: equals)...].trimmingCharacters(in: .whitespaces)
            let lowered = key.lowercased()

            switch section {
            case .none:
                error(lineNumber, "\"\(key)\" is outside a section")
            case .interface:
                if ignoredInterfaceKeys.contains(lowered) {
                    ignored.append(IgnoredKey(key: key, value: value, line: lineNumber))
                    continue
                }
                guard interfaceKeys.contains(lowered) else { error(lineNumber, "Unknown key \"\(key)\" in [Interface]"); continue }
                guard interfaceCount == 1 else { continue }
                store(&interface!, lowered, value, lineNumber, multi: multiKeys.contains(lowered), error: error)
            case .peer:
                guard peerKeys.contains(lowered) else { error(lineNumber, "Unknown key \"\(key)\" in [Peer]"); continue }
                store(&peers[peers.count - 1], lowered, value, lineNumber, multi: multiKeys.contains(lowered), error: error)
            }
        }

        func store(_ p: inout Pending, _ key: String, _ value: String, _ line: Int, multi: Bool, error: (Int?, String) -> Void) {
            if multi {
                p.multi[key, default: []].append((value, line))
            } else if p.values[key] != nil {
                error(line, "Duplicate key \"\(key)\"")
            } else {
                p.values[key] = (value, line)
            }
        }

        // Splits "a, b,c" into trimmed non-empty items, keeping each item's line.
        func items(_ entries: [(String, Int)]?) -> [(String, Int)] {
            (entries ?? []).flatMap { value, line in
                value.split(separator: ",").map { ($0.trimmingCharacters(in: .whitespaces), line) }.filter { !$0.0.isEmpty }
            }
        }

        guard let iface = interface else {
            error(nil, "Missing [Interface] section")
            return ParseResult(configuration: nil, diagnostics: diagnostics)
        }

        var interfaceConfig: InterfaceConfiguration?
        if let (value, line) = iface.values["privatekey"] {
            if let key = WireGuardKey(base64: value) { interfaceConfig = InterfaceConfiguration(privateKey: key) }
            else { error(line, "PrivateKey is not a valid key (44 base64 characters)") }
        } else {
            error(iface.line, "[Interface] has no PrivateKey")
        }

        var addresses: [IPAddressRange] = []
        for (item, line) in items(iface.multi["address"]) {
            if let range = IPAddressRange(item) { addresses.append(range) }
            else { error(line, "Address \"\(item)\" is not an IP address with optional /prefix") }
        }

        var dnsServers: [String] = []
        var dnsSearch: [String] = []
        for (item, line) in items(iface.multi["dns"]) {
            if dnsServers.count + dnsSearch.count >= maxDNSEntries {
                error(line, "More than \(maxDNSEntries) DNS entries")
                break
            }
            if let ip = IPAddressRange(item), ip.prefixLength == ip.maxPrefix, !item.contains("/") {
                dnsServers.append(ip.addressString)
            } else if Endpoint.isValidHostname(item) {
                dnsSearch.append(item.lowercased())
            } else {
                error(line, "DNS \"\(item)\" is neither an IP address nor a domain name")
            }
        }

        var listenPort: UInt16?
        if let (value, line) = iface.values["listenport"] {
            if let port = UInt16(value), value.allSatisfy(\.isASCIIDigit) { listenPort = port }
            else { error(line, "ListenPort must be a number from 0 to 65535") }
        }
        var mtu: UInt16?
        if let (value, line) = iface.values["mtu"] {
            if value.allSatisfy(\.isASCIIDigit), let m = UInt16(value), (576...65535).contains(m) { mtu = m }
            else { error(line, "MTU must be a number from 576 to 65535") }
        }

        var peerConfigs: [PeerConfiguration] = []
        var seenPeers = Set<WireGuardKey>()
        for peer in peers {
            guard let (value, line) = peer.values["publickey"] else {
                error(peer.line, "[Peer] has no PublicKey")
                continue
            }
            guard let publicKey = WireGuardKey(base64: value) else {
                error(line, "PublicKey is not a valid key (44 base64 characters)")
                continue
            }
            // A repeated peer is ambiguous, and WireGuardKit aborts the process on it.
            guard seenPeers.insert(publicKey).inserted else {
                error(line, "Peer \(publicKey.abbreviated) appears more than once")
                continue
            }
            var p = PeerConfiguration(publicKey: publicKey)
            if let (value, line) = peer.values["presharedkey"] {
                if let k = WireGuardKey(base64: value) { p.presharedKey = k }
                else { error(line, "PresharedKey is not a valid key (44 base64 characters)") }
            }
            for (item, line) in items(peer.multi["allowedips"]) {
                if let range = IPAddressRange(item) { p.allowedIPs.append(range) }
                else { error(line, "AllowedIPs entry \"\(item)\" is not an IP address with optional /prefix") }
            }
            if let (value, line) = peer.values["endpoint"] {
                if let e = Endpoint(value) { p.endpoint = e }
                else { error(line, "Endpoint \"\(value)\" must be host:port or [IPv6]:port") }
            }
            if let (value, line) = peer.values["persistentkeepalive"] {
                if value.lowercased() == "off" { p.persistentKeepalive = nil }
                else if value.allSatisfy(\.isASCIIDigit), let k = UInt16(value) { p.persistentKeepalive = k == 0 ? nil : k }
                else { error(line, "PersistentKeepalive must be \"off\" or a number of seconds") }
            }
            peerConfigs.append(p)
        }

        if let mtu, mtu < 1280, addresses.contains(where: { $0.family == .v6 }) {
            warning(iface.values["mtu"]?.line, "MTU \(mtu) is below 1280, the minimum for IPv6: IPv6 traffic will fail")
        }
        for item in ignored {
            let hook = ["preup", "postup", "predown", "postdown"].contains(item.key.lowercased())
            let message: String
            if hook { message = "\(item.key) is ignored: this app never runs scripts from a tunnel file" }
            else if item.key.lowercased() == "table" { message = "Table is not supported: routes for AllowedIPs are always installed" }
            else { message = "\(item.key) is a wg-quick setting this app ignores" }
            warning(item.line, message)
        }

        guard diagnostics.allSatisfy({ $0.severity != .error }), var config = interfaceConfig else {
            return ParseResult(configuration: nil, diagnostics: diagnostics)
        }
        config.addresses = addresses
        config.dnsServers = dnsServers
        config.dnsSearchDomains = dnsSearch
        config.listenPort = listenPort
        config.mtu = mtu
        config.ignored = ignored
        return ParseResult(configuration: TunnelConfiguration(interface: config, peers: peerConfigs), diagnostics: diagnostics)
    }

    /// Writes wg-quick text. Ignored keys (PostUp, …) are not written back.
    public static func serialize(_ c: TunnelConfiguration, includePrivateKey: Bool = true) -> String {
        var out = "[Interface]\n"
        out += "PrivateKey = \(includePrivateKey ? c.interface.privateKey.base64 : "(hidden)")\n"
        if !c.interface.addresses.isEmpty { out += "Address = \(c.interface.addresses.map(\.description).joined(separator: ", "))\n" }
        let dns = c.interface.dnsServers + c.interface.dnsSearchDomains
        if !dns.isEmpty { out += "DNS = \(dns.joined(separator: ", "))\n" }
        if let port = c.interface.listenPort { out += "ListenPort = \(port)\n" }
        if let mtu = c.interface.mtu { out += "MTU = \(mtu)\n" }
        for peer in c.peers {
            out += "\n[Peer]\nPublicKey = \(peer.publicKey.base64)\n"
            if let psk = peer.presharedKey { out += "PresharedKey = \(includePrivateKey ? psk.base64 : "(hidden)")\n" }
            if !peer.allowedIPs.isEmpty { out += "AllowedIPs = \(peer.allowedIPs.map(\.description).joined(separator: ", "))\n" }
            if let e = peer.endpoint { out += "Endpoint = \(e)\n" }
            if let k = peer.persistentKeepalive { out += "PersistentKeepalive = \(k)\n" }
        }
        return out
    }
}
