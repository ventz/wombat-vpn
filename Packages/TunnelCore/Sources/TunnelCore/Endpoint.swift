import Foundation
import Network

/// A peer endpoint: "host:port", "1.2.3.4:51820" or "[2001:db8::1]:51820".
public struct Endpoint: Hashable, Sendable, CustomStringConvertible {
    public enum Host: Hashable, Sendable {
        case ipv4(String)
        case ipv6(String)
        case name(String)
    }

    public let host: Host
    public let port: UInt16

    public init?(_ text: String) {
        let s = text.trimmingCharacters(in: .whitespaces)
        if s.hasPrefix("[") {
            guard let close = s.firstIndex(of: "]") else { return nil }
            let inner = String(s[s.index(after: s.startIndex)..<close])
            let rest = s[s.index(after: close)...]
            guard rest.hasPrefix(":"), IPv6Address(inner) != nil, !inner.contains("%"),
                  let port = Self.port(rest.dropFirst()) else { return nil }
            host = .ipv6(inner)
            self.port = port
            return
        }
        guard let colon = s.lastIndex(of: ":") else { return nil }
        let name = String(s[..<colon])
        guard !name.contains(":"), let port = Self.port(s[s.index(after: colon)...]) else { return nil }
        if name.split(separator: ".", omittingEmptySubsequences: false).count == 4,
           name.allSatisfy({ $0.isASCIIDigit || $0 == "." }) {
            guard IPv4Address(name) != nil else { return nil }
            host = .ipv4(name)
        } else {
            guard Self.isValidHostname(name) else { return nil }
            host = .name(name.lowercased())
        }
        self.port = port
    }

    public var hostString: String {
        switch host {
        case .ipv4(let s), .ipv6(let s), .name(let s): return s
        }
    }

    public var description: String {
        if case .ipv6(let s) = host { return "[\(s)]:\(port)" }
        return "\(hostString):\(port)"
    }

    /// A hostname endpoint is resolved outside the tunnel, which leaks that lookup to the local network.
    public var isHostname: Bool { if case .name = host { return true }; return false }

    private static func port<S: StringProtocol>(_ text: S) -> UInt16? {
        guard !text.isEmpty, text.count <= 5, text.allSatisfy(\.isASCIIDigit),
              let value = UInt16(text), value > 0 else { return nil }
        return value
    }

    /// RFC 1123 labels: letters, digits, hyphens; no leading/trailing hyphen; ≤253 total. The last
    /// label must not be all digits: resolvers read "2130706433" or "10.1" as IP addresses, which
    /// would let a config hide its real endpoint (127.0.0.1) behind a "hostname".
    static func isValidHostname(_ name: String) -> Bool {
        guard !name.isEmpty, name.utf8.count <= 253 else { return false }
        let labels = name.hasSuffix(".") ? name.dropLast().split(separator: ".", omittingEmptySubsequences: false)
                                          : name.split(separator: ".", omittingEmptySubsequences: false)
        guard let last = labels.last, !last.allSatisfy(\.isASCIIDigit) else { return false }
        // inet_aton also reads hex and octal forms ("0x7f000001", "127.0.0.0x1", "0177.1"), which
        // getaddrinfo turns into an address without any lookup (audit WOM-16).
        var scratch = in_addr()
        if inet_aton(name, &scratch) != 0 { return false }
        return labels.allSatisfy { label in
            !label.isEmpty && label.utf8.count <= 63 && !label.hasPrefix("-") && !label.hasSuffix("-")
                && label.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-") }
        }
    }
}
