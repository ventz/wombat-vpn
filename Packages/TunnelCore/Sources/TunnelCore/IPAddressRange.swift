import Foundation
import Network

/// An IPv4 or IPv6 address with a prefix length ("10.0.0.2/32", "fd00::/64").
public struct IPAddressRange: Hashable, Sendable, CustomStringConvertible {
    public enum Family: Sendable { case v4, v6 }

    public let address: Data          // 4 or 16 network-order bytes
    public let prefixLength: UInt8

    public var family: Family { address.count == 4 ? .v4 : .v6 }
    public var maxPrefix: UInt8 { family == .v4 ? 32 : 128 }

    /// Parses "addr" or "addr/prefix". A missing prefix means a single host.
    public init?(_ text: String) {
        let trimmed = text.trimmingCharacters(in: .whitespaces)
        let parts = trimmed.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 1 || parts.count == 2 else { return nil }
        let host = String(parts[0])
        let bytes: Data
        if let v4 = IPv4Address(host), !host.contains(":") {
            // IPv4Address accepts shorthand like "10.1"; require four dotted parts.
            guard host.split(separator: ".", omittingEmptySubsequences: false).count == 4 else { return nil }
            bytes = v4.rawValue
        } else if let v6 = IPv6Address(host), host.contains(":"), !host.contains("%") {
            bytes = v6.rawValue
        } else {
            return nil
        }
        let max: UInt8 = bytes.count == 4 ? 32 : 128
        if parts.count == 2 {
            let p = parts[1]
            guard !p.isEmpty, p.count <= 3, p.allSatisfy(\.isASCIIDigit),
                  let value = UInt8(p), value <= max else { return nil }
            prefixLength = value
        } else {
            prefixLength = max
        }
        address = bytes
    }

    public init(address: Data, prefixLength: UInt8) {
        precondition(address.count == 4 || address.count == 16)
        self.address = address
        self.prefixLength = prefixLength
    }

    public var addressString: String {
        if family == .v4 { return "\(IPv4Address(address)!)" }
        return "\(IPv6Address(address)!)"
    }

    public var description: String { "\(addressString)/\(prefixLength)" }

    /// The range with host bits cleared ("10.0.0.7/24" → "10.0.0.0/24").
    public var network: IPAddressRange {
        IPAddressRange(address: Self.mask(address, prefixLength), prefixLength: prefixLength)
    }

    /// True when every address in `other` is also in this range.
    public func contains(_ other: IPAddressRange) -> Bool {
        guard family == other.family, other.prefixLength >= prefixLength else { return false }
        return Self.mask(address, prefixLength) == Self.mask(other.address, prefixLength)
    }

    public func overlaps(_ other: IPAddressRange) -> Bool { contains(other) || other.contains(self) }

    /// 0.0.0.0/0 or ::/0.
    public var isDefaultRoute: Bool { prefixLength == 0 }

    static func mask(_ bytes: Data, _ prefix: UInt8) -> Data {
        var out = [UInt8](bytes)
        var remaining = Int(prefix)
        for i in out.indices {
            if remaining >= 8 { remaining -= 8; continue }
            out[i] &= remaining == 0 ? 0 : UInt8(truncatingIfNeeded: 0xFF << (8 - remaining))
            remaining = 0
        }
        return Data(out)
    }
}

extension Character {
    var isASCIIDigit: Bool { isASCII && isNumber }
}
