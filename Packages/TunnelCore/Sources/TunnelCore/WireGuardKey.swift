import CryptoKit
import Foundation

/// A 32-byte Curve25519 key in WireGuard's base64 text form.
public struct WireGuardKey: Hashable, Sendable, CustomStringConvertible {
    public let rawValue: Data

    public init?(rawValue: Data) {
        guard rawValue.count == 32 else { return nil }
        self.rawValue = rawValue
    }

    /// Accepts exactly 44 base64 characters ending in "=" (what `wg genkey` prints).
    public init?(base64: String) {
        guard base64.utf8.count == 44, base64.hasSuffix("="),
              let data = Data(base64Encoded: base64), data.count == 32 else { return nil }
        rawValue = data
    }

    /// Accepts the 64-character lowercase hex form used by the UAPI.
    public init?(hex: String) {
        // ASCII hex only: a multi-byte character would make the 2-character stepping below
        // run past the end of the string.
        guard hex.utf8.count == 64, hex.utf8.allSatisfy({ ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102) || ($0 >= 65 && $0 <= 70) }) else { return nil }
        var bytes = [UInt8]()
        bytes.reserveCapacity(32)
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else { return nil }
            bytes.append(byte)
            index = next
        }
        rawValue = Data(bytes)
    }

    public var base64: String { rawValue.base64EncodedString() }
    public var hex: String { rawValue.map { String(format: "%02x", $0) }.joined() }

    /// Short, non-secret fingerprint for public keys in tight UI ("xTIB…dHw=").
    public var abbreviated: String {
        let s = base64
        return "\(s.prefix(4))…\(s.suffix(4))"
    }

    /// Never print key material by accident: use `base64` explicitly.
    public var description: String { "WireGuardKey(\(abbreviated))" }

    /// The all-zero key is what an unset key looks like in the UAPI.
    public var isZero: Bool { rawValue.allSatisfy { $0 == 0 } }
}

public enum KeyPair {
    /// A fresh private key, clamped the way `wg genkey` clamps it.
    public static func generatePrivateKey() -> WireGuardKey {
        var raw = [UInt8](Curve25519.KeyAgreement.PrivateKey().rawRepresentation)
        raw[0] &= 248
        raw[31] = (raw[31] & 127) | 64
        return WireGuardKey(rawValue: Data(raw))!
    }

    /// The public key for a private key (X25519 clamps internally, so unclamped input works too).
    public static func publicKey(for privateKey: WireGuardKey) -> WireGuardKey {
        let key = try! Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey.rawValue)
        return WireGuardKey(rawValue: key.publicKey.rawRepresentation)!
    }

    /// A random preshared key (`wg genpsk`).
    public static func generatePresharedKey() -> WireGuardKey {
        WireGuardKey(rawValue: SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) })!
    }
}
