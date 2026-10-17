import CommonCrypto
import CryptoKit
import Foundation

/// Cisco's STRAP keys, for single sign-on in the system browser ("external browser" mode).
///
/// The client sends two P-256 public keys with every sign-in request. When the identity
/// provider is done, the browser goes to `http://localhost:29786/api/sso/<blob>`: the blob is the
/// SSO token, encrypted to the DH key (ECDH with the gateway's ephemeral key, HKDF-SHA256 with
/// info "AC_ECIES", AES-256-GCM with a 12-byte tag). The signing key then proves, at the tunnel's
/// CONNECT, that the tunnel belongs to the client that signed in (libopenconnect does that part).
/// Reimplemented from OpenConnect's hpke.c and openssl.c (v9.21).
public struct AnyConnectStrap: Sendable {
    let signing: P256.Signing.PrivateKey
    let agreement: P256.KeyAgreement.PrivateKey

    public init() {
        signing = P256.Signing.PrivateKey()
        agreement = P256.KeyAgreement.PrivateKey()
    }

    /// `X-AnyConnect-STRAP-Pubkey`: the signing key's SubjectPublicKeyInfo, base64.
    public var publicKey: String { signing.publicKey.derRepresentation.base64EncodedString() }
    /// `X-AnyConnect-STRAP-DH-Pubkey`.
    public var dhPublicKey: String { agreement.publicKey.derRepresentation.base64EncodedString() }

    /// The signing key for libopenconnect (`openconnect_strapkey`): a SEC1 ECPrivateKey in
    /// base64, the form OpenSSL's d2i_ECPrivateKey reads. A credential, handled like the token.
    public var signingKeyForTunnel: String {
        // SEQUENCE { INTEGER 1, OCTET STRING d, [0] OID prime256v1, [1] BIT STRING Q }
        let d = [UInt8](signing.rawRepresentation)
        let q = [UInt8](signing.publicKey.x963Representation)
        let oid: [UInt8] = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]
        var body: [UInt8] = [0x02, 0x01, 0x01, 0x04, UInt8(d.count)] + d
        body += [0xA0, UInt8(oid.count)] + oid
        let bits: [UInt8] = [0x03, UInt8(q.count + 1), 0x00] + q
        body += [0xA1, UInt8(bits.count)] + bits
        // DER lengths are minimal: one byte below 128 (this body is 119 bytes).
        let header: [UInt8] = body.count < 128 ? [0x30, UInt8(body.count)] : [0x30, 0x81, UInt8(body.count)]
        return Data(header + body).base64EncodedString()
    }

    public struct Failure: Error, Equatable, Sendable, CustomStringConvertible {
        public let description: String
    }

    static let maxBlob = 4096

    /// Decrypts the blob the browser delivered; the token must be alphanumeric, as Cisco's are.
    public func decryptToken(_ blob: Data) throws -> String {
        guard blob.count <= Self.maxBlob, blob.count >= 2 else { throw Failure(description: "The sign-in result has the wrong size") }
        let bytes = [UInt8](blob)
        guard bytes[0] == 0x00, bytes[1] == 0x01 else { throw Failure(description: "The sign-in result has an unknown format") }
        var fields: [UInt16: [UInt8]] = [:]
        var pos = 2
        while pos < bytes.count {
            guard pos + 4 <= bytes.count else { throw Failure(description: "The sign-in result is truncated") }
            let tag = UInt16(bytes[pos]) << 8 | UInt16(bytes[pos + 1])
            let length = Int(UInt16(bytes[pos + 2]) << 8 | UInt16(bytes[pos + 3]))
            guard (1...4).contains(tag), fields[tag] == nil, pos + 4 + length <= bytes.count else {
                throw Failure(description: "The sign-in result is malformed")
            }
            fields[tag] = Array(bytes[(pos + 4)..<(pos + 4 + length)])
            pos += 4 + length
        }
        guard let serverKey = fields[1], let tag = fields[2], tag.count == 12, let ciphertext = fields[3],
              let iv = fields[4], iv.count == 12 else {
            throw Failure(description: "The sign-in result is incomplete")
        }
        let peer: P256.KeyAgreement.PublicKey
        do { peer = try P256.KeyAgreement.PublicKey(derRepresentation: serverKey) } catch {
            throw Failure(description: "The gateway's key in the sign-in result is invalid")
        }
        let shared = try agreement.sharedSecretFromKeyAgreement(with: peer)
        // OpenSSL's HKDF with no salt is RFC 5869's default salt (zeros), as CryptoKit's empty salt.
        let key = shared.withUnsafeBytes { raw in
            HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: Data(raw)), salt: Data(),
                                   info: Data("AC_ECIES".utf8), outputByteCount: 32)
        }
        let plain = try key.withUnsafeBytes { try GCM.decrypt(key: [UInt8]($0), iv: iv, ciphertext: ciphertext, tag: tag) }
        guard !plain.isEmpty, plain.count <= 1024, plain.allSatisfy({ $0 < 0x80 && (Character(UnicodeScalar($0)).isLetter || Character(UnicodeScalar($0)).isNumber) }) else {
            throw Failure(description: "The decrypted sign-in token isn't alphanumeric")
        }
        return String(decoding: plain, as: UTF8.self)
    }
}

/// AES-256-GCM decryption with a truncated tag, which CryptoKit doesn't accept (it wants 16
/// bytes). Built on the AES block cipher alone (CommonCrypto, ECB on single blocks), per NIST
/// SP 800-38D, for the small STRAP payloads only. The tag is compared in constant time.
enum GCM {
    struct Failure: Error {}

    static func decrypt(key: [UInt8], iv: [UInt8], ciphertext: [UInt8], tag: [UInt8], aad: [UInt8] = []) throws -> [UInt8] {
        guard key.count == 32, iv.count == 12, (12...16).contains(tag.count) else { throw Failure() }
        let h = try block(key, [UInt8](repeating: 0, count: 16))
        let j0 = iv + [0, 0, 0, 1]
        // Tag first: nothing is decrypted from an unauthenticated message.
        var full = ghash(h, aad: aad, ciphertext: ciphertext)
        let ej0 = try block(key, j0)
        for i in 0..<16 { full[i] ^= ej0[i] }
        var difference: UInt8 = 0
        for i in 0..<tag.count { difference |= full[i] ^ tag[i] }
        guard difference == 0 else { throw AnyConnectStrap.Failure(description: "The sign-in result failed authentication") }
        var counter = j0
        var out = [UInt8]()
        out.reserveCapacity(ciphertext.count)
        var offset = 0
        while offset < ciphertext.count {
            increment(&counter)
            let stream = try block(key, counter)
            for i in 0..<min(16, ciphertext.count - offset) { out.append(ciphertext[offset + i] ^ stream[i]) }
            offset += 16
        }
        return out
    }

    static func block(_ key: [UInt8], _ input: [UInt8]) throws -> [UInt8] {
        var output = [UInt8](repeating: 0, count: 16)
        var moved = 0
        let status = CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionECBMode),
                             key, key.count, nil, input, 16, &output, 16, &moved)
        guard status == kCCSuccess, moved == 16 else { throw Failure() }
        return output
    }

    static func increment(_ counter: inout [UInt8]) {
        for i in stride(from: 15, through: 12, by: -1) {
            counter[i] &+= 1
            if counter[i] != 0 { break }
        }
    }

    static func ghash(_ h: [UInt8], aad: [UInt8], ciphertext: [UInt8]) -> [UInt8] {
        var y = [UInt8](repeating: 0, count: 16)
        func absorb(_ data: [UInt8]) {
            var offset = 0
            while offset < data.count {
                for i in 0..<16 where offset + i < data.count { y[i] ^= data[offset + i] }
                y = multiply(y, h)
                offset += 16
            }
        }
        absorb(aad)
        absorb(ciphertext)
        var lengths = [UInt8](repeating: 0, count: 16)
        let aBits = UInt64(aad.count) * 8, cBits = UInt64(ciphertext.count) * 8
        for i in 0..<8 {
            lengths[7 - i] = UInt8(truncatingIfNeeded: aBits >> (8 * UInt64(i)))
            lengths[15 - i] = UInt8(truncatingIfNeeded: cBits >> (8 * UInt64(i)))
        }
        for i in 0..<16 { y[i] ^= lengths[i] }
        return multiply(y, h)
    }

    /// GF(2^128) multiplication, bit by bit (SP 800-38D algorithm 1).
    static func multiply(_ x: [UInt8], _ y: [UInt8]) -> [UInt8] {
        var z = [UInt8](repeating: 0, count: 16)
        var v = y
        for i in 0..<128 {
            if x[i / 8] & (0x80 >> UInt8(i % 8)) != 0 { for j in 0..<16 { z[j] ^= v[j] } }
            let lsb = v[15] & 1
            for j in stride(from: 15, to: 0, by: -1) { v[j] = (v[j] >> 1) | (v[j - 1] << 7) }
            v[0] >>= 1
            if lsb != 0 { v[0] ^= 0xE1 }
        }
        return z
    }
}
