import CryptoKit
import Foundation
import Security

/// Certificates with a private key (identities) in the user's keychains (not smart cards yet: the sandboxed query would need a token access group; quality-6 M4),
/// for AnyConnect certificate sign-in. Wombat stores only the certificate's SHA-256 in the
/// profile and finds the identity again at sign-in: the private key never leaves the keychain,
/// and macOS asks the user before Wombat may sign with it.
enum ClientIdentities {
    struct Item: Identifiable, Hashable {
        /// SHA-256 of the certificate (DER), lowercase hex: what profiles store.
        let id: String
        let name: String
        let issuer: String?
        let expires: Date?

        var isExpired: Bool { expires.map { $0 < Date() } ?? false }
    }

    static func all() -> [Item] {
        identities().compactMap { identity in
            var certificate: SecCertificate?
            guard SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess, let certificate else { return nil }
            return item(certificate)
        }
        .reduce(into: [String: Item]()) { $0[$1.id] = $1 }  // the same certificate in two keychains
        .values
        .sorted { ($0.isExpired ? 1 : 0, $0.name.lowercased()) < ($1.isExpired ? 1 : 0, $1.name.lowercased()) }
    }

    /// The identity whose certificate has this SHA-256, or nil when it's gone.
    static func identity(sha256: String) -> SecIdentity? {
        identities().first { identity in
            var certificate: SecCertificate?
            guard SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess, let certificate else { return false }
            return hash(certificate) == sha256
        }
    }

    static func item(sha256: String) -> Item? { all().first { $0.id == sha256 } }

    private static func identities() -> [SecIdentity] {
        let query: [CFString: Any] = [
            kSecClass: kSecClassIdentity,
            kSecReturnRef: true,
            kSecMatchLimit: kSecMatchLimitAll,
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess, let array = result as? [Any] else { return [] }
        // The query returns SecIdentity references; anything else is skipped.
        return array.compactMap { item in
            CFGetTypeID(item as CFTypeRef) == SecIdentityGetTypeID() ? (item as! SecIdentity) : nil
        }
    }

    static func hash(_ certificate: SecCertificate) -> String {
        SHA256.hash(data: SecCertificateCopyData(certificate) as Data).map { String(format: "%02x", $0) }.joined()
    }

    private static func item(_ certificate: SecCertificate) -> Item {
        let name = SecCertificateCopySubjectSummary(certificate) as String? ?? "Certificate"
        var issuer: String?
        var expires: Date?
        if let values = SecCertificateCopyValues(certificate, [kSecOIDX509V1IssuerName, kSecOIDX509V1ValidityNotAfter] as CFArray, nil) as? [CFString: Any] {
            if let entry = values[kSecOIDX509V1ValidityNotAfter] as? [CFString: Any], let seconds = entry[kSecPropertyKeyValue] as? NSNumber {
                expires = Date(timeIntervalSinceReferenceDate: seconds.doubleValue)
            }
            if let entry = values[kSecOIDX509V1IssuerName] as? [CFString: Any], let parts = entry[kSecPropertyKeyValue] as? [[CFString: Any]] {
                issuer = parts.first { ($0[kSecPropertyKeyLabel] as? String) == (kSecOIDCommonName as String) }?[kSecPropertyKeyValue] as? String
            }
        }
        return Item(id: hash(certificate), name: name, issuer: issuer, expires: expires)
    }
}
