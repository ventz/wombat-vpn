import CryptoKit
import Foundation
import Testing
@testable import TunnelCore

func hex(_ s: String) -> [UInt8] {
    var out = [UInt8]()
    var i = s.startIndex
    while i < s.endIndex { let n = s.index(i, offsetBy: 2); out.append(UInt8(s[i..<n], radix: 16)!); i = n }
    return out
}

@Suite struct AnyConnectStrapTests {
    /// "The Galois/Counter Mode of Operation" (McGrew & Viega), test case 16: AES-256, AAD.
    @Test func gcmPublishedVector() throws {
        let key = hex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
        let iv = hex("cafebabefacedbaddecaf888")
        let aad = hex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
        let plain = hex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39")
        let cipher = hex("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662")
        let tag = hex("76fc6ece0f4e1768cddf8853bb2d551b")
        #expect(try GCM.decrypt(key: key, iv: iv, ciphertext: cipher, tag: tag, aad: aad) == plain)
        #expect(try GCM.decrypt(key: key, iv: iv, ciphertext: cipher, tag: Array(tag.prefix(12)), aad: aad) == plain)  // truncated tag
        var bad = tag
        bad[0] ^= 1
        #expect(throws: (any Error).self) { try GCM.decrypt(key: key, iv: iv, ciphertext: cipher, tag: bad, aad: aad) }
    }

    /// Against an independent implementation: CryptoKit's GCM (16-byte tags), truncated to 12.
    @Test func gcmMatchesCryptoKit() throws {
        for length in [0, 1, 15, 16, 17, 100] {
            let key = SymmetricKey(size: .bits256)
            let nonce = AES.GCM.Nonce()
            let message = Data((0..<length).map { UInt8($0 & 0xFF) })
            let sealed = try AES.GCM.seal(message, using: key, nonce: nonce)
            let keyBytes = key.withUnsafeBytes { [UInt8]($0) }
            let out = try GCM.decrypt(key: keyBytes, iv: [UInt8](nonce), ciphertext: [UInt8](sealed.ciphertext), tag: Array([UInt8](sealed.tag).prefix(12)))
            #expect(out == [UInt8](message))
        }
    }

    /// A blob built the way the gateway builds it, decrypted by the client's DH key.
    @Test func decryptsAGatewayBlob() throws {
        let client = AnyConnectStrap()
        let gateway = P256.KeyAgreement.PrivateKey()
        let clientDH = try P256.KeyAgreement.PublicKey(derRepresentation: Data(base64Encoded: client.dhPublicKey)!)
        let shared = try gateway.sharedSecretFromKeyAgreement(with: clientDH)
        let key = shared.withUnsafeBytes { raw in
            HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: Data(raw)), salt: Data(), info: Data("AC_ECIES".utf8), outputByteCount: 32)
        }
        let nonce = AES.GCM.Nonce()
        let sealed = try AES.GCM.seal(Data("ABCDEF0123456789TOKEN".utf8), using: key, nonce: nonce)
        func tlv(_ tag: UInt16, _ value: [UInt8]) -> [UInt8] {
            [UInt8(tag >> 8), UInt8(tag & 0xFF), UInt8(value.count >> 8), UInt8(value.count & 0xFF)] + value
        }
        var blob: [UInt8] = [0x00, 0x01]
        blob += tlv(1, [UInt8](gateway.publicKey.derRepresentation))
        blob += tlv(2, Array([UInt8](sealed.tag).prefix(12)))
        blob += tlv(3, [UInt8](sealed.ciphertext))
        blob += tlv(4, [UInt8](nonce))
        #expect(try client.decryptToken(Data(blob)) == "ABCDEF0123456789TOKEN")
        // Someone else's DH key (another client, a forged blob) can't produce a valid token.
        #expect(throws: (any Error).self) { try AnyConnectStrap().decryptToken(Data(blob)) }
        // Malformed blobs are refused, not crashed on.
        for broken in [Data(), Data([0, 1]), Data(blob.dropLast(3)), Data([0, 2] + blob.dropFirst(2)), Data(blob + tlv(4, [1]))] {
            #expect(throws: (any Error).self) { try client.decryptToken(broken) }
        }
    }

    /// The SEC1 key round-trips: same private and public key, minimal DER lengths.
    @Test func signingKeyEncoding() throws {
        let strap = AnyConnectStrap()
        let der = try #require(Data(base64Encoded: strap.signingKeyForTunnel))
        #expect(der.count == 121 && der[0] == 0x30 && der[1] == 119)
        #expect(der[7..<39] == strap.signing.rawRepresentation)
        #expect(Data(der.suffix(65)) == strap.signing.publicKey.x963Representation)
    }
}

/// Builds the blob a gateway's success page hands the browser for this client.
func gatewayBlob(for client: AnyConnectStrap, token: String) throws -> Data {
    let gateway = P256.KeyAgreement.PrivateKey()
    let shared = try gateway.sharedSecretFromKeyAgreement(with: try P256.KeyAgreement.PublicKey(derRepresentation: Data(base64Encoded: client.dhPublicKey)!))
    let key = shared.withUnsafeBytes { HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: Data($0)), salt: Data(), info: Data("AC_ECIES".utf8), outputByteCount: 32) }
    let nonce = AES.GCM.Nonce()
    let sealed = try AES.GCM.seal(Data(token.utf8), using: key, nonce: nonce)
    func tlv(_ tag: UInt16, _ v: [UInt8]) -> [UInt8] { [0, UInt8(tag), UInt8(v.count >> 8), UInt8(v.count & 0xFF)] + v }
    return Data([0, 1] + tlv(1, [UInt8](gateway.publicKey.derRepresentation)) + tlv(2, Array([UInt8](sealed.tag).prefix(12)))
                + tlv(3, [UInt8](sealed.ciphertext)) + tlv(4, [UInt8](nonce)))
}

@Suite struct ExternalBrowserSignInTests {
    let external = ocSSO.replacingOccurrences(of: "<form>", with: "<sso-v2-browser-mode>external</sso-v2-browser-mode><form>")

    @Test func systemBrowserFlow() async throws {
        let strap = AnyConnectStrap()
        let blob = try gatewayBlob(for: strap, token: "SAMLTOKEN42")
        let gateway = ScriptedGateway([xmlReply(external), xmlReply(ocComplete)])
        let signIn = AnyConnectSignIn(profile: ocTestProfile, transport: gateway,
                                      prompts: AnyConnectPrompts(fill: { _ in nil }, singleSignOn: { _ in Issue.record("embedded used"); return "" },
                                                                 externalBrowser: { _ in blob }),
                                      hasClientCertificate: false, strap: strap)
        let session = try await signIn.run()
        let methods = gateway.requests[0].body.child("capabilities")?.children.map(\.allText)
        #expect(methods == ["single-sign-on-v2", "single-sign-on-external-browser"])
        #expect(gateway.requests[1].body.child("auth")?.child("sso-token")?.allText == "SAMLTOKEN42")
        #expect(session.strapKey == strap.signingKeyForTunnel)
        #expect(session.validate() == nil)
    }

    @Test func forgedBlobIsRefused() async throws {
        let forged = try gatewayBlob(for: AnyConnectStrap(), token: "EVIL")  // encrypted to someone else's key
        let signIn = AnyConnectSignIn(profile: ocTestProfile, transport: ScriptedGateway([xmlReply(external)]),
                                      prompts: AnyConnectPrompts(fill: { _ in nil }, singleSignOn: { _ in "" }, externalBrowser: { _ in forged }),
                                      hasClientCertificate: false, strap: AnyConnectStrap())
        await #expect(throws: AnyConnectSignInError.self) { try await signIn.run() }
    }

    @Test func withoutABrowserHandlerTheModeIsRefused() async {
        let signIn = AnyConnectSignIn(profile: ocTestProfile, transport: ScriptedGateway([xmlReply(external)]),
                                      prompts: AnyConnectPrompts(fill: { _ in nil }, singleSignOn: { _ in "" }),
                                      hasClientCertificate: false, strap: AnyConnectStrap())
        await #expect(throws: AnyConnectSignInError.externalBrowserRequired) { try await signIn.run() }
    }
}
