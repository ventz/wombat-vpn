import CryptoKit
import Foundation
import Security
import Testing
@testable import TunnelCore

/// Signs in to the throwaway ocserv gateway from scripts/dev/ocserv-peer.sh with the real
/// URLSession transport. Skipped unless the gateway is up:
///
///     scripts/dev/ocserv-peer.sh up          # or: up --cert
///     WOMBAT_OCSERV_LIVE=1 swift test --filter AnyConnectLive
@Suite(.enabled(if: ProcessInfo.processInfo.environment["WOMBAT_OCSERV_LIVE"] == "1"))
struct AnyConnectLiveTests {
    static let env: [String: String] = {
        let file = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .appendingPathComponent("../../../../build/ocserv-peer/test.env").standardizedFileURL
        guard let text = try? String(contentsOf: file, encoding: .utf8) else { return [:] }
        var values: [String: String] = [:]
        for line in text.split(separator: "\n") {
            let parts = line.split(separator: "=", maxSplits: 1).map(String.init)
            if parts.count == 2 { values[parts[0]] = parts[1] }
        }
        return values
    }()

    static func totp(_ hex: String, at date: Date = Date()) -> String {
        var key = Data()
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            key.append(UInt8(hex[index..<next], radix: 16)!)
            index = next
        }
        var counter = UInt64(date.timeIntervalSince1970 / 30).bigEndian
        let mac = Data(HMAC<Insecure.SHA1>.authenticationCode(for: Data(bytes: &counter, count: 8), using: SymmetricKey(data: key)))
        let offset = Int(mac[mac.count - 1] & 0x0F)
        let value = (UInt32(mac[offset]) << 24 | UInt32(mac[offset + 1]) << 16 | UInt32(mac[offset + 2]) << 8 | UInt32(mac[offset + 3])) & 0x7FFF_FFFF
        return String(format: "%06d", value % 1_000_000)
    }

    @Test func rfc6238Vector() {
        // RFC 6238 appendix B, SHA-1, T = 59 s: 94287082 (8 digits) → the last 6 are 287082.
        #expect(Self.totp("3132333435363738393031323334353637383930", at: Date(timeIntervalSince1970: 59)) == "287082")
    }

    @Test func signsInAndGetsASession() async throws {
        let env = Self.env
        let url = try #require(env["WOMBAT_OCSERV_URL"].flatMap(URL.init(string:)), "run scripts/dev/ocserv-peer.sh up first")
        var identity: SecIdentity?
        var profile = OpenConnectProfile(server: url, username: env["WOMBAT_OCSERV_USER"], serverCertificate: env["WOMBAT_OCSERV_PIN"])
        if env["WOMBAT_OCSERV_MODE"] == "cert" {
            let data = try Data(contentsOf: URL(fileURLWithPath: try #require(env["WOMBAT_OCSERV_CLIENT_P12"])))
            var items: CFArray?
            let status = SecPKCS12Import(data as CFData, [kSecImportExportPassphrase: env["WOMBAT_OCSERV_CLIENT_P12_PASSWORD"] ?? ""] as CFDictionary, &items)
            #expect(status == errSecSuccess)
            let first = try #require((items as? [[String: Any]])?.first)
            identity = (first[kSecImportItemIdentity as String] as! SecIdentity)
            profile.clientCertificate = "set"
        }
        let password = env["WOMBAT_OCSERV_PASSWORD"] ?? ""
        let secret = env["WOMBAT_OCSERV_OTP_SECRET"] ?? ""
        let steps = Recorder()
        let signIn = AnyConnectSignIn(
            profile: profile,
            transport: URLSessionGatewayTransport(profile: profile, identity: identity),
            prompts: AnyConnectPrompts(fill: { prompt in
                steps.append(prompt)
                var answers = prompt.prefilled
                for field in prompt.form.fields {
                    switch field.kind {
                    case .text: answers[field.name] = answers[field.name] ?? "test"
                    case .password:
                        let wantsOTP = (prompt.message ?? "").lowercased().contains("otp")
                        answers[field.name] = wantsOTP ? Self.totp(secret) : password
                    default: continue
                    }
                }
                return answers
            }, singleSignOn: { _ in throw CancellationError() }),
            hasClientCertificate: identity != nil)
        let session = try await signIn.run()
        #expect(session.validate() == nil)
        #expect(session.host == "localhost")
        #expect(session.port == url.port)
        #expect(session.serverCertificateSHA256 == env["WOMBAT_OCSERV_PIN"])
        #expect(session.address != nil)
        #expect(!steps.prompts.isEmpty)
        print("live sign-in: \(steps.prompts.count) prompt(s): \(steps.prompts.map { $0.message ?? "-" }); gateway address \(session.address ?? "?")")
    }

    /// In --cert mode, a profile without a certificate must not present one (no identity
    /// preference, S5-NV1): the gateway refuses, and the sign-in says a certificate is needed.
    @Test func certificateGatewayWithoutIdentity() async throws {
        guard Self.env["WOMBAT_OCSERV_MODE"] == "cert" else { return }
        let url = try #require(Self.env["WOMBAT_OCSERV_URL"].flatMap(URL.init(string:)))
        let profile = OpenConnectProfile(server: url, username: "test", serverCertificate: Self.env["WOMBAT_OCSERV_PIN"])
        let signIn = AnyConnectSignIn(profile: profile, transport: URLSessionGatewayTransport(profile: profile, identity: nil),
                                      prompts: AnyConnectPrompts(fill: { _ in ["username": "test", "password": "test-password"] }, singleSignOn: { _ in "" }),
                                      hasClientCertificate: false)
        do {
            _ = try await signIn.run()
            Issue.record("signed in to a certificate gateway without a certificate")
        } catch {
            print("cert gateway without identity: \(error.localizedDescription)")
        }
    }

    @Test func refusesAWrongPin() async throws {
        let url = try #require(Self.env["WOMBAT_OCSERV_URL"].flatMap(URL.init(string:)))
        let profile = OpenConnectProfile(server: url, serverCertificate: String(repeating: "0", count: 64))
        let signIn = AnyConnectSignIn(profile: profile, transport: URLSessionGatewayTransport(profile: profile, identity: nil),
                                      prompts: AnyConnectPrompts(fill: { _ in nil }, singleSignOn: { _ in "" }), hasClientCertificate: false)
        await #expect(throws: AnyConnectSignInError.self) {
            do { _ = try await signIn.run() } catch let e as AnyConnectSignInError {
                guard case .pinMismatch = e else { Issue.record("expected pinMismatch, got \(e)"); throw e }
                throw e
            }
        }
    }

    @Test func refusesAnUntrustedCertificateWithoutAPin() async throws {
        let url = try #require(Self.env["WOMBAT_OCSERV_URL"].flatMap(URL.init(string:)))
        let profile = OpenConnectProfile(server: url)
        let signIn = AnyConnectSignIn(profile: profile, transport: URLSessionGatewayTransport(profile: profile, identity: nil),
                                      prompts: AnyConnectPrompts(fill: { _ in nil }, singleSignOn: { _ in "" }), hasClientCertificate: false)
        do {
            _ = try await signIn.run()
            Issue.record("signed in to a gateway with an untrusted certificate")
        } catch let AnyConnectSignInError.untrustedServer(host, sha256, _) {
            #expect(host == "localhost")
            #expect(sha256 == Self.env["WOMBAT_OCSERV_PIN"])
        }
    }
}
