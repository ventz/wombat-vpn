// Developer probe for the OpenConnect engine, outside NetworkExtension: signs in to the test
// gateway (scripts/dev/ocserv-peer.sh) with the app's Swift sign-in, then hands the session to
// libopenconnect exactly as the system extension does and prints what the gateway assigned.
// No tunnel device is created and nothing on the Mac changes. Build and run:
//     scripts/dev/oc-probe.sh
import CryptoKit
import Foundation
import Security

let root = URL(fileURLWithPath: CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : FileManager.default.currentDirectoryPath)
let envText = (try? String(contentsOf: root.appendingPathComponent("build/ocserv-peer/test.env"), encoding: .utf8)) ?? ""
var env: [String: String] = [:]
for line in envText.split(separator: "\n") {
    let parts = line.split(separator: "=", maxSplits: 1).map(String.init)
    if parts.count == 2 { env[parts[0]] = parts[1] }
}
if let override = ProcessInfo.processInfo.environment["OCPROBE_URL"] { env["WOMBAT_OCSERV_URL"] = override }
guard let url = env["WOMBAT_OCSERV_URL"].flatMap(URL.init(string:)) else {
    FileHandle.standardError.write(Data("oc-probe: run scripts/dev/ocserv-peer.sh up first\n".utf8))
    exit(1)
}

func totp(_ hex: String) -> String {
    var key = Data()
    var i = hex.startIndex
    while i < hex.endIndex { let n = hex.index(i, offsetBy: 2); key.append(UInt8(hex[i..<n], radix: 16)!); i = n }
    var counter = UInt64(Date().timeIntervalSince1970 / 30).bigEndian
    let mac = Data(HMAC<Insecure.SHA1>.authenticationCode(for: Data(bytes: &counter, count: 8), using: SymmetricKey(data: key)))
    let o = Int(mac[mac.count - 1] & 0x0F)
    let v = (UInt32(mac[o]) << 24 | UInt32(mac[o + 1]) << 16 | UInt32(mac[o + 2]) << 8 | UInt32(mac[o + 3])) & 0x7FFF_FFFF
    return String(format: "%06d", v % 1_000_000)
}

var identity: SecIdentity?
var profile = OpenConnectProfile(server: url, username: env["WOMBAT_OCSERV_USER"], serverCertificate: env["WOMBAT_OCSERV_PIN"])
if env["WOMBAT_OCSERV_MODE"] == "cert", let path = env["WOMBAT_OCSERV_CLIENT_P12"], let data = try? Data(contentsOf: URL(fileURLWithPath: path)) {
    var items: CFArray?
    _ = SecPKCS12Import(data as CFData, [kSecImportExportPassphrase: env["WOMBAT_OCSERV_CLIENT_P12_PASSWORD"] ?? ""] as CFDictionary, &items)
    identity = ((items as? [[String: Any]])?.first?[kSecImportItemIdentity as String] as! SecIdentity)
}
let password = env["WOMBAT_OCSERV_PASSWORD"] ?? ""
let secret = env["WOMBAT_OCSERV_OTP_SECRET"] ?? ""

// SSO discovery mode: the real transport and parser against a real gateway, stopping where the
// sign-in window would open (no credentials are sent): OCPROBE_SSO=https://vpn.example.edu/group
if let target = ProcessInfo.processInfo.environment["OCPROBE_SSO"], let server = URL(string: target) {
    let profile = OpenConnectProfile(server: server, userAgent: ProcessInfo.processInfo.environment["OCPROBE_UA"])
    let finished = DispatchSemaphore(value: 0)
    Task {
        let signIn = AnyConnectSignIn(profile: profile, transport: URLSessionGatewayTransport(profile: profile, identity: nil),
            prompts: AnyConnectPrompts(fill: { prompt in
                print("sso-probe: the gateway asks for a form: \(prompt.form.fields.map(\.name))"); return nil
            }, singleSignOn: { request in
                print("sso-probe: SSO login \(request.loginURL.host() ?? "?"), final \(request.finalURL), token cookie \(request.tokenCookie), mode \(request.browserMode ?? "embedded")")
                throw CancellationError()
            }), hasClientCertificate: false)
        do { _ = try await signIn.run() } catch { print("sso-probe: stopped: \(error.localizedDescription)") }
        finished.signal()
    }
    finished.wait()
    exit(0)
}

// Hostile-gateway mode: no sign-in, a made-up session against scripts/dev/hostile-gateway.py.
// Tunnel-TLS check: OCPROBE_TLS_HOST=vpn.example.edu OCPROBE_TLS_SHA256=<leaf> connects with an invalid
// token, so the TLS handshake shows the negotiated cipher and the gateway then refuses the CONNECT.
if let host = ProcessInfo.processInfo.environment["OCPROBE_TLS_HOST"], let sha = ProcessInfo.processInfo.environment["OCPROBE_TLS_SHA256"] {
    let session = AnyConnectSession(cookie: "invalid-session-for-tls-check", host: host, port: 443, address: nil, serverCertificateSHA256: sha)
    let engine = OpenConnectEngine(settings: .init(session: session, pin: nil, userAgent: ProcessInfo.processInfo.environment["OCPROBE_UA"] ?? AnyConnectXML.defaultUserAgent, dtls: false)) { level, message in
        print("tls[\(level)]: \(message)")
    }
    do { _ = try engine.connect(); print("tls-probe: connected (unexpected)") } catch { print("tls-probe: stopped as expected: \(error.localizedDescription)") }
    engine.shutdown()
    exit(0)
}

if let port = ProcessInfo.processInfo.environment["OCPROBE_HOSTILE"].flatMap(Int.init) {
    let session = AnyConnectSession(cookie: "hostile-test", host: "localhost", port: port, address: "127.0.0.1",
                                    serverCertificateSHA256: env["WOMBAT_OCSERV_PIN"] ?? "")
    let engine = OpenConnectEngine(settings: .init(session: session, pin: env["WOMBAT_OCSERV_PIN"], userAgent: AnyConnectXML.defaultUserAgent, dtls: false)) { level, message in
        print("hostile[\(level)]: \(message)")
    }
    do {
        let info = try engine.connect()
        let plan = try OpenConnectNetworkPlan.make(info)
        print("oc-probe: connected to the hostile gateway; routes kept: \(plan.ipv4Included.count) (capped at \(OpenConnectNetworkPlan.maxRoutes))")
    } catch {
        print("oc-probe: hostile gateway refused: \(error.localizedDescription)")
    }
    exit(0)
}

let done = DispatchSemaphore(value: 0)
Task {
    do {
        // STRAP keys on, as the app sends them (the gateway may ignore them; the tunnel must
        // still take the key: libopenconnect logs an error if it can't decode it).
        // As the app does: no browser sign-in, so no STRAP keys, with a pinned certificate (NEW-1).
        let strap = profile.usesBrowserSignIn ? AnyConnectStrap() : nil
        let signIn = AnyConnectSignIn(profile: profile, transport: URLSessionGatewayTransport(profile: profile, identity: identity, strap: strap),
            prompts: AnyConnectPrompts(fill: { prompt in
                print("sign-in: \(prompt.message ?? "(form)")")
                var answers = prompt.prefilled
                for field in prompt.form.fields {
                    switch field.kind {
                    case .text: answers[field.name] = answers[field.name] ?? "test"
                    case .password: answers[field.name] = (prompt.message ?? "").lowercased().contains("otp") ? totp(secret) : password
                    default: continue
                    }
                }
                return answers
            }, singleSignOn: { _ in throw CancellationError() }, externalBrowser: { _ in throw CancellationError() }),
            hasClientCertificate: identity != nil, strap: strap)
        let session = try await signIn.run()
        print("session STRAP key: \(session.strapKey == nil ? "none" : "present")")
        print("session: host \(session.host):\(session.port), address \(session.address ?? "-"), certificate \(session.serverCertificateSHA256.prefix(16))…, token \(session.cookie.count) characters")

        let engine = OpenConnectEngine(settings: .init(session: session, pin: profile.serverCertificate,
                                                       userAgent: AnyConnectXML.defaultUserAgent, dtls: profile.dtls)) { level, message in
            print("engine[\(level)]: \(message)")
        }
        let info = try engine.connect()
        let plan = try OpenConnectNetworkPlan.make(info)
        print("assigned: \(info)")
        print("plan: v4 \(plan.ipv4Address.map { "\($0.address)/\($0.prefixLength)" } ?? "-"), routes \(plan.ipv4Included.map { "\($0.address)/\($0.prefixLength)" }), DNS \(plan.dnsServers), search \(plan.searchDomains), blocked v6 \(plan.blockedIPv6)")
        print("transport: \(engine.transport)")

        // The main loop on a socket pair (a stand-in for utun), a forced reconnect (what wake
        // and network changes do), then a stop that must log off and end the loop.
        var pair: [Int32] = [-1, -1]
        _ = socketpair(AF_UNIX, SOCK_DGRAM, 0, &pair)
        let exited = DispatchSemaphore(value: 0)
        nonisolated(unsafe) var exitReason: String? = "not exited"
        try engine.start(tunnelFD: pair[0]) { reason in exitReason = reason; exited.signal() }
        Thread.sleep(forTimeInterval: 2)
        engine.reconnectNow()
        Thread.sleep(forTimeInterval: 4)
        engine.requestStats()
        Thread.sleep(forTimeInterval: 0.5)
        print("after reconnect: running \(engine.isRunning), transport \(engine.transport)")
        engine.stop()
        if exited.wait(timeout: .now() + 10) == .timedOut { print("oc-probe: FAILED: the main loop didn't end after stop"); exit(1) }
        print("main loop ended, reason: \(exitReason ?? "requested stop")")
        close(pair[1])

        // A session that never reaches the main loop is still logged off.
        // (The gateway refuses a one-time code twice: wait for the next 30 s window.)
        if env["WOMBAT_OCSERV_MODE"] != "cert" { Thread.sleep(forTimeInterval: 31) }
        let second = try await AnyConnectSignIn(profile: profile, transport: URLSessionGatewayTransport(profile: profile, identity: identity),
            prompts: signIn.prompts, hasClientCertificate: identity != nil).run()
        let early = OpenConnectEngine(settings: .init(session: second, pin: profile.serverCertificate, userAgent: AnyConnectXML.defaultUserAgent, dtls: true)) { level, message in
            print("early[\(level)]: \(message)")
        }
        _ = try early.connect()
        early.logOffWithoutTunnel()
        // The extension must refuse a gateway certificate other than the one signed in to,
        // even with a valid token (a second, tampered hand-off).
        var tampered = session
        tampered.serverCertificateSHA256 = String(repeating: "0", count: 64)
        let refused = OpenConnectEngine(settings: .init(session: tampered, pin: nil, userAgent: AnyConnectXML.defaultUserAgent, dtls: false)) { _, _ in }
        do {
            _ = try refused.connect()
            print("oc-probe: FAILED: connected with a certificate other than the signed-in one")
            exit(1)
        } catch {
            print("refused as expected: \(error.localizedDescription)")
        }
        // And with no pin, macOS trust decides: the test CA isn't trusted, so this must fail too.
        let untrusted = OpenConnectEngine(settings: .init(session: session, pin: nil, userAgent: AnyConnectXML.defaultUserAgent, dtls: false)) { _, _ in }
        do {
            _ = try untrusted.connect()
            print("oc-probe: FAILED: connected to a gateway macOS doesn't trust, without a pin")
            exit(1)
        } catch {
            print("refused as expected: \(error.localizedDescription)")
        }
        print("oc-probe: OK")
    } catch {
        print("oc-probe: FAILED: \(error.localizedDescription)")
        exit(1)
    }
    done.signal()
}
done.wait()
