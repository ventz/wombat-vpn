// Developer probe for the OpenConnect engine, outside NetworkExtension: signs in to the test
// gateway (scripts/dev/ocserv-peer.sh) with the app's Swift sign-in, then hands the session to
// libopenconnect exactly as the system extension does and prints what the gateway assigned.
// No tunnel device is created and nothing on the Mac changes. Build and run:
//     scripts/dev/oc-probe.sh
import CryptoKit
import Foundation
import Security

setvbuf(stdout, nil, _IOLBF, 0)  // line by line, so a watcher can react to engine lines
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

        // OCPROBE_DEBUG=1: libopenconnect at debug level, as with Wombat's debug logging, and a
        // check that the scrubbed lines (what the Log tab and diagnostics get) hold no secret.
        let debug = ProcessInfo.processInfo.environment["OCPROBE_DEBUG"] == "1"
        let collected = Collected()
        let engine = OpenConnectEngine(settings: .init(session: session, pin: profile.serverCertificate,
                                                       userAgent: AnyConnectXML.defaultUserAgent, dtls: profile.dtls, debug: debug)) { level, message in
            print("engine[\(level)]: \(debug ? LogScrubber.scrub(message) : message)")
            collected.add(message)
        }
        defer { if debug { collected.check(secrets: [session.cookie] + (session.strapKey.map { [$0] } ?? [])) } }
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
        // OCPROBE_PING=1: echo requests of several sizes to the gateway's tunnel address
        // (10.98.0.1) through the socket pair, after DTLS and its MTU detection settle. Shows
        // which packet sizes the tunnel really carries (MTU A/B test, 2026-11-10).
        if ProcessInfo.processInfo.environment["OCPROBE_PING"] == "1", let source = info.address {
            Thread.sleep(forTimeInterval: 8)
            print("transport before pings: \(engine.transport)")
            var timeout = timeval(tv_sec: 2, tv_usec: 0)
            setsockopt(pair[1], SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
            for (index, size) in [84, 500, 576, 600, 1000, 1300].enumerated() {
                var replies = 0
                for seq in 0..<3 {
                    // libopenconnect's macOS tun I/O carries a 4-byte address family first.
                    let packet = [0, 0, 0, UInt8(AF_INET)] + echoRequest(from: source, to: "10.98.0.1", totalLength: size, id: UInt16(index), seq: UInt16(seq))
                    _ = packet.withUnsafeBytes { write(pair[1], $0.baseAddress, packet.count) }
                    // Skip anything else the gateway sends (IPv6 router traffic, earlier replies).
                    let deadline = Date().addingTimeInterval(2)
                    var buffer = [UInt8](repeating: 0, count: 2048)
                    while Date() < deadline {
                        let n = read(pair[1], &buffer, buffer.count) - 4
                        guard n > 0 else { break }
                        if n >= 28, buffer[4] >> 4 == 4, buffer[4 + 9] == 1, buffer[4 + 20] == 0,
                           buffer[4 + 24] == UInt8(index >> 8), buffer[4 + 25] == UInt8(index & 0xff), buffer[4 + 27] == UInt8(seq & 0xff) {
                            if n == size { replies += 1 }
                            break
                        }
                    }
                }
                print("ping \(size) bytes: \(replies)/3 replies")
            }
            engine.stop()
            _ = exited.wait(timeout: .now() + 10)
            exit(0)
        }
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

/// Engine lines from a debug run, checked after it (OCPROBE_DEBUG).
final class Collected: @unchecked Sendable {
    private let lock = NSLock()
    private var lines: [String] = []
    func add(_ line: String) { lock.withLock { lines.append(line) } }

    /// Secrets: the token and STRAP key the probe holds, plus every value of a header named like
    /// a secret in the raw lines. None may survive LogScrubber.
    func check(secrets known: [String]) {
        let raw = lock.withLock { lines }
        var secrets = known
        for line in raw {
            guard let colon = line.firstIndex(of: ":") else { continue }
            let name = line[..<colon].lowercased()
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespacesAndNewlines)
            if ["session-id", "cookie", "secret", "strap", "app-id", "token", "auth", "saml"].contains(where: name.contains), value.count >= 6 { secrets.append(value) }
        }
        let scrubbed = raw.map { LogScrubber.scrub($0) }
        let leaks = secrets.filter { s in scrubbed.contains { $0.contains(s) } }
        let changed = zip(raw, scrubbed).filter { LogScrubber.scrub($0.0) != TunnelName.line(String($0.0.prefix(LogScrubber.maxLineLength))) }
        print("debug check: \(raw.count) lines, \(secrets.count) secret values, \(changed.count) lines changed by the scrubber, \(leaks.count) leaked")
        for (before, after) in changed { print("  scrubbed: \(after)  [was \(before.count) chars]") }
        if !leaks.isEmpty { print("oc-probe: FAILED: a secret survived the scrubber"); exit(1) }
    }
}

/// An IPv4 ICMP echo request of exactly `totalLength` bytes (OCPROBE_PING).
func echoRequest(from source: String, to destination: String, totalLength: Int, id: UInt16, seq: UInt16) -> [UInt8] {
    func checksum(_ bytes: ArraySlice<UInt8>) -> UInt16 {
        var sum: UInt32 = 0
        var i = bytes.startIndex
        while i < bytes.endIndex {
            let hi = UInt32(bytes[i]) << 8
            let lo = i + 1 < bytes.endIndex ? UInt32(bytes[i + 1]) : 0
            sum += hi | lo
            i += 2
        }
        while sum >> 16 != 0 { sum = (sum & 0xffff) + (sum >> 16) }
        return ~UInt16(sum)
    }
    var p = [UInt8](repeating: 0, count: totalLength)
    p[0] = 0x45
    p[2] = UInt8(totalLength >> 8); p[3] = UInt8(totalLength & 0xff)
    p[6] = 0x40  // DF
    p[8] = 64; p[9] = 1
    var addr = in_addr()
    inet_pton(AF_INET, source, &addr); withUnsafeBytes(of: addr.s_addr) { for (k, b) in $0.enumerated() { p[12 + k] = b } }
    inet_pton(AF_INET, destination, &addr); withUnsafeBytes(of: addr.s_addr) { for (k, b) in $0.enumerated() { p[16 + k] = b } }
    let ipSum = checksum(p[0..<20]); p[10] = UInt8(ipSum >> 8); p[11] = UInt8(ipSum & 0xff)
    p[20] = 8
    p[24] = UInt8(id >> 8); p[25] = UInt8(id & 0xff); p[26] = UInt8(seq >> 8); p[27] = UInt8(seq & 0xff)
    for k in 28..<totalLength { p[k] = UInt8(k & 0xff) }
    let icmpSum = checksum(p[20...]); p[22] = UInt8(icmpSum >> 8); p[23] = UInt8(icmpSum & 0xff)
    return p
}
