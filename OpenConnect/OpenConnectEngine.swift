import CryptoKit
import Foundation
import Security
#if canImport(TunnelCore)
import TunnelCore
#endif

/// One AnyConnect tunnel on libopenconnect. Sign-in already happened in the app; this only
/// connects the tunnel (CSTP over TLS, then DTLS) with the session token it was handed, and
/// moves packets between the utun device and the gateway.
///
/// libopenconnect's state isn't thread-safe: after `start` only the main-loop thread touches
/// it, and other threads talk to it through its command pipe (stop, stats).
final class OpenConnectEngine: @unchecked Sendable {
    struct Settings {
        var session: AnyConnectSession
        /// The profile's pin, if the gateway's certificate isn't trusted by macOS.
        var pin: String?
        var userAgent: String
        var dtls: Bool
    }

    struct Failure: LocalizedError {
        let errorDescription: String?
    }

    private let settings: Settings
    private let logLine: @Sendable (_ level: Int32, _ message: String) -> Void
    private var vpn: OpaquePointer?
    private var commandFD: Int32 = -1
    private let lock = NSLock()
    private var certificateProblem: String?
    private var counters = (rx: UInt64(0), tx: UInt64(0))
    private var running = false
    private var loopThread: Thread?
    /// The CSTP session is up (make_cstp_connection succeeded): a teardown owes the gateway a logoff.
    private var sessionOpen = false
    /// Which transport carries packets and its cipher, copied on the main-loop thread: the
    /// libopenconnect getters free and reallocate state, so no other thread may call them (Q5-H1).
    private var cachedTransport: (name: String, cipher: String?) = ("TLS", nil)
    private var pauseRequested = false
    /// A stop that arrived while a pause was in flight: CANCEL is held back (with it queued, the
    /// reconnect would abort before any connection exists, so no BYE could be sent; S5C) and
    /// sent from the reconnected callback instead.
    private var cancelAfterReconnect = false

    /// Called on the main-loop thread after libopenconnect reconnected (new network, gateway
    /// restart): the gateway may hand out different settings.
    var onReconnected: (@Sendable (OpenConnectIPInfo) -> Void)?

    init(settings: Settings, log: @escaping @Sendable (_ level: Int32, _ message: String) -> Void) {
        self.settings = settings
        logLine = log
        Self.setUp
    }

    deinit {
        // Normally freed by shutdown(), while the engine is fully alive: libopenconnect may log
        // during free, and its log callback reaches back into the engine (S5B-I4).
        if let vpn { openconnect_vpninfo_free(vpn) }
    }

    /// Frees libopenconnect's state. Call once the main loop has ended (or never ran), on the
    /// provider queue; the engine is useless afterwards.
    func shutdown() {
        guard let vpn, !isRunning else { return }
        lock.withLock { commandFD = -1 }
        self.vpn = nil
        openconnect_vpninfo_free(vpn)
    }

    private static let setUp: Void = {
        _ = openconnect_init_ssl()
        wombat_oc_set_logger { privdata, level, message in
            guard let privdata, let message else { return }
            Unmanaged<OpenConnectEngine>.fromOpaque(privdata).takeUnretainedValue().log(level, String(cString: message))
        }
    }()

    private func log(_ level: Int32, _ message: String) {
        // The token never reaches a log, whatever the library prints (at PRG_INFO it doesn't).
        var scrubbed = settings.session.cookie.count >= 8
            ? message.replacingOccurrences(of: settings.session.cookie, with: "<session>") : message
        if let key = settings.session.strapKey { scrubbed = scrubbed.replacingOccurrences(of: key, with: "<key>") }
        logLine(level, String(scrubbed.prefix(1024)))
    }

    // MARK: Connecting

    /// Connects the tunnel (blocking, so call it off the provider's queue) and returns what the
    /// gateway assigned.
    func connect() throws -> OpenConnectIPInfo {
        let context = Unmanaged.passUnretained(self).toOpaque()
        guard let vpn = wombat_oc_vpninfo_new(settings.userAgent, Self.validatePeer, Self.authForm, context) else {
            throw Failure(errorDescription: "libopenconnect could not start")
        }
        self.vpn = vpn
        openconnect_set_loglevel(vpn, PRG_INFO)
        // The full user agent the sign-in used: the gateway may tie the session to it.
        _ = openconnect_set_useragent(vpn, settings.userAgent)
        guard openconnect_set_protocol(vpn, "anyconnect") == 0,
              openconnect_set_reported_os(vpn, AnyConnectXML.deviceID) == 0,
              openconnect_parse_url(vpn, settings.session.connectURL) == 0,
              // As "webvpn=<token>": libopenconnect splits a bare cookie at its first "=", and
              // tokens are often base64 (ocserv's end in "="). AnyConnectSession.validate()
              // refuses ";", the only other separator.
              // With STRAP, the signing key rides along in libopenconnect's own cookie format;
              // it then signs the CONNECT's channel binding (X-AnyConnect-STRAP-Verify).
              openconnect_set_cookie(vpn, (settings.session.strapKey.map { "openconnect_strapkey=\($0); " } ?? "") + "webvpn=" + settings.session.cookie) == 0 else {
            throw Failure(errorDescription: "libopenconnect refused the session settings")
        }
        // OpenSSL has no trust store here (and must not use one of its own): every certificate
        // goes through validatePeer, which uses macOS trust and the sign-in's certificate.
        openconnect_set_system_trust(vpn, 0)
        // No compression: it saves little on today's traffic, and its decompressors are C fed
        // by the gateway (the build also refuses a compression the gateway imposes; patch 5).
        _ = openconnect_set_compression_mode(vpn, OC_COMPRESSION_MODE_NONE)
        openconnect_override_getaddrinfo(vpn, Self.resolve)
        if !settings.dtls { _ = openconnect_disable_dtls(vpn) }
        let pipe = Int32(openconnect_setup_cmd_pipe(vpn))
        guard pipe >= 0 else { throw Failure(errorDescription: "libopenconnect could not create its command pipe") }
        // A stop that came before the pipe existed had nothing to write to: honor it now (S5B-M4).
        let stopEarly = lock.withLock { () -> Bool in
            commandFD = pipe
            return stopRequested
        }
        if stopEarly { throw Failure(errorDescription: Self.describe(-EINTR)) }
        openconnect_set_stats_handler(vpn, Self.stats)
        openconnect_set_reconnected_handler(vpn, Self.reconnected)

        let result = openconnect_make_cstp_connection(vpn)
        guard result == 0 else {
            if let problem = lock.withLock({ certificateProblem }) { throw Failure(errorDescription: problem) }
            throw Failure(errorDescription: Self.describe(result))
        }
        let stopNow = lock.withLock { () -> Bool in
            sessionOpen = true
            return stopRequested
        }
        // Stopped during the connect: the caller's teardown logs the session off.
        if stopNow { throw Failure(errorDescription: Self.describe(-EINTR)) }
        if settings.dtls, openconnect_setup_dtls(vpn, 60) != 0 {
            log(PRG_INFO, "DTLS unavailable; using TLS only")
        }
        refreshTransport()
        return ipInfo()
    }

    /// Hands libopenconnect the utun device and runs its main loop on a thread of its own until
    /// the tunnel ends. `onExit` gets nil for a requested stop, else the reason.
    func start(tunnelFD: Int32, onExit: @escaping @Sendable (String?) -> Void) throws {
        guard let vpn else { throw Failure(errorDescription: "The tunnel isn't connected") }
        // libopenconnect gets its own descriptor for NetworkExtension's utun socket, and the
        // engine closes exactly that one; NetworkExtension's stays NetworkExtension's (S5B-L4).
        let ownFD = dup(tunnelFD)
        guard ownFD >= 0 else { throw Failure(errorDescription: "Could not use the tunnel device") }
        // The copy is a utun socket too: claimed, so another tunnel's lookup skips it (S5C).
        TunnelDevice.claimExisting(ownFD)
        guard openconnect_setup_tun_fd(vpn, ownFD) == 0 else {
            TunnelDevice.closeAndRelease(ownFD)
            throw Failure(errorDescription: "libopenconnect could not use the tunnel device")
        }
        lock.withLock { running = true }
        let thread = Thread { [self] in
            var result: Int32 = 0
            var byeSent = false
            while true {
                // Reconnect for up to 5 minutes (network changes, sleep), retrying from every 10 s;
                // only briefly when the pass exists just to say goodbye.
                let stopping = lock.withLock { cancelAfterReconnect }
                result = openconnect_mainloop(vpn, stopping ? 15 : 300, RECONNECT_INTERVAL_MIN)
                let (paused, stop) = lock.withLock { () -> (Bool, Bool) in
                    defer { pauseRequested = false }
                    return (pauseRequested, stopRequested)
                }
                // A pause (wake, new network) closes the sockets and returns; entering the loop
                // again reconnects at once with the same session instead of waiting for DPD.
                if paused && !stop {
                    log(PRG_INFO, "Reconnecting on the new network")
                    continue
                }
                // A stop that landed on a pause: the session is still open at the gateway. One more
                // pass reconnects, and the reconnected callback sends the held-back CANCEL, so the
                // BYE goes over a live connection (S5B-L2/M5, S5C).
                if paused && stop && !byeSent {
                    byeSent = true
                    continue
                }
                break
            }
            let requested = lock.withLock { stopRequested }
            // libopenconnect only closes the tun descriptor when it ran a vpnc-script.
            TunnelDevice.closeAndRelease(ownFD)
            lock.withLock { running = false; sessionOpen = false }  // only after the close (S5B-L4)
            onExit(requested ? nil : Self.describe(result))
        }
        thread.name = "net.vpetkov.wombat.openconnect.mainloop"
        thread.stackSize = 1 << 20
        loopThread = thread
        thread.start()
    }

    private var stopRequested = false

    /// Ends the tunnel and logs the session off at the gateway (the token is useless after).
    func stop() {
        let hold = lock.withLock { () -> Bool in
            stopRequested = true
            if pauseRequested { cancelAfterReconnect = true }
            return pauseRequested
        }
        if !hold { send(WOMBAT_OC_CMD_CANCEL) }
    }

    /// Gives up on the clean goodbye and forces the main loop to end, so a gateway that stalls a
    /// reconnect after a stop-during-pause can't keep the thread, sockets and utun fd alive
    /// (S5D-M2). The queued CANCEL interrupts the mainloop's select even mid-reconnect.
    func forceStop() {
        lock.withLock { stopRequested = true; cancelAfterReconnect = false }
        send(WOMBAT_OC_CMD_CANCEL)
    }

    /// Drops the current connections and reconnects at once (after wake, or on a new network).
    func reconnectNow() {
        // One pause at a time: a second queued PAUSE made the loop return with the flag
        // already cleared, ending the tunnel without a logoff (S5C).
        let send = lock.withLock { () -> Bool in
            guard running && !stopRequested && !pauseRequested else { return false }
            pauseRequested = true
            return true
        }
        if send { self.send(WOMBAT_OC_CMD_PAUSE) }
    }

    /// For a teardown before the main loop ever ran (stopped while connecting, settings failed):
    /// libopenconnect sends the gateway's logoff only from its main loop, so run it once on a
    /// throwaway socket pair with the cancel already queued. Blocking; call on the provider queue.
    func logOffWithoutTunnel() {
        guard let vpn, lock.withLock({ sessionOpen && !running }) else { return }
        var pair: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, SOCK_DGRAM, 0, &pair) == 0 else { return }
        defer { close(pair[0]); close(pair[1]) }
        guard openconnect_setup_tun_fd(vpn, pair[0]) == 0 else { return }
        lock.withLock { stopRequested = true; running = true }
        send(WOMBAT_OC_CMD_CANCEL)
        _ = openconnect_mainloop(vpn, 0, RECONNECT_INTERVAL_MIN)
        lock.withLock { sessionOpen = false; running = false }
        log(PRG_INFO, "Logged the session off at the gateway")
    }

    var isRunning: Bool { lock.withLock { running } }

    /// Asks the main loop for fresh counters; `traffic` has them a moment later.
    func requestStats() { send(WOMBAT_OC_CMD_STATS) }
    var traffic: (rx: UInt64, tx: UInt64) { lock.withLock { counters } }

    private func send(_ command: UInt8) {
        // Under the lock: the fd is set on the provider queue and used from NetworkExtension's
        // thread, and shutdown() retires it (S5B-I2).
        lock.withLock {
            guard commandFD >= 0 else { return }
            var byte = command
            _ = write(commandFD, &byte, 1)
        }
    }

    /// Which transport carries packets now, and its cipher, as of the last stats poll.
    var transport: (name: String, cipher: String?) { lock.withLock { cachedTransport } }

    /// Only on the thread that owns libopenconnect (before `start`, or in a main-loop callback).
    private func refreshTransport() {
        guard let vpn else { return }
        let value: (String, String?)
        if let dtls = openconnect_get_dtls_cipher(vpn) {
            value = ("DTLS", String(cString: dtls))
        } else {
            value = ("TLS", openconnect_get_cstp_cipher(vpn).map { String(cString: $0) })
        }
        lock.withLock { cachedTransport = value }
    }

    /// The gateway's settings as plain values. Only valid on the thread that owns libopenconnect
    /// (before `start`, or in a main-loop callback).
    private func ipInfo() -> OpenConnectIPInfo {
        var out = OpenConnectIPInfo()
        guard let vpn else { return out }
        var info: UnsafePointer<oc_ip_info>?
        guard openconnect_get_ip_info(vpn, &info, nil, nil) == 0, let i = info?.pointee else { return out }
        func s(_ p: UnsafePointer<CChar>?) -> String? { p.map { String(cString: $0) } }
        func list(_ head: UnsafeMutablePointer<oc_split_include>?) -> [String] {
            var items: [String] = []
            var node = head
            while let n = node, items.count < OpenConnectNetworkPlan.maxRoutes {
                if let r = n.pointee.route { items.append(String(cString: r)) }
                node = n.pointee.next
            }
            return items
        }
        out.address = s(i.addr)
        out.netmask = s(i.netmask)
        out.address6 = s(i.addr6)
        out.netmask6 = s(i.netmask6)
        out.dns = [i.dns.0, i.dns.1, i.dns.2].compactMap(s)
        out.domain = s(i.domain)
        out.splitDNS = list(i.split_dns)
        out.splitIncludes = list(i.split_includes)
        out.splitExcludes = list(i.split_excludes)
        out.mtu = Int(i.mtu)
        return out
    }

    // MARK: Callbacks (C function pointers; privdata is the engine)

    private static func engine(_ privdata: UnsafeMutableRawPointer?) -> OpenConnectEngine? {
        privdata.map { Unmanaged<OpenConnectEngine>.fromOpaque($0).takeUnretainedValue() }
    }

    /// libopenconnect found no trust anchor (it has none, by design) and asks. Accept only the
    /// exact certificate the app signed in to, and then only if macOS trusts it for this host or
    /// it is the one pinned in the profile.
    private static let validatePeer: openconnect_validate_peer_cert_vfn = { privdata, _ in
        guard let engine = engine(privdata) else { return 1 }
        if let problem = engine.peerProblem() {
            engine.lock.withLock { engine.certificateProblem = problem }
            engine.log(PRG_ERR, problem)
            return 1
        }
        return 0
    }

    private func peerProblem() -> String? {
        guard let vpn else { return "No connection" }
        var der: UnsafeMutablePointer<UInt8>?
        let length = openconnect_get_peer_cert_DER(vpn, &der)
        guard length > 0, let der else { return "The gateway sent no certificate" }
        let leaf = Data(bytes: der, count: Int(length))
        openconnect_free_cert_info(vpn, der)
        let hash = SHA256.hash(data: leaf).map { String(format: "%02x", $0) }.joined()
        let host = settings.session.host
        guard hash == settings.session.serverCertificateSHA256 else {
            return "The certificate of \(host) changed since you signed in (SHA-256 \(hash.prefix(16))…); the tunnel was not connected"
        }
        if let pin = settings.pin { return hash == pin ? nil : "The certificate of \(host) doesn't match the pinned one" }

        var chain: UnsafeMutablePointer<oc_cert>?
        let count = openconnect_get_peer_cert_chain(vpn, &chain)
        var certificates: [SecCertificate] = []
        if count > 0, let chain {
            for index in 0..<Int(count) {
                let item = chain[index]
                guard let bytes = item.der_data, item.der_len > 0,
                      let cert = SecCertificateCreateWithData(nil, Data(bytes: bytes, count: Int(item.der_len)) as CFData) else { continue }
                certificates.append(cert)
            }
            openconnect_free_peer_cert_chain(vpn, chain)
        }
        if certificates.isEmpty, let cert = SecCertificateCreateWithData(nil, leaf as CFData) { certificates = [cert] }
        var trust: SecTrust?
        guard SecTrustCreateWithCertificates(certificates as CFArray, SecPolicyCreateSSL(true, host as CFString), &trust) == errSecSuccess,
              let trust else { return "Could not check the certificate of \(host)" }
        var error: CFError?
        guard SecTrustEvaluateWithError(trust, &error) else {
            return "The certificate of \(host) isn't trusted by macOS: \((error as Error?)?.localizedDescription ?? "not trusted")"
        }
        return nil
    }

    /// The tunnel phase never needs a form; a request for one (an expired session asking to
    /// sign in again) is refused rather than answered.
    private static let authForm: openconnect_process_auth_form_vfn = { privdata, _ in
        engine(privdata)?.log(PRG_ERR, "The gateway asked to sign in again; connect from Wombat")
        return OC_FORM_RESULT_CANCELLED
    }

    /// The gateway's name resolves to the address the sign-in talked to (a round-robin name
    /// could land elsewhere, and with the kill switch on the system resolver is blocked).
    private static let resolve: openconnect_getaddrinfo_vfn = { privdata, node, service, hints, result in
        guard let engine = engine(privdata) else { return EAI_FAIL }
        if let node, String(cString: node) == engine.settings.session.host, let address = engine.settings.session.address {
            var numeric = hints?.pointee ?? addrinfo()
            numeric.ai_flags |= AI_NUMERICHOST
            return getaddrinfo(address, service, &numeric, result)
        }
        return getaddrinfo(node, service, hints, result)
    }

    private static let stats: openconnect_stats_vfn = { privdata, stats in
        guard let engine = engine(privdata), let s = stats?.pointee else { return }
        engine.lock.withLock { engine.counters = (s.rx_bytes, s.tx_bytes) }
        engine.refreshTransport()  // on the main loop, where libopenconnect may be touched
    }

    private static let reconnected: @convention(c) (UnsafeMutableRawPointer?) -> Void = { privdata in
        guard let engine = engine(privdata) else { return }
        engine.log(PRG_INFO, "Reconnected to the gateway")
        // The goodbye pass after a stop during a pause: cancel now that a connection exists.
        if engine.lock.withLock({ () -> Bool in defer { engine.cancelAfterReconnect = false }; return engine.cancelAfterReconnect }) {
            engine.send(WOMBAT_OC_CMD_CANCEL)
            return
        }
        engine.refreshTransport()
        engine.onReconnected?(engine.ipInfo())
    }

    static func describe(_ code: Int32) -> String {
        switch -code {
        case EPERM: return "The gateway refused the session (it may have expired); connect from Wombat to sign in again"
        case EINTR: return "The connection was canceled"
        case ECONNREFUSED: return "The gateway refused the connection"
        case ETIMEDOUT: return "The gateway didn't answer in time"
        case EPIPE: return "The gateway ended the session"
        case EIO: return "The connection to the gateway failed"
        default: return "The connection to the gateway failed (\(String(cString: strerror(-code))))"
        }
    }
}
