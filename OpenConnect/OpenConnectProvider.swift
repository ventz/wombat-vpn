import Foundation
import Network
import NetworkExtension
import os
import SystemConfiguration
import TunnelCore

/// A Cisco AnyConnect tunnel. The app signs in (it has the user, the browser for SSO and the
/// keychain for client certificates) and hands this extension the session; this side only
/// connects the tunnel with libopenconnect and carries packets.
final class OpenConnectProvider: NEPacketTunnelProvider {
    private let log = Logger(subsystem: AppIdentity.logSubsystem, category: "openconnect")
    private let recentLog = RecentLog()
    private let queue = DispatchQueue(label: "net.vpetkov.wombat.openconnect.provider")
    private let stateLock = NSLock()
    private var stopped = false
    /// The tunnel's engine; under stateLock (stop reads it while the queue may be connecting).
    private var current: OpenConnectEngine?
    /// NetworkExtension's utun descriptor, claimed until this tunnel has fully stopped.
    private var claimedDevice: UtunClaim?
    private var tunnelID: String?
    private var plan: OpenConnectNetworkPlan?
    private var gateway: String?
    private var connectedSince: Date?
    /// This start asked for debug logging (StartOption.debugLogging) until then: libopenconnect
    /// runs at PRG_DEBUG, and its debug lines are kept only before the deadline (quality-10 M6).
    private var debugUntil: Date?
    /// This start's token in the store, and the generation of the session it used: its cleanup
    /// drops only that session, never one the app handed over for a later start.
    private var startToken: UInt64?
    private var sessionGeneration: UInt64?
    /// When this start began, for the hand-off diagnosis; when it stopped, for the cleanup.
    private var startedAt = Date()
    private var stopRequestedAt: Date?
    /// This connect attempt's nonce from the app (decision 2-B); nil from an app before 1.4.6 or
    /// a start made by macOS (System Settings), which then can't use a session the app sent for
    /// one of its own connects. Never logged.
    private var startNonce: String?

    private var store: OpenConnectStore { SecretStore.shared as! OpenConnectStore }

    override func startTunnel(options: [String: NSObject]?, completionHandler handler: @escaping (Error?) -> Void) {
        let source = options?[StartOption.source] as? String ?? "the system (System Settings or on-demand)"
        note("Starting tunnel, requested by \(source)")
        let debugUntil = DebugLoggingDeadline.effective(stored: (options?[StartOption.debugLogging] as? NSNumber)?.doubleValue ?? 0)
        let debug = debugUntil != nil
        recentLog.setDebug(debug)
        recentLog.append(RecentLog.versionLine + (debug ? "; debug logging on" : ""))
        self.debugUntil = debugUntil
        stateLock.withLock { stopped = false }
        let provider = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration
        guard let id = provider?[ProviderConfigKey.tunnelID] as? String else { return handler(ProviderError.ns(OpenConnectError.missingConfiguration)) }
        let revision = provider?[ProviderConfigKey.revision] as? String
        tunnelID = id
        // Per-start state, reset in case macOS ever reuses a provider instance (review S6).
        startedAt = Date()
        stopRequestedAt = nil
        sessionGeneration = nil
        handOffDiagnosis = nil
        startNonce = options?[StartOption.startNonce] as? String
        let store = self.store
        let token = store.beginStart(for: id)
        startToken = token
        // Every failure crosses to the app as NSError, or its text is lost (ProviderError). A
        // failed start no longer runs here (the self-restart rule counts running starts). The
        // token is this start's own, captured, not read from `self` later (review round 2, S3).
        let completionHandler: (Error?) -> Void = { error in
            if error != nil, let token { store.finishStart(token) }
            handler(error.map(ProviderError.ns))
        }
        // This start may be what launched the process: wait (at most 10 s) for the app to hand
        // over the profile and the session.
        if options?[StartOption.awaitHandOff] != nil, let revision {
            waitForHandOff(id: id, revision: revision, attempt: 0) { [weak self] timedOut in
                guard let self else { return completionHandler(OpenConnectError.canceled) }
                self.queue.async {
                    if timedOut { self.diagnoseHandOff(id: id, revision: revision) }
                    self.begin(id: id, revision: revision, token: token, handOffTimedOut: timedOut, completionHandler: completionHandler)
                }
            }
        } else {
            queue.async { self.begin(id: id, revision: revision, token: token, handOffTimedOut: false, completionHandler: completionHandler) }
        }
    }

    private func waitForHandOff(id: String, revision: String, attempt: Int, then: @escaping (_ timedOut: Bool) -> Void) {
        if stateLock.withLock({ stopped }) { return then(false) }
        if store.revision(of: id) == .some(revision), store.hasSession(for: id, revision: revision, nonce: startNonce) { return then(false) }
        if attempt >= 40 { return then(true) }
        queue.asyncAfter(deadline: .now() + 0.25) { [weak self] in
            // A released provider still ends its start (and finishes its token), as canceled.
            guard let self else { return then(false) }
            self.waitForHandOff(id: id, revision: revision, attempt: attempt + 1, then: then)
        }
    }

    /// Set when the wait for the hand-off ended without a session.
    private var handOffDiagnosis: HandOffDiagnosis?

    /// Says which stage of the hand-off failed (fixed words and counts only), so the next report
    /// tells "the app never reached the extension" from "it was refused" from "no session sent".
    /// The line also goes into the error, the one thing that surely reaches the app.
    private func diagnoseHandOff(id: String, revision: String) {
        let profile: HandOffDiagnosis.Profile = store.config(for: id) == nil ? .missing
            : store.revision(of: id) == .some(revision) ? .current : .older
        let seen = store.handOffActivity(for: id, since: startedAt.addingTimeInterval(-HandOffDiagnosis.lookback))
        let diagnosis = HandOffDiagnosis(requests: seen.requests, profile: profile, refusals: seen.refusals)
        log.error("Hand-off wait ended without a session; \(diagnosis.line, privacy: .public)")
        recentLog.append("Hand-off wait ended without a session; \(diagnosis.line)")
        handOffDiagnosis = diagnosis
    }

    private var timeoutError: OpenConnectError {
        handOffDiagnosis?.appNeverReachedExtension == true ? .handOffUnreachable : .handOffTimedOut(handOffDiagnosis)
    }

    // MARK: Self-restart (decision 1-B; ExtensionSelfRestart has the rules and why they're safe)

    /// For a start failing with `.handOffUnreachable`, after its own session cleanup: whether this
    /// process should quit so macOS starts a fresh one. The exit comes `delay` later, after the
    /// failing start's completion has reached NetworkExtension, and only if the check still holds
    /// then; the time is recorded right before it (no record, no exit).
    private func restartDecision(token: UInt64?) -> OpenConnectError {
        let since = startedAt.addingTimeInterval(-HandOffDiagnosis.lookback)
        let decision = ExtensionSelfRestart.decide(store.selfRestartInput(excluding: token, requestsSince: since))
        if case .stay(let reason) = decision {
            log.notice("Not restarting the OpenConnect extension: \(reason, privacy: .public)")
            return .handOffUnreachable
        }
        // Nothing from the provider: it may be released before this runs (review round 2, M2).
        let store = self.store, log = self.log
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + ExtensionSelfRestart.delay) {
            let reason = store.exitIfIdle(excluding: token, requestsSince: since)  // returns only to stay
            log.notice("Not restarting the OpenConnect extension after all: \(reason, privacy: .public)")
        }
        log.notice("Restarting the OpenConnect extension in \(Int(ExtensionSelfRestart.delay), privacy: .public) s unless something arrives")
        return .handOffRestarting
    }

    /// `token`: this start's own, passed in rather than read from `self` (review round 3, R2).
    private func begin(id: String, revision: String?, token: UInt64?, handOffTimedOut: Bool, completionHandler: @escaping (Error?) -> Void) {
        let engine: OpenConnectEngine
        let session: AnyConnectSession
        var ownerChecked = false
        do {
            if isStopped { throw OpenConnectError.canceled }
            guard let text = store.config(for: id) else { throw handOffTimedOut ? timeoutError : OpenConnectError.notHandedOver }
            try checkOwner(id)
            ownerChecked = true
            // Never start from a profile older than the configuration (fail closed; S3-M1/M2).
            if let revision, store.revision(of: id) != .some(revision) {
                throw handOffTimedOut ? timeoutError : OpenConnectError.outdatedCopy
            }
            let parsed = OpenConnectFile.parse(text)
            guard let profile = parsed.profile else {
                throw OpenConnectError.invalidProfile(parsed.errors.map(\.description).joined(separator: "; "))
            }
            guard let held = store.session(for: id, revision: revision, nonce: startNonce) else {
                throw handOffTimedOut ? timeoutError : OpenConnectError.signInRequired
            }
            session = held.session
            sessionGeneration = held.generation
            engine = OpenConnectEngine(settings: .init(session: held.session, pin: profile.serverCertificate,
                                                       userAgent: profile.userAgent ?? AnyConnectXML.defaultUserAgent,
                                                       dtls: profile.dtls, debug: debugUntil != nil)) { [weak self] level, message in
                self?.engineLog(level, message)
            }
        } catch {
            // A session handed over for a start that is refused here goes now, not at its
            // 10-minute expiry (review NEW-10). Only once the owner is known to have asked: the
            // session is the owner's, maybe for a start of their own that is on its way. And only
            // while no newer start of this tunnel has begun: that one's session stays.
            if ownerChecked, let token { store.dropSession(for: id, ifLatestStart: token, nonce: startNonce, receivedBy: Date()) }
            var error = error
            if case OpenConnectError.handOffUnreachable = error { error = restartDecision(token: token) }
            // The label is fixed and public; the error, which can name the gateway, stays
            // private in the system log (SEC-10, review NEW-10).
            fail("Cannot start", error, completionHandler)
            return
        }
        // Published before connecting, so a stop can cancel a connect in progress; a stop that
        // came between the check above and here is caught now (S5C).
        let stoppedMeanwhile = stateLock.withLock { () -> Bool in
            current = engine
            return stopped
        }
        if stoppedMeanwhile {
            teardown(id, engine)
            return completionHandler(OpenConnectError.canceled)
        }
        gateway = session.address ?? session.host

        let info: OpenConnectIPInfo
        let plan: OpenConnectNetworkPlan
        do {
            info = try engine.connect()  // blocking, on this provider's own queue
            plan = try OpenConnectNetworkPlan.make(info)
        } catch {
            teardown(id, engine)
            fail("Connection failed", error is OpenConnectNetworkPlan.Failure ? OpenConnectError.engine(error.localizedDescription) : error, completionHandler)
            return
        }
        if isStopped {
            teardown(id, engine)
            return completionHandler(OpenConnectError.canceled)
        }
        self.plan = plan
        engine.onReconnected = { [weak self] info in self?.reapply(info) }
        note("Connected to the gateway; \(plan.ipv4Included.count + plan.ipv6Included.count) route(s), \(plan.dnsServers.count) DNS server(s)\(plan.blockedIPv6 ? ", IPv6 kept inside the tunnel" : "")")
        if !plan.dropped.isEmpty {
            note("The gateway sent more than Wombat accepts. Left out: \(plan.dropped.joined(separator: "; ")).")
        }

        setTunnelNetworkSettings(Self.networkSettings(plan, remote: session.address, localDiscovery: localDiscovery)) { [weak self] error in
            guard let queue = self?.queue else {
                // The provider is gone: end this start, or its token would count as running
                // forever and block the self-restart (review 2026-11-18).
                engine.logOffWithoutTunnel()
                engine.shutdown()
                return completionHandler(OpenConnectError.canceled)
            }
            queue.async { [weak self] in
                guard let self else {
                    engine.logOffWithoutTunnel()
                    engine.shutdown()
                    return completionHandler(OpenConnectError.canceled)
                }
                // A stop while macOS applied the settings wins: nothing may start after it (Q5-M1).
                if self.isStopped {
                    self.teardown(id, engine)
                    return completionHandler(OpenConnectError.canceled)
                }
                if let error {
                    self.teardown(id, engine)
                    self.fail("Could not apply network settings", OpenConnectError.networkSettings(error.localizedDescription), completionHandler)
                    return
                }
                let device: UtunClaim
                switch TunnelDevice.claim() {
                case .success(let claim): device = claim
                case .failure(let lookup):
                    self.note("Tunnel device lookup: \(lookup)")
                    self.teardown(id, engine)
                    self.fail("Could not find the tunnel device", OpenConnectError.noTunnelDevice, completionHandler)
                    return
                }
                self.claimedDevice = device
                do {
                    let generation = self.sessionGeneration
                    let store = self.store
                    try engine.start(tunnel: device) { [weak self] reason in
                        // The tunnel no longer runs here, whether or not stopTunnel follows (S2).
                        if reason != nil, let token { store.finishStart(token) }
                        // The engine closed its own copy of the descriptor; the claim on
                        // NetworkExtension's lasts until stopTunnel. Only this start's session
                        // goes: the loop can end after the app handed over a new one.
                        if let generation { self?.store.dropSession(for: id, generation: generation) }
                        self?.queue.async { engine.shutdown() }
                        // Ended on its own: the claim on NetworkExtension's utun goes now, not in
                        // a stopTunnel that macOS may never call after cancelTunnelWithError (a
                        // claim left behind hid the next utun: 1.4.6 report, 2026-11-18). release
                        // only drops this claim, so a newer tunnel's on a reused number stays.
                        if reason != nil {
                            TunnelDevice.release(device)
                            self?.endedOnItsOwn(device)
                        }
                        guard let self, let reason else { return }
                        // The gateway ended it, or reconnecting failed for 5 minutes.
                        self.note("Tunnel ended: \(reason)")
                        self.cancelTunnelWithError(ProviderError.ns(OpenConnectError.engine(reason)))
                    }
                } catch {
                    self.claimedDevice = nil
                    TunnelDevice.release(device)  // NetworkExtension owns the descriptor
                    self.teardown(id, engine)
                    self.fail("Could not start", error, completionHandler)
                    return
                }
                self.connectedSince = Date()
                self.note("Tunnel up on \(TunnelDevice.name(device.fd) ?? "utun")")
                self.watchPath()
                completionHandler(nil)
            }
        }
    }

    private var isStopped: Bool { stateLock.withLock { stopped } }

    /// The engine ended without a stop request: its claim is already released; forget it here
    /// and stop watching the network (on the provider queue).
    private func endedOnItsOwn(_ device: UtunClaim) {
        queue.async { [weak self] in
            guard let self else { return }
            if self.claimedDevice == device { self.claimedDevice = nil }
            self.pathMonitor?.cancel()
            self.pathMonitor = nil
        }
    }

    /// Ends a tunnel that never reached its main loop: the gateway still gets its logoff, and
    /// the token goes. On the provider queue.
    private func teardown(_ id: String, _ engine: OpenConnectEngine) {
        engine.logOffWithoutTunnel()
        dropOwnSession(id)
        engine.shutdown()
        stateLock.withLock { if current === engine { current = nil } }
    }

    /// The session this start used, or (if it never got one) whatever the app sent for it, as
    /// long as no newer start of the tunnel has begun.
    private func dropOwnSession(_ id: String) {
        if let generation = sessionGeneration {
            store.dropSession(for: id, generation: generation)
        } else if let startToken {
            store.dropSession(for: id, ifLatestStart: startToken, nonce: startNonce, receivedBy: stopRequestedAt ?? Date())
        }
    }

    /// After a reconnect the gateway may assign other settings; apply them if they changed.
    private func reapply(_ info: OpenConnectIPInfo) {
        guard let next = try? OpenConnectNetworkPlan.make(info) else {
            note("The gateway's new settings are invalid; keeping the current ones")
            return
        }
        queue.async { [weak self] in
            guard let self, next != self.plan else { return }
            // The plan changes only once macOS has applied it, and a failure ends the tunnel:
            // routes the gateway now expects must not flow outside it while the status says
            // they're covered (review 2026-11-18).
            self.setTunnelNetworkSettings(Self.networkSettings(next, remote: self.gateway, localDiscovery: self.localDiscovery)) { [weak self] error in
                self?.queue.async { [weak self] in
                    guard let self, !self.isStopped else { return }
                    if let error {
                        self.note("Could not apply the gateway's new settings: \(error.localizedDescription); disconnecting")
                        self.stateLock.withLock { self.current }?.stop()
                        self.cancelTunnelWithError(ProviderError.ns(OpenConnectError.networkSettings(error.localizedDescription)))
                        return
                    }
                    self.plan = next
                }
            }
        }
    }

    // MARK: Network changes

    private var pathMonitor: NWPathMonitor?
    private var lastInterfaces: [String] = []

    /// A new network (Wi-Fi to Ethernet, another Wi-Fi) leaves the sockets on a dead path until
    /// the gateway's dead-peer timeout; reconnect at once instead (Q5-M9). Tunnel interfaces
    /// (utun, type "other") are ignored, including this one.
    private func watchPath() {
        let monitor = NWPathMonitor(prohibitedInterfaceTypes: [.other, .loopback])
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self else { return }
            let interfaces = path.availableInterfaces.map(\.name)
            self.queue.async {
                defer { self.lastInterfaces = interfaces }
                guard path.status == .satisfied, !self.lastInterfaces.isEmpty, interfaces.first != self.lastInterfaces.first else { return }
                self.note("Network changed; reconnecting")
                self.stateLock.withLock { self.current }?.reconnectNow()
            }
        }
        monitor.start(queue: queue)
        pathMonitor = monitor
    }

    override func wake() {
        note("Woke from sleep; reconnecting")
        stateLock.withLock { current }?.reconnectNow()
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        let engine = stateLock.withLock { () -> OpenConnectEngine? in
            stopped = true
            return current
        }
        let stopAt = Date()
        queue.async { self.stopRequestedAt = stopAt }
        note("Stopping tunnel (reason \(reason.rawValue))")
        // Cancels a connect in progress, or ends the main loop with a logoff at the gateway.
        engine?.stop()
        let id = tunnelID
        queue.async {
            self.pathMonitor?.cancel()
            self.pathMonitor = nil
            // Give the main loop a moment to say goodbye to the gateway.
            for _ in 0..<50 where engine?.isRunning == true { usleep(100_000) }
            // Still running means a reconnect is stalling the clean goodbye: force the exit so
            // nothing is left holding the utun fd (S5D-M2).
            if engine?.isRunning == true {
                engine?.forceStop()
                for _ in 0..<50 where engine?.isRunning == true { usleep(100_000) }
            }
            if let engine, let id { self.teardown(id, engine) } else if let id { self.dropOwnSession(id) }
            if let token = self.startToken { self.store.finishStart(token) }
            if let device = self.claimedDevice {
                TunnelDevice.release(device)
                self.claimedDevice = nil
            }
            completionHandler()
        }
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        guard let completionHandler else { return }
        guard messageData.count == 1, let message = ProviderMessage(rawValue: messageData[0]) else { return completionHandler(nil) }
        switch message {
        case .recentLog:
            completionHandler(Data(recentLog.lines().joined(separator: "\n").utf8))
        case .openConnectStatus:
            queue.async { completionHandler(try? JSONEncoder().encode(self.status())) }
        case .runtimeConfiguration, .tailnetStatus, .tailnetLogin, .tailnetLogout:
            completionHandler(nil)  // the other extensions'
        }
    }

    private func status() -> OpenConnectStatus {
        var s = OpenConnectStatus()
        guard let engine = stateLock.withLock({ current }), let plan else { return s }
        engine.requestStats()  // the next poll shows the counters this asks for
        let traffic = engine.traffic
        s.rxBytes = traffic.rx
        s.txBytes = traffic.tx
        s.ipv4 = plan.blockedIPv4 ? nil : plan.ipv4Address.map { "\($0.address)/\($0.prefixLength)" }
        s.ipv6 = plan.blockedIPv6 ? nil : plan.ipv6Address.map { "\($0.address)/\($0.prefixLength)" }
        s.dnsServers = plan.dnsServers
        s.fullTunnel = plan.isFullTunnelIPv4 || plan.isFullTunnelIPv6
        s.routes = (plan.ipv4Included + (plan.blockedIPv6 ? [] : plan.ipv6Included)).prefix(64).map { "\($0.address)/\($0.prefixLength)" }
        s.gateway = gateway
        let transport = engine.transport
        s.transport = transport.name
        s.cipher = transport.cipher
        s.connectedSince = connectedSince
        return s
    }

    /// A VPN starts only for the user at the screen who stored it (F-3). Unlike WireGuard there
    /// is no exception for the login window: AnyConnect has no on-demand, and each connect needs
    /// a sign-in by someone at the screen (SEC-2).
    private func checkOwner(_ id: String) throws {
        guard let owner = store.owner(of: id) else { return }
        guard ConsoleOwner.mayStart(owner: owner, onDemandStart: false) else { throw OpenConnectError.notOwner }
    }

    /// Bonjour exception (issue #2): only as a sub-setting of kill switch + local network.
    private var localDiscovery: Bool {
        let wants = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration?[ProviderConfigKey.localDiscovery] as? Bool ?? false
        return wants && protocolConfiguration.includeAllNetworks && protocolConfiguration.excludeLocalNetworks
    }

    static func networkSettings(_ plan: OpenConnectNetworkPlan, remote: String?, localDiscovery: Bool = false) -> NEPacketTunnelNetworkSettings {
        // The gateway's address when it's an IP literal; the provider's own sockets bypass the
        // tunnel either way.
        let remoteAddress = remote.flatMap { IPAddressRange($0) != nil ? $0 : nil } ?? "127.0.0.1"
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: remoteAddress)
        if let a = plan.ipv4Address {
            let v4 = NEIPv4Settings(addresses: [a.address], subnetMasks: [a.mask])
            v4.includedRoutes = plan.ipv4Included.map { $0.prefixLength == 0 ? .default() : NEIPv4Route(destinationAddress: $0.address, subnetMask: $0.mask) }
            v4.excludedRoutes = plan.ipv4Excluded.map { NEIPv4Route(destinationAddress: $0.address, subnetMask: $0.mask) }
                + (localDiscovery ? [NEIPv4Route(destinationAddress: "224.0.0.251", subnetMask: "255.255.255.255")] : [])
            settings.ipv4Settings = v4
        }
        if let a = plan.ipv6Address {
            let v6 = NEIPv6Settings(addresses: [a.address], networkPrefixLengths: [NSNumber(value: a.prefixLength)])
            v6.includedRoutes = plan.ipv6Included.map { $0.prefixLength == 0 ? .default() : NEIPv6Route(destinationAddress: $0.address, networkPrefixLength: NSNumber(value: $0.prefixLength)) }
            v6.excludedRoutes = plan.ipv6Excluded.map { NEIPv6Route(destinationAddress: $0.address, networkPrefixLength: NSNumber(value: $0.prefixLength)) }
                + (localDiscovery ? [NEIPv6Route(destinationAddress: "ff02::fb", networkPrefixLength: 128)] : [])
            settings.ipv6Settings = v6
        }
        if !plan.dnsServers.isEmpty {
            let dns = NEDNSSettings(servers: plan.dnsServers)
            dns.searchDomains = plan.searchDomains
            // [""]: every query goes to the tunnel's DNS first; a split tunnel's split DNS list
            // sends only those domains there.
            dns.matchDomains = plan.matchDomains ?? [""]
            settings.dnsSettings = dns
        }
        if let mtu = plan.mtu { settings.mtu = NSNumber(value: mtu) }
        return settings
    }

    // MARK: Logging

    /// The system log (readable by anyone on the Mac) gets the step, privately; the app's Log
    /// tab gets the full text.
    private func note(_ message: String) {
        log.notice("\(message, privacy: .private)")
        recentLog.append(message)
    }

    private func fail(_ context: String, _ error: Error, _ completionHandler: (Error?) -> Void) {
        log.error("\(context, privacy: .public): \(error.localizedDescription, privacy: .private)")
        recentLog.append("\(context): \(error.localizedDescription)")
        completionHandler(error)
    }

    /// Engine lines name the gateway and addresses: private in the system log. Some carry text
    /// the gateway sent (the CONNECT status line, X-Reason), cleaned to one line (review NEW-8).
    /// Debug-level lines (debug logging) go only to the Log tab, never the system log (quality-10
    /// M3), and only until the deadline.
    private func engineLog(_ level: Int32, _ message: String) {
        if level >= PRG_DEBUG {
            guard let until = debugUntil, Date() < until else { return }
            return recentLog.append(message)
        }
        let message = LogScrubber.scrub(message)
        if level == PRG_ERR { log.error("engine: \(message, privacy: .private)") } else { log.debug("engine: \(message, privacy: .private)") }
        recentLog.append(message)
    }
}

enum OpenConnectError: LocalizedError {
    case missingConfiguration
    case notHandedOver
    case outdatedCopy
    case handOffTimedOut(HandOffDiagnosis?)
    /// The wait ended and no request (or refusal) for this tunnel reached this process.
    case handOffUnreachable
    /// As `handOffUnreachable`, and this process is quitting so macOS starts a fresh one.
    case handOffRestarting
    case canceled
    case invalidProfile(String)
    case signInRequired
    case engine(String)
    case networkSettings(String)
    case noTunnelDevice
    case notOwner

    var errorDescription: String? {
        switch self {
        case .missingConfiguration: return "The VPN has no saved configuration"
        case .notHandedOver: return "The OpenConnect extension has no copy of this VPN; connect from Wombat"
        case .outdatedCopy: return "This VPN was edited while the OpenConnect extension wasn't running; connect from Wombat to hand over the new settings"
        case .handOffTimedOut(let diagnosis): return HandOffTimeoutText.openConnect(diagnosis)
        case .handOffUnreachable: return HandOffDiagnosis.unreachableMessage
        case .handOffRestarting: return ExtensionSelfRestart.message
        case .canceled: return "The start was canceled"
        case .invalidProfile(let s): return "Invalid profile: \(s)"
        case .signInRequired: return "Sign in from Wombat to connect this VPN"
        case .engine(let s): return s
        case .networkSettings(let s): return "Could not apply network settings: \(s)"
        case .noTunnelDevice: return "Could not find the tunnel device"
        case .notOwner: return "This VPN belongs to another user of this Mac"
        }
    }
}
