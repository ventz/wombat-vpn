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
    private var claimedFD: Int32?
    private var tunnelID: String?
    private var plan: OpenConnectNetworkPlan?
    private var gateway: String?
    private var connectedSince: Date?

    private var store: OpenConnectStore { SecretStore.shared as! OpenConnectStore }

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        let source = options?[StartOption.source] as? String ?? "the system (System Settings or on-demand)"
        note("Starting tunnel, requested by \(source)")
        stateLock.withLock { stopped = false }
        let provider = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration
        guard let id = provider?[ProviderConfigKey.tunnelID] as? String else { return completionHandler(OpenConnectError.missingConfiguration) }
        let revision = provider?[ProviderConfigKey.revision] as? String
        tunnelID = id
        // This start may be what launched the process: wait (at most 10 s) for the app to hand
        // over the profile and the session.
        if options?[StartOption.awaitHandOff] != nil, let revision {
            waitForHandOff(id: id, revision: revision, attempt: 0) { [weak self] timedOut in
                self?.queue.async { self?.begin(id: id, revision: revision, handOffTimedOut: timedOut, completionHandler: completionHandler) }
            }
        } else {
            queue.async { self.begin(id: id, revision: revision, handOffTimedOut: false, completionHandler: completionHandler) }
        }
    }

    private func waitForHandOff(id: String, revision: String, attempt: Int, then: @escaping (_ timedOut: Bool) -> Void) {
        if stateLock.withLock({ stopped }) { return then(false) }
        if store.revision(of: id) == .some(revision), store.hasSession(for: id, revision: revision) { return then(false) }
        if attempt >= 40 { return then(true) }
        queue.asyncAfter(deadline: .now() + 0.25) { [weak self] in
            self?.waitForHandOff(id: id, revision: revision, attempt: attempt + 1, then: then)
        }
    }

    private func begin(id: String, revision: String?, handOffTimedOut: Bool, completionHandler: @escaping (Error?) -> Void) {
        let engine: OpenConnectEngine
        let session: AnyConnectSession
        var ownerChecked = false
        do {
            if isStopped { throw OpenConnectError.canceled }
            guard let text = store.config(for: id) else { throw OpenConnectError.notHandedOver }
            try checkOwner(id)
            ownerChecked = true
            // Never start from a profile older than the configuration (fail closed; S3-M1/M2).
            if let revision, store.revision(of: id) != .some(revision) {
                throw handOffTimedOut ? OpenConnectError.handOffTimedOut : OpenConnectError.outdatedCopy
            }
            let parsed = OpenConnectFile.parse(text)
            guard let profile = parsed.profile else {
                throw OpenConnectError.invalidProfile(parsed.errors.map(\.description).joined(separator: "; "))
            }
            guard let held = store.session(for: id, revision: revision) else {
                throw handOffTimedOut ? OpenConnectError.handOffTimedOut : OpenConnectError.signInRequired
            }
            session = held
            engine = OpenConnectEngine(settings: .init(session: held, pin: profile.serverCertificate,
                                                       userAgent: profile.userAgent ?? AnyConnectXML.defaultUserAgent,
                                                       dtls: profile.dtls)) { [weak self] level, message in
                self?.engineLog(level, message)
            }
        } catch {
            // A session handed over for a start that is refused here goes now, not at its
            // 10-minute expiry (review NEW-10). Only once the owner is known to have asked: the
            // session is the owner's, maybe for a start of their own that is on its way.
            if ownerChecked { store.dropSession(for: id) }
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

        setTunnelNetworkSettings(Self.networkSettings(plan, remote: session.address)) { [weak self] error in
            self?.queue.async { [weak self] in
                guard let self else { return }
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
                guard let fd = TunnelDevice.claim() else {
                    self.teardown(id, engine)
                    self.fail("Could not find the tunnel device", OpenConnectError.noTunnelDevice, completionHandler)
                    return
                }
                self.claimedFD = fd
                do {
                    try engine.start(tunnelFD: fd) { [weak self] reason in
                        // The engine closed its own copy of the descriptor; the claim on
                        // NetworkExtension's lasts until stopTunnel.
                        self?.store.dropSession(for: id)
                        self?.queue.async { engine.shutdown() }
                        guard let self, let reason else { return }
                        // The gateway ended it, or reconnecting failed for 5 minutes.
                        self.note("Tunnel ended: \(reason)")
                        self.cancelTunnelWithError(OpenConnectError.engine(reason))
                    }
                } catch {
                    self.claimedFD = nil
                    TunnelDevice.release(fd)  // NetworkExtension owns the descriptor
                    self.teardown(id, engine)
                    self.fail("Could not start", error, completionHandler)
                    return
                }
                self.connectedSince = Date()
                self.note("Tunnel up on \(TunnelDevice.name(fd) ?? "utun")")
                self.watchPath()
                completionHandler(nil)
            }
        }
    }

    private var isStopped: Bool { stateLock.withLock { stopped } }

    /// Ends a tunnel that never reached its main loop: the gateway still gets its logoff, and
    /// the token goes. On the provider queue.
    private func teardown(_ id: String, _ engine: OpenConnectEngine) {
        engine.logOffWithoutTunnel()
        store.dropSession(for: id)
        engine.shutdown()
        stateLock.withLock { if current === engine { current = nil } }
    }

    /// After a reconnect the gateway may assign other settings; apply them if they changed.
    private func reapply(_ info: OpenConnectIPInfo) {
        guard let next = try? OpenConnectNetworkPlan.make(info) else {
            note("The gateway's new settings are invalid; keeping the current ones")
            return
        }
        queue.async { [weak self] in
            guard let self, next != self.plan else { return }
            self.plan = next
            self.setTunnelNetworkSettings(Self.networkSettings(next, remote: self.gateway)) { [weak self] error in
                if let error { self?.note("Could not apply the gateway's new settings: \(error.localizedDescription)") }
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
            if let engine, let id { self.teardown(id, engine) } else if let id { self.store.dropSession(for: id) }
            if let fd = self.claimedFD {
                TunnelDevice.release(fd)
                self.claimedFD = nil
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

    static func networkSettings(_ plan: OpenConnectNetworkPlan, remote: String?) -> NEPacketTunnelNetworkSettings {
        // The gateway's address when it's an IP literal; the provider's own sockets bypass the
        // tunnel either way.
        let remoteAddress = remote.flatMap { IPAddressRange($0) != nil ? $0 : nil } ?? "127.0.0.1"
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: remoteAddress)
        if let a = plan.ipv4Address {
            let v4 = NEIPv4Settings(addresses: [a.address], subnetMasks: [a.mask])
            v4.includedRoutes = plan.ipv4Included.map { $0.prefixLength == 0 ? .default() : NEIPv4Route(destinationAddress: $0.address, subnetMask: $0.mask) }
            v4.excludedRoutes = plan.ipv4Excluded.map { NEIPv4Route(destinationAddress: $0.address, subnetMask: $0.mask) }
            settings.ipv4Settings = v4
        }
        if let a = plan.ipv6Address {
            let v6 = NEIPv6Settings(addresses: [a.address], networkPrefixLengths: [NSNumber(value: a.prefixLength)])
            v6.includedRoutes = plan.ipv6Included.map { $0.prefixLength == 0 ? .default() : NEIPv6Route(destinationAddress: $0.address, networkPrefixLength: NSNumber(value: $0.prefixLength)) }
            v6.excludedRoutes = plan.ipv6Excluded.map { NEIPv6Route(destinationAddress: $0.address, networkPrefixLength: NSNumber(value: $0.prefixLength)) }
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
    private func engineLog(_ level: Int32, _ message: String) {
        let message = TunnelName.line(message)
        if level == PRG_ERR { log.error("engine: \(message, privacy: .private)") } else { log.debug("engine: \(message, privacy: .private)") }
        recentLog.append(message)
    }
}

enum OpenConnectError: LocalizedError {
    case missingConfiguration
    case notHandedOver
    case outdatedCopy
    case handOffTimedOut
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
        case .handOffTimedOut: return "Wombat didn't deliver this VPN's sign-in to the OpenConnect extension in time; try connecting again"
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
