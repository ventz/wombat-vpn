import Foundation
import NetworkExtension
import os
import TunnelCore

/// A tailnet tunnel (Tailscale or Headscale). The Go engine runs the node on the utun; this side
/// owns everything the OS sees: it applies only what TailnetNetworkPlan lets through, and the
/// engine never configures routes or DNS itself (spike design 2.6).
final class TailnetProvider: NEPacketTunnelProvider {
    private let log = Logger(subsystem: AppIdentity.logSubsystem, category: "tailnet")
    private let recentLog = RecentLog()
    private let queue = DispatchQueue(label: "net.vpetkov.wombat.tailnet.provider")
    private let stateLock = NSLock()
    private var stopped = false
    /// Engine handle and the token its callbacks carry; under stateLock.
    private var handle: Int32?
    private var token: Int64?
    /// NetworkExtension's utun descriptor and the engine's copy, claimed until the stop.
    private var claimedFD: Int32?
    private var engineFD: Int32?
    private var profile: TailnetProfile?
    private var tunnelID: String?
    private var stateDirectory: URL?
    private var plan: TailnetNetworkPlan?
    /// One setTunnelNetworkSettings at a time; a plan that arrives meanwhile waits here, and
    /// only the newest is kept (quality-9 L2). On the provider queue.
    private var applying = false
    private var pendingPlanJSON: Data?
    private var ownerWatch: ConsoleOwnerWatch?

    private var store: TailnetStore { SecretStore.shared as! TailnetStore }
    private var isStopped: Bool { stateLock.withLock { stopped } }

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        let source = options?[StartOption.source] as? String ?? "the system (System Settings)"
        note("Starting tunnel, requested by \(source)")
        stateLock.withLock { stopped = false }
        let provider = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration
        guard let id = provider?[ProviderConfigKey.tunnelID] as? String else { return completionHandler(Self.nsError(TailnetError.missingConfiguration)) }
        let revision = provider?[ProviderConfigKey.revision] as? String
        if options?[StartOption.awaitHandOff] != nil, let revision {
            waitForHandOff(id: id, revision: revision, attempt: 0) { [weak self] timedOut in
                self?.queue.async { self?.begin(id: id, revision: revision, handOffTimedOut: timedOut, completionHandler: completionHandler) }
            }
        } else {
            queue.async { self.begin(id: id, revision: revision, handOffTimedOut: false, completionHandler: completionHandler) }
        }
    }

    private func waitForHandOff(id: String, revision: String, attempt: Int, then: @escaping (_ timedOut: Bool) -> Void) {
        if isStopped { return then(false) }
        if store.revision(of: id) == .some(revision) { return then(false) }
        if attempt >= 40 { return then(true) }
        queue.asyncAfter(deadline: .now() + 0.25) { [weak self] in
            self?.waitForHandOff(id: id, revision: revision, attempt: attempt + 1, then: then)
        }
    }

    private func begin(id: String, revision: String?, handOffTimedOut: Bool, completionHandler: @escaping (Error?) -> Void) {
        let profile: TailnetProfile
        let stateDirectory: URL
        do {
            if isStopped { throw TailnetError.canceled }
            guard let text = store.config(for: id) else { throw TailnetError.notHandedOver }
            try checkOwner(id)
            // Never start from a profile older than the configuration (fail closed; S3-M1/M2).
            if let revision, store.revision(of: id) != .some(revision) {
                throw handOffTimedOut ? TailnetError.handOffTimedOut : TailnetError.outdatedCopy
            }
            let parsed = TailnetFile.parse(text)
            guard let p = parsed.profile else { throw TailnetError.invalidProfile(parsed.errors.map(\.description).joined(separator: "; ")) }
            profile = p
            stateDirectory = try store.stateDirectory(for: id, control: p.controlURL)
        } catch {
            fail("Cannot start", error, completionHandler)
            return
        }
        self.profile = profile
        self.tunnelID = id
        self.stateDirectory = stateDirectory

        // The utun exists once settings are applied. These carry no route or DNS: the node's
        // own settings come from the coordination server, through the plan gate, later.
        let initial = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: Self.remotePlaceholder)
        initial.mtu = NSNumber(value: TailnetNetworkPlan.defaultMTU)
        setTunnelNetworkSettings(initial) { [weak self] error in
            self?.queue.async { [weak self] in
                guard let self else { return }
                if self.isStopped { return completionHandler(Self.nsError(TailnetError.canceled)) }
                if let error { return self.fail("Could not apply network settings", TailnetError.networkSettings(error.localizedDescription), completionHandler) }
                guard let fd = TunnelDevice.claim() else { return self.fail("Could not find the tunnel device", TailnetError.noTunnelDevice, completionHandler) }
                let copy = TunnelDevice.duplicateAndClaim(fd)
                guard copy >= 0 else {
                    TunnelDevice.release(fd)
                    return self.fail("Could not find the tunnel device", TailnetError.noTunnelDevice, completionHandler)
                }
                let token = TailnetEngine.register(.init(
                    log: { [weak self] line in self?.engineLog(line) },
                    plan: { [weak self] data in self?.queue.async { self?.apply(planJSON: data) } }))
                do {
                    let handle = try TailnetEngine.start(stateDirectory: stateDirectory, control: profile.controlURL,
                                                         hostname: profile.hostname, acceptDNS: profile.acceptDNS, tunFD: copy, token: token)
                    let stoppedMeanwhile = self.stateLock.withLock { () -> Bool in
                        self.handle = handle
                        self.token = token
                        self.claimedFD = fd
                        self.engineFD = copy
                        return self.stopped
                    }
                    if stoppedMeanwhile {
                        // stopTunnel ran while the engine was starting and found no handle to stop
                        // (quality-7 H1): this start's engine and claims go now, or the node keeps
                        // running and every later start finds "another tailnet already running".
                        self.teardown(handle: handle, token: token, fd: fd, copy: copy)
                        return completionHandler(Self.nsError(TailnetError.canceled))
                    }
                } catch {
                    TailnetEngine.unregister(token)
                    TunnelDevice.release(copy)  // the engine closed it
                    TunnelDevice.release(fd)    // NetworkExtension owns it
                    return self.fail("Could not start the tailnet engine", error, completionHandler)
                }
                self.note("Tailnet engine \(TailnetEngine.version) up on \(TunnelDevice.name(fd) ?? "utun"); coordination server \(profile.displayServer)")
                completionHandler(nil)
            }
        }
    }

    // MARK: Network plan

    /// A plan from the engine: through the gate, then onto the utun. An address outside tailnet
    /// space ends the tunnel (fail closed); anything else outside the rules is left out and
    /// named in the log. On the provider queue.
    private func apply(planJSON: Data) {
        guard !isStopped, let profile else { return }
        if applying { pendingPlanJSON = planJSON; return }
        let pinned = stateDirectory.flatMap { store.pinnedSuffix(in: $0) }
        let next: TailnetNetworkPlan
        do {
            next = try TailnetNetworkPlan.make(TailnetNetworkPlan.decode(planJSON), acceptDNS: profile.acceptDNS,
                                               control: profile.controlURL, pinnedSuffix: pinned)
        } catch {
            note("Refused the coordination server's network settings: \(error.localizedDescription)")
            cancelTunnelWithError(Self.nsError(TailnetError.invalidPlan(error.localizedDescription)))
            return
        }
        // The first MagicDNS name this tailnet uses is the one it keeps (security-9-astra S9-1).
        if pinned == nil, let suffix = next.magicDNSSuffix, let dir = stateDirectory {
            store.pinSuffix(suffix, in: dir)
            note("This tailnet's DNS name is \(suffix)")
        }
        guard next != plan else { return }
        // No address: the node is waiting for a sign-in, or was signed out (quality-7 H2). Back to
        // the bare settings, so no route of the old session stays.
        guard next.ipv4Address != nil || next.ipv6Address != nil else {
            plan = next
            note("Not signed in; no tailnet routes")
            let bare = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: Self.remotePlaceholder)
            bare.mtu = NSNumber(value: TailnetNetworkPlan.defaultMTU)
            setSettings(bare)
            return
        }
        if !next.dropped.isEmpty { note("The coordination server sent more than Wombat accepts. Left out: \(next.dropped.joined(separator: "; ")).") }
        plan = next
        note("Network settings: \(next.ipv4Routes.count + next.ipv6Routes.count) route(s), \(next.matchDomains.count) DNS domain(s)")
        setSettings(Self.networkSettings(next))
    }

    /// Applies settings, then the newest plan that arrived meanwhile. On the provider queue.
    private func setSettings(_ settings: NEPacketTunnelNetworkSettings) {
        applying = true
        setTunnelNetworkSettings(settings) { [weak self] error in
            self?.queue.async { [weak self] in
                guard let self else { return }
                self.applying = false
                if let error {
                    self.note("Could not apply the network settings: \(error.localizedDescription)")
                    self.cancelTunnelWithError(Self.nsError(TailnetError.networkSettings(error.localizedDescription)))
                    return
                }
                if let waiting = self.pendingPlanJSON {
                    self.pendingPlanJSON = nil
                    self.apply(planJSON: waiting)
                }
            }
        }
    }

    /// There is no single remote. NetworkExtension routes the remote address outside the
    /// tunnel, so it must never be quad100 (MagicDNS would leave in clear text; security-7 NV1):
    /// loopback, as WireGuardKit does.
    static let remotePlaceholder = "127.0.0.1"

    static func networkSettings(_ plan: TailnetNetworkPlan) -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: remotePlaceholder)
        if let a = plan.ipv4Address {
            let v4 = NEIPv4Settings(addresses: [a.addressString], subnetMasks: ["255.255.255.255"])
            v4.includedRoutes = plan.ipv4Routes.map { NEIPv4Route(destinationAddress: $0.addressString, subnetMask: mask(for: $0.prefixLength)) }
            settings.ipv4Settings = v4
        }
        if let a = plan.ipv6Address {
            let v6 = NEIPv6Settings(addresses: [a.addressString], networkPrefixLengths: [128])
            v6.includedRoutes = plan.ipv6Routes.map { NEIPv6Route(destinationAddress: $0.addressString, networkPrefixLength: NSNumber(value: $0.prefixLength)) }
            settings.ipv6Settings = v6
        }
        if !plan.dnsServers.isEmpty {
            let dns = NEDNSSettings(servers: plan.dnsServers)
            // Split DNS only: the gate never produces [""], so the Mac's resolver keeps every
            // name outside the tailnet.
            dns.matchDomains = plan.matchDomains
            // Match domains are not search domains: otherwise every single-label name typed on
            // the Mac ("printer") would be tried under the server's names (security-9-fable L1).
            dns.matchDomainsNoSearch = true
            settings.dnsSettings = dns
        }
        settings.mtu = NSNumber(value: plan.mtu)
        return settings
    }

    static func mask(for prefix: UInt8) -> String {
        let bits: UInt32 = prefix == 0 ? 0 : ~UInt32(0) << (32 - UInt32(prefix))
        return [24, 16, 8, 0].map { String((bits >> UInt32($0)) & 0xFF) }.joined(separator: ".")
    }

    // MARK: Lifecycle

    override func wake() {
        guard let handle = stateLock.withLock({ self.handle }) else { return }
        note("Woke from sleep; re-probing paths")
        queue.async { TailnetEngine.rebind(handle) }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        let (handle, token, fd, copy) = stateLock.withLock { () -> (Int32?, Int64?, Int32?, Int32?) in
            stopped = true
            defer { self.handle = nil; self.token = nil; claimedFD = nil; engineFD = nil }
            return (self.handle, self.token, claimedFD, engineFD)
        }
        stopOwnerWatch()
        note("Stopping tunnel (reason \(reason.rawValue))")
        queue.async {
            self.teardown(handle: handle, token: token, fd: fd, copy: copy)
            completionHandler()
        }
    }

    /// Stops an engine and releases its utun claims. Takes the values out of the state first, so
    /// it runs once per engine. On the provider queue.
    private func teardown(handle: Int32?, token: Int64?, fd: Int32?, copy: Int32?) {
        stateLock.withLock {
            if self.handle == handle { self.handle = nil; self.token = nil; claimedFD = nil; engineFD = nil }
        }
        if let handle { TailnetEngine.stop(handle) }  // closes the engine's copy of the utun
        if let token { TailnetEngine.unregister(token) }
        if let copy { TunnelDevice.release(copy) }
        if let fd { TunnelDevice.release(fd) }
        plan = nil
        pendingPlanJSON = nil
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        guard let completionHandler else { return }
        guard messageData.count == 1, let message = ProviderMessage(rawValue: messageData[0]) else { return completionHandler(nil) }
        let handle = stateLock.withLock { self.handle }
        switch message {
        case .recentLog:
            completionHandler(Data(recentLog.lines().joined(separator: "\n").utf8))
        case .tailnetStatus:
            guard let handle else { return completionHandler(nil) }
            // Without the sign-in URL: it is a bearer link, and the status goes to every poll
            // (security-9-fable NV2). It travels only in the reply to .tailnetLogin.
            queue.async { completionHandler(TailnetEngine.status(handle).map(Self.withoutAuthURL)) }
        case .tailnetLogin:
            guard let handle else { return completionHandler(TailnetCommandReply(error: "The tailnet isn't running").encoded) }
            queue.async {
                do {
                    try TailnetEngine.login(handle)
                    self.note("Asked the coordination server for a sign-in page")
                } catch {
                    return completionHandler(TailnetCommandReply(error: error.localizedDescription).encoded)
                }
                self.awaitAuthURL(handle, attempt: 0) { completionHandler($0.encoded) }
            }
        case .tailnetLogout:
            guard let handle else { return completionHandler(TailnetCommandReply(error: "The tailnet isn't running").encoded) }
            // Only the owner, at the screen: signing out expires the node at the server
            // (security-9-fable NV2).
            guard let id = tunnelID, let owner = store.owner(of: id), ConsoleOwner.currentUser() == owner else {
                return completionHandler(TailnetCommandReply(error: "Only the user who added this tailnet can sign it out, from their own session").encoded)
            }
            queue.async {
                do {
                    try TailnetEngine.logout(handle)
                    self.note("Signed out; the coordination server expired this node's key")
                    completionHandler(TailnetCommandReply().encoded)
                } catch {
                    completionHandler(TailnetCommandReply(error: error.localizedDescription).encoded)
                }
            }
        case .runtimeConfiguration, .openConnectStatus:
            completionHandler(nil)  // the other extensions'
        }
    }

    /// Waits up to 15 s for the coordination server's sign-in page after a login request; the
    /// engine checks it against the server (Go ValidLoginURL), the app again before opening it.
    private func awaitAuthURL(_ handle: Int32, attempt: Int, reply: @escaping (TailnetCommandReply) -> Void) {
        if let data = TailnetEngine.status(handle), let status = TailnetStatus.decode(data), let url = status.authURL {
            return reply(TailnetCommandReply(authURL: url))
        }
        if attempt >= 60 || isStopped {
            return reply(TailnetCommandReply(error: "The coordination server didn't offer a sign-in page"))
        }
        queue.asyncAfter(deadline: .now() + 0.25) { [weak self] in self?.awaitAuthURL(handle, attempt: attempt + 1, reply: reply) }
    }

    static func withoutAuthURL(_ data: Data) -> Data {
        guard var status = TailnetStatus.decode(data) else { return data.isEmpty ? data : Data() }
        status.authURL = nil
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601  // what TailnetStatus.decode reads back
        return (try? encoder.encode(status)) ?? Data()
    }

    /// A tailnet starts only for the user at the screen who stored it, and stops when another
    /// account takes the screen: a node must not carry the next user's traffic (SEC-2). No
    /// login-window exception: there is no on-demand for tailnets in the spike.
    private func checkOwner(_ id: String) throws {
        guard let owner = store.owner(of: id) else { throw TailnetError.notHandedOver }
        guard ConsoleOwner.mayStart(owner: owner, onDemandStart: false) else { throw TailnetError.notOwner }
        guard let watch = ConsoleOwnerWatch(owner: owner, onOtherUser: { [weak self] in
            self?.note("Another user took the screen; stopping the tailnet")
            self?.cancelTunnelWithError(Self.nsError(TailnetError.notOwner))
        }) else { throw TailnetError.notOwner }
        let previous: ConsoleOwnerWatch?? = stateLock.withLock {
            if stopped { return .none }
            defer { ownerWatch = watch }
            return .some(ownerWatch)
        }
        guard let previous else {
            watch.cancel()
            throw TailnetError.canceled
        }
        previous?.cancel()
    }

    private func stopOwnerWatch() {
        stateLock.withLock { () -> ConsoleOwnerWatch? in
            defer { ownerWatch = nil }
            return ownerWatch
        }?.cancel()
    }

    // MARK: Logging

    /// The system log gets the step, privately (it names the server and peers); the Log tab
    /// gets the text.
    private func note(_ message: String) {
        log.notice("\(message, privacy: .private)")
        recentLog.append(message)
    }

    /// Every failed start ends here: the owner watch goes too (quality-9 L13).
    private func fail(_ context: String, _ error: Error, _ completionHandler: (Error?) -> Void) {
        stopOwnerWatch()
        log.error("\(context, privacy: .public): \(error.localizedDescription, privacy: .private)")
        recentLog.append("\(context): \(error.localizedDescription)")
        completionHandler(Self.nsError(error, context: context))
    }

    /// A Swift error crosses to the app as "TailnetError error 1": only an NSError's description
    /// survives NE's transport (device test, 2026-10-26; quality-9 M3). The texts name files,
    /// system calls and addresses, never keys.
    static func nsError(_ error: Error, context: String? = nil) -> NSError {
        let text = context.map { "\($0): \(error.localizedDescription)" } ?? error.localizedDescription
        return NSError(domain: "net.vpetkov.wombat.tailnet", code: 1, userInfo: [NSLocalizedDescriptionKey: text])
    }

    /// Engine lines are redacted in Go (keys, sign-in URLs); they still name peers and
    /// addresses, so they stay private in the system log.
    private func engineLog(_ line: String) {
        let line = TunnelName.line(line)
        log.debug("engine: \(line, privacy: .private)")
        recentLog.append(line)
    }
}

enum TailnetError: LocalizedError {
    case missingConfiguration
    case notHandedOver
    case outdatedCopy
    case handOffTimedOut
    case canceled
    case invalidProfile(String)
    case invalidPlan(String)
    case networkSettings(String)
    case noTunnelDevice
    case notOwner

    var errorDescription: String? {
        switch self {
        case .missingConfiguration: return "The tailnet has no saved configuration"
        case .notHandedOver: return "The Tailnet extension has no copy of this tailnet; connect from Wombat"
        case .outdatedCopy: return "This tailnet was edited while the Tailnet extension wasn't running; connect from Wombat to hand over the new settings"
        case .handOffTimedOut: return "Wombat didn't deliver this tailnet to the Tailnet extension in time; try connecting again"
        case .canceled: return "The start was canceled"
        case .invalidProfile(let s): return "Invalid profile: \(s)"
        case .invalidPlan(let s): return s
        case .networkSettings(let s): return "Could not apply network settings: \(s)"
        case .noTunnelDevice: return "Could not find the tunnel device"
        case .notOwner: return "This tailnet belongs to another user of this Mac"
        }
    }
}
