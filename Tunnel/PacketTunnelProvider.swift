// Based on the official WireGuard app's PacketTunnelProvider (MIT, © 2018-2023 WireGuard LLC).

import Foundation
import NetworkExtension
import os
import SystemConfiguration
import TunnelCore

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let log = Logger(subsystem: AppIdentity.logSubsystem, category: "tunnel")
    /// Per tunnel: one extension process serves every tunnel, and a shared buffer would hand one
    /// tunnel's history to another's log request (audit WOM-14).
    private let recentLog = RecentLog()
    private var handshakeWatch: Task<Void, Never>?
    /// Set by stopTunnel, so a start still waiting for the hand-off gives up (audit S3-L5).
    private let stateLock = NSLock()
    private var stopped = false
    private let handOffQueue = DispatchQueue(label: "net.vpetkov.wombat.tunnel.handoff")

    private lazy var adapter: WireGuardAdapter = {
        WireGuardAdapter(with: self) { [weak self] level, message in
            self?.engineLog(level, message)
        }
    }()

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        let source = options?[StartOption.source] as? String ?? "the system (on-demand or System Settings)"
        log.notice("Starting tunnel, requested by \(source, privacy: .public)")
        self.recentLog.append("Starting tunnel, requested by \(source)")
        stateLock.withLock { stopped = false }
        // Created here, on NE's queue, before any wait: the lazy adapter must not be first touched
        // from two queues at once (S3-L5).
        _ = adapter
        // This start may be what launched the process, before the app could hand over a new or
        // edited configuration: wait (at most 10 s) for the copy with this configuration's
        // revision. begin() refuses any other copy either way.
        let provider = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration
        if options?[StartOption.awaitHandOff] != nil,
           let id = provider?[ProviderConfigKey.tunnelID] as? String,
           let revision = provider?[ProviderConfigKey.revision] as? String {
            waitForHandOff(id: id, revision: revision, attempt: 0) { [weak self] timedOut in
                self?.begin(options: options, handOffTimedOut: timedOut, completionHandler: completionHandler)
            } canceled: {
                completionHandler(TunnelError.canceled)
            }
        } else {
            begin(options: options, completionHandler: completionHandler)
        }
    }

    private func waitForHandOff(id: String, revision: String, attempt: Int, then: @escaping (_ timedOut: Bool) -> Void, canceled: @escaping () -> Void) {
        if stateLock.withLock({ stopped }) { return canceled() }
        if SecretStore.shared.revision(of: id) == .some(revision) { return then(false) }
        if attempt >= 40 {
            log.error("The app did not hand the configuration over within 10 s")
            return then(true)
        }
        handOffQueue.asyncAfter(deadline: .now() + 0.25) { [weak self] in
            self?.waitForHandOff(id: id, revision: revision, attempt: attempt + 1, then: then, canceled: canceled)
        }
    }

    private func begin(options: [String: NSObject]?, handOffTimedOut: Bool = false, completionHandler: @escaping (Error?) -> Void) {
        // A stop that arrived during the hand-off wait wins: don't bring the engine up after it.
        if stateLock.withLock({ stopped }) { return completionHandler(TunnelError.canceled) }
        let configuration: TunnelConfiguration
        var pending: (id: String, hosts: Set<String>, addresses: [String: [String]]) = ("", [], [:])
        let killSwitch = protocolConfiguration.includeAllNetworks
        do {
            let (id, text) = try loadConfigurationText()
            try checkOwner(id)
            // Never start from a copy older than the configuration (fail closed; S3-M1/M2). A copy
            // without a revision (stored before they existed) doesn't match either: the app
            // re-sends it as soon as the extension runs (quality-3).
            let expected = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration?[ProviderConfigKey.revision] as? String
            if let expected, SecretStore.shared.revision(of: id) != .some(expected) {
                // Wombat started this very connect, so "connect from Wombat" would be no help (Q3-L8).
                throw handOffTimedOut ? TunnelError.handOffTimedOut : TunnelError.outdatedCopy
            }
            let parsed = WgQuick.parse(text)
            guard let core = parsed.configuration else {
                throw TunnelError.invalidConfiguration(parsed.errors.map(\.description).joined(separator: "; "))
            }
            let hosts = Set(core.peers.compactMap(\.endpoint).filter(\.isHostname).map(\.hostString))
            let addresses = EndpointAddresses.resolve(tunnelID: id, hosts: hosts, options: options, killSwitch: killSwitch)
            configuration = try ConfigBridge.wireGuardKit(core, name: protocolConfiguration.serverAddress, addresses: addresses.chosen)
            pending = (id, hosts, addresses.pending)
            // The engine only, never the settings: they identify the server to a censor. Private,
            // since using AmneziaWG at all can be sensitive for whoever reads a sysdiagnose (S4-L2).
            log.notice("Protocol: \(core.isAmnezia ? "AmneziaWG (amneziawg-go \(WireGuardAdapter.amneziaBackendVersion)+wombat)" : "WireGuard (wireguard-go \(WireGuardAdapter.backendVersion))", privacy: .private)")
            // Counts only (no names or addresses): shows whether the app's lookups arrived.
            log.notice("Endpoints: \(hosts.count, privacy: .public) hostname(s), \(addresses.pending.count, privacy: .public) looked up by the app, \(addresses.chosen.count, privacy: .public) in use")
        } catch {
            // Private: parser messages can quote config values (endpoints, AmneziaWG numbers).
            // The app's Log tab still shows it in full (recentLog).
            log.error("Cannot start: \(error.localizedDescription, privacy: .private)")
            self.recentLog.append("Cannot start: \(error.localizedDescription)")
            completionHandler(error)
            return
        }

        let handshakePending = pending
        adapter.start(tunnelConfiguration: configuration) { [weak self] adapterError in
            guard let self else { return }
            guard let adapterError else {
                let name = self.adapter.interfaceName ?? "unknown"
                self.log.notice("Tunnel up on \(name, privacy: .public)")
                self.recentLog.append("Tunnel up on \(name)")
                self.confirmAddressesAfterHandshake(handshakePending)
                completionHandler(nil)
                return
            }
            var error = TunnelError(adapterError)
            if killSwitch, case .dnsResolution(let hosts) = error { error = .dnsBlockedByKillSwitch(hosts) }
            self.log.error("Start failed: \(error.localizedDescription, privacy: .public)")
            self.recentLog.append("Start failed: \(error.localizedDescription)")
            completionHandler(error)
        }
    }

    /// Caches the endpoint addresses once the engine reports a handshake (checked for 2 minutes).
    private func confirmAddressesAfterHandshake(_ pending: (id: String, hosts: Set<String>, addresses: [String: [String]])) {
        guard !pending.addresses.isEmpty else { return }
        handshakeWatch?.cancel()
        handshakeWatch = Task { [weak self] in
            for _ in 0..<24 {
                try? await Task.sleep(for: .seconds(5))
                guard let self, !Task.isCancelled else { return }
                let uapi: String? = await withCheckedContinuation { c in self.adapter.getRuntimeConfiguration { c.resume(returning: $0) } }
                let handshook = uapi?.split(separator: "\n").contains { $0.hasPrefix("last_handshake_time_sec=") && $0 != "last_handshake_time_sec=0" } ?? false
                if handshook {
                    EndpointAddresses.confirm(tunnelID: pending.id, pending.addresses, hosts: pending.hosts)
                    return
                }
            }
            self?.log.notice("No handshake within 2 minutes; endpoint addresses not saved")
        }
    }

    /// VPN configurations are shared by every account on the Mac. A tunnel starts only for the
    /// user who stored it, or when nobody is logged in at the screen (on-demand at boot); this
    /// stops another account from bringing up your tunnel with your keys (audit F-3).
    private func checkOwner(_ id: String) throws {
        guard let owner = SecretStore.shared.owner(of: id) else { return }  // loadConfigurationText already failed otherwise
        var uid: uid_t = 0
        if let user = SCDynamicStoreCopyConsoleUser(nil, &uid, nil) as String?, user != "loginwindow", uid != owner {
            throw TunnelError.notOwner
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        stateLock.withLock { stopped = true }
        handshakeWatch?.cancel()
        log.notice("Stopping tunnel (reason \(reason.rawValue, privacy: .public))")
        self.recentLog.append("Stopping tunnel (reason \(reason.rawValue))")
        adapter.stop { [weak self] error in
            if let error {
                self?.log.error("Stop failed: \(String(describing: error), privacy: .public)")
            }
            // No exit(0) here, unlike the official app (an app extension, one process per
            // tunnel): a system extension is one process for every tunnel and also serves the
            // app's XPC connection, so exiting would kill both.
            completionHandler()
        }
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        guard let completionHandler else { return }
        guard messageData.count == 1, let message = ProviderMessage(rawValue: messageData[0]) else {
            completionHandler(nil)
            return
        }
        switch message {
        case .runtimeConfiguration:
            adapter.getRuntimeConfiguration { uapi in
                completionHandler(uapi.map { Data(Self.withoutSecrets($0).utf8) })
            }
        case .recentLog:
            completionHandler(Data(recentLog.lines().joined(separator: "\n").utf8))
        }
    }

    /// The UAPI dump includes private_key and preshared_key. Only keys the app needs for
    /// counters pass (an allowlist, so a new secret field upstream can't slip through).
    static let publicUAPIKeys: Set<Substring> = [
        "listen_port", "fwmark", "public_key", "endpoint", "allowed_ip", "persistent_keepalive_interval",
        "last_handshake_time_sec", "last_handshake_time_nsec", "rx_bytes", "tx_bytes", "protocol_version", "errno",
    ]

    static func withoutSecrets(_ uapi: String) -> String {
        uapi.split(separator: "\n")
            .filter { line in line.split(separator: "=", maxSplits: 1).first.map(publicUAPIKeys.contains) ?? false }
            .joined(separator: "\n")
    }

    /// Reads the wg-quick text the app handed over (SecretStore, root-only). There is
    /// deliberately no fallback to providerConfiguration: that file is world-readable, and the
    /// user's login keychain is out of reach for a root process anyway.
    private func loadConfigurationText() throws -> (id: String, text: String) {
        guard let proto = protocolConfiguration as? NETunnelProviderProtocol,
              let id = proto.providerConfiguration?[ProviderConfigKey.tunnelID] as? String else {
            throw TunnelError.missingConfiguration
        }
        guard let text = SecretStore.shared.config(for: id) else { throw TunnelError.notHandedOver }
        return (id, text)
    }

    /// Engine lines mention endpoints and peer key fragments, so they're private in the system
    /// log (anyone on the Mac can read it); the full text stays in the app-only RecentLog.
    private func engineLog(_ level: WireGuardLogLevel, _ message: String) {
        switch level {
        case .verbose: log.debug("engine: \(message, privacy: .private)")
        case .error: log.error("engine: \(message, privacy: .private)")
        }
        self.recentLog.append(message)
    }
}

enum TunnelError: LocalizedError {
    case missingConfiguration
    case notHandedOver
    case outdatedCopy
    case handOffTimedOut
    case canceled
    case invalidConfiguration(String)
    case dnsResolution(String)
    case dnsBlockedByKillSwitch(String)
    case networkSettings(String)
    case backend(Int32)
    case noTunnelDevice
    case invalidState
    case notOwner

    init(_ error: WireGuardAdapterError) {
        switch error {
        case .cannotLocateTunnelFileDescriptor: self = .noTunnelDevice
        case .dnsResolution(let errors): self = .dnsResolution(errors.map(\.address).joined(separator: ", "))
        case .setNetworkSettings(let e): self = .networkSettings(e.localizedDescription)
        case .startWireGuardBackend(let code): self = .backend(code)
        case .invalidState: self = .invalidState
        }
    }

    var errorDescription: String? {
        switch self {
        case .missingConfiguration: return "The tunnel has no saved configuration"
        case .notHandedOver: return "The extension has no copy of this tunnel's configuration; open Wombat once to hand it over"
        case .outdatedCopy: return "This tunnel was edited while the network extension wasn't running; connect it from Wombat to hand over the new configuration"
        case .canceled: return "The start was canceled"
        case .handOffTimedOut: return "Wombat didn't deliver this tunnel's configuration to the network extension in time; try connecting again"
        case .invalidConfiguration(let s): return "Invalid configuration: \(s)"
        case .dnsResolution(let hosts): return "Could not resolve endpoint \(hosts)"
        case .dnsBlockedByKillSwitch(let hosts):
            return "Could not look up \(hosts): the kill switch blocks lookups outside the tunnel. Connect once from Wombat (it looks the name up first), or use an IP address as the endpoint"
        case .networkSettings(let s): return "Could not apply network settings: \(s)"
        case .backend(let code): return "WireGuard failed to start (code \(code))"
        case .noTunnelDevice: return "Could not find the tunnel device"
        case .invalidState: return "The tunnel is in an unexpected state"
        case .notOwner: return "This tunnel belongs to another user of this Mac"
        }
    }
}

/// The last few hundred engine log lines, for the app's log pane. Unified logging has the full
/// history (`wombat logs`), but reading it from a sandboxed app needs privileges we don't want.
final class RecentLog: @unchecked Sendable {
    private let lock = NSLock()
    private var buffer: [String] = []
    private let capacity = 500
    private let formatter: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()

    func append(_ line: String) {
        lock.lock(); defer { lock.unlock() }
        buffer.append("\(formatter.string(from: Date())) \(line)")
        if buffer.count > capacity { buffer.removeFirst(buffer.count - capacity) }
    }

    func lines() -> [String] {
        lock.lock(); defer { lock.unlock() }
        return buffer
    }
}
