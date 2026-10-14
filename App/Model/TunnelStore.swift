import AppKit
import Combine
import Foundation
import NetworkExtension
import os
import TunnelCore

/// One tunnel as the UI sees it: the NE manager plus the parsed (non-secret) view of its config.
@MainActor
final class Tunnel: ObservableObject, Identifiable {
    /// Replaced on every reload: NE hands out fresh manager objects, and saving through a stale
    /// one fails with "configuration is stale".
    private(set) var manager: NETunnelProviderManager
    let id: UUID
    @Published private(set) var status: NEVPNStatus
    @Published private(set) var configuration: TunnelConfiguration?
    /// Computed once per configuration change, never in a view body (a hostile config can make
    /// the review expensive).
    @Published private(set) var findings: [Finding] = []
    @Published var stats: RuntimeStats?
    @Published var lastError: String?
    /// The error says the network extension is off: the UI offers to open its settings. Derived
    /// from the message, so a later, unrelated error never shows the button (quality-3).
    var errorNeedsExtension: Bool { lastError == ExtensionSecrets.notRunning }
    /// The last engine log lines fetched from the extension, kept after the tunnel stops.
    @Published var recentLog: [String] = []

    init(manager: NETunnelProviderManager, id: UUID) {
        self.manager = manager
        self.id = id
        status = manager.connection.status
    }

    var name: String { manager.localizedDescription ?? "Tunnel" }
    var proto: NETunnelProviderProtocol? { manager.protocolConfiguration as? NETunnelProviderProtocol }
    var isOnDemand: Bool { manager.isOnDemandEnabled }
    var connectedSince: Date? {
        #if DEBUG
        if demoStatus != nil { return status == .connected ? demoSince : nil }
        #endif
        return status == .connected ? manager.connection.connectedDate : nil
    }
    var isActive: Bool { [.connected, .connecting, .reasserting].contains(status) }

    func replaceManager(_ manager: NETunnelProviderManager) {
        self.manager = manager
        refreshStatus()
        objectWillChange.send()
    }

    func refreshStatus() {
        #if DEBUG
        if let demoStatus { status = demoStatus; return }
        #endif
        status = manager.connection.status
    }

    #if DEBUG
    /// Demo mode (screenshots): fixed status, config and counters, no NE configuration.
    var demoStatus: NEVPNStatus?
    var demoSince: Date?
    func setDemo(status: NEVPNStatus, config: TunnelConfiguration, stats: RuntimeStats?, since: Date?) {
        demoStatus = status
        demoSince = since
        self.status = status
        configuration = config
        findings = ConfigReview.review(config)
        self.stats = stats
    }
    #endif

    /// Loads the app's keychain copy for display (public keys, addresses). Keys are rendered
    /// only after authentication.
    func loadConfiguration() {
        guard let reference = proto?.passwordReference else { configuration = nil; findings = []; return }
        configuration = (try? ConfigKeychain.read(reference)).flatMap { WgQuick.parse($0).configuration }
        findings = configuration.map(ConfigReview.review) ?? []
    }

    var statusText: String {
        switch status {
        case .connected: return "Connected"
        case .connecting: return "Connecting…"
        case .disconnecting: return "Disconnecting…"
        case .reasserting: return "Reconnecting…"
        case .disconnected: return "Disconnected"
        case .invalid: return "Invalid"
        @unknown default: return "Unknown"
        }
    }

    var cliStatus: String {
        switch status {
        case .connected: return "connected"
        case .connecting: return "connecting"
        case .disconnecting: return "disconnecting"
        case .reasserting: return "reasserting"
        case .disconnected: return "disconnected"
        default: return "invalid"
        }
    }
}

@MainActor
final class TunnelStore: ObservableObject {
    @Published private(set) var tunnels: [Tunnel] = []
    @Published private(set) var loaded = false
    @Published var loadError: String?

    private let log = Logger(subsystem: AppIdentity.logSubsystem, category: "app")
    private var statusObserver: NSObjectProtocol?
    private var configObserver: NSObjectProtocol?
    private var statsTimer: Timer?
    private var statsWatchers = 0
    private var statsInFlight = false

    /// Tunnels whose new or edited configuration the extension hasn't received yet, because it
    /// wasn't running (macOS launches it only to run a tunnel). Ids only, never configs; handed
    /// over at the next connect or whenever the extension is up.
    @Published private(set) var pendingHandOff: Set<UUID> = Set((UserDefaults.standard.stringArray(forKey: "pendingHandOff") ?? []).compactMap(UUID.init(uuidString:))) {
        didSet { UserDefaults.standard.set(pendingHandOff.map(\.uuidString), forKey: "pendingHandOff") }
    }

    init() {
        statusObserver = NotificationCenter.default.addObserver(forName: .NEVPNStatusDidChange, object: nil, queue: .main) { [weak self] note in
            MainActor.assumeIsolated {
                guard let self, let session = note.object as? NETunnelProviderSession,
                      let tunnel = self.tunnels.first(where: { $0.manager.connection === session }) else { return }
                let before = tunnel.status
                tunnel.refreshStatus()
                if before != tunnel.status { self.announce(tunnel, from: before) }
                // Kept while a hand-off is pending: the error explains why (S3-M1).
                if tunnel.status == .connected, !self.pendingHandOff.contains(tunnel.id) { tunnel.lastError = nil }
                // The extension runs (or just refused an outdated copy): deliver what waited for it.
                if !self.pendingHandOff.isEmpty { Task { await self.syncToExtension() } }
                if tunnel.status == .disconnected { tunnel.stats = nil }  // no stale counters (Q2-L4)
                // A start that fails ends in .disconnected; the extension's reason (for example
                // the kill-switch DNS message) is only available from the connection.
                if before == .connecting, tunnel.status == .disconnected {
                    tunnel.manager.connection.fetchLastDisconnectError { error in
                        guard let error else { return }
                        // macOS may wrap the provider's error; its own message is the useful one.
                        let ns = error as NSError
                        let text = (ns.userInfo[NSUnderlyingErrorKey] as? NSError)?.localizedDescription
                            ?? ns.localizedFailureReason ?? ns.localizedDescription
                        Task { @MainActor in tunnel.lastError = text }
                    }
                }
                self.objectWillChange.send()
            }
        }
        configObserver = NotificationCenter.default.addObserver(forName: .NEVPNConfigurationChange, object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { _ = Task { await self?.reload() } }
        }
    }

    /// One place announces connection changes, so VoiceOver users hear them whether the window,
    /// the menu bar popover or nothing is open.
    private func announce(_ tunnel: Tunnel, from before: NEVPNStatus) {
        let text: String
        // Routine changes are medium priority (they don't interrupt); failures are high (A-M1).
        var priority = NSAccessibilityPriorityLevel.medium
        switch tunnel.status {
        case .connected: text = "\(tunnel.name) connected"
        case .disconnected where before == .connecting: text = "\(tunnel.name) failed to connect"; priority = .high
        case .disconnected: text = "\(tunnel.name) disconnected"
        case .reasserting: text = "\(tunnel.name) reconnecting"
        default: return
        }
        NSAccessibility.post(element: NSApp as Any, notification: .announcementRequested, userInfo: [
            .announcement: text,
            .priority: priority.rawValue,
        ])
        Preferences.postStatusNotification(text)
    }

    /// Failures that happen before the status changes never reach announce(); say them too.
    private func announceFailure(_ tunnel: Tunnel, _ error: Error) {
        NSAccessibility.post(element: NSApp as Any, notification: .announcementRequested, userInfo: [
            .announcement: "\(tunnel.name): \(error.localizedDescription)",
            .priority: NSAccessibilityPriorityLevel.high.rawValue,
        ])
    }

    // MARK: Loading

    private var reloading = false
    private var reloadAgain = false

    /// Configuration-change notifications arrive in bursts; one reload runs at a time and a
    /// burst collapses into one more pass, so an older result can't overwrite a newer one.
    func reload() async {
        #if DEBUG
        if DemoMode.isOn { return }
        #endif
        if reloading { reloadAgain = true; return }
        reloading = true
        defer { reloading = false }
        repeat {
            reloadAgain = false
            await reloadOnce()
        } while reloadAgain
    }

    private func reloadOnce() async {
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            var next: [Tunnel] = []
            for manager in managers {
                guard let proto = manager.protocolConfiguration as? NETunnelProviderProtocol,
                      proto.providerBundleIdentifier == AppIdentity.extensionBundleID,
                      let id = (proto.providerConfiguration?[ProviderConfigKey.tunnelID] as? String).flatMap(UUID.init) else { continue }
                // Another account's tunnel (configurations are system-wide): not ours to show,
                // start or change. Tunnels from before the owner was recorded count as ours only
                // if their keychain item is in this user's keychain.
                if let owner = proto.providerConfiguration?[ProviderConfigKey.ownerUID] as? NSNumber {
                    guard owner.uint32Value == getuid() else { continue }
                } else {
                    guard let reference = proto.passwordReference, ConfigKeychain.exists(reference) else { continue }
                }
                // Keep the existing object (views, stats, errors) and swap in the fresh manager.
                if let existing = tunnels.first(where: { $0.id == id }) {
                    existing.replaceManager(manager)
                    existing.loadConfiguration()
                    next.append(existing)
                } else {
                    let tunnel = Tunnel(manager: manager, id: id)
                    tunnel.loadConfiguration()
                    next.append(tunnel)
                }
            }
            tunnels = next.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
            // Forget queued hand-offs of tunnels that no longer exist (removed elsewhere, or a
            // failed add), so nothing waits for them forever (quality-3).
            let existing = Set(tunnels.map(\.id))
            if !pendingHandOff.isSubset(of: existing) { pendingHandOff.formIntersection(existing) }
            loadError = nil
        } catch {
            loadError = error.localizedDescription
            log.error("Loading tunnels failed: \(error.localizedDescription, privacy: .public)")
        }
        loaded = true
    }

    private var pendingRetry: Task<Void, Never>?
    /// A failure talking to the extension that isn't about one tunnel (shown as a banner; Q3-L6).
    @Published private(set) var extensionProblem: String?
    private var syncing = false
    private var syncAgain = false

    /// While something waits for the extension, look again every 15 s (a Mach lookup, cheap):
    /// macOS may start it on its own (after an update, or on demand) without any status change
    /// the app would see, and the launch-time sync can run before its service is registered.
    private func retryWhilePending() {
        guard pendingRetry == nil, !pendingHandOff.isEmpty else { return }
        pendingRetry = Task { [weak self] in
            try? await Task.sleep(for: .seconds(15))
            guard let self else { return }
            self.pendingRetry = nil
            await self.syncToExtension()
        }
    }

    /// Hands over configurations the extension doesn't have, or has in an older revision (first
    /// run after an extension reinstall, edits made while it wasn't running).
    func syncToExtension() async {
        // Started from several places (status changes, the retry, a connect): one at a time, and
        // a burst collapses into one more pass, like reload() (Q3-L5).
        if syncing { syncAgain = true; return }
        syncing = true
        defer { syncing = false }
        repeat {
            syncAgain = false
            await syncPass()
        } while syncAgain
    }

    private func syncPass() async {
        let pending = pendingHandOff
        for tunnel in tunnels {
            await stampOwner(tunnel)
            switch await ExtensionSecrets.has(id: tunnel.id, revision: Self.revision(tunnel)) {
            case .notRunning:  // normal: it runs only with a tunnel
                retryWhilePending()
                return
            case .failed(let message): extensionProblem = message; return
            case .yes:  // current already
                extensionProblem = nil
                if pending.contains(tunnel.id) { pendingHandOff.remove(tunnel.id) }
                continue
            case .no: break
            }
            do {
                try await handOff(tunnel)
            } catch let failure as ExtensionSecrets.Failure where failure.unreachable {
                return
            } catch {
                tunnel.lastError = error.localizedDescription
            }
        }
        // Keys of tunnels deleted while the extension was unreachable, or removed in System
        // Settings, would otherwise stay in its store forever. Only after a clean load: a failed
        // load must not look like "no tunnels".
        if loaded, loadError == nil {
            let removed = await ExtensionSecrets.prune(keeping: tunnels.map(\.id))
            if removed > 0 { log.notice("The extension dropped \(removed, privacy: .public) orphaned configuration(s)") }
        }
    }

    /// Records the owner on tunnels created before it was stored, so the extension and other
    /// accounts can tell them apart.
    /// Records the owner and a revision on configurations made before those existed.
    private func stampOwner(_ tunnel: Tunnel) async {
        guard let proto = tunnel.proto, proto.providerConfiguration?[ProviderConfigKey.ownerUID] == nil
            || proto.providerConfiguration?[ProviderConfigKey.revision] == nil else { return }
        do {
            try await tunnel.manager.loadFromPreferences()
            guard let fresh = tunnel.proto else { return }
            var config = fresh.providerConfiguration ?? [:]
            if config[ProviderConfigKey.ownerUID] == nil { config[ProviderConfigKey.ownerUID] = NSNumber(value: getuid()) }
            if config[ProviderConfigKey.revision] == nil {
                config[ProviderConfigKey.revision] = UUID().uuidString
                pendingHandOff.insert(tunnel.id)  // the extension's copy needs the new revision
            }
            fresh.providerConfiguration = config
            try await tunnel.manager.saveToPreferences()
        } catch {
            log.error("Could not record the owner of \(tunnel.name, privacy: .public): \(error.localizedDescription, privacy: .public)")
        }
    }

    func tunnel(named name: String) -> Tunnel? {
        tunnels.first { $0.name.caseInsensitiveCompare(name) == .orderedSame }
    }

    // MARK: Adding and editing

    /// Saves a new tunnel: the app's keychain copy, the extension's copy, then the VPN
    /// configuration (macOS asks the user to allow VPN configurations the first time).
    @discardableResult
    func add(name requested: String, text: String) async throws -> Tunnel {
        let parsed = WgQuick.parse(text)
        guard let config = parsed.configuration else {
            throw StoreError.invalid(parsed.errors.map(\.description).joined(separator: "\n"))
        }
        let name = TunnelName.unique(TunnelName.sanitize(requested), existing: tunnels.map(\.name))
        let id = UUID()
        let reference = try ConfigKeychain.store(text, tunnelID: id, name: name)
        let revision = UUID().uuidString
        do {
            try await ExtensionSecrets.store(id: id, text: text, revision: revision)
        } catch let failure as ExtensionSecrets.Failure where failure.unreachable {
            pendingHandOff.insert(id)  // handed over when the extension next runs
        } catch {
            ConfigKeychain.delete(reference)
            throw error
        }

        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = AppIdentity.extensionBundleID
        proto.passwordReference = reference  // the app's own copy; the extension never reads it
        proto.providerConfiguration = [ProviderConfigKey.formatVersion: 1, ProviderConfigKey.tunnelID: id.uuidString,
                                       ProviderConfigKey.ownerUID: NSNumber(value: getuid()),
                                       ProviderConfigKey.revision: revision]
        proto.serverAddress = Self.serverAddress(config)
        // Tunnels that carry most traffic default to the kill switch with the LAN blocked:
        // TunnelVision (CVE-2024-3661) and TunnelCrack LocalNet (CVE-2023-36672) both abuse
        // routes the local network controls. Users can relax it per tunnel.
        if config.isFullTunnel {
            proto.includeAllNetworks = true
            proto.excludeLocalNetworks = false
        }

        let manager = NETunnelProviderManager()
        manager.localizedDescription = name
        manager.protocolConfiguration = proto
        // Only one of our configurations is enabled at a time; enabling a new one would silently
        // switch off the on-demand rules of the current one. connect() enables it when used.
        manager.isEnabled = tunnels.isEmpty
        do {
            try await manager.saveToPreferences()
        } catch {
            ConfigKeychain.delete(reference)
            pendingHandOff.remove(id)
            try? await ExtensionSecrets.remove(id: id)
            throw error
        }
        log.notice("Added tunnel \(name, privacy: .public)")
        await reload()
        return tunnels.first { $0.id == id } ?? Tunnel(manager: manager, id: id)
    }

    /// Replaces a tunnel's config text (and optionally its name).
    func update(_ tunnel: Tunnel, name: String? = nil, text: String) async throws {
        let parsed = WgQuick.parse(text)
        guard let config = parsed.configuration else {
            throw StoreError.invalid(parsed.errors.map(\.description).joined(separator: "\n"))
        }
        try await tunnel.manager.loadFromPreferences()
        guard let proto = tunnel.proto else { throw StoreError.invalid("Tunnel has no protocol configuration") }
        let newName = name.map { TunnelName.unique(TunnelName.sanitize($0), existing: tunnels.filter { $0 !== tunnel }.map(\.name)) } ?? tunnel.name
        let oldReference = proto.passwordReference
        let oldName = tunnel.manager.localizedDescription
        let oldServer = proto.serverAddress
        let oldProviderConfiguration = proto.providerConfiguration
        let oldRevision = oldProviderConfiguration?[ProviderConfigKey.revision] as? String ?? ""
        let revision = UUID().uuidString
        // Without the current text there is nothing to roll the extension back to (F-19).
        guard let oldText = oldReference.flatMap({ try? ConfigKeychain.read($0) }) else {
            throw StoreError.invalid("The keychain item for this tunnel is missing; delete and re-import it")
        }

        let reference = try ConfigKeychain.store(text, tunnelID: tunnel.id, name: newName)
        var deferred = false
        do {
            do {
                try await ExtensionSecrets.store(id: tunnel.id, text: text, revision: revision)
            } catch let failure as ExtensionSecrets.Failure where failure.unreachable {
                deferred = true  // the extension keeps the old copy until it runs again
            }
            proto.passwordReference = reference
            proto.serverAddress = Self.serverAddress(config)
            var providerConfiguration = proto.providerConfiguration ?? [:]
            providerConfiguration[ProviderConfigKey.revision] = revision
            proto.providerConfiguration = providerConfiguration
            tunnel.manager.localizedDescription = newName
            try await tunnel.manager.saveToPreferences()
        } catch {
            // Roll everything back: in-memory manager, keychain, extension copy.
            proto.passwordReference = oldReference
            proto.serverAddress = oldServer
            proto.providerConfiguration = oldProviderConfiguration
            tunnel.manager.localizedDescription = oldName
            ConfigKeychain.delete(reference)
            if !deferred {
                // If even the rollback fails, the extension holds the rejected text: re-send the
                // current one at the next chance (the revisions differ, so it won't start; S3-L2).
                do { try await ExtensionSecrets.store(id: tunnel.id, text: oldText, revision: oldRevision) } catch { pendingHandOff.insert(tunnel.id) }
            }
            throw error
        }
        if deferred { pendingHandOff.insert(tunnel.id) }
        if let oldReference { ConfigKeychain.delete(oldReference) }
        tunnel.loadConfiguration()
        objectWillChange.send()
    }

    func delete(_ tunnel: Tunnel) async throws {
        if tunnel.isActive { tunnel.manager.connection.stopVPNTunnel() }
        let reference = tunnel.proto?.passwordReference
        try await tunnel.manager.removeFromPreferences()
        if let reference { ConfigKeychain.delete(reference) }
        pendingHandOff.remove(tunnel.id)
        do {
            try await ExtensionSecrets.remove(id: tunnel.id)
        } catch {
            // The tunnel is gone either way; syncToExtension prunes the extension's copy the
            // next time the extension is reachable.
            log.error("Extension copy of \(tunnel.name, privacy: .public) not removed yet: \(error.localizedDescription, privacy: .public)")
        }
        await reload()
    }

    /// A copy under a new name (same keys): handy for variants such as split vs full tunnel.
    @discardableResult
    func duplicate(_ tunnel: Tunnel) async throws -> Tunnel {
        guard let reference = tunnel.proto?.passwordReference else { throw StoreError.invalid("The keychain item is missing") }
        return try await add(name: "\(tunnel.name) copy", text: try ConfigKeychain.read(reference))
    }

    func rename(_ tunnel: Tunnel, to requested: String) async throws {
        guard !TunnelName.sanitize(requested).isEmpty else { throw StoreError.invalid("The name can't be empty") }
        let name = TunnelName.unique(TunnelName.sanitize(requested), existing: tunnels.filter { $0 !== tunnel }.map(\.name))
        try await tunnel.manager.loadFromPreferences()
        tunnel.manager.localizedDescription = name
        try await tunnel.manager.saveToPreferences()
        await reload()
    }

    /// What System Settings shows under the VPN's "Server" field.
    private static func serverAddress(_ c: TunnelConfiguration) -> String {
        switch c.peers.count {
        case 0: return "No peers"
        case 1: return c.peers[0].endpoint?.description ?? "No endpoint"
        default: return "\(c.peers.count) peers"
        }
    }

    // MARK: Connecting

    func connect(_ tunnel: Tunnel, source: String = "the app") async throws {
        // Look the endpoints up first: once another tunnel's kill switch is being torn down, or
        // this one's starts, the system resolver may be blocked (audit Q2-M2).
        let endpoints = await resolvedEndpoints(tunnel)
        // One of our tunnels at a time. Another tunnel with on-demand on would be restarted by
        // macOS right away, so switching tunnels also turns its on-demand off.
        for other in tunnels where other !== tunnel {
            if other.manager.isOnDemandEnabled {
                try? await other.manager.loadFromPreferences()
                other.manager.isOnDemandEnabled = false
                try? await other.manager.saveToPreferences()
            }
            if other.isActive { other.manager.connection.stopVPNTunnel() }
        }
        try await tunnel.manager.loadFromPreferences()  // NE rejects starts on a stale copy
        if !tunnel.manager.isEnabled {
            tunnel.manager.isEnabled = true
            try await tunnel.manager.saveToPreferences()
            try await tunnel.manager.loadFromPreferences()
        }
        var options: [String: NSObject] = [StartOption.source: source as NSString]
        if let endpoints, !endpoints.isEmpty {
            options[StartOption.endpoints] = endpoints as NSDictionary
        }
        // Make sure the extension starts from the current configuration. If it isn't running,
        // this start launches it, and it waits for the hand-off below (StartOption.awaitHandOff).
        let wakesExtension: Bool
        switch await ExtensionSecrets.has(id: tunnel.id, revision: Self.revision(tunnel)) {
        case .notRunning:
            wakesExtension = true
            options[StartOption.awaitHandOff] = true as NSNumber
        case .failed(let message):
            throw ExtensionSecrets.Failure(errorDescription: message)
        case .no:
            try await handOff(tunnel)
            wakesExtension = false
        case .yes:
            pendingHandOff.remove(tunnel.id)
            wakesExtension = false
        }
        try tunnel.manager.connection.startVPNTunnel(options: options)
        tunnel.lastError = nil
        if wakesExtension { Task { await handOffAfterLaunch(tunnel) } }
    }

    private static func revision(_ tunnel: Tunnel) -> String {
        tunnel.proto?.providerConfiguration?[ProviderConfigKey.revision] as? String ?? ""
    }

    /// Sends the tunnel's current configuration from the keychain to the extension.
    private func handOff(_ tunnel: Tunnel) async throws {
        guard let reference = tunnel.proto?.passwordReference, let text = try? ConfigKeychain.read(reference) else {
            throw StoreError.invalid("The keychain item for this tunnel is missing; delete and re-import it")
        }
        try await ExtensionSecrets.store(id: tunnel.id, text: text, revision: Self.revision(tunnel))
        pendingHandOff.remove(tunnel.id)
        log.notice("Handed \(tunnel.name, privacy: .public) to the extension")
    }

    /// The start just launched the extension: hand over as soon as it answers (it waits up to
    /// 10 s), then catch up on anything else that was waiting.
    private func handOffAfterLaunch(_ tunnel: Tunnel) async {
        for _ in 0..<36 {
            try? await Task.sleep(for: .milliseconds(250))
            do {
                try await handOff(tunnel)
                await syncToExtension()
                return
            } catch let failure as ExtensionSecrets.Failure where failure.unreachable {
                continue
            } catch {
                tunnel.lastError = error.localizedDescription
                announceFailure(tunnel, error)
                return
            }
        }
        log.error("The extension did not start within 9 s")
        tunnel.lastError = ExtensionSecrets.notRunning
        announceFailure(tunnel, ExtensionSecrets.Failure(errorDescription: ExtensionSecrets.notRunning))
    }

    /// Looks up the tunnel's endpoint hostnames now, while nothing blocks the system resolver, so
    /// the extension can start with the kill switch on (see `StartOption.endpoints`). A name that
    /// doesn't resolve is left out; the extension then tries its own lookup or its cache.
    private func resolvedEndpoints(_ tunnel: Tunnel) async -> [String: [String]]? {
        guard let reference = tunnel.proto?.passwordReference,
              let text = try? ConfigKeychain.read(reference),
              let config = WgQuick.parse(text).configuration else { return nil }
        let hosts = Set(config.peers.compactMap(\.endpoint).filter(\.isHostname).map(\.hostString))
        var result: [String: [String]] = [:]
        await withTaskGroup(of: (String, [String]).self) { group in
            for host in hosts {
                group.addTask { (host, await EndpointLookup.addresses(for: host)) }
            }
            for await (host, addresses) in group where !addresses.isEmpty { result[host] = addresses }
        }
        return result
    }

    func disconnect(_ tunnel: Tunnel) async throws {
        // With on-demand on, the system would reconnect at once; turning it off is what the
        // user means by "disconnect" in the app. (CLI callers get an approval prompt first.)
        if tunnel.manager.isOnDemandEnabled {
            try await tunnel.manager.loadFromPreferences()
            tunnel.manager.isOnDemandEnabled = false
            try await tunnel.manager.saveToPreferences()
        }
        tunnel.manager.connection.stopVPNTunnel()
    }

    func toggle(_ tunnel: Tunnel) async {
        do {
            if tunnel.isActive { try await disconnect(tunnel) } else { try await connect(tunnel) }
        } catch {
            tunnel.lastError = error.localizedDescription
            announceFailure(tunnel, error)
        }
    }

    /// Stops and restarts a tunnel to apply a new configuration.
    func reconnect(_ tunnel: Tunnel) async {
        tunnel.manager.connection.stopVPNTunnel()
        for _ in 0..<50 where tunnel.status != .disconnected {
            try? await Task.sleep(for: .milliseconds(100))
            tunnel.refreshStatus()
        }
        do { try await connect(tunnel) } catch { tunnel.lastError = error.localizedDescription; announceFailure(tunnel, error) }
    }

    // MARK: On-demand, protection

    func setOnDemand(_ tunnel: Tunnel, _ settings: Control.OnDemand) async throws {
        try await tunnel.manager.loadFromPreferences()
        tunnel.manager.onDemandRules = settings.neRules()
        tunnel.manager.isOnDemandEnabled = settings.enabled
        // Rules only run for the enabled configuration.
        if settings.enabled { tunnel.manager.isEnabled = true }
        try await tunnel.manager.saveToPreferences()
        if settings.enabled {
            for other in tunnels where other !== tunnel && other.manager.isOnDemandEnabled {
                try? await other.manager.loadFromPreferences()
                other.manager.isOnDemandEnabled = false
                try? await other.manager.saveToPreferences()
            }
        }
        await reload()
    }

    /// Kill switch: route everything through the tunnel and block traffic while it's down.
    func setProtection(_ tunnel: Tunnel, _ protection: Control.Protection) async throws {
        try await tunnel.manager.loadFromPreferences()
        guard let proto = tunnel.proto else { return }
        proto.includeAllNetworks = protection.killSwitch
        proto.excludeLocalNetworks = protection.allowLAN
        try await tunnel.manager.saveToPreferences()
        await reload()
    }

    // MARK: Runtime data

    func fetchStats(_ tunnel: Tunnel) async -> RuntimeStats? {
        #if DEBUG
        if tunnel.demoStatus != nil { return tunnel.stats }
        #endif
        guard tunnel.status == .connected || tunnel.status == .reasserting,
              let session = tunnel.manager.connection as? NETunnelProviderSession,
              let reply = await send(.runtimeConfiguration, to: session) else { return nil }
        let stats = RuntimeStats.parse(uapi: String(decoding: reply, as: UTF8.self))
        tunnel.stats = stats
        return stats
    }

    func fetchRecentLog(_ tunnel: Tunnel) async -> [String] {
        guard let session = tunnel.manager.connection as? NETunnelProviderSession,
              tunnel.status != .disconnected, tunnel.status != .invalid,
              let reply = await send(.recentLog, to: session) else { return [] }
        return String(decoding: reply, as: UTF8.self).split(separator: "\n").map(String.init)
    }

    private func send(_ message: ProviderMessage, to session: NETunnelProviderSession) async -> Data? {
        await withCheckedContinuation { continuation in
            do {
                try session.sendProviderMessage(Data([message.rawValue])) { reply in
                    continuation.resume(returning: reply)
                }
            } catch {
                continuation.resume(returning: nil)
            }
        }
    }

    /// Polls counters once a second while at least one view shows them; never more than one
    /// round in flight.
    func watchStats(_ on: Bool) {
        statsWatchers = max(0, statsWatchers + (on ? 1 : -1))
        if statsWatchers > 0, statsTimer == nil {
            let timer = Timer(timeInterval: 1, repeats: true) { [weak self] _ in
                MainActor.assumeIsolated {
                    guard let self, !self.statsInFlight else { return }
                    self.statsInFlight = true
                    Task {
                        for t in self.tunnels where t.status == .connected { _ = await self.fetchStats(t) }
                        self.statsInFlight = false
                    }
                }
            }
            timer.tolerance = 0.2
            RunLoop.main.add(timer, forMode: .common)
            statsTimer = timer
            timer.fire()
        } else if statsWatchers == 0 {
            statsTimer?.invalidate()
            statsTimer = nil
        }
    }

    var activeTunnel: Tunnel? { tunnels.first { $0.isActive } }

    #if DEBUG
    func setDemoTunnels(_ demo: [Tunnel]) {
        tunnels = demo
        loaded = true
    }
    #endif
}

enum StoreError: LocalizedError {
    case invalid(String)
    var errorDescription: String? {
        switch self { case .invalid(let s): return s }
    }
}
