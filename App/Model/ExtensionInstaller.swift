import Foundation
import NetworkExtension
import os
import SystemExtensions

/// Activates a bundled packet tunnel system extension. The first activation needs the user's
/// approval in System Settings › General › Login Items & Extensions; later app updates replace
/// the extension without asking again. There are two: WireGuard (always) and OpenConnect
/// (activated once the user has an AnyConnect VPN, so nobody approves an extension they don't use).
@MainActor
class ExtensionInstaller: NSObject, ObservableObject {
    enum State: Equatable {
        case unknown, activating, needsApproval, active, failed(String), requiresApplicationsFolder
    }

    @Published private(set) var state: State = .unknown
    let identifier: String
    /// "WireGuard" or "OpenConnect", for banners.
    let engineName: String
    private let log = Logger(subsystem: AppIdentity.logSubsystem, category: "extension")
    /// The next replacement may go ahead: this extension's tunnels were stopped for it.
    private var replacementPrepared = false
    /// A replacement was canceled on purpose while its tunnels stop; its failure isn't one.
    private var deferringReplacement = false
    /// The canceled request, until its own "canceled" callback arrives: only then is the next
    /// request sent, or a late callback would read as "same build installed" (Fable 2).
    private var deferredRequest: ObjectIdentifier?

    /// Whether a replacement first stops this extension's tunnels (OpenConnect only).
    let stopsTunnelsBeforeReplacing: Bool

    init(identifier: String = AppIdentity.extensionBundleID, engineName: String = "WireGuard", stopsTunnelsBeforeReplacing: Bool = false) {
        self.identifier = identifier
        self.engineName = engineName
        self.stopsTunnelsBeforeReplacing = stopsTunnelsBeforeReplacing
    }

    #if DEBUG
    /// Demo mode (screenshots) only.
    func setDemoState(_ state: State) { self.state = state }
    #endif

    /// Activates once; later calls only retry after a failure.
    func activateIfNeeded() {
        switch state {
        case .unknown, .failed: activate()
        default: return
        }
    }

    func activate() {
        // System extensions only activate from /Applications (unless developer mode is on, which needs SIP off).
        guard Bundle.main.bundlePath.hasPrefix("/Applications/") else {
            state = .requiresApplicationsFolder
            return
        }
        state = .activating
        let request = OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: identifier, queue: .main)
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    var needsAttention: Bool {
        switch state {
        case .needsApproval, .failed, .requiresApplicationsFolder: return true
        default: return false
        }
    }
}

extension ExtensionInstaller: OSSystemExtensionRequestDelegate {
    nonisolated func request(_ request: OSSystemExtensionRequest,
                             actionForReplacingExtension existing: OSSystemExtensionProperties,
                             withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        #if DEBUG
        // Local builds keep the same version number, so always install the one just built.
        return .replace
        #else
        // Replace only with a newer build. An older notarized Wombat, launched from anywhere by a
        // same-user process, would otherwise put back its older extension and its fixed bugs
        // (review NEW-10). Release builds always carry a higher build number than the test
        // builds before them (CLAUDE.md, pitfall 11). Rolling back means removing the extension
        // first (System Settings › General › Login Items & Extensions).
        let installed = Int(existing.bundleVersion) ?? 0, offered = Int(ext.bundleVersion) ?? 0
        guard offered > installed else { return .cancel }
        // Only the OpenConnect extension: its hand-off needs the XPC service at every connect
        // (review security-11 M1); the others keep their configurations between starts.
        guard stopsTunnelsBeforeReplacing else { return .replace }
        // macOS SIGKILLs the old extension and creates the new launchd job without waiting for the
        // old process to exit. One still busy with a connected VPN takes long enough that the new
        // job is created without its XPC service, which then stays missing until a restart
        // (2026-11-18: 1.4.6 → 1.4.8, the old OpenConnect process died 13 ms after the kill, the
        // job was made at 6 ms). So the first time, cancel, stop this extension's tunnels, wait
        // for them to end, and ask again; the second time, replace. The update would end those
        // tunnels anyway. Not a guarantee (an idle process can be slow too): the app also has a
        // backup hand-off route (ProviderHandOff).
        let canceled = ObjectIdentifier(request)
        return MainActor.assumeIsolated { () -> OSSystemExtensionRequest.ReplacementAction in
            if replacementPrepared {
                replacementPrepared = false
                return .replace
            }
            replacementPrepared = true
            deferringReplacement = true
            deferredRequest = canceled
            Task { @MainActor in
                await self.stopTunnelsBeforeReplacing()
                // Its "canceled" callback first (at most 5 s), then the request that replaces.
                for _ in 0..<50 where self.deferredRequest != nil {
                    try? await Task.sleep(for: .milliseconds(100))
                }
                self.deferredRequest = nil
                self.deferringReplacement = false
                self.activate()
            }
            return .cancel
        }
        #endif
    }

    /// Stops this user's connected or connecting VPNs in this extension and waits (at most 15 s)
    /// until they have ended. Never another account's, and never one with the kill switch or
    /// on-demand on: ending those needs the user's approval (SEC-1), and on-demand would start it
    /// again (review security-11 M1). Those take their chances with the replacement, which the
    /// backup hand-off route covers.
    private func stopTunnelsBeforeReplacing() async {
        let managers = (try? await NETunnelProviderManager.loadAllFromPreferences()) ?? []
        let active = managers.filter {
            guard let proto = $0.protocolConfiguration as? NETunnelProviderProtocol,
                  proto.providerBundleIdentifier == identifier,
                  (proto.providerConfiguration?[ProviderConfigKey.ownerUID] as? NSNumber)?.uint32Value == getuid(),
                  !proto.includeAllNetworks, !$0.isOnDemandEnabled else { return false }
            return [.connected, .connecting, .reasserting].contains($0.connection.status)
        }
        guard !active.isEmpty else { return }
        log.notice("Stopping \(active.count, privacy: .public) VPN(s) before replacing \(self.identifier, privacy: .public)")
        active.forEach { $0.connection.stopVPNTunnel() }
        for _ in 0..<150 where active.contains(where: { ![.disconnected, .invalid].contains($0.connection.status) }) {
            try? await Task.sleep(for: .milliseconds(100))
        }
        // The extension's own stop work (the gateway's goodbye) ends just after the status does.
        try? await Task.sleep(for: .seconds(1))
    }

    nonisolated func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        MainActor.assumeIsolated {
            log.notice("System extension \(self.identifier, privacy: .public) needs approval")
            state = .needsApproval
        }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        MainActor.assumeIsolated {
            log.notice("System extension \(self.identifier, privacy: .public) active (result \(result.rawValue, privacy: .public))")
            replacementPrepared = false  // a later update stops the tunnels again (L7)
            state = .active
        }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        let failed = ObjectIdentifier(request)
        MainActor.assumeIsolated {
            let code = (error as NSError).code
            // .requestCanceled after `.cancel` above means the same build is already installed.
            if code == OSSystemExtensionError.requestCanceled.rawValue {
                // Canceled on purpose while the tunnels stop: the next request replaces it.
                if deferringReplacement {
                    if deferredRequest == failed { deferredRequest = nil }
                    return
                }
                replacementPrepared = false
                state = .active
                return
            }
            replacementPrepared = false
            log.error("System extension \(self.identifier, privacy: .public) failed: \(error.localizedDescription, privacy: .public)")
            state = .failed(error.localizedDescription)
        }
    }
}

/// The Tailnet extension's installer, activated only once a tailnet exists.
@MainActor
final class TailnetInstaller: ExtensionInstaller {
    init() { super.init(identifier: AppIdentity.tailnetExtensionBundleID, engineName: "Tailnet") }
}

/// The OpenConnect extension's installer (its own type, so views can observe both).
@MainActor
final class OpenConnectInstaller: ExtensionInstaller {
    init() { super.init(identifier: AppIdentity.openConnectExtensionBundleID, engineName: "OpenConnect", stopsTunnelsBeforeReplacing: true) }
}
