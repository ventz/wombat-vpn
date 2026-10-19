import Foundation
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

    init(identifier: String = AppIdentity.extensionBundleID, engineName: String = "WireGuard") {
        self.identifier = identifier
        self.engineName = engineName
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
        return offered > installed ? .replace : .cancel
        #endif
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
            state = .active
        }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        MainActor.assumeIsolated {
            let code = (error as NSError).code
            // .requestCanceled after `.cancel` above means the same build is already installed.
            if code == OSSystemExtensionError.requestCanceled.rawValue {
                state = .active
                return
            }
            log.error("System extension \(self.identifier, privacy: .public) failed: \(error.localizedDescription, privacy: .public)")
            state = .failed(error.localizedDescription)
        }
    }
}

/// The OpenConnect extension's installer (its own type, so views can observe both).
@MainActor
final class OpenConnectInstaller: ExtensionInstaller {
    init() { super.init(identifier: AppIdentity.openConnectExtensionBundleID, engineName: "OpenConnect") }
}
