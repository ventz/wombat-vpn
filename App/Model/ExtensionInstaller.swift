import Foundation
import os
import SystemExtensions

/// Activates the bundled packet tunnel system extension. The first activation needs the user's
/// approval in System Settings › General › Login Items & Extensions; later app updates replace
/// the extension without asking again.
@MainActor
final class ExtensionInstaller: NSObject, ObservableObject {
    enum State: Equatable {
        case unknown, activating, needsApproval, active, failed(String), requiresApplicationsFolder
    }

    @Published private(set) var state: State = .unknown
    private let log = Logger(subsystem: AppIdentity.logSubsystem, category: "extension")

    func activate() {
        // System extensions only activate from /Applications (unless developer mode is on, which needs SIP off).
        guard Bundle.main.bundlePath.hasPrefix("/Applications/") else {
            state = .requiresApplicationsFolder
            return
        }
        state = .activating
        let request = OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: AppIdentity.extensionBundleID, queue: .main)
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
        // Replace whenever the build differs, including a downgrade to a release build after testing.
        return existing.bundleVersion == ext.bundleVersion && existing.bundleShortVersion == ext.bundleShortVersion ? .cancel : .replace
        #endif
    }

    nonisolated func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        MainActor.assumeIsolated {
            log.notice("System extension needs approval")
            state = .needsApproval
        }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        MainActor.assumeIsolated {
            log.notice("System extension active (result \(result.rawValue, privacy: .public))")
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
            log.error("System extension failed: \(error.localizedDescription, privacy: .public)")
            state = .failed(error.localizedDescription)
        }
    }
}
