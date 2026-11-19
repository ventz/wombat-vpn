import Foundation

/// How many tunnel provider objects this extension process holds. NE makes one per session
/// and releases it after the session ends; while one lives, the process may be running (or
/// about to run) a tunnel, so it must not quit for a replacement. A provider NE keeps longer
/// only means the process stays: that fails safe.
final class ProviderLifetime: @unchecked Sendable {
    /// Also held across the final check and `_exit` in `SecretStore.quitIfStillIdle`, so no
    /// provider can be made in between.
    static let lock = NSLock()
    nonisolated(unsafe) private static var count = 0

    init() { Self.lock.withLock { Self.count += 1 } }
    deinit { Self.lock.withLock { Self.count -= 1 } }

    /// Under `lock`.
    static var liveUnlocked: Int { count }
}
