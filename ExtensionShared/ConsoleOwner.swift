import Foundation
import SystemConfiguration

/// VPN configurations are shared by every account on the Mac, so both extensions start a tunnel
/// only for the user who stored it (audit F-3). The exception is an on-demand tunnel that macOS
/// starts on its own while nobody is at the screen (at boot), and such a tunnel stops as soon as
/// another account takes the screen (review SEC-2).
enum ConsoleOwner {
    /// Who is at the screen: nil while the login window has it, or when macOS can't say.
    static func currentUser() -> uid_t? {
        var uid: uid_t = 0
        guard let name = SCDynamicStoreCopyConsoleUser(nil, &uid, nil) as String?, name != "loginwindow" else { return nil }
        return uid
    }

    /// `onDemandStart`: macOS started the tunnel without a request from Wombat (no start options)
    /// AND its on-demand is on. Without the on-demand condition, `scutil --nc start` from an
    /// account logged in over SSH would pass too (security-6 L4).
    static func mayStart(owner: uid_t, onDemandStart: Bool) -> Bool {
        if let user = currentUser() { return user == owner }
        return onDemandStart
    }
}

/// Calls `onOtherUser` once if an account other than `owner` takes the screen. Used for tunnels
/// that started with nobody logged in, so they don't carry the next user's traffic with the
/// owner's VPN identity (SEC-2).
///
/// The dynamic store retains this object (context retain/release), so a callback can never run
/// on a freed watch; `cancel()` breaks that cycle and may be called from any queue, any number of
/// times (security-6 L5).
final class ConsoleOwnerWatch {
    private let lock = NSLock()
    private var store: SCDynamicStore?
    private var fired = false
    private let owner: uid_t
    private let onOtherUser: () -> Void
    private let queue = DispatchQueue(label: "net.vpetkov.wombat.console-owner")

    init?(owner: uid_t, onOtherUser: @escaping () -> Void) {
        self.owner = owner
        self.onOtherUser = onOtherUser
        var context = SCDynamicStoreContext(
            version: 0, info: Unmanaged.passUnretained(self).toOpaque(),
            retain: { info in
                _ = Unmanaged<ConsoleOwnerWatch>.fromOpaque(info).retain()
                return info
            },
            release: { info in Unmanaged<ConsoleOwnerWatch>.fromOpaque(info).release() },
            copyDescription: nil)
        guard let store = SCDynamicStoreCreate(nil, "Wombat console owner" as CFString, { _, _, info in
            guard let info else { return }
            Unmanaged<ConsoleOwnerWatch>.fromOpaque(info).takeUnretainedValue().check()
        }, &context) else { return nil }
        guard SCDynamicStoreSetNotificationKeys(store, [SCDynamicStoreKeyCreateConsoleUser(nil)] as CFArray, nil),
              SCDynamicStoreSetDispatchQueue(store, queue) else {
            SCDynamicStoreSetDispatchQueue(store, nil)
            return nil
        }
        self.store = store
        queue.async { self.check() }  // someone may have logged in before the watch began
    }

    private func check() {
        guard let user = ConsoleOwner.currentUser(), user != owner else { return }
        let fire: Bool = lock.withLock {
            guard !fired else { return false }
            fired = true
            return true
        }
        if fire { onOtherUser() }
    }

    func cancel() {
        let store: SCDynamicStore? = lock.withLock {
            fired = true
            defer { self.store = nil }
            return self.store
        }
        // Releases the store, and with it the store's reference to this object.
        if let store { SCDynamicStoreSetDispatchQueue(store, nil) }
    }
}
