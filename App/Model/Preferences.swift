import AppKit
import SwiftUI
import UserNotifications

/// Appearance and behavior settings, stored in the app's own UserDefaults. None of them affect
/// security: tunnels, on-demand rules and the kill switch run in the system either way.
enum Preferences {
    enum Key {
        static let showInDock = "showInDock"
        static let showInMenuBar = "showInMenuBar"
        static let menuBarShowsName = "menuBarShowsName"
        /// "shield" (status symbols, the default) or "w" (the app's ribbon W, dimmed when off).
        static let menuBarIcon = "menuBarIcon"
        static let openWindowAtLaunch = "openWindowAtLaunch"
        static let notifyOnChange = "notifyOnChange"
        static let confirmQuit = "confirmQuit"
    }

    static func register() {
        UserDefaults.standard.register(defaults: [
            Key.showInDock: true,
            Key.showInMenuBar: true,
            Key.menuBarShowsName: false,
            Key.menuBarIcon: "shield",
            Key.openWindowAtLaunch: true,
            Key.notifyOnChange: false,
            Key.confirmQuit: true,
        ])
    }

    private static var defaults: UserDefaults { .standard }
    static var showInDock: Bool { defaults.bool(forKey: Key.showInDock) }
    static var showInMenuBar: Bool { defaults.bool(forKey: Key.showInMenuBar) }
    static var openWindowAtLaunch: Bool { defaults.bool(forKey: Key.openWindowAtLaunch) }
    static var notifyOnChange: Bool { defaults.bool(forKey: Key.notifyOnChange) }
    static var confirmQuit: Bool {
        get { defaults.bool(forKey: Key.confirmQuit) }
        set { defaults.set(newValue, forKey: Key.confirmQuit) }
    }

    /// Without a Dock icon the app is an accessory: no Dock tile and no app menu, but its windows
    /// still work. The menu bar item (or reopening the app in Finder) brings the window back.
    @MainActor
    static func applyDockPolicy(activate: Bool = false) {
        // Hiding both would leave no way back except relaunching from Finder; Settings prevents it,
        // and a hand-edited defaults file falls back to showing the Dock icon.
        let dock = showInDock || !showInMenuBar
        // Changing the policy deactivates the app, and the window in front (Settings, where the
        // switch is) fell behind other apps as if it had closed (user, 2026-10-14). Bring it back,
        // but only when the user just changed the setting, never at launch (login items must not
        // steal focus; Q2-L3).
        let front = activate ? NSApp.keyWindow : nil
        NSApp.setActivationPolicy(dock ? .regular : .accessory)
        guard activate else { return }
        DispatchQueue.main.async {
            NSApp.activate()
            front?.makeKeyAndOrderFront(nil)
        }
    }

    // MARK: Notifications

    /// Asks once, when the user turns the setting on. Returns whether macOS allows alerts.
    static func requestNotificationPermission() async -> Bool {
        (try? await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound])) ?? false
    }

    /// Tunnel names only, never addresses or keys: notifications can show on the lock screen.
    static func postStatusNotification(_ text: String) {
        guard notifyOnChange else { return }
        let content = UNMutableNotificationContent()
        content.title = "Wombat"
        content.body = text
        UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: "status", content: content, trigger: nil))
    }
}

/// Lets AppKit code (Dock reopen, Finder relaunch) open the SwiftUI main window, which only views
/// can do through `openWindow`.
@MainActor
enum MainWindow {
    static var open: (() -> Void)?

    static func show() {
        if let window = NSApp.windows.first(where: { $0.identifier?.rawValue == "main" }) {
            window.makeKeyAndOrderFront(nil)
        } else {
            open?()
        }
        NSApp.activate()
    }
}
