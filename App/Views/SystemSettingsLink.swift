import AppKit

/// Opens System Settings where Wombat's extension switches are: General › Login Items &
/// Extensions › Extensions (By Category) › Network Extensions (ⓘ), the sheet itself.
enum SystemSettingsLink {
    /// The query Apple's own FSKit `openFileSystemExtensionsSettings()` opens for its category
    /// (`extensionPointIdentifier=com.apple.fskit.fsmodule`, found in the dyld cache), with the
    /// extension point System Settings lists network system extensions under
    /// (`/System/Library/ExtensionKit/ExtensionPoints/com.apple.system-extension-categories-ui.appexpt`).
    /// No public API opens it: the macOS 27 SDK's NetworkExtension and SystemExtensions have none,
    /// and `SMAppService.openSystemSettingsLoginItems()` stops at the top of the pane.
    /// Verified 2026-10-27 on macOS 27.0: opens the "Network Extensions" sheet listing Wombat.app.
    static let networkExtensions = URL(string: "x-apple.systempreferences:com.apple.ExtensionsPreferences?extensionPointIdentifier=com.apple.system_extension.network_extension.extension-point")!
    /// Login Items & Extensions, top of the pane: the fallback.
    static let loginItemsAndExtensions = URL(string: "x-apple.systempreferences:com.apple.LoginItems-Settings.extension")!

    @MainActor static func openNetworkExtensions() {
        if !NSWorkspace.shared.open(networkExtensions) {
            NSWorkspace.shared.open(loginItemsAndExtensions)
        }
    }
}
