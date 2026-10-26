import Foundation

/// Identifiers shared by the app, the tunnel extension and the CLI. Values come from each
/// bundle's Info.plist (set from build settings in project.yml) so the Debug variant
/// (`…wombat.debug`) gets its own extension, app group and keychain items.
enum AppIdentity {
    /// The app's bundle identifier, e.g. net.vpetkov.wombat (also correct inside the extension).
    static let appBundleID: String = info("WombatAppBundleID") ?? "net.vpetkov.wombat"
    /// Team-prefixed app group, e.g. 8J9W3ZG4ZN.net.vpetkov.wombat.
    static let appGroup: String = info("WombatAppGroup") ?? "8J9W3ZG4ZN.net.vpetkov.wombat"
    static var extensionBundleID: String { appBundleID + ".tunnel" }
    /// The OpenConnect (Cisco AnyConnect) system extension: a separate process with its own
    /// sandbox, so the OpenConnect C code never shares memory with WireGuard keys.
    static var openConnectExtensionBundleID: String { appBundleID + ".openconnect" }
    /// The tailnet (Tailscale/Headscale) system extension: a third process, so Tailscale's
    /// control plane, DERP and peers never share memory with WireGuard keys (spike design).
    /// The bundle id may name Tailscale; the display name may not (trademark).
    static var tailnetExtensionBundleID: String { appBundleID + ".tailscale" }
    /// Unified logging subsystem: `log stream --predicate 'subsystem == "net.vpetkov.wombat"'`.
    static var logSubsystem: String { appBundleID }
    /// Keychain service for tunnel configurations (one generic password per tunnel).
    static var keychainService: String { appBundleID + ".tunnel-config" }

    private static func info(_ key: String) -> String? {
        let value = Bundle.main.object(forInfoDictionaryKey: key) as? String
        return value?.isEmpty == false && value?.hasPrefix("$(") == false ? value : nil
    }
}

/// Messages from the app to the running extension (`sendProviderMessage`). One opcode byte.
enum ProviderMessage: UInt8 {
    /// Reply: WireGuard UAPI text with private and preshared keys removed.
    case runtimeConfiguration = 0
    /// Reply: recent log lines from the extension, newline separated.
    case recentLog = 1
    /// OpenConnect extension only. Reply: `OpenConnectStatus` as JSON (no secrets).
    case openConnectStatus = 2
    /// Tailnet extension only. Reply: `TailnetStatus` as JSON (no keys).
    case tailnetStatus = 3
    /// Tailnet extension only: ask the coordination server for a sign-in page. Reply: empty on
    /// success, else the error text. The page's URL then appears in `TailnetStatus`.
    case tailnetLogin = 4
    /// Tailnet extension only: sign out (the server expires the node key). Reply as for login.
    case tailnetLogout = 5
}

/// providerConfiguration keys. Holds no secrets: /Library/Preferences/com.apple.networkextension.plist
/// is readable by every local user. The wg-quick text (with keys) lives in the keychain.
enum ProviderConfigKey {
    static let formatVersion = "v"
    static let tunnelID = "id"
    /// The macOS user who created the tunnel. VPN configurations are shared by every account on
    /// the Mac, so each user's Wombat lists (and the extension starts) only that user's own.
    static let ownerUID = "uid"
    /// A random id, new on every add and edit (never a hash of the text: that would cover the
    /// private key in this world-readable file). The extension starts only from a copy with the
    /// same revision, so a tunnel edited while the extension wasn't running can't start from its
    /// old configuration (audit S3-M1/M2): it fails closed until the app hands the new one over.
    static let revision = "rev"
    /// Mirrors the manager's on-demand switch, which the extension can't read: a start at the
    /// login window is allowed only for an on-demand tunnel (review SEC-2, security-6 L4).
    /// Not a secret: on-demand rules sit in the same world-readable file.
    static let onDemand = "od"
}

/// Keys of the options dictionary passed to `startVPNTunnel(options:)`.
enum StartOption {
    /// Who asked for the start, for the log.
    static let source = "source"
    /// Endpoint hostname -> IP address strings, looked up by the app before the start. With the
    /// kill switch on (includeAllNetworks) the extension can't look them up itself: macOS blocks
    /// the system resolver as soon as the tunnel starts, before the tunnel can carry anything.
    static let endpoints = "endpoints"
    /// Set when the app couldn't reach the extension before the start. macOS launches the
    /// extension only to run a tunnel (its launchd job has no Mach service of its own), so after a
    /// reboot or an update the app can't hand configurations over until this start launches it.
    /// The extension then waits (at most 10 s) for a copy with the configuration's revision.
    static let awaitHandOff = "awaitHandOff"
}
