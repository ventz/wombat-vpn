import NetworkExtension
import SwiftUI
import TunnelCore

/// One set of status symbols for the menu bar and the window, so both say the same thing.
/// Shapes read the right way round (audit A-M9) and carry the state without color, for a
/// monochrome menu bar and color-blind users: a lock in a filled shield when protected, a
/// half-filled shield while changing, an exclamation mark on an error, and a struck-through
/// shield when no tunnel is up.
enum TunnelSymbol {
    static func name(_ status: NEVPNStatus?, error: Bool) -> String {
        switch status {
        case .connected: return "lock.shield.fill"
        case .connecting, .reasserting, .disconnecting: return "shield.lefthalf.filled"
        default: return error ? "exclamationmark.shield.fill" : "shield.slash"
        }
    }
}

/// Menu bar state shared by both icon styles.
private enum MenuBarState {
    case connected, changing, off, error

    init(_ status: NEVPNStatus?, error: Bool) {
        switch status {
        case .connected: self = .connected
        case .connecting, .reasserting, .disconnecting: self = .changing
        default: self = error ? .error : .off
        }
    }

    var color: NSColor {
        switch self {
        case .connected: .systemGreen
        case .changing: .systemOrange
        case .off, .error: .systemRed
        }
    }

    var spoken: String {
        switch self {
        case .connected: "connected"
        case .changing: "changing"
        case .off: "not connected"
        case .error: "error"
        }
    }
}

/// The menu bar size of both marks: about as tall as the neighbors' icons (Calendar, Slack),
/// not the 13 pt SwiftUI gives a bare `Image(systemName:)` in a MenuBarExtra (user,
/// 2026-11-10: "too small").
private enum MenuBarMetrics {
    static let symbolPointSize: CGFloat = 20
    static let markHeight: CGFloat = 22
}

/// The shield status item. Colored (the default): a white lock on a green shield when
/// connected, a white open lock on a red shield when not, an orange half shield while changing,
/// a white "!" on red for an error. The shapes still differ without color (color-blind users,
/// the monochrome option), as `TunnelSymbol` describes.
@MainActor
enum ShieldMark {
    private static var cache: [String: NSImage] = [:]

    static func image(_ status: NEVPNStatus?, error: Bool, colored: Bool) -> NSImage {
        let state = MenuBarState(status, error: error)
        let key = "\(state)-\(colored)"
        if let cached = cache[key] { return cached }
        let pt = MenuBarMetrics.symbolPointSize
        // Monochrome (a template) uses the symbols' own rendering, where the lock and "!" are
        // cut out; colored paints them white on the state's color.
        let colors: (NSColor) -> [NSColor]? = { colored ? [.white, $0] : nil }
        let image: NSImage
        switch state {
        case .connected: image = symbol("lock.shield.fill", pt, colors(state.color))
        case .changing: image = symbol("shield.lefthalf.filled", pt, colored ? [state.color] : nil)
        case .error: image = symbol("exclamationmark.shield.fill", pt, colors(state.color))
        case .off:
            // No "lock.open.shield" symbol exists: an open lock drawn on a filled shield.
            let shield = symbol("shield.fill", pt, colored ? [state.color] : nil)
            let lock = symbol("lock.open.fill", pt * 0.5, colored ? [.white] : nil, weight: .bold)
            let size = shield.size
            image = NSImage(size: size, flipped: false) { _ in
                shield.draw(in: NSRect(origin: .zero, size: size))
                let l = lock.size
                let rect = NSRect(x: (size.width - l.width) / 2 + 1, y: (size.height - l.height) / 2 - 0.5,
                                  width: l.width, height: l.height)
                lock.draw(in: rect, from: .zero, operation: colored ? .sourceOver : .destinationOut, fraction: 1)
                return true
            }
        }
        let result = NSImage(size: image.size, flipped: false) { rect in
            image.draw(in: rect)
            return true
        }
        result.isTemplate = !colored
        result.accessibilityDescription = "Wombat, \(state.spoken)"
        cache[key] = result
        return result
    }

    private static func symbol(_ name: String, _ pointSize: CGFloat, _ colors: [NSColor]?,
                               weight: NSFont.Weight = .medium) -> NSImage {
        var config = NSImage.SymbolConfiguration(pointSize: pointSize, weight: weight)
        if let colors { config = config.applying(.init(paletteColors: colors)) }
        return NSImage(systemSymbolName: name, accessibilityDescription: nil)?
            .withSymbolConfiguration(config) ?? NSImage()
    }
}

/// The app's ribbon "W" in the menu bar (Resources/MenuBarW, from scripts/make-menubar-icon.py),
/// tinted by state when colored; as a template, solid when connected and dimmed otherwise (the
/// usual macOS convention for an inactive status item). Every state but connected also has a
/// badge shape (accessibility-3 M5): "…" changing, "−" off, "!" error. The image carries its
/// state as its accessibility description (M6).
@MainActor
enum WombatMark {
    private static var cache: [String: NSImage] = [:]

    static func image(_ status: NEVPNStatus?, error: Bool, colored: Bool) -> NSImage {
        let state = MenuBarState(status, error: error)
        let key = "\(state)-\(colored)"
        if let cached = cache[key] { return cached }
        let alpha: CGFloat = switch state {
        case .connected: 1
        case .changing: colored ? 1 : 0.65
        case .off, .error: colored ? 1 : 0.4
        }
        let badge: String? = switch state {
        case .connected: nil
        case .changing: "ellipsis.circle.fill"
        case .off: "minus.circle.fill"
        case .error: "exclamationmark.circle.fill"
        }
        guard let mark = NSImage(named: "MenuBarW") else { return NSImage() }
        let h = MenuBarMetrics.markHeight
        let markSize = NSSize(width: mark.size.width * h / mark.size.height, height: h)
        let badgeSide: CGFloat = 10
        let size = NSSize(width: markSize.width + (badge != nil ? 5 : 0), height: h)
        let tint = state.color
        let image = NSImage(size: size, flipped: false) { _ in
            let markRect = NSRect(origin: .zero, size: markSize)
            mark.draw(in: markRect, from: .zero, operation: .sourceOver, fraction: alpha)
            if colored {
                // Keeps the ribbon's shading (its alpha) and swaps its color for the state's.
                tint.set()
                markRect.fill(using: .sourceAtop)
            }
            let badgeConfig = NSImage.SymbolConfiguration(pointSize: badgeSide, weight: .bold)
            if let badge, let symbol = NSImage(systemSymbolName: badge, accessibilityDescription: nil)?
                .withSymbolConfiguration(colored ? badgeConfig.applying(.init(paletteColors: [.white, tint])) : badgeConfig) {
                let rect = NSRect(x: size.width - badgeSide, y: 0, width: badgeSide, height: badgeSide)
                // A clear ring separates the badge from the W behind it.
                NSGraphicsContext.current?.compositingOperation = .clear
                NSBezierPath(ovalIn: rect.insetBy(dx: -1, dy: -1)).fill()
                NSGraphicsContext.current?.compositingOperation = .sourceOver
                symbol.draw(in: rect)
            }
            return true
        }
        image.isTemplate = !colored
        image.accessibilityDescription = "Wombat, \(state.spoken)"
        cache[key] = image
        return image
    }
}

/// The status item, with the same symbols as the window (`TunnelSymbol`).
struct MenuBarLabel: View {
    @ObservedObject var store: TunnelStore
    @AppStorage(Preferences.Key.menuBarShowsName) private var showsName = false
    @AppStorage(Preferences.Key.menuBarIcon) private var icon = "shield"
    @AppStorage(Preferences.Key.menuBarColored) private var colored = true
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        let active = store.activeTunnel
        let failed = active == nil ? store.tunnels.first { $0.lastError != nil } : nil
        // TunnelStore announces connection changes centrally (no second announcement here).
        HStack(spacing: 4) {
            if icon == "w" {
                Image(nsImage: WombatMark.image(active?.status, error: failed != nil, colored: colored))
            } else {
                Image(nsImage: ShieldMark.image(active?.status, error: failed != nil, colored: colored))
            }
            if showsName, let active { Text(active.name) }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Wombat")
        .accessibilityValue(active.map { "\($0.name) \($0.statusText)" } ?? failed.map { "\($0.name): error" } ?? "Not connected")
        // The label exists for the app's lifetime, so AppKit code can open the window through it.
        .onAppear { MainWindow.open = { openWindow(id: "main") } }
    }
}

struct MenuBarContent: View {
    @EnvironmentObject private var model: AppModel
    @EnvironmentObject private var store: TunnelStore
    @Environment(\.openWindow) private var openWindow
    @Environment(\.openSettings) private var openSettings
    @ObservedObject private var signIn = SignInCoordinator.shared

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            if store.tunnels.isEmpty {
                Text("No tunnels")
                    .foregroundStyle(.secondary)
                    .padding(14)
            } else {
                ForEach(store.tunnels) { tunnel in
                    MenuTunnelRow(tunnel: tunnel)
                }
                .padding(.vertical, 4)
            }
            Divider()
            VStack(alignment: .leading, spacing: 0) {
                // A sign-in waiting in the main window must be reachable from here (A6-M2).
                if signIn.activeTunnelID != nil {
                    MenuButton(title: "Show Sign-In…", shortcut: "") {
                        openWindow(id: "main")
                        signIn.showPanel()
                    }
                }
                MenuButton(title: "Open Wombat", shortcut: "O") {
                    openWindow(id: "main")
                    NSApp.activate()
                }
                MenuButton(title: "Settings…", shortcut: ",") {
                    openSettings()
                    NSApp.activate()
                }
                MenuButton(title: "Quit Wombat", shortcut: "Q") { NSApp.terminate(nil) }
            }
            .padding(.vertical, 4)
        }
        .frame(width: 300)
        .onAppear { store.watchStats(true) }
        .onDisappear { store.watchStats(false) }
    }
}

private struct MenuTunnelRow: View {
    @ObservedObject var tunnel: Tunnel
    @EnvironmentObject private var store: TunnelStore
    @ObservedObject private var signIn = SignInCoordinator.shared
    @Environment(\.openWindow) private var openWindow

    /// A sign-in for this VPN waits on the user: said in red under its name, and a click brings
    /// it back (user, 2026-11-10: connecting from the menu bar left it out of sight).
    private var waitingForSignIn: Bool { signIn.activeTunnelID == tunnel.id }

    var body: some View {
        HStack(spacing: 10) {
            if waitingForSignIn {
                Image(systemName: "person.badge.key.fill")
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(.red)
                    .frame(width: 14)
                    .accessibilityHidden(true)
            } else {
                StatusDot(status: tunnel.status)
            }
            VStack(alignment: .leading, spacing: 1) {
                Text(tunnel.name).fontWeight(.medium).lineLimit(1)
                if waitingForSignIn {
                    Button(action: showSignIn) {
                        Text(signInText).font(.caption.weight(.semibold)).foregroundStyle(.red).lineLimit(1)
                    }
                    .buttonStyle(.plain)
                    .help("Show the sign-in")
                } else {
                    Text(detail).font(.caption).foregroundStyle(.secondary).monospacedDigit().lineLimit(1)
                }
            }
            Spacer()
            // The visible name is the toggle's label; status stays visible text.
            Toggle(tunnel.name, isOn: Binding(get: { tunnel.isActive }, set: { _ in Task { await store.toggle(tunnel) } }))
                .toggleStyle(.switch)
                .controlSize(.small)
                .labelsHidden()
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 6)
        // One element per tunnel: its name, its state in words, and a toggle action (A-L3).
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(tunnel.name)
        .accessibilityValue(spokenDetail)
        .accessibilityAddTraits(.isToggle)
        .accessibilityAction { Task { await store.toggle(tunnel) } }
        .accessibilityAction(named: "Show Sign-In") { if waitingForSignIn { showSignIn() } }
    }

    private var signInText: String {
        if case .browser = signIn.step { return "Sign in in your browser · Show" }
        return "Waiting for you to sign in · Show"
    }

    private func showSignIn() {
        openWindow(id: "main")
        signIn.showPanel()
    }

    private var spokenDetail: String {
        if waitingForSignIn { return "Waiting for you to sign in" }
        guard tunnel.status == .connected, let stats = tunnel.stats else { return tunnel.statusText }
        if let oc = stats.openConnect {
            return "Connected, received \(Format.bytes(stats.rxBytes)), sent \(Format.bytes(stats.txBytes)), over \(oc.transport ?? "TLS")"
        }
        return "Connected, received \(Format.bytes(stats.rxBytes)), sent \(Format.bytes(stats.txBytes)), last handshake \(Format.handshakeAge(stats.latestHandshake))"
    }

    private var detail: String {
        guard tunnel.status == .connected else { return tunnel.statusText }
        guard let stats = tunnel.stats else { return "Connected" }
        // AnyConnect has no handshakes: the transport instead (Q5-M5).
        let tail = stats.openConnect.map { $0.transport ?? "TLS" } ?? Format.handshakeAge(stats.latestHandshake)
        return "↓ \(Format.bytes(stats.rxBytes))  ↑ \(Format.bytes(stats.txBytes))  · \(tail)"
    }
}

/// A full-width, hover-highlighted row like a native menu item.
private struct MenuButton: View {
    let title: String
    let shortcut: String
    let action: () -> Void
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            HStack {
                Text(title)
                Spacer()
                if !shortcut.isEmpty {
                    Text("⌘\(shortcut)")
                        .foregroundStyle(hovering ? Color(nsColor: .alternateSelectedControlTextColor).opacity(0.8) : .secondary)
                        .accessibilityHidden(true)  // the shortcut is announced from keyboardShortcut
                }
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 4)
            // The system's selection pair keeps contrast with any accent color (A-M3).
            .foregroundStyle(hovering ? Color(nsColor: .alternateSelectedControlTextColor) : .primary)
            .background(hovering ? Color(nsColor: .selectedContentBackgroundColor) : .clear, in: RoundedRectangle(cornerRadius: 5))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .padding(.horizontal, 5)
        .onHover { hovering = $0 }
        // Character("") would trap: an item without a shortcut gets none.
        .keyboardShortcut(shortcut.isEmpty ? nil : KeyboardShortcut(KeyEquivalent(Character(shortcut.lowercased())), modifiers: .command))
    }
}
