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

/// The app's ribbon "W" as a menu bar template (Resources/MenuBarW, from
/// scripts/make-menubar-icon.py): solid when connected, dimmed otherwise (the usual macOS
/// convention for an inactive status item). Dimming alone is too faint a cue, so every state
/// but connected also has a badge shape (accessibility-3 M5): "…" changing, "−" off, "!" error.
/// The image carries its state as its accessibility description (M6).
@MainActor
enum WombatMark {
    private static var cache: [String: NSImage] = [:]

    static func image(_ status: NEVPNStatus?, error: Bool) -> NSImage {
        let alpha: CGFloat
        switch status {
        case .connected: alpha = 1
        case .connecting, .reasserting, .disconnecting: alpha = 0.65
        default: alpha = 0.4
        }
        let badge: String? = switch status {
        case .connected: nil
        case .connecting, .reasserting, .disconnecting: "ellipsis.circle.fill"
        default: error ? "exclamationmark.circle.fill" : "minus.circle.fill"
        }
        let state = switch status {
        case .connected: "connected"
        case .connecting, .reasserting, .disconnecting: "changing"
        default: error ? "error" : "not connected"
        }
        let key = "\(alpha)-\(badge ?? "")"
        if let cached = cache[key] { return cached }
        guard let mark = NSImage(named: "MenuBarW") else { return NSImage() }
        let size = NSSize(width: mark.size.width + (badge != nil ? 5 : 0), height: max(mark.size.height, 16))
        let image = NSImage(size: size, flipped: false) { _ in
            mark.draw(in: NSRect(x: 0, y: (size.height - mark.size.height) / 2, width: mark.size.width, height: mark.size.height),
                      from: .zero, operation: .sourceOver, fraction: alpha)
            if let badge, let bang = NSImage(systemSymbolName: badge, accessibilityDescription: nil)?
                .withSymbolConfiguration(.init(pointSize: 9, weight: .bold)) {
                bang.draw(in: NSRect(x: size.width - 9, y: 0, width: 9, height: 9))
            }
            return true
        }
        image.isTemplate = true
        image.accessibilityDescription = "Wombat, \(state)"
        cache[key] = image
        return image
    }
}

/// The status item, with the same symbols as the window (`TunnelSymbol`).
struct MenuBarLabel: View {
    @ObservedObject var store: TunnelStore
    @AppStorage(Preferences.Key.menuBarShowsName) private var showsName = false
    @AppStorage(Preferences.Key.menuBarIcon) private var icon = "shield"
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        let active = store.activeTunnel
        let failed = active == nil ? store.tunnels.first { $0.lastError != nil } : nil
        // TunnelStore announces connection changes centrally (no second announcement here).
        HStack(spacing: 4) {
            if icon == "w" {
                Image(nsImage: WombatMark.image(active?.status, error: failed != nil))
            } else {
                Image(systemName: TunnelSymbol.name(active?.status, error: failed != nil))
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

    var body: some View {
        HStack(spacing: 10) {
            StatusDot(status: tunnel.status)
            VStack(alignment: .leading, spacing: 1) {
                Text(tunnel.name).fontWeight(.medium).lineLimit(1)
                Text(detail).font(.caption).foregroundStyle(.secondary).monospacedDigit().lineLimit(1)
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
    }

    private var spokenDetail: String {
        guard tunnel.status == .connected, let stats = tunnel.stats else { return tunnel.statusText }
        return "Connected, received \(Format.bytes(stats.rxBytes)), sent \(Format.bytes(stats.txBytes)), last handshake \(Format.handshakeAge(stats.latestHandshake))"
    }

    private var detail: String {
        guard tunnel.status == .connected else { return tunnel.statusText }
        guard let stats = tunnel.stats else { return "Connected" }
        return "↓ \(Format.bytes(stats.rxBytes))  ↑ \(Format.bytes(stats.txBytes))  · \(Format.handshakeAge(stats.latestHandshake))"
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
                Text("⌘\(shortcut)")
                    .foregroundStyle(hovering ? Color(nsColor: .alternateSelectedControlTextColor).opacity(0.8) : .secondary)
                    .accessibilityHidden(true)  // the shortcut is announced from keyboardShortcut
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
        .keyboardShortcut(KeyEquivalent(Character(shortcut.lowercased())), modifiers: .command)
    }
}
