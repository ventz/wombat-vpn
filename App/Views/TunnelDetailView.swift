import NetworkExtension
import SwiftUI
import TunnelCore

/// Overview: live status. Connection: when it connects and how it protects (macOS-side settings,
/// not part of the .conf). Config File: the wg-quick text. Log: recent engine output.
/// Whole-tunnel actions (rename, export, delete) are in the header's ⋯ menu, not in a tab.
enum DetailTab: String, CaseIterable, Identifiable {
    case overview = "Overview", connection = "Connection", configFile = "Config File", log = "Log"
    var id: String { rawValue }
}

struct TunnelDetailView: View {
    @ObservedObject var tunnel: Tunnel
    @EnvironmentObject private var store: TunnelStore
    @EnvironmentObject private var model: AppModel

    var body: some View {
        VStack(spacing: 0) {
            DetailHeader(tunnel: tunnel)
            Divider()
            switch model.detailTab {
            case .overview: OverviewTab(tunnel: tunnel)
            case .connection: ConnectionTab(tunnel: tunnel)
            case .configFile: ConfigFileTab(tunnel: tunnel)
            case .log: LogTab(tunnel: tunnel)
            }
        }
        .navigationTitle(tunnel.name)
        // The tab picker is in ContentView's toolbar, so the gear can sit after it.
    }
}

struct DetailHeader: View {
    @ObservedObject var tunnel: Tunnel
    @EnvironmentObject private var store: TunnelStore

    var body: some View {
        HStack(spacing: 14) {
            ZStack {
                Circle().fill(tint.opacity(0.15)).frame(width: 44, height: 44)
                Image(systemName: TunnelSymbol.name(tunnel.status, error: tunnel.lastError != nil))
                    .accessibilityHidden(true)  // the status text says it (accessibility-3 L2)
                    .font(.title2)
                    .foregroundStyle(tint)
            }
            VStack(alignment: .leading, spacing: 2) {
                Text(tunnel.name).font(.title2.weight(.semibold))
                HStack(spacing: 6) {
                    Text(tunnel.statusText)
                    if let since = tunnel.connectedSince {
                        Text("·")
                        Text(since, style: .timer).monospacedDigit()
                    }
                    if tunnel.isOnDemand {
                        Text("·")
                        Label("On demand", systemImage: "bolt.horizontal.circle").labelStyle(.titleAndIcon)
                    }
                    if tunnel.configuration?.isAmnezia == true {
                        Text("·")
                        Label("AmneziaWG", systemImage: "theatermasks")
                            .labelStyle(.titleAndIcon)
                            .help("Speaks AmneziaWG, which disguises WireGuard traffic. It needs an AmneziaWG server.")
                    }
                }
                .font(.callout)
                .foregroundStyle(.secondary)
                if let error = tunnel.lastError {
                    Label {
                        Text(error).foregroundStyle(.primary).textSelection(.enabled)
                    } icon: {
                        Image(systemName: "exclamationmark.octagon.fill").foregroundStyle(.red)
                    }
                    .font(.callout)
                    .accessibilityLabel("Error: \(error)")
                    if tunnel.errorNeedsExtension {
                        Button("Fix It…") {
                            NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.LoginItems-Settings.extension")!)
                        }
                        .help("Opens Login Items & Extensions. Under Extensions › Network Extensions (ⓘ), turn Wombat on.")
                        .accessibilityLabel("Fix it: open System Settings to turn on the network extension")
                        .accessibilityInputLabels(["Fix It", "Turn On Extension"])
                    }
                }
                if store.pendingHandOff.contains(tunnel.id) {
                    // An edit the extension hasn't received: it refuses to start the old copy (S3-M2).
                    Label("Changes reach the network extension the next time it runs. Connect from Wombat to apply them.", systemImage: "clock.arrow.circlepath")
                        .font(.callout)
                }
            }
            Spacer()
            TunnelActionsMenu(tunnel: tunnel)
            Toggle("", isOn: Binding(get: { tunnel.isActive }, set: { _ in Task { await store.toggle(tunnel) } }))
                .toggleStyle(.switch)
                .controlSize(.large)
                .labelsHidden()
                // Not "Connection": that is a tab name now, and Voice Control needs unique names.
                .accessibilityLabel("Tunnel switch")  // stable label; the switch speaks on/off
                .help(tunnel.isActive ? "Disconnect (⌘↩)" : "Connect (⌘↩)")
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 14)
    }

    private var tint: Color {
        switch tunnel.status {
        case .connected: return .green
        case .connecting, .reasserting, .disconnecting: return .orange
        default: return tunnel.lastError != nil ? .red : .secondary
        }
    }
}

/// Actions on the whole tunnel: the header's Actions button and the sidebar's right-click menu
/// show the same items (user, 2026-10-14). Delete is always behind a confirmation whose default
/// button is Cancel.
struct TunnelActionsMenu: View {
    @ObservedObject var tunnel: Tunnel

    var body: some View {
        Menu {
            TunnelActionItems(tunnel: tunnel)
        } label: {
            // Words next to the "⋯": the icon alone wasn't noticed as the place for rename/delete.
            Label("Actions", systemImage: "ellipsis.circle")
                .labelStyle(.titleAndIcon)
        }
        .menuStyle(.button)
        .buttonStyle(.bordered)
        .fixedSize()
        .help("Rename, duplicate, export or delete this tunnel")
        .accessibilityLabel("Tunnel actions")
        .accessibilityInputLabels(["Actions", "Tunnel Actions"])
    }
}

/// The items themselves. Each selects its tunnel first: the model acts on the selection, and a
/// right-click can land on a row that isn't selected.
struct TunnelActionItems: View {
    let tunnel: Tunnel
    @EnvironmentObject private var store: TunnelStore
    @EnvironmentObject private var model: AppModel

    var body: some View {
        Button("Rename…") { select(); model.renameSelected() }
        Button("Duplicate") { select(); model.run { model.selection = try await store.duplicate($0).id } }
        Divider()
        Button("Export .conf File…") { select(); model.run { try await Exporter.exportOne($0) } }
        Button("Show QR Code…") { select(); model.showingQR = true }
        Divider()
        Button("Delete Tunnel…", role: .destructive) { select(); model.deleteSelected() }
    }

    private func select() { model.selection = tunnel.id }
}

// MARK: Overview

struct OverviewTab: View {
    @ObservedObject var tunnel: Tunnel
    @EnvironmentObject private var store: TunnelStore

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                if let config = tunnel.configuration {
                    if tunnel.status == .connected { TrafficCard(stats: tunnel.stats) }
                    InterfaceCard(config: config, stats: tunnel.stats)
                    ForEach(Array(config.peers.prefix(50).enumerated()), id: \.offset) { _, peer in
                        PeerCard(peer: peer, stats: tunnel.stats?.peers.first { $0.publicKey == peer.publicKey.base64 })
                    }
                    if config.peers.count > 50 {
                        Text("…and \(config.peers.count - 50) more peers").foregroundStyle(.secondary)
                    }
                    FindingsCard(findings: tunnel.findings)
                } else {
                    ContentUnavailableView("Configuration unavailable", systemImage: "key.slash",
                                           description: Text("The keychain item for this tunnel is missing. Delete the tunnel and import it again."))
                }
            }
            .padding(20)
        }
        .onAppear { store.watchStats(true) }
        .onDisappear { store.watchStats(false) }
    }
}

struct Card<Content: View>: View {
    let title: String
    let systemImage: String
    @ViewBuilder var content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label(title, systemImage: systemImage)
                .font(.headline)
                .accessibilityAddTraits(.isHeader)
            content
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.background.secondary, in: RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(.separator.opacity(0.5)))
    }
}

struct InfoRow: View {
    let label: String
    let value: String
    var monospaced = false
    var copyable = false

    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            Text(label)
                .foregroundStyle(.secondary)
                .frame(width: 140, alignment: .leading)
            Text(value)
                .font(monospaced ? .body.monospaced() : .body)
                .textSelection(.enabled)
                .lineLimit(3)
            if copyable {
                Button {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(value, forType: .string)
                    NSAccessibility.post(element: NSApp as Any, notification: .announcementRequested,
                                         userInfo: [.announcement: "\(label) copied"])
                } label: { Image(systemName: "doc.on.doc") }
                .buttonStyle(.borderless)
                .help("Copy \(label)")
                .accessibilityLabel("Copy \(label)")
            }
            Spacer(minLength: 0)
        }
        .accessibilityElement(children: copyable ? .contain : .combine)
    }
}

struct TrafficCard: View {
    let stats: RuntimeStats?

    var body: some View {
        HStack(spacing: 12) {
            metric("Received", Format.bytes(stats?.rxBytes ?? 0), "arrow.down.circle.fill", .blue)
            metric("Sent", Format.bytes(stats?.txBytes ?? 0), "arrow.up.circle.fill", .purple)
            metric("Latest handshake",
                   Format.handshakeAge(stats?.latestHandshake) + (Format.isHandshakeStale(stats?.latestHandshake) ? " (no current session)" : ""),
                   Format.isHandshakeStale(stats?.latestHandshake) ? "exclamationmark.triangle.fill" : "hand.wave.fill",
                   Format.isHandshakeStale(stats?.latestHandshake) ? .orange : .green)
        }
    }

    private func metric(_ title: String, _ value: String, _ icon: String, _ color: Color) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Label { Text(title).foregroundStyle(.secondary) } icon: { Image(systemName: icon).foregroundStyle(color) }
                .font(.caption)
            Text(value).font(.title3.weight(.semibold)).monospacedDigit().contentTransition(.numericText())
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.background.secondary, in: RoundedRectangle(cornerRadius: 12))
        .accessibilityElement(children: .combine)
    }
}

struct InterfaceCard: View {
    let config: TunnelConfiguration
    let stats: RuntimeStats?

    var body: some View {
        Card(title: "Interface", systemImage: "network") {
            InfoRow(label: "Public key", value: config.interface.publicKey.base64, monospaced: true, copyable: true)
            if !config.interface.addresses.isEmpty {
                InfoRow(label: "Addresses", value: config.interface.addresses.map(\.description).joined(separator: ", "), monospaced: true)
            }
            if !(config.interface.dnsServers + config.interface.dnsSearchDomains).isEmpty {
                InfoRow(label: "DNS", value: (config.interface.dnsServers + config.interface.dnsSearchDomains).joined(separator: ", "), monospaced: true)
            }
            if let port = stats?.listenPort ?? config.interface.listenPort {
                InfoRow(label: "Listen port", value: "\(port)", monospaced: true)
            }
            if let mtu = config.interface.mtu {
                InfoRow(label: "MTU", value: "\(mtu)", monospaced: true)
            }
            if config.isAmnezia, let amnezia = config.interface.amnezia {
                InfoRow(label: "Protocol", value: "AmneziaWG (\(AmneziaSummary.text(amnezia)))")
            } else {
                InfoRow(label: "Protocol", value: "WireGuard")
            }
        }
    }
}

struct PeerCard: View {
    let peer: PeerConfiguration
    let stats: PeerStats?

    var body: some View {
        Card(title: "Peer \(peer.publicKey.abbreviated)", systemImage: "point.3.connected.trianglepath.dotted") {
            InfoRow(label: "Public key", value: peer.publicKey.base64, monospaced: true, copyable: true)
            if let endpoint = stats?.endpoint ?? peer.endpoint?.description {
                InfoRow(label: "Endpoint", value: endpoint, monospaced: true, copyable: true)
            }
            InfoRow(label: "Allowed IPs", value: peer.allowedIPs.map(\.description).joined(separator: ", "), monospaced: true)
            InfoRow(label: "Preshared key", value: peer.presharedKey == nil ? "None" : "Set")
            if let keepalive = peer.persistentKeepalive {
                InfoRow(label: "Keepalive", value: "Every \(keepalive) s")
            }
            if let stats {
                InfoRow(label: "Latest handshake", value: Format.handshakeAge(stats.lastHandshake))
                InfoRow(label: "Transfer", value: "\(Format.bytes(stats.rxBytes)) received, \(Format.bytes(stats.txBytes)) sent")
            }
        }
    }
}

struct FindingsCard: View {
    let findings: [Finding]

    var body: some View {
        if !findings.isEmpty {
            Card(title: "Review", systemImage: "checklist") {
                ForEach(Array(findings.enumerated()), id: \.offset) { _, f in
                    Label {
                        Text(f.message).textSelection(.enabled)
                    } icon: {
                        Image(systemName: icon(f.level)).foregroundStyle(color(f.level))
                    }
                    .accessibilityLabel("\(f.level == .risk ? "Risk" : f.level == .warning ? "Warning" : "Note"): \(f.message)")
                }
            }
        }
    }

    private func icon(_ level: Finding.Level) -> String {
        switch level {
        case .risk: return "exclamationmark.octagon.fill"
        case .warning: return "exclamationmark.triangle.fill"
        case .info: return "info.circle"
        }
    }

    private func color(_ level: Finding.Level) -> Color {
        switch level {
        case .risk: return .red
        case .warning: return .orange
        case .info: return .secondary
        }
    }
}
