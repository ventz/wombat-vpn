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
    @EnvironmentObject private var model: AppModel
    @ObservedObject private var signIn = SignInCoordinator.shared
    /// The status stays "Disconnected" until the sign-in ends: show that it is under way (A5-M2).
    private var signingIn: Bool { signIn.activeTunnelID == tunnel.id }

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
                    Text(signingIn ? "Signing in…" : tunnel.statusText)
                    if let since = tunnel.connectedSince {
                        Text("·")
                        Text(since, style: .timer).monospacedDigit()
                    }
                    if tunnel.isOnDemand {
                        Text("·")
                        Label("On demand", systemImage: "bolt.horizontal.circle").labelStyle(.titleAndIcon)
                    }
                    if tunnel.isOnDemandPaused {
                        Text("·")
                        // Orange icon only: orange text is below 4.5:1 in light mode.
                        Label {
                            Text("On demand paused").foregroundStyle(.primary)  // not the row's gray (A6-L6)
                        } icon: {
                            Image(systemName: "bolt.horizontal.circle.fill").foregroundStyle(.orange)
                        }
                            .labelStyle(.titleAndIcon)
                            .accessibilityHint("Another VPN configuration on this Mac is the enabled one. Connect this tunnel to take its on-demand rules back.")
                            .help("Another VPN configuration on this Mac is now the enabled one, so macOS isn't running this tunnel's on-demand rules. Connect this tunnel to take them back.")
                    }
                    if tunnel.isOpenConnect {
                        Text("·")
                        Label("AnyConnect", systemImage: "building.columns")
                            .labelStyle(.titleAndIcon)
                            .help("A Cisco AnyConnect VPN, run by OpenConnect in its own system extension.")
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
                if signingIn && model.detailTab != .overview {
                    Button("Show Sign-In") { signIn.showPanel() }
                        .help("The sign-in is on the Overview tab")
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
                .accessibilityValue(signingIn ? "Signing in" : (tunnel.isActive ? "On" : "Off"))
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
        .help(tunnel.isOpenConnect ? "Edit, rename, duplicate, export, forget sign-in data or delete this VPN" : "Rename, duplicate, export or delete this tunnel")
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
        if tunnel.isOpenConnect {
            Button("Edit VPN…") { select(); model.anyConnectEditor = AnyConnectEditorTarget(tunnelID: tunnel.id) }
        }
        Button("Rename…") { select(); model.renameSelected() }
        Button("Duplicate") { select(); model.run { model.selection = try await store.duplicate($0).id } }
        Divider()
        if tunnel.isOpenConnect {
            Button("Export Profile…") { select(); model.run { try await Exporter.exportOne($0) } }
            // The identity provider's "remember me" cookies for this VPN's single sign-on.
            Button("Forget Sign-In Data") {
                select()
                Task {
                    guard await SSODataStore.remove(tunnel.id) else {
                        model.actionError = "Wombat couldn't remove the sign-in data for \(tunnel.name). Close its sign-in, then try again."
                        return
                    }
                    NSAccessibility.post(element: NSApp as Any, notification: .announcementRequested, userInfo: [
                        .announcement: "Sign-in data for \(tunnel.name) removed. Your identity provider will ask you to sign in again.",
                        .priority: NSAccessibilityPriorityLevel.medium.rawValue,
                    ])
                }
            }
        } else {
            Button("Export .conf File…") { select(); model.run { try await Exporter.exportOne($0) } }
            Button("Show QR Code…") { select(); model.showingQR = true }
        }
        Divider()
        Button("Delete Tunnel…", role: .destructive) { select(); model.deleteSelected() }
    }

    private func select() { model.selection = tunnel.id }
}

// MARK: Overview

struct OverviewTab: View {
    @ObservedObject var tunnel: Tunnel
    @EnvironmentObject private var store: TunnelStore
    @ObservedObject private var signIn = SignInCoordinator.shared

    var body: some View {
        if signIn.activeTunnelID == tunnel.id && signIn.showsPage {
            // The identity provider's page gets the whole column, outside the scroll view, so
            // tabbing through it keeps the focused field on screen (accessibility-6 H1).
            SignInView().environmentObject(signIn).padding(20)
        } else {
            overview
        }
    }

    private var overview: some View {
        ScrollViewReader { scroller in
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                if tunnel.isOpenConnect {
                    if let profile = tunnel.profile {
                        if tunnel.status == .connected { TrafficCard(stats: tunnel.stats) }
                        AnyConnectCards(profile: profile, certificateName: tunnel.clientCertificateName,
                                        status: tunnel.status == .connected ? tunnel.stats?.openConnect : nil)
                        // The sign-in, under the gateway it signs in to (user, 2026-10-16: not a
                        // pop-up window, on the main screen).
                        if signIn.activeTunnelID == tunnel.id {
                            SignInView().environmentObject(signIn).id("signin")
                        }
                    } else {
                        ContentUnavailableView("Profile unavailable", systemImage: "key.slash",
                                               description: Text("The keychain item for this VPN is missing. Delete it and add it again."))
                    }
                } else if let config = tunnel.configuration {
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
        // Every step, not only the start, so a new prompt is never below the fold (A6-H1).
        .onChange(of: signIn.activeTunnelID == tunnel.id ? signIn.stepKey : "", initial: true) { _, key in
            if !key.isEmpty { withAnimation { scroller.scrollTo("signin", anchor: .top) } }
        }
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
            if let oc = stats?.openConnect {
                metric("Transport", oc.transport ?? "TLS", oc.transport == "DTLS" ? "bolt.horizontal.circle.fill" : "lock.circle.fill", .green)
            } else {
            metric("Latest handshake",
                   Format.handshakeAge(stats?.latestHandshake) + (Format.isHandshakeStale(stats?.latestHandshake) ? " (no current session)" : ""),
                   Format.isHandshakeStale(stats?.latestHandshake) ? "exclamationmark.triangle.fill" : "hand.wave.fill",
                   Format.isHandshakeStale(stats?.latestHandshake) ? .orange : .green)
            }
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

/// An AnyConnect VPN's Overview: where it goes and how you sign in, then (while connected) what
/// the gateway assigned.
struct AnyConnectCards: View {
    let profile: OpenConnectProfile
    let certificateName: String?
    let status: OpenConnectStatus?

    var body: some View {
        Card(title: "Gateway", systemImage: "building.columns") {
            InfoRow(label: "Server", value: profile.server.absoluteString, monospaced: true, copyable: true)
            if let group = profile.group { InfoRow(label: "Group", value: group) }
            if let username = profile.username { InfoRow(label: "Username", value: username) }
            InfoRow(label: "Sign-in", value: profile.clientCertificate == nil
                    ? "At each connect (password, Duo or single sign-on)"
                    : "Client certificate \(certificateName.flatMap { $0.isEmpty ? nil : $0 } ?? "(missing from the keychain)"), plus whatever the gateway asks")
            InfoRow(label: "Server certificate", value: profile.serverCertificate.map { "Pinned, SHA-256 \($0.prefix(16))…" } ?? "Trusted by macOS")
            InfoRow(label: "Protocol", value: "Cisco AnyConnect (OpenConnect\(profile.dtls ? ", DTLS allowed" : ", TLS only"))")
        }
        if let status {
            Card(title: "Connection", systemImage: "network") {
                if let v4 = status.ipv4 { InfoRow(label: "IPv4 address", value: v4, monospaced: true, copyable: true) }
                if let v6 = status.ipv6 { InfoRow(label: "IPv6 address", value: v6, monospaced: true, copyable: true) }
                InfoRow(label: "Routes", value: status.fullTunnel ? "All traffic" : status.routes.prefix(12).joined(separator: ", ") + (status.routes.count > 12 ? " (+\(status.routes.count - 12) more)" : ""), monospaced: !status.fullTunnel)
                if !status.dnsServers.isEmpty { InfoRow(label: "DNS", value: status.dnsServers.joined(separator: ", "), monospaced: true) }
                if let gateway = status.gateway { InfoRow(label: "Gateway address", value: gateway, monospaced: true) }
                if let cipher = status.cipher { InfoRow(label: "Encryption", value: "\(status.transport ?? "TLS"): \(cipher)", monospaced: true) }
            }
        }
    }
}
