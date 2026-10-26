import AppKit
import SwiftUI
import TunnelCore

/// A tailnet's Overview: the coordination server, the sign-in, this Mac on the tailnet and its
/// peers. Spike UI: status comes from the Tailnet extension's status message (no keys).
struct TailnetCards: View {
    @ObservedObject var tunnel: Tunnel
    let profile: TailnetProfile
    @EnvironmentObject private var store: TunnelStore
    @EnvironmentObject private var model: AppModel
    /// The sign-in page opens only from a click on Sign In (spike design 2.5): the extension
    /// hands its URL to that click alone, never to the status (security-9-fable NV2).
    @State private var openedSignIn = false
    @State private var busy = false

    private var status: TailnetStatus? { tunnel.status == .connected ? tunnel.tailnetStatus : nil }

    var body: some View {
        Card(title: "Tailnet", systemImage: "point.3.connected.trianglepath.dotted") {
            InfoRow(label: "Coordination server", value: profile.controlURL, monospaced: true, copyable: true)
            InfoRow(label: "State", value: Self.stateText(status?.state, connected: tunnel.status == .connected))
            if let tailnet = status?.tailnet, !tailnet.isEmpty { InfoRow(label: "Tailnet", value: tailnet) }
            if let me = status?.`self` {
                InfoRow(label: "This Mac", value: me.dnsName ?? me.name, monospaced: true, copyable: true)
                InfoRow(label: "Addresses", value: me.addresses.joined(separator: ", "), monospaced: true, copyable: true)
            }
            if let suffix = status?.magicDNSSuffix, !suffix.isEmpty, profile.acceptDNS { InfoRow(label: "MagicDNS", value: suffix, monospaced: true) }
            if let health = status?.health, !health.isEmpty {
                // These come from the tailnet engine and the coordination server, not from Wombat:
                // a server's text must not pass for Wombat's own warning (security-9-astra S9-4).
                Text("Reported by the tailnet").font(.caption).foregroundStyle(.secondary)
                ForEach(health, id: \.self) { warning in
                    Label(warning, systemImage: "info.circle").foregroundStyle(.secondary)
                }
            }
            signIn
        }
        if let status, !status.peers.isEmpty {
            Card(title: "Peers", systemImage: "desktopcomputer") {
                ForEach(Array(status.peers.prefix(100).enumerated()), id: \.offset) { _, peer in
                    HStack(alignment: .firstTextBaseline) {
                        Image(systemName: "circle.fill").font(.caption2)
                            .foregroundStyle(peer.online ? .green : .secondary)
                            .accessibilityLabel(peer.online ? "Online" : "Offline")
                        Text(peer.dnsName?.split(separator: ".").first.map(String.init) ?? peer.name)
                            .frame(width: 160, alignment: .leading)
                        Text(peer.addresses.first ?? "").font(.body.monospaced()).textSelection(.enabled)
                        Spacer()
                        if peer.active {
                            Text(peer.direct ? "direct" : "relay \(peer.relay ?? "")").foregroundStyle(.secondary)
                        }
                    }
                }
                if status.peers.count > 100 || status.peersTruncated == true {
                    Text("…and more peers").foregroundStyle(.secondary)
                }
            }
        }
    }

    @ViewBuilder private var signIn: some View {
        if let status, status.state == "NeedsLogin" {
            HStack {
                Button(openedSignIn ? "Open Sign-In Page Again" : "Sign In…") {
                    run {
                        let url = try await store.tailnetLogin(tunnel)
                        openedSignIn = true
                        NSWorkspace.shared.open(url)
                    }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(busy)
                Text("in your browser, at \(URL(string: profile.controlURL)?.host() ?? "the coordination server")").foregroundStyle(.secondary)
            }
            if openedSignIn {
                Text("This goes away by itself once you have signed in.").font(.callout).foregroundStyle(.secondary)
            }
        } else if status?.state == "Running" {
            Button("Sign Out") { run { try await store.tailnetLogout(tunnel) } }.disabled(busy)
        }
    }

    private func run(_ action: @escaping () async throws -> Void) {
        busy = true
        Task {
            defer { busy = false }
            do { try await action() } catch { model.actionError = error.localizedDescription }
        }
    }

    static func stateText(_ state: String?, connected: Bool) -> String {
        guard connected else { return "Not connected" }
        switch state {
        case "NeedsLogin": return "Needs sign-in"
        case "NeedsMachineAuth": return "Waiting for an administrator to approve this Mac"
        case "Starting": return "Starting"
        case "Running": return "Connected"
        case "Stopped": return "Stopped"
        case nil: return "Starting the engine"
        case let other?: return other
        }
    }
}

/// Tailscale shipped as a preview in 1.4.0 (user, 2026-10-26: "push it out as a release with a
/// note in the updater about a new feature"), so the menu item is always there; the label says
/// Preview until exit nodes, subnet routes, on-demand and the CLI land.
enum TailnetPreview {
    static let enabled = true
}

/// Adds a tailnet from a coordination server URL (Tailscale's by default, or a Headscale).
struct AddTailnetSheet: View {
    @EnvironmentObject private var store: TunnelStore
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var name = "Tailnet"
    @State private var control = ""
    @State private var hostname = ""
    @State private var acceptDNS = true
    @State private var problem: String?

    var body: some View {
        Form {
            Text("Add a Tailnet (preview)").font(.headline)
            Text("Leave the server empty for Tailscale. After you connect, Sign In opens your coordination server's page in your browser.")
                .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            TextField("Name", text: $name)
            TextField("Coordination server", text: $control, prompt: Text("Empty for Tailscale, or https://headscale.example.com"))
            TextField("Host name", text: $hostname, prompt: Text("Optional"))
            Toggle("Use MagicDNS", isOn: $acceptDNS)
            if let problem { Text(problem).foregroundStyle(.red) }
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }
                Button("Add") { add() }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 460)
    }

    private func add() {
        var profile = TailnetProfile(acceptDNS: acceptDNS)
        switch TailnetControl.canonical(control.trimmingCharacters(in: .whitespaces)) {
        case .success(let url): profile.controlURL = url
        case .failure(let p): problem = p.message; return
        }
        profile.hostname = hostname.isEmpty ? nil : hostname
        let text = TailnetFile.serialize(profile)
        guard TailnetFile.parse(text).profile != nil else { problem = TailnetFile.parse(text).errors.map(\.description).joined(separator: "\n"); return }
        Task {
            do {
                model.selection = try await store.addTailnet(name: name, text: text).id
                dismiss()
            } catch {
                problem = error.localizedDescription
            }
        }
    }
}
