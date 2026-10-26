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
                Text("Reported by the tailnet").font(.callout)
                ForEach(health, id: \.self) { warning in
                    Label { Text(warning) } icon: { Image(systemName: "info.circle").foregroundStyle(.secondary) }
                }
            }
            signIn
        }
        if let status, !status.peers.isEmpty {
            Card(title: "Peers", systemImage: "desktopcomputer") {
                // Keyed by the peer's name and address, so a refresh doesn't move the VoiceOver
                // cursor onto another peer (accessibility-9 M3).
                ForEach(status.peers.prefix(100), id: \.rowID) { peer in
                    let name = peer.dnsName?.split(separator: ".").first.map(String.init) ?? peer.name
                    let path = peer.active ? (peer.direct ? "direct" : "relay \(peer.relay ?? "")") : nil
                    HStack(alignment: .firstTextBaseline) {
                        // Shape and word as well as color (accessibility-9 M2).
                        Image(systemName: peer.online ? "circle.fill" : "circle").font(.caption2)
                            .foregroundStyle(peer.online ? Color.green : Color.secondary)
                        Text(name).frame(width: 160, alignment: .leading)
                        Text(peer.addresses.first ?? "").font(.body.monospaced()).textSelection(.enabled)
                        Spacer()
                        Text(path ?? (peer.online ? "online" : "offline")).foregroundStyle(.secondary)
                    }
                    .accessibilityElement(children: .ignore)
                    .accessibilityLabel(name)
                    .accessibilityValue([peer.online ? "online" : "offline", peer.addresses.first, path].compactMap { $0 }.joined(separator: ", "))
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
                .disabled(busy)
                .accessibilityHint("Opens the sign-in page at \(signInHost) in your browser")
                Text("in your browser, at \(signInHost)")
            }
            if openedSignIn {
                Text("This goes away by itself once you have signed in.").font(.callout)
            }
        } else if status?.state == "Running" {
            Button("Sign Out") { run { try await store.tailnetLogout(tunnel) } }.disabled(busy)
        }
    }

    private var signInHost: String { URL(string: profile.controlURL)?.host() ?? "the coordination server" }

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

/// Adds a tailnet. The coordination server is an explicit choice, Tailscale's or your own
/// (Headscale), never an empty field that means Tailscale (user, 2026-10-26: "super confusing").
struct AddTailnetSheet: View {
    @EnvironmentObject private var store: TunnelStore
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss

    enum Server: Hashable { case tailscale, own }
    @State private var server: Server = .tailscale
    @State private var address = ""
    @State private var name = ""
    @State private var hostname = ""
    @State private var acceptDNS = true
    @State private var problem: String?
    @State private var addressProblem: String?
    @State private var saving = false
    @FocusState private var addressFocused: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Add Tailnet").font(.title2.weight(.semibold)).accessibilityAddTraits(.isHeader)
            Text("Joins a Tailscale network. Preview: tailnet addresses and MagicDNS work; exit nodes and subnet routes come later.")
                .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            Form {
                Picker("Coordination server", selection: $server) {
                    Text("Tailscale").tag(Server.tailscale)
                    Text("My own server (Headscale)").tag(Server.own)
                }
                .pickerStyle(.radioGroup)
                if server == .own {
                    TextField("Server address", text: $address, prompt: Text("headscale.example.com"))
                        .textContentType(.URL)
                        .focused($addressFocused)
                        .accessibilityHint(addressProblem ?? "Your Headscale's https address; a port is allowed")
                    if let addressProblem { ErrorLabel(addressProblem).font(.caption) }
                    else if address.trimmingCharacters(in: .whitespaces).isEmpty {
                        Text("Enter your server's address.").font(.caption)
                    }
                }
                TextField("Name", text: $name, prompt: Text(defaultName))
                TextField("Host name for this Mac", text: $hostname, prompt: Text("Optional"))
                    .help("How this Mac appears in the tailnet. Empty uses the Mac's own name.")
                Toggle("Use MagicDNS (reach devices by name)", isOn: $acceptDNS)
            }
            .formStyle(.grouped)
            Text("After you add it, connect, then click Sign In: the sign-in page opens in your browser.")
                .font(.callout).fixedSize(horizontal: false, vertical: true)
            if let problem { ErrorLabel(problem) }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Add Tailnet") { add() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(saving || (server == .own && address.trimmingCharacters(in: .whitespaces).isEmpty))
            }
        }
        .padding(20)
        .frame(width: 520)
        .onChange(of: address) { problem = nil; addressProblem = nil }
        .onChange(of: server) { problem = nil; addressProblem = nil; addressFocused = server == .own }
    }

    /// Errors are shown and spoken: focus stays on the Add button, so VoiceOver users would
    /// otherwise not learn why nothing happened (accessibility-9 M1).
    private func fail(_ message: String, address: Bool = false) {
        if address { addressProblem = message } else { problem = message }
        NSAccessibility.post(element: NSApp as Any, notification: .announcementRequested, userInfo: [
            .announcement: "Couldn't add the tailnet: \(message)",
            .priority: NSAccessibilityPriorityLevel.high.rawValue,
        ])
    }

    private var defaultName: String {
        guard server == .own else { return "Tailscale" }
        return URL(string: Self.withScheme(address))?.host() ?? "Headscale"
    }

    /// "headscale.example.com" means https; anything else is checked as typed (http is refused).
    static func withScheme(_ text: String) -> String {
        let t = text.trimmingCharacters(in: .whitespaces)
        return t.isEmpty || t.contains("://") ? t : "https://" + t
    }

    private func add() {
        var profile = TailnetProfile(acceptDNS: acceptDNS)
        if server == .own {
            switch TailnetControl.canonical(Self.withScheme(address)) {
            case .success(let url): profile.controlURL = url
            case .failure(let p): fail(p.message, address: true); return
            }
        }
        let host = hostname.trimmingCharacters(in: .whitespaces)
        profile.hostname = host.isEmpty ? nil : host
        let text = TailnetFile.serialize(profile)
        let parsed = TailnetFile.parse(text)
        guard parsed.profile != nil else { fail(parsed.errors.map(\.description).joined(separator: "\n")); return }
        let chosen = name.trimmingCharacters(in: .whitespaces)
        saving = true
        Task {
            defer { saving = false }
            do {
                model.selection = try await store.addTailnet(name: chosen.isEmpty ? defaultName : chosen, text: text).id
                dismiss()
            } catch {
                fail(error.localizedDescription)
            }
        }
    }
}
