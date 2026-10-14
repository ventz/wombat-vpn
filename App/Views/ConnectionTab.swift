import Combine
import NetworkExtension
import SwiftUI
import TunnelCore

/// The Connection tab: when the tunnel connects (on-demand rules) and how it protects traffic
/// (kill switch, local network). These are macOS settings, not part of the .conf file.
struct ConnectionTab: View {
    @ObservedObject var tunnel: Tunnel
    @EnvironmentObject private var store: TunnelStore
    @State private var rules = Control.OnDemand(enabled: false)
    @State private var protection = Control.Protection(killSwitch: false, allowLAN: true)
    @State private var newSSID = ""
    @State private var error: String?
    @State private var applying = false

    var body: some View {
        Form {
            Section {
                Toggle("Connect automatically", isOn: $rules.enabled)
                Toggle("On Wi-Fi", isOn: $rules.onWiFi).disabled(!rules.enabled)
                Toggle("On Ethernet", isOn: $rules.onEthernet).disabled(!rules.enabled)
            } header: {
                Text("When to connect")
            } footer: {
                Text("macOS keeps the tunnel up on these networks, even while Wombat is closed. Turning the tunnel off by hand also turns this off.")
            }

            Section {
                ForEach(rules.trustedSSIDs, id: \.self) { ssid in
                    HStack {
                        Label(ssid, systemImage: "wifi")
                        Spacer()
                        Button(role: .destructive) { rules.trustedSSIDs.removeAll { $0 == ssid } } label: {
                            Image(systemName: "minus.circle")
                        }
                        .buttonStyle(.borderless)
                        .accessibilityLabel("Remove \(ssid)")
                    }
                }
                HStack {
                    TextField("Wi-Fi network name", text: $newSSID)
                        .onSubmit(addSSID)
                    Button("Add", action: addSSID).disabled(newSSID.trimmingCharacters(in: .whitespaces).isEmpty)
                }
            } header: {
                Text("Except on these Wi-Fi networks")
            } footer: {
                Text("The tunnel disconnects on these networks, such as home or office. Wi-Fi names are not authenticated: anyone can broadcast the same name, so only trust networks where a disconnected tunnel is acceptable.")
            }
            .disabled(!rules.enabled)

            Section {
                Toggle("Kill switch", isOn: $protection.killSwitch)
                Toggle("Allow local network", isOn: $protection.allowLAN).disabled(!protection.killSwitch)
            } header: {
                Text("Protection")
            } footer: {
                Text(protection.allowLAN && protection.killSwitch
                     ? "Local-network traffic bypasses the tunnel. That keeps printers, AirPlay and file sharing working, but on an untrusted Wi-Fi network it lets the network redirect some traffic (TunnelVision, LocalNet)."
                     : "With the kill switch on, traffic goes only through the tunnel, also while it reconnects. Allowing the local network keeps printers, AirPlay and file sharing working.")
            }

            if let error {
                ErrorLabel(error)
            }
        }
        .formStyle(.grouped)
        .onAppear(perform: load)
        // Changes made elsewhere (the CLI, another tunnel's switch, System Settings) replace the
        // manager; show them instead of writing stale values back later (audit Q2-M6).
        .onReceive(tunnel.objectWillChange) { _ in
            DispatchQueue.main.async { if !applying { load() } }
        }
        .onChange(of: rules) { _, value in
            guard value != Control.OnDemand(manager: tunnel.manager) else { return }
            Task { await apply { try await store.setOnDemand(tunnel, value) } }
        }
        .onChange(of: protection) { old, value in
            guard value != Control.Protection(proto: tunnel.proto) else { return }
            Task {
                // Turning the kill switch off asks for Touch ID or the password, as from the CLI:
                // a click is easy to fake for a process with accessibility access (WOM-06).
                if old.killSwitch, !value.killSwitch,
                   !(await Authenticator.confirm(reason: "turn off the kill switch for “\(tunnel.name)”")) {
                    load()
                    return
                }
                await apply { try await store.setProtection(tunnel, value) }
            }
        }
    }

    private func load() {
        rules = Control.OnDemand(manager: tunnel.manager)
        protection = Control.Protection(proto: tunnel.proto)
    }

    private func addSSID() {
        let ssid = newSSID.trimmingCharacters(in: .whitespaces)
        guard !ssid.isEmpty, !rules.trustedSSIDs.contains(ssid) else { return }
        rules.trustedSSIDs.append(ssid)
        newSSID = ""
    }

    private func apply(_ work: () async throws -> Void) async {
        applying = true
        defer { applying = false; load() }
        do {
            try await work()
            error = nil
        } catch {
            self.error = error.localizedDescription
            load()
        }
    }
}

/// The tunnel's recent engine log. Lines stay after the tunnel goes down (that is when the
/// reason matters), refreshing can be paused to read without the view jumping, and Copy Log
/// confirms itself (audits A-M4, A-L8).
struct LogTab: View {
    @ObservedObject var tunnel: Tunnel
    @EnvironmentObject private var store: TunnelStore
    @State private var paused = false
    @State private var copied = false
    @State private var timer = Timer.publish(every: 2, tolerance: 0.5, on: .main, in: .common).autoconnect()

    private var lines: [String] { tunnel.recentLog }

    var body: some View {
        VStack(spacing: 0) {
            if lines.isEmpty {
                ContentUnavailableView("No log yet", systemImage: "text.alignleft",
                                       description: Text("The tunnel's recent log appears here once it starts. Full history: wombat logs -f"))
            } else {
                ScrollViewReader { proxy in
                    List(Array(lines.enumerated()), id: \.offset) { index, line in
                        Text(line)
                            .font(.caption.monospaced())
                            .textSelection(.enabled)
                            .id(index)
                    }
                    .listStyle(.plain)
                    .onChange(of: lines.count) { _, count in
                        if !paused { proxy.scrollTo(count - 1, anchor: .bottom) }
                    }
                }
            }
            Divider()
            HStack {
                Text("Stream everything: ").foregroundStyle(.secondary)
                Text("wombat logs -f").font(.callout.monospaced()).textSelection(.enabled)
                Spacer()
                Toggle("Pause", isOn: $paused)
                    .toggleStyle(.button)
                    .help("Stop refreshing so you can read and select lines")
                Button(copied ? "Copied" : "Copy Log") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(lines.joined(separator: "\n"), forType: .string)
                    copied = true
                    NSAccessibility.post(element: NSApp as Any, notification: .announcementRequested,
                                         userInfo: [.announcement: "Log copied", .priority: NSAccessibilityPriorityLevel.medium.rawValue])
                    Task { try? await Task.sleep(for: .seconds(2)); copied = false }
                }
                .disabled(lines.isEmpty)
            }
            .font(.callout)
            .padding(10)
        }
        .task { await refresh() }
        .onReceive(timer) { _ in Task { await refresh() } }
    }

    private func refresh() async {
        guard !paused else { return }
        let fresh = await store.fetchRecentLog(tunnel)
        // An empty answer means the tunnel is down: keep what was there.
        if !fresh.isEmpty { tunnel.recentLog = fresh }
    }
}
