import ServiceManagement
import SwiftUI

struct SettingsView: View {
    var body: some View {
        TabView {
            GeneralSettings().tabItem { Label("General", systemImage: "gearshape") }
            CommandLineSettings().tabItem { Label("Command Line", systemImage: "terminal") }
            AboutSettings().tabItem { Label("About", systemImage: "info.circle") }
        }
        .frame(width: 580, height: 560)
    }
}

private struct GeneralSettings: View {
    @EnvironmentObject private var installer: ExtensionInstaller
    @State private var launchAtLogin = SMAppService.mainApp.status == .enabled
    /// Set while the switch is put back after a failure, so that change isn't acted on (and the
    /// error it explains isn't cleared by it; quality-3).
    @State private var revertingLaunchAtLogin = false
    @State private var error: String?
    @AppStorage(Preferences.Key.showInDock) private var showInDock = true
    @AppStorage(Preferences.Key.showInMenuBar) private var showInMenuBar = true
    @AppStorage(Preferences.Key.menuBarShowsName) private var menuBarShowsName = false
    @AppStorage(Preferences.Key.menuBarIcon) private var menuBarIcon = "shield"
    @AppStorage(Preferences.Key.confirmQuit) private var confirmQuit = true
    @AppStorage(Preferences.Key.openWindowAtLaunch) private var openWindowAtLaunch = true
    @AppStorage(Preferences.Key.notifyOnChange) private var notifyOnChange = false

    var body: some View {
        Form {
            Section {
                Toggle("Open Wombat at login", isOn: $launchAtLogin)
                    .onChange(of: launchAtLogin) { _, on in
                        if revertingLaunchAtLogin { revertingLaunchAtLogin = false; return }
                        do {
                            if on { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() }
                            error = nil
                        } catch {
                            self.error = error.localizedDescription
                            let actual = SMAppService.mainApp.status == .enabled
                            if actual != launchAtLogin {
                                revertingLaunchAtLogin = true
                                launchAtLogin = actual
                            }
                        }
                    }
                Toggle("Open the main window when Wombat starts", isOn: $openWindowAtLaunch)
            } footer: {
                Text("Tunnels and on-demand rules run in the system and don't need the app. Turn off the window to start quietly in the menu bar.")
            }
            Section {
                Toggle("Show in the Dock", isOn: $showInDock)
                    // At least one of Dock and menu bar stays on, or there'd be no way back in.
                    .disabled(showInDock && !showInMenuBar)
                    .onChange(of: showInDock) { _, _ in Preferences.applyDockPolicy(activate: true) }
                Toggle("Show in the menu bar", isOn: $showInMenuBar)
                    .disabled(showInMenuBar && !showInDock)
                    .onChange(of: showInMenuBar) { _, _ in Preferences.applyDockPolicy(activate: true) }
                Picker("Menu bar icon", selection: $menuBarIcon) {
                    Text("Shield").tag("shield")
                    Text("Wombat W").tag("w")
                }
                .disabled(!showInMenuBar)
                Toggle("Show the connected tunnel's name in the menu bar", isOn: $menuBarShowsName)
                    .disabled(!showInMenuBar)
            } header: {
                Text("Appearance")
            } footer: {
                Text("Wombat keeps at least one of the two, so you can always get back to it. Opening the app again in Finder also shows the window.")
            }
            Section {
                Toggle("Ask before quitting", isOn: $confirmQuit)
            } header: {
                Text("Quitting")
            } footer: {
                Text("Tunnels keep running when Wombat quits; the menu bar item and the wombat tunnel commands come back when you open it again.")
            }
            Section("Notifications") {
                Toggle("Notify when a tunnel connects, disconnects or fails", isOn: $notifyOnChange)
                    .onChange(of: notifyOnChange) { _, on in
                        guard on else { return }
                        Task {
                            if !(await Preferences.requestNotificationPermission()) {
                                notifyOnChange = false
                                error = "Notifications are off for Wombat in System Settings › Notifications."
                            }
                        }
                    }
            }
            UpdatesSection()
            Section("Network extension") {
                LabeledContent("Status", value: statusText)
                Button("Reinstall Extension") { installer.activate() }
            }
            if let error { ErrorLabel(error) }
        }
        .formStyle(.grouped)
    }

    private var statusText: String {
        switch installer.state {
        case .active: return "Active"
        case .activating: return "Activating…"
        case .needsApproval: return "Waiting for approval in System Settings"
        case .requiresApplicationsFolder: return "Move the app to /Applications"
        case .failed(let message): return "Failed: \(message)"
        case .unknown: return "Unknown"
        }
    }
}

private struct UpdatesSection: View {
    @ObservedObject private var updates = UpdaterModel.shared

    var body: some View {
        Section("Updates") {
            if updates.updatesEnabled {
                Picker("When a new version is out", selection: Binding(get: { updates.alertMode }, set: { updates.setAlertMode($0) })) {
                    ForEach(UpdateAlertMode.allCases) { Text($0.title).tag($0) }
                }
                LabeledContent("Last checked") {
                    Text(updates.lastUpdateCheckDate.map { $0.formatted(date: .abbreviated, time: .shortened) } ?? "Never")
                }
                Button(updates.availableUpdate.map { "Update to Wombat \($0.version)…" } ?? "Check Now") { updates.checkForUpdates() }
                    .disabled(!updates.canCheckForUpdates)
            } else {
                Text("This build doesn't update itself (a development build, or a fork without its own feed).")
                    .foregroundStyle(.secondary)
            }
        }
    }
}

private struct CommandLineSettings: View {
    private static let linkPath = "/usr/local/bin/wombat"
    private var cliPath: String { Bundle.main.bundlePath + "/Contents/Helpers/wombat" }
    /// Single-quoted for the shell, with any ' in the path escaped (F-15, WOM-17). `mkdir` because
    /// /usr/local/bin doesn't exist on an Apple silicon Mac until something (usually Homebrew's
    /// installer) creates it; it is already on the default PATH (/etc/paths).
    private var installCommand: String {
        "sudo mkdir -p /usr/local/bin && sudo ln -sf '\(cliPath.replacingOccurrences(of: "'", with: "'\\''"))' \(Self.linkPath)"
    }

    private enum LinkState: Equatable {
        case installed(String), notInstalled
        case elsewhere(String)
    }

    @State private var state: LinkState?
    @State private var copied = false
    private var isInstalled: Bool { if case .installed = state { true } else { false } }

    /// The sandbox lets the app read the link (verified 2026-10-16) but not write it: the install
    /// needs an admin password, so it stays a command the user runs in Terminal. The Homebrew
    /// cask links the CLI into Homebrew's bin instead, so that counts as installed too.
    private func readLink() -> LinkState {
        let ours = URL(fileURLWithPath: cliPath).resolvingSymlinksInPath().path
        var other: String?
        for path in [Self.linkPath, "/opt/homebrew/bin/wombat"] {
            let fm = FileManager.default
            guard let dest = try? fm.destinationOfSymbolicLink(atPath: path) else {
                if path == Self.linkPath, fm.fileExists(atPath: path) { other = path }
                continue
            }
            let resolved = URL(fileURLWithPath: dest, relativeTo: URL(fileURLWithPath: (path as NSString).deletingLastPathComponent))
                .standardizedFileURL.resolvingSymlinksInPath().path
            if resolved == ours { return .installed(path) }
            if path == Self.linkPath { other = dest }
        }
        return other.map(LinkState.elsewhere) ?? .notInstalled
    }

    var body: some View {
        Form {
            Section {
                Text("The wombat command controls tunnels from the terminal and scripts: status, connect, import, lint configs, generate keys, stream logs.")
                LabeledContent("Status") { status }
                if case .elsewhere(let dest) = state {
                    Text("\(Self.linkPath) runs \(dest), not this copy of Wombat. Run the command below to point it here.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                if !isInstalled {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Install")
                        Text(installCommand)
                            .font(.callout.monospaced())
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(8)
                            .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 6))
                    }
                    HStack {
                        Button(copied ? "Copied" : "Copy Install Command", systemImage: copied ? "checkmark" : "doc.on.doc") {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(installCommand, forType: .string)
                            copied = true
                        }
                        Button("Open Terminal", systemImage: "terminal") {
                            NSWorkspace.shared.open(URL(fileURLWithPath: "/System/Applications/Utilities/Terminal.app"))
                        }
                    }
                    Text("Paste the command into Terminal and enter your Mac's password. It links \(Self.linkPath) to the copy inside Wombat, creating /usr/local/bin first, since a new Mac doesn't have it. That folder is already on your PATH, and this page updates once the link is there.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
            } footer: {
                Text("From the command line, adding, deleting or renaming a tunnel, switching away from a protected one, and anything that lowers protection ask for your approval here; exporting keys and turning the kill switch off ask for Touch ID.")
            }
            Section("Examples") {
                ForEach(["wombat status", "wombat up home", "wombat show home", "wombat check wg0.conf", "wombat logs -f"], id: \.self) {
                    Text($0).font(.callout.monospaced()).textSelection(.enabled)
                }
            }
        }
        .formStyle(.grouped)
        .task {
            // Polls while the page is open, so it turns green as soon as the command has run.
            while !Task.isCancelled {
                state = readLink()
                try? await Task.sleep(for: .seconds(2))
            }
        }
        .task(id: copied) {
            guard copied else { return }
            try? await Task.sleep(for: .seconds(2))
            copied = false
        }
    }

    @ViewBuilder private var status: some View {
        switch state {
        case .installed(let path):
            Label("Installed at \(path)", systemImage: "checkmark.circle.fill")
                .foregroundStyle(.green)
        case .elsewhere:
            Label("Points to another copy", systemImage: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
        case .notInstalled:
            Label("Not installed", systemImage: "circle.dashed")
                .foregroundStyle(.secondary)
        case nil:
            Text("Checking…").foregroundStyle(.secondary)
        }
    }
}

/// Makes it obvious that Wombat is open source: name, version, license and where the code lives.
private struct AboutSettings: View {
    static let repository = URL(string: "https://github.com/ventz/wombat-wireguard-mac-app")!
    private var version: String {
        let info = Bundle.main.infoDictionary
        return "\(info?["CFBundleShortVersionString"] as? String ?? "?") (\(info?["CFBundleVersion"] as? String ?? "?"))"
    }

    var body: some View {
        Form {
            Section {
                HStack(spacing: 14) {
                    Image(nsImage: NSApp.applicationIconImage)
                        .resizable()
                        .frame(width: 56, height: 56)
                        .accessibilityHidden(true)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Wombat").font(.title2.weight(.semibold)).accessibilityAddTraits(.isHeader)
                        Text("A native, free and open-source WireGuard® client for macOS.")
                            .foregroundStyle(.secondary)
                    }
                }
                LabeledContent("Version", value: version)
                LabeledContent("License") {
                    HStack(spacing: 4) {
                        Link("MIT", destination: Self.repository.appendingPathComponent("blob/main/LICENSE"))
                            .underline()  // a link by shape, not only by color (accessibility-3 L5)
                        Text("© Ventz Petkov")
                    }
                }
                LabeledContent("Source code") {
                    Link("github.com/ventz/wombat-wireguard-mac-app", destination: Self.repository)
                }
                LabeledContent("Report a problem") {
                    Link("GitHub Issues", destination: Self.repository.appendingPathComponent("issues"))
                }
            } footer: {
                Text("© 2026 Ventz Petkov. Free and open source under the MIT License: use, change and share it.")
            }
            Section("Credits") {
                Text("Tunnel engine: wireguard-go and WireGuardKit (MIT, © WireGuard LLC).")
                Text("“WireGuard” and the “WireGuard” logo are registered trademarks of Jason A. Donenfeld. Wombat is not affiliated with or endorsed by the WireGuard project.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
    }
}
