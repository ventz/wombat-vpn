import NetworkExtension
import SwiftUI
import TunnelCore
import UniformTypeIdentifiers

struct ContentView: View {
    @EnvironmentObject private var model: AppModel
    @EnvironmentObject private var store: TunnelStore
    @EnvironmentObject private var installer: ExtensionInstaller
    @EnvironmentObject private var openConnectInstaller: OpenConnectInstaller
    @State private var showingNewTunnel = false
    @State private var showingAddTailnet = false
    @State private var dropTargeted = false

    var body: some View {
        NavigationSplitView {
            SidebarView(selection: $model.selection)
                .navigationSplitViewColumnWidth(min: 220, ideal: 250)
        } detail: {
            detail
                .safeAreaInset(edge: .top, spacing: 0) {
                    // In the detail column only: across the whole split view it covered the sidebar.
                    if installer.needsAttention {
                        ExtensionBanner(installer: installer)
                    } else if openConnectInstaller.needsAttention, store.tunnels.contains(where: \.isOpenConnect) {
                        // Only while an AnyConnect VPN exists: the extension is requested by the first
                        // one, and the banner must not stay after the last is deleted (user, 2026-10-16).
                        ExtensionBanner(installer: openConnectInstaller)
                    } else if model.tailnetInstaller.needsAttention, store.tunnels.contains(where: \.isTailnet) {
                        ExtensionBanner(installer: model.tailnetInstaller)
                    } else if let problem = store.extensionProblem {
                        ExtensionProblemBanner(message: problem)
                    }
                }
        }
        .toolbar {
            ToolbarItem {
                // One "+" with words, not a separate import icon: the tray-and-arrow glyph reads as "download".
                Menu {
                    Button("Import from File…") { ImportPanel.present(model: model) }
                    Button("Import from Clipboard") {
                        model.importFromClipboard()
                    }
                    Button("Scan QR Code…") { model.showingScanner = true }
                    Divider()
                    Button("New Empty Tunnel…") { showingNewTunnel = true }
                    Button("Add AnyConnect VPN…") { model.anyConnectEditor = AnyConnectEditorTarget(tunnelID: nil) }
                    if TailnetPreview.enabled {
                        Button("Add Tailnet (Preview)…") { showingAddTailnet = true }
                    }
                } label: {
                    Label("Add Tunnel", systemImage: "plus")
                }
                .help("Import .conf files, a zip or a QR code (⌘O), create a new WireGuard tunnel (⌘N), or add a Cisco AnyConnect VPN")
            }
            // In this toolbar, not the detail view's: as a centered (.principal) item the picker
            // left the gear stranded before it, and the gear belongs at the trailing edge.
            if model.selectedTunnel != nil {
                ToolbarItem {
                    Picker("View", selection: $model.detailTab) {
                        ForEach(DetailTab.allCases) { Text($0.rawValue).tag($0) }
                    }
                    .pickerStyle(.segmented)
                    .labelsHidden()
                }
            }
            ToolbarItem {
                HStack(spacing: 2) {
                    SettingsLink {
                        Label("Settings", systemImage: "gearshape")
                    }
                    .help("Settings (⌘,)")
                    UpdateDot()  // only while an update is waiting
                }
            }
        }
        .onDrop(of: [.fileURL], isTargeted: $dropTargeted) { providers in
            loadURLs(providers) { model.stageImport($0) }
            return true
        }
        .overlay {
            if dropTargeted {
                RoundedRectangle(cornerRadius: 12)
                    .strokeBorder(Color.accentColor, style: StrokeStyle(lineWidth: 3, dash: [8]))
                    .padding(8)
                    .allowsHitTesting(false)
            }
        }
        .sheet(isPresented: Binding(get: { !model.pendingImport.isEmpty }, set: { if !$0 { model.pendingImport = [] } })) {
            ImportSheet()
        }
        .sheet(isPresented: $model.showingScanner, onDismiss: {
            guard let text = model.scannedConfig else { return }
            model.scannedConfig = nil
            model.stageImport(text: text, name: "QR Code", source: "QR code (camera)")
        }) {
            QRScannerSheet()
        }
        .sheet(isPresented: $showingNewTunnel) {
            NewTunnelSheet()
        }
        .sheet(isPresented: $showingAddTailnet) {
            AddTailnetSheet()
        }
        .sheet(item: $model.anyConnectEditor) { target in
            AnyConnectEditor(tunnel: target.tunnelID.flatMap { id in store.tunnels.first { $0.id == id } })
        }
        .sheet(isPresented: $model.showingQR) {
            if let tunnel = model.selectedTunnel { QRCodeSheet(tunnel: tunnel) }
        }
        .alert("Something went wrong", isPresented: Binding(get: { model.actionError != nil }, set: { if !$0 { model.actionError = nil } })) {
            Button("OK") { model.actionError = nil }
        } message: {
            Text(model.actionError ?? "")
        }
        .onReceive(NotificationCenter.default.publisher(for: .newTunnel)) { _ in showingNewTunnel = true }
        .onChange(of: store.tunnels.map(\.id)) { _, ids in
            if model.selection == nil || !ids.contains(model.selection!) { model.selection = ids.first }
        }
    }

    @ViewBuilder
    private var detail: some View {
        if let id = model.selection, let tunnel = store.tunnels.first(where: { $0.id == id }) {
            TunnelDetailView(tunnel: tunnel)
                .id(tunnel.id)
        } else if store.loaded && store.tunnels.isEmpty {
            EmptyStateView(showingNewTunnel: $showingNewTunnel)
        } else {
            Text("Select a tunnel")
                .font(.title3)
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    private func loadURLs(_ providers: [NSItemProvider], completion: @escaping ([URL]) -> Void) {
        let group = DispatchGroup()
        let lock = NSLock()
        var urls: [URL] = []
        for provider in providers {
            group.enter()
            _ = provider.loadObject(ofClass: URL.self) { url, _ in
                if let url { lock.lock(); urls.append(url); lock.unlock() }
                group.leave()
            }
        }
        group.notify(queue: .main) { completion(urls) }
    }
}

struct SidebarView: View {
    @EnvironmentObject private var store: TunnelStore
    @Binding var selection: UUID?
    @FocusState private var focused: Bool
    @Environment(\.colorSchemeContrast) private var contrast

    var body: some View {
        // The selection is drawn here, not by List(selection:): the system highlight is the
        // accent blue, and the blue tunnel switches disappeared into it (user, 2026-10-14). What
        // the native list gave for free is rebuilt (accessibility-3): a 3:1 accent bar on the
        // selected row, a focus ring while the list has keyboard focus, arrow keys, and spoken
        // selection changes.
        List {
            Section("Tunnels") {
                ForEach(store.tunnels) { tunnel in
                    let selected = selection == tunnel.id
                    SidebarRow(tunnel: tunnel)
                        .contentShape(Rectangle())
                        .onTapGesture {
                            selection = tunnel.id
                            focused = true
                        }
                        .listRowBackground(rowBackground(selected: selected))
                        .accessibilityAddTraits(selected ? [.isSelected, .isButton] : .isButton)
                        .accessibilityAction { selection = tunnel.id }
                }
            }
        }
        .focusable()
        .focused($focused)
        .focusEffectDisabled()  // the selected row shows the focus ring instead
        .onMoveCommand { direction in
            let ids = store.tunnels.map(\.id)
            guard !ids.isEmpty else { return }
            let index = selection.flatMap { ids.firstIndex(of: $0) }
            switch direction {
            case .up: selection = ids[max((index ?? ids.count) - 1, 0)]
            case .down: selection = ids[min((index ?? -1) + 1, ids.count - 1)]
            default: return
            }
            // The custom list has no selected table row for VoiceOver to report: say it.
            if let tunnel = store.tunnels.first(where: { $0.id == selection }) {
                NSAccessibility.post(element: NSApp as Any, notification: .announcementRequested, userInfo: [
                    .announcement: "\(tunnel.name), \(tunnel.statusText), selected",
                    .priority: NSAccessibilityPriorityLevel.medium.rawValue,
                ])
            }
        }
        .frame(minWidth: 220)
        .overlay {
            if let error = store.loadError {
                ContentUnavailableView("Can't Load Tunnels", systemImage: "exclamationmark.triangle", description: Text(error))
            }
        }
    }

    private func rowBackground(selected: Bool) -> some View {
        let shape = RoundedRectangle(cornerRadius: 8, style: .continuous)
        return shape
            .fill(selected ? Color.primary.opacity(contrast == .increased ? 0.2 : 0.12) : .clear)
            .overlay(alignment: .leading) {
                // The selection cue that meets 3:1 on its own; the fill alone doesn't.
                if selected {
                    Capsule().fill(Color(nsColor: .controlAccentColor)).frame(width: 3).padding(.vertical, 8).padding(.leading, 3)
                }
            }
            .overlay {
                if selected && focused {
                    shape.strokeBorder(Color(nsColor: .keyboardFocusIndicatorColor), lineWidth: 2)
                }
            }
            .padding(.horizontal, 10)
    }
}

struct SidebarRow: View {
    @ObservedObject private var signIn = SignInCoordinator.shared
    @ObservedObject var tunnel: Tunnel
    @EnvironmentObject private var store: TunnelStore
    @EnvironmentObject private var model: AppModel

    var body: some View {
        HStack(spacing: 10) {
            StatusDot(status: tunnel.status)
            VStack(alignment: .leading, spacing: 1) {
                Text(tunnel.name).lineLimit(1)
                Text(subtitle)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Spacer()
            Toggle("", isOn: Binding(get: { tunnel.isActive }, set: { _ in Task { await store.toggle(tunnel) } }))
                .toggleStyle(.switch)
                .controlSize(.small)
                // The system blue, like every other switch; SidebarView's neutral selection keeps
                // it visible on the selected row.
                .labelsHidden()
                .focusable(false)  // not a silent Tab stop: the row carries its action
                .accessibilityHidden(true)  // exposed as the row's named action below
        }
        .padding(.vertical, 2)
        // Name, then the status once (the symbol and the subtitle both carried it; A-L1).
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(tunnel.name)
        .accessibilityValue(spokenStatus)
        .accessibilityAction(named: tunnel.isActive ? "Disconnect" : "Connect") { Task { await store.toggle(tunnel) } }
        .contextMenu {
            Button(tunnel.isActive ? "Disconnect" : "Connect") { Task { await store.toggle(tunnel) } }
            Divider()
            TunnelActionItems(tunnel: tunnel)
        }
    }

    /// A sign-in under way shows in the row too, so it can't go unnoticed (accessibility-6 M2).
    private var signingIn: Bool { signIn.activeTunnelID == tunnel.id }

    private var spokenStatus: String {
        if signingIn { return "Signing in, waiting for you" }
        if let error = tunnel.lastError { return "\(tunnel.statusText), error: \(error)" }
        if tunnel.status == .connected, let since = tunnel.connectedSince {
            return "Connected " + since.formatted(.relative(presentation: .named))
        }
        if tunnel.isOnDemand && tunnel.status == .disconnected { return "Disconnected, on demand" }
        if tunnel.isOnDemandPaused { return "\(tunnel.statusText), on demand paused" }
        return tunnel.statusText
    }

    private var subtitle: String {
        if signingIn { return "Signing in…" }
        if let error = tunnel.lastError { return "Error: \(error)" }
        if tunnel.status == .connected, let since = tunnel.connectedSince {
            return "Connected · " + since.formatted(.relative(presentation: .named))
        }
        if tunnel.isOnDemand && tunnel.status == .disconnected { return "On demand" }
        if tunnel.isOnDemandPaused && tunnel.status == .disconnected { return "On demand paused" }
        let detail = tunnel.serverText ?? tunnel.statusText
        return tunnel.protocolName == "WireGuard" ? detail : "\(tunnel.protocolName) · \(detail)"
    }
}

/// Status as shape and color: checkmark connected, arrows in progress, octagon invalid, empty
/// circle off. Color alone isn't enough (color blindness, monochrome).
struct StatusDot: View {
    let status: NEVPNStatus

    var body: some View {
        Image(systemName: symbol)
            .font(.system(size: 11, weight: .semibold))
            .foregroundStyle(color)
            .frame(width: 14)
            .accessibilityLabel(label)
    }

    private var symbol: String {
        switch status {
        case .connected: return "checkmark.circle.fill"
        case .connecting, .reasserting, .disconnecting: return "arrow.triangle.2.circlepath.circle"
        case .invalid: return "xmark.octagon.fill"
        default: return "circle"
        }
    }

    private var color: Color {
        switch status {
        case .connected: return .green
        case .connecting, .reasserting, .disconnecting: return .orange
        case .invalid: return .red
        default: return Color(nsColor: .tertiaryLabelColor)
        }
    }

    private var label: String {
        switch status {
        case .connected: return "Connected"
        case .connecting, .reasserting: return "Connecting"
        case .disconnecting: return "Disconnecting"
        case .invalid: return "Invalid"
        default: return "Disconnected"
        }
    }
}

struct EmptyStateView: View {
    @EnvironmentObject private var model: AppModel
    @Binding var showingNewTunnel: Bool

    var body: some View {
        VStack(spacing: 18) {
            Image(nsImage: NSApp.applicationIconImage)
                .resizable()
                .frame(width: 96, height: 96)
            Text("No tunnels yet")
                .font(.title2.weight(.semibold))
            Text("Drop .conf files or a QR code picture here, import the zip from the official app\n(Manage Tunnels › Export Tunnels to Zip), scan a QR code, create a new tunnel,\nor add a Cisco AnyConnect VPN.")
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
            HStack {
                Button("Import…") { ImportPanel.present(model: model) }
                    .keyboardShortcut(.defaultAction)
                Button("Scan QR Code…") { model.showingScanner = true }
                Button("New Tunnel…") { showingNewTunnel = true }
                Button("Add AnyConnect VPN…") { model.anyConnectEditor = AnyConnectEditorTarget(tunnelID: nil) }
            }
            .controlSize(.large)
        }
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

/// A problem with the extension itself (a code-signing mismatch, say), not with one tunnel.
struct ExtensionProblemBanner: View {
    let message: String

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: "exclamationmark.shield.fill")
                .font(.title2)
                .foregroundStyle(.red)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text("Wombat can't talk to its network extension").font(.headline)
                Text(message).font(.callout).foregroundStyle(.secondary).textSelection(.enabled)
            }
            .accessibilityElement(children: .combine)
            Spacer()
        }
        .padding(12)
        .background(.red.opacity(0.1))
        .overlay(alignment: .bottom) { Divider() }
    }
}

struct ExtensionBanner: View {
    @ObservedObject var installer: ExtensionInstaller

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: "exclamationmark.shield.fill")
                .font(.title2)
                .foregroundStyle(.orange)
                .accessibilityHidden(true)  // the title says it (A6-L4)
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.headline)
                if !detail.isEmpty { Text(detail).font(.callout).foregroundStyle(.secondary) }
                // Numbered steps rather than one long sentence (user, 2026-10-16).
                ForEach(Array(steps.enumerated()), id: \.offset) { index, step in
                    HStack(alignment: .firstTextBaseline, spacing: 6) {
                        Text("\(index + 1).").monospacedDigit().fontWeight(.semibold)
                        Text(step)
                    }
                    .font(.callout)
                    // One stop per step, read as words: VoiceOver says "ⓘ" and "›" literally (A6-L4).
                    .accessibilityElement(children: .ignore)
                    .accessibilityLabel("Step \(index + 1): " + step.replacingOccurrences(of: " › ", with: ", then ")
                        .replacingOccurrences(of: " (ⓘ)", with: ""))
                }
                if !footer.isEmpty { Text(footer).font(.callout).foregroundStyle(.secondary) }
            }
            Spacer()
            // What the switches look like in System Settings (user, 2026-10-16: "a PREVIEW
            // screenshot in the app is helpful"). Drawn, not a screenshot: sharp, dark mode.
            if installer.state == .needsApproval {
                ExtensionSwitchPreview(highlight: installer.identifier)
                    .accessibilityHidden(true)  // the steps say the same in words
            }
            switch installer.state {
            case .needsApproval:
                Button("Open System Settings") {
                    NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.LoginItems-Settings.extension")!)
                }
            case .failed:
                Button("Try Again") { installer.activate() }
            default:
                EmptyView()
            }
        }
        .padding(12)
        .background(.orange.opacity(0.12))
        .overlay(alignment: .bottom) { Divider() }
    }

    private var title: String {
        switch installer.state {
        case .needsApproval:
            return isOpenConnect ? "Allow Wombat's OpenConnect extension" : isTailnet ? "Allow Wombat's Tailnet extension" : "Allow the Wombat network extension"
        case .requiresApplicationsFolder: return "Move Wombat to the Applications folder"
        case .failed: return "The \(isOpenConnect ? "OpenConnect" : isTailnet ? "Tailnet" : "network") extension could not be activated"
        default: return ""
        }
    }

    private var isOpenConnect: Bool { installer.engineName == "OpenConnect" }
    private var isTailnet: Bool { installer.engineName == "Tailnet" }

    private var detail: String {
        switch installer.state {
        case .needsApproval:
            if isOpenConnect { return "AnyConnect VPNs run in a second extension, kept apart from your WireGuard keys." }
            return isTailnet ? "Tailnets run in their own extension, kept apart from your WireGuard keys." : ""
        case .requiresApplicationsFolder:
            return "macOS only runs network extensions for apps in /Applications."
        case .failed(let message):
            return message
        default:
            return ""
        }
    }

    /// The exact clicks, matching macOS 15+ (verified 2026-10-14): the switch is behind the ⓘ.
    private var steps: [String] {
        guard installer.state == .needsApproval else { return [] }
        let app = ExtensionSwitchPreview.appName
        // System Settings lists each extension by its display name under the app (verified
        // 2026-10-16: "Wombat Tunnel" and "Wombat OpenConnect" under Wombat.app).
        return [
            "Click Open System Settings (General › Login Items & Extensions).",
            "Scroll to Extensions and choose By Category.",
            "Click the Info button (ⓘ) next to Network Extensions.",
            "Under \(app), turn on “\(ExtensionSwitchPreview.displayName(installer.identifier))”, then click Done.",
        ]
    }

    private var footer: String {
        guard installer.state == .needsApproval else { return "" }
        return "\(isOpenConnect ? "AnyConnect VPNs" : isTailnet ? "Tailnets" : "Tunnels") can't connect until you do."
    }
}

/// A small drawing of System Settings' Network Extensions sheet: the app, its extensions with
/// their switches, and the one to turn on highlighted.
struct ExtensionSwitchPreview: View {
    let highlight: String

    /// The name System Settings shows: the extension's CFBundleDisplayName.
    static func displayName(_ identifier: String) -> String {
        let url = Bundle.main.bundleURL.appendingPathComponent("Contents/Library/SystemExtensions/\(identifier).systemextension")
        return shown(Bundle(url: url)?.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String ?? identifier)
    }

    static var appName: String {
        shown((Bundle.main.object(forInfoDictionaryKey: "CFBundleName") as? String ?? "Wombat") + ".app")
    }

    /// Screenshots come from the Debug build but show the release names.
    private static func shown(_ name: String) -> String {
        #if DEBUG
        if DemoMode.isOn { return name.replacingOccurrences(of: "Wombat Debug", with: "Wombat") }
        #endif
        return name
    }

    /// As System Settings shows them: the OpenConnect extension appears only once requested,
    /// and by then the WireGuard one ("Wombat Tunnel") is normally on already.
    private var rows: [String] {
        switch highlight {
        case AppIdentity.openConnectExtensionBundleID: [AppIdentity.extensionBundleID, AppIdentity.openConnectExtensionBundleID]
        case AppIdentity.tailnetExtensionBundleID: [AppIdentity.extensionBundleID, AppIdentity.tailnetExtensionBundleID]
        default: [AppIdentity.extensionBundleID]
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 6) {
                Image(nsImage: NSApp.applicationIconImage).resizable().frame(width: 18, height: 18)
                Text(Self.appName).font(.caption.weight(.semibold))
            }
            .padding(.vertical, 5)
            ForEach(rows, id: \.self) { id in
                Divider()
                HStack(spacing: 6) {
                    Image(systemName: "puzzlepiece.extension.fill")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .frame(width: 18)
                    Text(Self.displayName(id)).font(.caption).lineLimit(1).fixedSize()
                    Spacer(minLength: 12)
                    // The one to turn on is drawn off, with a tag; the others are on already (A6-L5).
                    if id == highlight {
                        Text("Turn on")
                            .font(.caption2.weight(.semibold))
                            .foregroundStyle(.white)
                            .padding(.horizontal, 5).padding(.vertical, 1)
                            .background(Color.accentColor, in: Capsule())
                    }
                    Capsule()
                        .fill(id == highlight ? Color.secondary.opacity(0.35) : Color.accentColor)
                        .frame(width: 22, height: 13)
                        .overlay(alignment: id == highlight ? .leading : .trailing) {
                            Circle().fill(.white).frame(width: 11, height: 11).padding(1)
                        }
                }
                .padding(.vertical, 4)
                .padding(.horizontal, 4)
                .background(id == highlight ? Color.accentColor.opacity(0.12) : .clear, in: RoundedRectangle(cornerRadius: 5))
                .overlay {
                    if id == highlight { RoundedRectangle(cornerRadius: 5).strokeBorder(Color.accentColor, lineWidth: 2) }
                }
            }
        }
        .padding(8)
        .frame(width: 290)
        .background(.background, in: RoundedRectangle(cornerRadius: 8))
        .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(.separator))
    }
}
