import NetworkExtension
import SwiftUI
import TunnelCore
import UniformTypeIdentifiers

struct ContentView: View {
    @EnvironmentObject private var model: AppModel
    @EnvironmentObject private var store: TunnelStore
    @EnvironmentObject private var installer: ExtensionInstaller
    @State private var showingNewTunnel = false
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
                        ExtensionBanner()
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
                    Divider()
                    Button("New Empty Tunnel…") { showingNewTunnel = true }
                } label: {
                    Label("Add Tunnel", systemImage: "plus")
                }
                .help("Import .conf files or a zip (⌘O), or create a new tunnel (⌘N)")
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
        .sheet(isPresented: $showingNewTunnel) {
            NewTunnelSheet()
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

    private var spokenStatus: String {
        if let error = tunnel.lastError { return "\(tunnel.statusText), error: \(error)" }
        if tunnel.status == .connected, let since = tunnel.connectedSince {
            return "Connected " + since.formatted(.relative(presentation: .named))
        }
        if tunnel.isOnDemand && tunnel.status == .disconnected { return "Disconnected, on demand" }
        return tunnel.statusText
    }

    private var subtitle: String {
        if let error = tunnel.lastError { return "Error: \(error)" }
        if tunnel.status == .connected, let since = tunnel.connectedSince {
            return "Connected · " + since.formatted(.relative(presentation: .named))
        }
        if tunnel.isOnDemand && tunnel.status == .disconnected { return "On demand" }
        let detail = tunnel.configuration?.peers.first?.endpoint?.hostString ?? tunnel.statusText
        return tunnel.configuration?.isAmnezia == true ? "AmneziaWG · \(detail)" : detail
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
            Text("Drop .conf files here, import the zip from the official app\n(Manage Tunnels › Export Tunnels to Zip), or create a new tunnel.")
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
            HStack {
                Button("Import…") { ImportPanel.present(model: model) }
                    .keyboardShortcut(.defaultAction)
                Button("New Tunnel…") { showingNewTunnel = true }
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
    @EnvironmentObject private var installer: ExtensionInstaller

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: "exclamationmark.shield.fill")
                .font(.title2)
                .foregroundStyle(.orange)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.headline)
                Text(detail).font(.callout).foregroundStyle(.secondary)
            }
            .accessibilityElement(children: .combine)
            Spacer()
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
        case .needsApproval: return "Allow the Wombat network extension"
        case .requiresApplicationsFolder: return "Move Wombat to the Applications folder"
        case .failed: return "The network extension could not be activated"
        default: return ""
        }
    }

    private var detail: String {
        switch installer.state {
        case .needsApproval:
            // The exact clicks, matching macOS 15+ (verified 2026-10-14): the switch is behind the ⓘ.
            let app = (Bundle.main.object(forInfoDictionaryKey: "CFBundleName") as? String ?? "Wombat") + ".app"
            return "In System Settings › General › Login Items & Extensions, scroll to Extensions, choose By Category, click ⓘ next to Network Extensions, turn on \(app), then click Done. Tunnels can't connect until you do."
        case .requiresApplicationsFolder:
            return "macOS only runs network extensions for apps in /Applications."
        case .failed(let message):
            return message
        default:
            return ""
        }
    }
}
