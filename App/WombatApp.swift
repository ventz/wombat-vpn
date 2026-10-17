import AppKit
import Combine
import SwiftUI
import TunnelCore

@main
struct WombatApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var model = AppModel.shared
    @AppStorage(Preferences.Key.showInMenuBar) private var showInMenuBar = true

    init() { Preferences.register() }

    var body: some Scene {
        Window("Wombat", id: "main") {
            ContentView()
                .environmentObject(model)
                .environmentObject(model.store)
                .environmentObject(model.installer)
                .environmentObject(model.openConnectInstaller)
                .frame(minWidth: 760, minHeight: 480)
        }
        .defaultSize(width: 980, height: 620)
        .defaultLaunchBehavior(Preferences.openWindowAtLaunch ? .presented : .suppressed)
        .commands {
            AppCommands(model: model)
            UpdateCommands()
        }

        MenuBarExtra(isInserted: $showInMenuBar) {
            MenuBarContent()
                .environmentObject(model)
                .environmentObject(model.store)
        } label: {
            MenuBarLabel(store: model.store)
        }
        .menuBarExtraStyle(.window)

        Settings {
            SettingsView()
                .environmentObject(model)
                .environmentObject(model.store)
                .environmentObject(model.installer)
                .environmentObject(model.openConnectInstaller)
        }
    }
}

/// App-wide state: the tunnel store, the extension installer and the CLI server.
@MainActor
final class AppModel: ObservableObject {
    static let shared = AppModel()

    let store = TunnelStore()
    let installer = ExtensionInstaller()
    /// Activated only once there is an AnyConnect VPN (TunnelStore.needsOpenConnect).
    let openConnectInstaller = OpenConnectInstaller()
    @Published var pendingImport: [ImportCandidate] = []
    @Published var selection: UUID?
    @Published var showingQR = false
    @Published var showingScanner = false
    /// A configuration the camera read, staged for review once the scanner sheet has closed.
    var scannedConfig: String?
    /// The detail tab, kept when switching tunnels.
    @Published var detailTab: DetailTab = .overview
    @Published var actionError: String?
    /// The AnyConnect add/edit sheet: nil closed, `.new`, or editing a VPN.
    @Published var anyConnectEditor: AnyConnectEditorTarget?

    var selectedTunnel: Tunnel? { store.tunnels.first { $0.id == selection } }

    /// Runs an action on the selected tunnel and surfaces failures in an alert.
    func run(_ action: @escaping (Tunnel) async throws -> Void) {
        guard let tunnel = selectedTunnel else { return }
        Task {
            do { try await action(tunnel) } catch Exporter.Failure.canceled { } catch { actionError = error.localizedDescription }
        }
    }

    /// Clipboard import: configuration text, or an image of a QR code; says so when there's
    /// neither (A-L6).
    func importFromClipboard() {
        let text = NSPasteboard.general.string(forType: .string) ?? ""
        // Text that is a configuration wins; an image copied from a browser can come with its URL.
        if text.range(of: "[Interface]", options: .caseInsensitive) == nil, let data = QRReader.clipboardImageData() {
            Task {
                do {
                    let configs = try await QRReader.configurations(inImageData: data, source: "The clipboard image")
                    present(Self.candidates(configs, base: "QR Code", source: "QR code (clipboard)"))
                } catch {
                    actionError = error.localizedDescription
                }
            }
            return
        }
        guard !text.isEmpty else {
            actionError = "The clipboard has no text or QR code to import. Copy a WireGuard configuration or a picture of its QR code first."
            return
        }
        stageImport(text: text, name: "Clipboard")
    }

    /// Rename with a native alert: focus starts in the field, Return renames, Escape cancels.
    func renameSelected() {
        guard let tunnel = selectedTunnel else { return }
        let alert = NSAlert()
        alert.messageText = "Rename “\(tunnel.name)”"
        let field = NSTextField(string: tunnel.name)
        field.frame = NSRect(x: 0, y: 0, width: 260, height: 24)
        field.setAccessibilityLabel("New name")
        alert.accessoryView = field
        alert.addButton(withTitle: "Rename")
        alert.addButton(withTitle: "Cancel")
        alert.window.initialFirstResponder = field
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        let name = field.stringValue
        guard name != tunnel.name else { return }
        guard !TunnelName.sanitize(name).isEmpty else {
            actionError = "A tunnel needs a name. “\(tunnel.name)” was not renamed."
            return
        }
        // The confirmed tunnel, not whatever is selected when the dialog closes (S3-L3).
        Task {
            do { try await store.rename(tunnel, to: name) } catch { actionError = error.localizedDescription }
        }
    }

    /// Delete behind a confirmation whose default (Return) is Cancel: deleting removes the keys
    /// for good (audit A-M2).
    func deleteSelected() {
        guard let tunnel = selectedTunnel else { return }
        let alert = NSAlert()
        alert.messageText = "Delete “\(tunnel.name)”?"
        alert.informativeText = tunnel.isOpenConnect
            ? "The VPN's profile and its saved single sign-on data are removed. This cannot be undone."
            : "The private key is removed from the keychain now, and from the network extension now or, if it isn't running, the next time it runs. This cannot be undone."
        alert.alertStyle = .warning
        alert.addButton(withTitle: "Cancel")
        let delete = alert.addButton(withTitle: tunnel.isOpenConnect ? "Delete VPN" : "Delete Tunnel and Keys")
        delete.hasDestructiveAction = true
        delete.keyEquivalent = ""
        guard alert.runModal() == .alertSecondButtonReturn else { return }
        // The confirmed tunnel, not whatever is selected when the dialog closes (S3-L3).
        Task {
            do {
                try await store.delete(tunnel)
                selection = store.tunnels.first?.id
            } catch {
                actionError = error.localizedDescription
            }
        }
    }

    func runAll(_ action: @escaping ([Tunnel]) async throws -> Void) {
        let tunnels = store.tunnels
        Task {
            do { try await action(tunnels) } catch Exporter.Failure.canceled { } catch { actionError = error.localizedDescription }
        }
    }
    private var server: ControlServer?
    private lazy var handler = ControlHandler(store: store)
    private var installerObserver: AnyCancellable?

    func start() {
        #if DEBUG
        if DemoMode.isOn { DemoMode.start(self); return }
        #endif
        // Whenever the extension becomes active (first approval, reinstall, update), hand it any
        // configurations it's missing.
        // Each publisher deduplicated on its own: merged first, the second extension's .active
        // could be dropped as a "duplicate" of the first's (Q5-L2).
        installerObserver = installer.$state.removeDuplicates().merge(with: openConnectInstaller.$state.removeDuplicates())
            .filter { $0 == .active }
            .sink { [weak self] _ in
                guard let self else { return }
                Task { await self.store.reload(); await self.store.syncToExtension() }
            }
        store.needsOpenConnect = { [weak self] in self?.openConnectInstaller.activateIfNeeded() }
        store.openConnectBlocker = { [weak self] in
            guard let installer = self?.openConnectInstaller else { return nil }
            // A request already approved answers within moments.
            for _ in 0..<30 where installer.state == .activating || installer.state == .unknown {
                try? await Task.sleep(for: .milliseconds(100))
            }
            switch installer.state {
            case .needsApproval:
                return "Allow “Wombat OpenConnect” first: System Settings › General › Login Items & Extensions › Network Extensions. Then connect again."
            case .requiresApplicationsFolder:
                return "Move Wombat to the Applications folder first: macOS only runs its VPN extensions from there."
            case .failed(let reason):
                return "The AnyConnect extension couldn't be activated: \(reason)"
            default:
                return nil  // active, or still activating: the start itself reports a problem
            }
        }
        // The sign-in shows in the main window, on the VPN's Overview.
        SignInCoordinator.shared.reveal = { [weak self] id in
            guard let self else { return }
            self.selection = id
            self.detailTab = .overview
            MainWindow.show()
        }
        store.signIn = { tunnel, profile in
            try await SignInCoordinator.shared.signIn(tunnelID: tunnel.id, name: tunnel.name, profile: profile)
        }
        store.confirmTrust = { host, sha256, reason in SignInCoordinator.shared.confirmTrust(host: host, sha256: sha256, reason: reason) }
        installer.activate()
        Task { await store.reload() }
        server = ControlServer { [weak self] request in
            guard let self else { return .failure("App is shutting down") }
            return await self.handler.handle(request)
        }
        server?.start()
    }

    func stop() { server?.stop() }

    /// Reads at most `limit` bytes from a regular file, whatever its size claimed a moment ago (it
    /// can grow, or be a FIFO that never ends; audit WOM-11).
    static func readBounded(_ url: URL, limit: Int) throws -> Data {
        guard (try? url.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile) == true else {
            throw StoreError.invalid("\(url.lastPathComponent) is not a regular file")
        }
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        let data = try handle.read(upToCount: limit + 1) ?? Data()
        guard data.count <= limit else { throw StoreError.invalid("\(url.lastPathComponent) is larger than \(limit / 1024) KB") }
        return data
    }

    /// Reads dropped or chosen files (.conf, or a .zip such as the official app's export) and
    /// stages them for the import sheet. Nothing is saved until the user confirms there.
    func stageImport(_ urls: [URL]) {
        Task { await stageImportAsync(urls) }
    }

    private func stageImportAsync(_ urls: [URL]) async {
        guard pendingImport.isEmpty else { return busy() }
        var candidates: [ImportCandidate] = []
        for url in urls {
            do {
                if QRReader.isImage(url) {
                    // Read while we have access; decoded off the main thread after.
                    let data = try Self.withAccess(url) { try Self.readBounded(url, limit: QRReader.maxImageBytes) }
                    let configs = try await QRReader.configurations(inImageData: data, source: url.lastPathComponent)
                    candidates += Self.candidates(configs, base: TunnelName.from(fileName: url.deletingPathExtension().lastPathComponent),
                                                  source: "QR code in \(url.lastPathComponent)")
                    continue
                }
                let accessing = url.startAccessingSecurityScopedResource()
                defer { if accessing { url.stopAccessingSecurityScopedResource() } }
                if url.pathExtension.lowercased() == "zip" {
                    let data = try Self.readBounded(url, limit: ZipReader.maxArchiveBytes)
                    for entry in try ZipReader.confEntries(data) {
                        candidates.append(ImportCandidate(name: TunnelName.from(fileName: entry.name), text: entry.text, source: url.lastPathComponent))
                    }
                } else {
                    let data = try Self.readBounded(url, limit: max(WgQuick.maxBytes, OpenConnectFile.maxBytes))
                    guard let text = String(data: data, encoding: .utf8) else { throw StoreError.invalid("\(url.lastPathComponent) is not UTF-8 text") }
                    candidates.append(ImportCandidate(name: TunnelName.from(fileName: url.lastPathComponent), text: text, source: url.lastPathComponent))
                }
            } catch {
                candidates.append(ImportCandidate(name: TunnelName.from(fileName: url.lastPathComponent), text: "", source: url.lastPathComponent, readError: error.localizedDescription))
            }
        }
        present(candidates)
    }

    func stageImport(text: String, name: String, source: String = "Clipboard") {
        present([ImportCandidate(name: TunnelName.sanitize(name), text: text, source: source)])
    }

    /// Opens the import review, unless one is already open: a new import (a drop, ⇧⌘V, a file
    /// another app opens in Wombat) must not change the list under review (security-5 L2/N4).
    private func present(_ candidates: [ImportCandidate]) {
        guard pendingImport.isEmpty else { return busy() }
        pendingImport = candidates
    }

    private func busy() {
        actionError = "Finish or cancel the import that's open first."
    }

    /// Candidates for the configurations in one picture. Several codes in one picture could hide
    /// a second, unexpected tunnel, so then none starts ticked (security-5 L4).
    private static func candidates(_ configs: [String], base: String, source: String) -> [ImportCandidate] {
        configs.enumerated().map { index, config in
            var candidate = ImportCandidate(name: configs.count > 1 ? "\(base) \(index + 1)" : base, text: config,
                                            source: configs.count > 1 ? "\(source), one of \(configs.count) QR codes" : source)
            candidate.include = configs.count == 1
            return candidate
        }
    }

    private static func withAccess<T>(_ url: URL, _ body: () throws -> T) rethrows -> T {
        let accessing = url.startAccessingSecurityScopedResource()
        defer { if accessing { url.stopAccessingSecurityScopedResource() } }
        return try body()
    }
}

struct ImportCandidate: Identifiable {
    let id = UUID()
    var name: String
    let text: String
    let source: String
    var readError: String?
    var include = true
    /// Parsed and reviewed once, not on every render: a hostile file must not cost per frame.
    let parse: WgQuick.ParseResult
    let findings: [Finding]
    /// Set when the text is an AnyConnect profile instead of a wg-quick file.
    let profile: OpenConnectFile.ParseResult?
    /// The profile's client certificate as named in the keychain (looked up once, not per render).
    let certificateName: String?

    init(name: String, text: String, source: String, readError: String? = nil) {
        self.name = name
        self.text = text
        self.source = source
        self.readError = readError
        if OpenConnectFile.looksLikeProfile(text) {
            profile = OpenConnectFile.parse(text)
            certificateName = profile?.profile?.clientCertificate.map { ClientIdentities.item(sha256: $0)?.name ?? "not in your keychain" }
            parse = WgQuick.parse("")
            findings = []
        } else {
            profile = nil
            certificateName = nil
            parse = WgQuick.parse(text)
            findings = parse.configuration.map(ConfigReview.review) ?? []
        }
        include = readError == nil && isValid
    }

    var isValid: Bool { profile.map { $0.profile != nil } ?? (parse.configuration != nil) }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        MainActor.assumeIsolated {
            Preferences.applyDockPolicy()
            AppModel.shared.start()
            _ = UpdaterModel.shared  // starts Sparkle's scheduled checks
        }
    }

    /// Clicking the Dock icon or opening the app again in Finder brings the window back, also
    /// when the Dock icon is hidden or the window wasn't opened at launch.
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows: Bool) -> Bool {
        MainActor.assumeIsolated {
            // Without a menu bar item nothing has registered an opener: let SwiftUI reopen it.
            guard !hasVisibleWindows, MainWindow.open != nil else { return true }
            MainWindow.show()
            return false
        }
    }

    /// Set by code that quits on purpose (demo captures, a future updater) to skip the question.
    @MainActor static var quitWithoutAsking = false

    /// ⌘Q asks first: it's easy to hit instead of ⌘W, and quitting takes away the menu bar item
    /// and the `wombat` command (tunnels themselves keep running in macOS). Only quits the user
    /// starts in the app ask; logout, restart and scripted quits arrive as an Apple event and
    /// go straight through, so they are never held up.
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        MainActor.assumeIsolated {
            guard !Self.quitWithoutAsking, Preferences.confirmQuit,
                  NSAppleEventManager.shared().currentAppleEvent == nil else { return .terminateNow }
            let connected = AppModel.shared.store.tunnels.filter(\.isActive).map(\.name)
            let alert = NSAlert()
            alert.messageText = "Quit Wombat?"
            // Plain words (user, 2026-10-16: "what does that mean -- on demand rules keep
            // working?"), and true: the CLI relaunches the app itself (Client.startApp).
            let still = connected.isEmpty ? ""
                : "\(ListFormatter.localizedString(byJoining: connected.map { "“\($0)”" })) stays connected. "
            alert.informativeText = still + "Your VPNs run in macOS, not in this app: they keep working, and so do automatic connections and the kill switch. Quitting only removes the menu bar icon."
            alert.addButton(withTitle: "Quit")
            alert.addButton(withTitle: "Cancel")
            alert.showsSuppressionButton = true
            alert.suppressionButton?.title = "Don't ask again"
            NSApp.activate()
            let quit = alert.runModal() == .alertFirstButtonReturn
            if quit, alert.suppressionButton?.state == .on { Preferences.confirmQuit = false }
            return quit ? .terminateNow : .terminateCancel
        }
    }

    func applicationWillTerminate(_ notification: Notification) {
        MainActor.assumeIsolated { AppModel.shared.stop() }
    }

    func application(_ application: NSApplication, open urls: [URL]) {
        MainActor.assumeIsolated { AppModel.shared.stageImport(urls) }
    }

    /// Right-click the Dock icon: every tunnel with a checkmark when connected; choosing one
    /// connects or disconnects it.
    func applicationDockMenu(_ sender: NSApplication) -> NSMenu? {
        // Built on the main actor and handed back as an unchecked value: NSMenu isn't Sendable,
        // which Swift 6 would reject at the assumeIsolated boundary (Q2-L9).
        nonisolated(unsafe) var built: NSMenu?
        MainActor.assumeIsolated {
            let menu = NSMenu()
            let store = AppModel.shared.store
            if store.tunnels.isEmpty {
                menu.addItem(NSMenuItem(title: "No tunnels", action: nil, keyEquivalent: ""))
            }
            for tunnel in store.tunnels {
                // Status in the title, not only a tooltip, so VoiceOver reads it (A-L9).
                let item = NSMenuItem(title: "\(tunnel.name) — \(tunnel.statusText)", action: #selector(toggleFromDock(_:)), keyEquivalent: "")
                item.target = self
                item.representedObject = tunnel.id
                item.state = tunnel.isActive ? .on : .off
                item.toolTip = tunnel.statusText
                menu.addItem(item)
            }
            built = menu
        }
        return built
    }

    @objc private func toggleFromDock(_ sender: NSMenuItem) {
        MainActor.assumeIsolated {
            guard let id = sender.representedObject as? UUID,
                  let tunnel = AppModel.shared.store.tunnels.first(where: { $0.id == id }) else { return }
            Task { await AppModel.shared.store.toggle(tunnel) }
        }
    }

    /// Closing the window keeps the app (and menu bar item) running; tunnels don't depend on it anyway.
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }
}

struct AppCommands: Commands {
    @ObservedObject var model: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some Commands {
        CommandGroup(replacing: .newItem) {
            Button("Import Tunnels…") { ImportPanel.present(model: model) }
                .keyboardShortcut("o")
            Button("Import from Clipboard") {
                model.importFromClipboard()
            }
            .keyboardShortcut("v", modifiers: [.command, .shift])
            Button("Scan QR Code…") { model.showingScanner = true }
            Button("New Tunnel…") { NotificationCenter.default.post(name: .newTunnel, object: nil) }
                .keyboardShortcut("n")
            Divider()
            Button("Export Tunnel…") { model.run { try await Exporter.exportOne($0) } }
                .keyboardShortcut("e", modifiers: [.command, .shift])
                .disabled(model.selectedTunnel == nil)
            Button("Export All Tunnels to Zip…") { model.runAll { try await Exporter.exportAll($0) } }
                .disabled(!model.store.tunnels.contains { !$0.isOpenConnect })  // WireGuard tunnels only
            Button("Show QR Code…") { model.showingQR = true }
                .disabled(model.selectedTunnel == nil || model.selectedTunnel?.isOpenConnect == true)
            Button("Duplicate Tunnel") { model.run { tunnel in model.selection = try await model.store.duplicate(tunnel).id } }
                .keyboardShortcut("d")
                .disabled(model.selectedTunnel == nil)
        }
        CommandGroup(replacing: .appInfo) {
            Button("About Wombat") { AboutPanel.show() }
        }
        // Everything the window offers is also in the menu bar, for keyboard and Voice Control
        // users (audit A-M6).
        CommandMenu("Tunnel") {
            Button(model.selectedTunnel?.isActive == true ? "Disconnect" : "Connect") {
                if let t = model.selectedTunnel { Task { await model.store.toggle(t) } }
            }
            .keyboardShortcut(.return, modifiers: .command)
            .disabled(model.selectedTunnel == nil)
            Divider()
            Button("Rename…") { model.renameSelected() }
                .disabled(model.selectedTunnel == nil)
            Button("Edit Config File…") { model.detailTab = .configFile }
                .disabled(model.selectedTunnel == nil)
            Divider()
            ForEach(Array(DetailTab.allCases.enumerated()), id: \.element) { index, tab in
                Button(tab.rawValue) { model.detailTab = tab }
                    .keyboardShortcut(KeyEquivalent(Character("\(index + 1)")), modifiers: .command)
                    .disabled(model.selectedTunnel == nil)
            }
            Divider()
            Button("Delete Tunnel…") { model.deleteSelected() }
                .keyboardShortcut(.delete, modifiers: .command)
                .disabled(model.selectedTunnel == nil)
        }
    }
}

extension Notification.Name {
    static let newTunnel = Notification.Name("WombatNewTunnel")
}

enum ImportPanel {
    @MainActor
    static func present(model: AppModel) {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = true
        panel.canChooseDirectories = false
        panel.allowedContentTypes = [.init(filenameExtension: "conf")!, .init(filenameExtension: "anyconnect")!, .zip, .png, .jpeg, .heic, .heif, .tiff]
        panel.message = "Choose WireGuard .conf files, a zip of them (such as the official app's “Export Tunnels to Zip”), .anyconnect profiles, or a picture of a QR code."
        if panel.runModal() == .OK { model.stageImport(panel.urls) }
    }
}

/// One list for the About panel and Settings › About (quality-6 L2).
enum Credits {
    static let engines = [
        "WireGuard tunnels: wireguard-go and WireGuardKit (MIT, © WireGuard LLC).",
        "AmneziaWG tunnels: amneziawg-go (MIT, © WireGuard LLC).",
        "AnyConnect VPNs: OpenConnect (LGPL-2.1, © David Woodhouse and contributors) and OpenSSL (Apache-2.0).",
    ]
    static let trademarks = [
        "“WireGuard” and the “WireGuard” logo are registered trademarks of Jason A. Donenfeld. Wombat is not affiliated with or endorsed by the WireGuard project.",
        "Cisco, AnyConnect and Cisco Secure Client are trademarks of Cisco Systems, Inc. Wombat is not affiliated with or endorsed by Cisco.",
    ]
}

enum AboutPanel {
    @MainActor
    static func show() {
        let credits = NSMutableAttributedString()
        let style = NSMutableParagraphStyle()
        style.alignment = .center
        func add(_ text: String, link: String? = nil) {
            var attributes: [NSAttributedString.Key: Any] = [.font: NSFont.systemFont(ofSize: 11), .paragraphStyle: style, .foregroundColor: NSColor.labelColor]
            if let link { attributes[.link] = URL(string: link) }
            credits.append(NSAttributedString(string: text + "\n", attributes: attributes))
        }
        add("© 2026 Ventz Petkov · MIT License")
        add("https://github.com/ventz/wombat-wireguard-mac-app", link: "https://github.com/ventz/wombat-wireguard-mac-app")
        add("")
        for line in Credits.engines { add(line) }
        add("https://www.wireguard.com", link: "https://www.wireguard.com")
        add("https://www.infradead.org/openconnect/", link: "https://www.infradead.org/openconnect/")
        add("")
        for line in Credits.trademarks { add(line) }
        NSApp.activate()
        NSApp.orderFrontStandardAboutPanel(options: [.credits: credits, .version: ""])
    }
}

/// What the AnyConnect sheet edits.
struct AnyConnectEditorTarget: Identifiable {
    let id = UUID()
    /// nil: add a new VPN.
    let tunnelID: UUID?
}
