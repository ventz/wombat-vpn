import Combine
import Sparkle
import SwiftUI

/// In-app updates through Sparkle (same design as Moo's). The app is Developer ID signed and
/// distributed outside the Mac App Store, so Sparkle reads the feed named by SUFeedURL in
/// Info.plist, which must be Wombat's own (wombat.vpetkov.net). Feed and updates are both
/// EdDSA-signed (SURequireSignedFeed, SUPublicEDKey); the private key lives only in the
/// release machine's login keychain (account "wombat").
///
/// The app is sandboxed, so Sparkle downloads and installs through its own XPC services
/// (SUEnableDownloaderService, SUEnableInstallerLauncherService).
enum UpdatePolicy {
    static var permitsUpdates: Bool {
        #if DEBUG
        false
        #else
        // No feed, no updater. Info.plist names Wombat's feed and key, so a fork that ships its
        // own builds must replace SUFeedURL and SUPublicEDKey (or remove SUFeedURL), or its
        // copies would check Wombat's feed (and refuse its updates, signed with another key).
        guard let feed = Bundle.main.object(forInfoDictionaryKey: "SUFeedURL") as? String,
              !feed.trimmingCharacters(in: .whitespaces).isEmpty else { return false }
        return Bundle.main.bundleIdentifier?.hasSuffix(".debug") != true
        #endif
    }
}

/// Settings › General › Updates.
enum UpdateAlertMode: String, CaseIterable, Identifiable {
    case window, dot, off
    var id: Self { self }

    var title: String {
        switch self {
        case .window: return "Show the update window"
        case .dot: return "Only show a dot on the Settings button"
        case .off: return "Don't check"
        }
    }

    static let key = "updatesAlertMode"

    static func current(sparkleChecksAutomatically: Bool) -> UpdateAlertMode {
        UserDefaults.standard.string(forKey: key).flatMap(Self.init(rawValue:))
            ?? (sparkleChecksAutomatically ? .window : .off)
    }

    /// A quiet check is due when there was none yet, or the last one is a day old.
    static func quietCheckIsDue(lastCheck: Date?, now: Date = Date()) -> Bool {
        guard let lastCheck else { return true }
        return now.timeIntervalSince(lastCheck) >= 86_400
    }
}

/// The one updater for the process.
@MainActor
final class UpdaterModel: ObservableObject {
    static let shared = UpdaterModel()

    let controller: SPUStandardUpdaterController
    let updatesEnabled: Bool

    @Published private(set) var canCheckForUpdates = false
    @Published private(set) var lastUpdateCheckDate: Date?
    /// A newer version found and neither installed nor skipped: drives the dot on the gear.
    @Published private(set) var availableUpdate: AvailableUpdate?

    private let delegate = UpdaterDelegate()  // Sparkle holds its delegate weakly
    private var quietCheckTimer: Timer?

    private init() {
        updatesEnabled = UpdatePolicy.permitsUpdates
        controller = SPUStandardUpdaterController(startingUpdater: updatesEnabled, updaterDelegate: delegate, userDriverDelegate: nil)
        delegate.model = self
        #if DEBUG
        // Debug builds never check; this shows the dot: open --env WOMBAT_PREVIEW_UPDATE=9.9.9 …
        if let version = ProcessInfo.processInfo.environment["WOMBAT_PREVIEW_UPDATE"] {
            availableUpdate = AvailableUpdate(feedVersion: version, date: Date())
        }
        #endif
        if updatesEnabled {
            controller.updater.publisher(for: \.canCheckForUpdates).assign(to: &$canCheckForUpdates)
            controller.updater.publisher(for: \.lastUpdateCheckDate).receive(on: DispatchQueue.main).assign(to: &$lastUpdateCheckDate)
            apply(alertMode)
        }
    }

    var updater: SPUUpdater { controller.updater }

    var alertMode: UpdateAlertMode {
        UpdateAlertMode.current(sparkleChecksAutomatically: updater.automaticallyChecksForUpdates)
    }

    func setAlertMode(_ mode: UpdateAlertMode) {
        UserDefaults.standard.set(mode.rawValue, forKey: UpdateAlertMode.key)
        apply(mode)
        objectWillChange.send()
    }

    private func apply(_ mode: UpdateAlertMode) {
        guard updatesEnabled else { return }
        updater.automaticallyChecksForUpdates = mode == .window
        quietCheckTimer?.invalidate()
        quietCheckTimer = nil
        guard mode == .dot else { return }
        // Shortly after launch, then hourly; each only checks once a day.
        DispatchQueue.main.asyncAfter(deadline: .now() + 10) { [weak self] in self?.quietCheckIfDue() }
        let timer = Timer(timeInterval: 3_600, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.quietCheckIfDue() }
        }
        RunLoop.main.add(timer, forMode: .common)
        quietCheckTimer = timer
    }

    private func quietCheckIfDue() {
        guard alertMode == .dot, updater.canCheckForUpdates,
              UpdateAlertMode.quietCheckIsDue(lastCheck: updater.lastUpdateCheckDate) else { return }
        updater.checkForUpdateInformation()  // finds an update without showing a window
    }

    func checkForUpdates() { controller.checkForUpdates(nil) }

    fileprivate func found(_ update: AvailableUpdate) { availableUpdate = update }
    fileprivate func clearAvailableUpdate() { availableUpdate = nil }
}

struct AvailableUpdate: Equatable {
    let version: String
    let date: Date?

    /// The feed's version text is data, even though the feed is signed: control and bidi
    /// characters become spaces and the length is capped, so it can't put instructions in
    /// Wombat's own UI.
    init(feedVersion: String, date: Date?) {
        let cleaned = String(feedVersion.unicodeScalars.map {
            CharacterSet.controlCharacters.contains($0) || $0.properties.generalCategory == .format ? " " : Character($0)
        })
        .split(whereSeparator: \.isWhitespace).joined(separator: " ")
        version = cleaned.isEmpty ? "a new version" : String(cleaned.prefix(32))
        self.date = date
    }

    static var installedVersion: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "?"
    }
}

/// Keeps the dot in step with Sparkle (which still shows its own window). Sparkle calls its
/// delegate on the main thread.
private final class UpdaterDelegate: NSObject, SPUUpdaterDelegate {
    weak var model: UpdaterModel?

    nonisolated func updater(_ updater: SPUUpdater, didFindValidUpdate item: SUAppcastItem) {
        let version = item.displayVersionString
        let date = item.date
        MainActor.assumeIsolated { model?.found(AvailableUpdate(feedVersion: version, date: date)) }
    }

    nonisolated func updaterDidNotFindUpdate(_ updater: SPUUpdater) {
        MainActor.assumeIsolated { model?.clearAvailableUpdate() }
    }

    /// "Remind Me Later" keeps the dot; installing or skipping clears it.
    nonisolated func updater(_ updater: SPUUpdater, userDidMake choice: SPUUserUpdateChoice,
                             forUpdate updateItem: SUAppcastItem, state: SPUUserUpdateState) {
        guard choice != .dismiss else { return }
        MainActor.assumeIsolated { model?.clearAvailableUpdate() }
    }

    /// Installing quits the app: that must not stop at the "Quit Wombat?" question.
    nonisolated func updaterWillRelaunchApplication(_ updater: SPUUpdater) {
        MainActor.assumeIsolated { AppDelegate.quitWithoutAsking = true }
    }
}

struct UpdateCommands: Commands {
    @ObservedObject private var model = UpdaterModel.shared

    var body: some Commands {
        CommandGroup(after: .appInfo) {
            if model.updatesEnabled {
                // Names a waiting update, so it's reachable by keyboard and VoiceOver too.
                Button(model.availableUpdate.map { "Update to Wombat \($0.version)…" } ?? "Check for Updates…") {
                    model.checkForUpdates()
                }
                .disabled(!model.canCheckForUpdates)
            }
        }
    }
}

/// The purple dot on the Settings gear while an update is waiting (Moo's update dot).
struct UpdateDot: View {
    @ObservedObject var model = UpdaterModel.shared
    @State private var showingDetails = false

    var body: some View {
        if let update = model.availableUpdate {
            Button { showingDetails.toggle() } label: {
                Circle()
                    .fill(Color(nsColor: .systemPurple))
                    .overlay(Circle().strokeBorder(Color(nsColor: .labelColor).opacity(0.5), lineWidth: 1))
                    .frame(width: 10, height: 10)
                    .frame(width: 20, height: 20)
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .help("Wombat \(update.version) is available")
            .accessibilityLabel("Update available: Wombat \(update.version)")
            .popover(isPresented: $showingDetails, arrowEdge: .bottom) {
                VStack(alignment: .leading, spacing: 8) {
                    Text("New Update").font(.headline)
                    Text("Wombat \(update.version) is available. You have \(AvailableUpdate.installedVersion).")
                        .fixedSize(horizontal: false, vertical: true)
                    if let date = update.date {
                        Text("Released \(date.formatted(date: .abbreviated, time: .omitted))")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    HStack {
                        Spacer()
                        Button("Show Update…") {
                            showingDetails = false
                            model.checkForUpdates()
                        }
                        .keyboardShortcut(.defaultAction)
                        .disabled(!model.updatesEnabled)
                    }
                }
                .padding(14)
                .frame(width: 260)
            }
        }
    }
}
