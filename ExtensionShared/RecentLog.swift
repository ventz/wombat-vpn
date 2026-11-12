import Foundation
#if canImport(TunnelCore)
import TunnelCore
#endif

/// The last few hundred engine log lines, for the app's log pane and Save Diagnostics. Unified
/// logging has the full history (`wombat logs`), but its useful lines are private there, and
/// reading it from a sandboxed app needs privileges we don't want.
///
/// Every line is scrubbed on the way in (`LogScrubber`): what is stored here can end up in a
/// diagnostics file attached to a public issue.
final class RecentLog: @unchecked Sendable {
    private let lock = NSLock()
    private var buffer: [String] = []
    private var capacity = 500
    private let formatter: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()

    /// "Wombat 1.4.1 (39), macOS 27.0.1": the first line of every start, so a log pasted into an
    /// issue says which build and system produced it.
    static var versionLine: String {
        let info = Bundle.main.infoDictionary
        let os = ProcessInfo.processInfo.operatingSystemVersion
        return "Wombat \(info?["CFBundleShortVersionString"] as? String ?? "?") (\(info?["CFBundleVersion"] as? String ?? "?")), macOS \(os.majorVersion).\(os.minorVersion).\(os.patchVersion)"
    }

    /// Debug logging (Settings › Troubleshooting) keeps more lines: the engine says more.
    func setDebug(_ on: Bool) {
        lock.lock(); defer { lock.unlock() }
        capacity = on ? 3000 : 500
    }

    func append(_ line: String) {
        let clean = LogScrubber.scrub(line)
        lock.lock(); defer { lock.unlock() }
        buffer.append("\(formatter.string(from: Date())) \(clean)")
        if buffer.count > capacity { buffer.removeFirst(buffer.count - capacity) }
    }

    func lines() -> [String] {
        lock.lock(); defer { lock.unlock() }
        return buffer
    }
}
