import Foundation

/// The last few hundred engine log lines, for the app's log pane. Unified logging has the full
/// history (`wombat logs`), but reading it from a sandboxed app needs privileges we don't want.
final class RecentLog: @unchecked Sendable {
    private let lock = NSLock()
    private var buffer: [String] = []
    private let capacity = 500
    private let formatter: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()

    func append(_ line: String) {
        lock.lock(); defer { lock.unlock() }
        buffer.append("\(formatter.string(from: Date())) \(line)")
        if buffer.count > capacity { buffer.removeFirst(buffer.count - capacity) }
    }

    func lines() -> [String] {
        lock.lock(); defer { lock.unlock() }
        return buffer
    }
}
