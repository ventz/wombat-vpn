import Foundation

/// When the app shows or clears a tunnel's error. Kept here, free of NetworkExtension, so
/// `swift test` covers the rules `TunnelStore` follows.
///
/// Trigger (2026-10-23, user report on 1.3.1): an AmneziaWG tunnel showed "Connected" with "The
/// network extension didn't start" under it. The app gave up handing the configuration over
/// after 9 s and wrote that error after the tunnel had already come up, and only a status change
/// cleared it.
public enum TunnelErrorRules {
    /// A tunnel that is up was started by the extension from its current copy (it refuses any
    /// other), so "the extension didn't start" is no longer true: drop that error, keep others.
    public static func error(_ current: String?, tunnelIsUp: Bool, extensionErrors: Set<String>) -> String? {
        guard tunnelIsUp, let current, extensionErrors.contains(current) else { return current }
        return nil
    }

    /// Up from a start made at `start` (nil: none in this run of the app, e.g. connected at
    /// launch). A session that connected before the start is the previous one, still running
    /// the old copy while a stop stalls (review round 1, security L3).
    public static func isUp(since start: Date?, connected: Bool, connectedDate: Date?) -> Bool {
        guard connected else { return false }
        guard let start else { return true }
        return (connectedDate ?? .distantPast) >= start
    }

    /// The extension answered with this tunnel's current copy: "it didn't start" is false.
    public static func errorAfterExtensionAnswered(_ current: String?, extensionErrors: Set<String>) -> String? {
        current.map(extensionErrors.contains) == true ? nil : current
    }

    /// The hand-off gave up on a tunnel that isn't up. An error set during the wait (the
    /// extension's own reason for a failed start, from the connection) says more than "it
    /// didn't start", so it stays (review round 1, quality M2).
    public static func errorAfterGivingUp(_ current: String?, notRunning: String) -> String {
        current ?? notRunning
    }

    /// What a failed connect or disconnect leaves on the tunnel, nil for none. A canceled sign-in
    /// isn't a failure, and a busy one already brought the running sign-in forward: it belongs
    /// to no tunnel, and left on this one it stayed until its next connect.
    public static func shownError(for error: Error) -> String? {
        if error as? AnyConnectSignInError == .canceled || error is SignInBusy { return nil }
        return error.localizedDescription
    }
}

/// Another AnyConnect sign-in is running (one at a time).
public struct SignInBusy: LocalizedError, Equatable {
    public init() {}
    public var errorDescription: String? { "Another sign-in is in progress; finish or cancel it first" }
}

/// The app's hand-off right after a start launched the extension: retry while the extension
/// isn't reachable yet, then report how it ended. Runs on the caller's actor.
public enum LaunchHandOff {
    public enum Outcome: Equatable, Sendable {
        case delivered
        /// The extension answered and refused, or something else failed. Shown even when the
        /// tunnel is up: a refusal, a signature mismatch or a peer that isn't root must not be
        /// quietly dropped (S3-L4; review round 1, security M1).
        case failed(String)
        /// Never reachable, and the tunnel isn't up: the extension really didn't start.
        case extensionNotRunning
        /// Never reachable, but this start brought the tunnel up: the extension started from
        /// its own current copy (it refuses any other), so there is nothing to report.
        case unreachableWhileUp
        /// A later connect or a disconnect replaced this start: its result describes nothing.
        case superseded
    }

    /// Gives up after `attempts` or once `deadline` has passed, whichever comes first: a slow
    /// `deliver` must not stretch the wait past what the extension itself waits (security-8 L2).
    public static func run(attempts: Int, interval: Duration, deadline: Duration? = nil,
                           isolation: isolated (any Actor)? = #isolation,
                           deliver: () async throws -> Void,
                           isUnreachable: (Error) -> Bool,
                           isCurrent: () -> Bool,
                           tunnelIsUp: () -> Bool) async -> Outcome {
        let clock = ContinuousClock()
        let end = deadline.map { clock.now + $0 }
        for _ in 0..<attempts {
            if let end, clock.now >= end { break }
            try? await Task.sleep(for: interval)
            guard isCurrent() else { return .superseded }
            do {
                try await deliver()
                return .delivered
            } catch where isUnreachable(error) {
                continue
            } catch {
                return isCurrent() ? .failed(error.localizedDescription) : .superseded
            }
        }
        // Asked only now: the tunnel may have come up (or gone) during the wait.
        guard isCurrent() else { return .superseded }
        return tunnelIsUp() ? .unreachableWhileUp : .extensionNotRunning
    }
}
