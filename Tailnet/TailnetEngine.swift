import Foundation

/// Swift side of the Go engine's C ABI (`Vendor/tailscale-bridge/tailnet.h`). The engine calls
/// back with log lines (already redacted in Go) and network plans, tagged with the token each
/// start was given, so a line from a stopped tunnel can't reach a newer one.
enum TailnetEngine {
    struct Sink {
        let log: (String) -> Void
        let plan: (Data) -> Void
    }

    private static let lock = NSLock()
    nonisolated(unsafe) private static var sinks: [Int64: Sink] = [:]
    nonisolated(unsafe) private static var nextToken: Int64 = 0
    /// Lines from the engine as a whole (token 0), for the process's log.
    nonisolated(unsafe) static var processLog: (String) -> Void = { _ in }

    static func installCallbacks() {
        tsSetCallbacks(nil, { _, token, line in
            guard let line else { return }
            TailnetEngine.deliver(token) { $0.log(String(cString: line)) } orElse: { TailnetEngine.processLog(String(cString: line)) }
        }, { _, token, json in
            guard let json else { return }
            let data = Data(bytes: json, count: strlen(json))
            TailnetEngine.deliver(token) { $0.plan(data) } orElse: {}
        })
    }

    static func register(_ sink: Sink) -> Int64 {
        lock.withLock {
            nextToken += 1
            sinks[nextToken] = sink
            return nextToken
        }
    }

    static func unregister(_ token: Int64) {
        _ = lock.withLock { sinks.removeValue(forKey: token) }
    }

    private static func deliver(_ token: Int64, _ body: (Sink) -> Void, orElse: () -> Void) {
        guard let sink = lock.withLock({ sinks[token] }) else { return orElse() }
        body(sink)
    }

    // MARK: Calls

    struct Failure: LocalizedError {
        let errorDescription: String?
    }

    /// Starts the node. The engine takes ownership of `tunFD` (closed on failure too).
    static func start(stateDirectory: URL, control: String, hostname: String?, acceptDNS: Bool, tunFD: Int32, token: Int64) throws -> Int32 {
        var error: UnsafeMutablePointer<CChar>?
        let handle = stateDirectory.path.withCString { dir in
            control.withCString { control in
                (hostname ?? "").withCString { host in
                    tsStart(dir, control, host, acceptDNS, tunFD, token, &error)
                }
            }
        }
        if handle > 0 { return handle }
        throw Failure(errorDescription: take(error) ?? "The tailnet engine didn't start")
    }

    static func stop(_ handle: Int32) { tsStop(handle) }

    static func status(_ handle: Int32) -> Data? {
        guard let json = tsStatus(handle) else { return nil }
        defer { free(json) }
        return Data(bytes: json, count: strlen(json))
    }

    static func login(_ handle: Int32) throws {
        var error: UnsafeMutablePointer<CChar>?
        if tsLogin(handle, &error) != 0 { throw Failure(errorDescription: take(error) ?? "Sign-in failed") }
    }

    static func logout(_ handle: Int32) throws {
        var error: UnsafeMutablePointer<CChar>?
        if tsLogout(handle, 5000, &error) != 0 { throw Failure(errorDescription: take(error) ?? "Sign-out failed") }
    }

    static func rebind(_ handle: Int32) { tsRebind(handle) }

    static var version: String {
        guard let v = tsVersion() else { return "unknown" }
        defer { free(v) }
        return String(cString: v)
    }

    private static func take(_ s: UnsafeMutablePointer<CChar>?) -> String? {
        guard let s else { return nil }
        defer { free(s) }
        return String(cString: s)
    }
}
