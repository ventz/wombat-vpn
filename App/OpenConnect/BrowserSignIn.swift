import AppKit
import Foundation
import Network
import TunnelCore

/// Single sign-on in the default browser (Cisco's "external browser" mode). The gateway's login
/// page opens in Safari, Chrome or whatever the user uses (passkeys, password managers and an
/// existing identity-provider session work there), and when it's done the browser is sent to
/// `http://localhost:29786/api/sso/<blob>?return=<page>`. The blob is the token, encrypted to
/// this sign-in's STRAP key, so another process that reached the port couldn't use one it made
/// up, and a captured one is useless without the key.
///
/// The listener is on 127.0.0.1 only, lives only while the browser step is open, accepts one
/// well-formed request whose blob decrypts, and answers everything else with 404. All network
/// work runs on a private serial queue (not the main queue), so a modal on the main thread — a
/// CLI approval or a trust prompt — can't stall the browser's answer (audit S5D-L1, pitfall 17).
final class BrowserSignIn: @unchecked Sendable {
    static let port: NWEndpoint.Port = 29786
    static let maxConnections = 8

    struct Failure: LocalizedError {
        let errorDescription: String?
    }

    // All of the following are touched only on `queue`.
    private let queue = DispatchQueue(label: "net.vpetkov.wombat.browsersignin")
    private var listeners: [NWListener] = []
    private var connections: [ObjectIdentifier: NWConnection] = [:]
    private var answering = Set<ObjectIdentifier>()
    private var failedListeners = 0
    private var readyListeners = 0
    private var openedLoginPage = false
    private var continuation: CheckedContinuation<Data, Error>?
    private var done = false

    /// True for a blob that decrypts with this sign-in's key: anything else (a stray or forged
    /// request) gets a 404 and the listener keeps waiting (the one-shot can't be wasted).
    private let accepts: @Sendable (Data) -> Bool
    /// Opens the login page; the default browser unless a test replaces it.
    private let open: @Sendable (URL) -> Void
    private let gatewayHost: String?
    private let request: SSORequest
    /// A sign-in left open in the browser would otherwise hold the one-at-a-time sign-in (and
    /// the port) until Cancel: "Another sign-in is in progress" on every later connect.
    private let timeout: DispatchTimeInterval

    init(request: SSORequest, accepts: @escaping @Sendable (Data) -> Bool = { _ in true },
         timeout: DispatchTimeInterval = .seconds(timeoutMinutes * 60),
         open: @escaping @Sendable (URL) -> Void = { url in DispatchQueue.main.async { NSWorkspace.shared.open(url) } }) {
        self.open = open
        self.timeout = timeout
        self.accepts = accepts
        self.request = request
        gatewayHost = URL(string: request.finalURL)?.host?.lowercased()
    }

    static let timeoutMinutes = 10
    static let timedOut = "The sign-in in the browser wasn't finished within \(timeoutMinutes) minutes. Connect again to start over."

    private static let portBusy =
        "Wombat couldn't listen on localhost port 29786 for the browser's answer. Another VPN client (Cisco Secure Client) may be using it; quit it, or sign in with Wombat's window (Edit VPN › Advanced)."

    /// Opens the login page and waits for the browser to come back (or `cancel()`).
    func run() async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            queue.async { [self] in
                // Canceled before this block ran: finish() found no continuation to resume, and
                // listening now would hold the port and the sign-in forever (review round 1, S-L5).
                if self.done { return continuation.resume(throwing: CancellationError()) }
                self.continuation = continuation
                do {
                    try self.listen()
                } catch {
                    return self.finish(.failure(Failure(errorDescription: Self.portBusy)))
                }
                // finish() runs once, so a timer firing after an answer or a cancel does nothing.
                // Weak, so a finished sign-in isn't kept for the rest of the timeout.
                let timedOut = Failure(errorDescription: Self.timedOut)
                // Wall clock: DispatchTime stops while the Mac sleeps (like pitfall 6), and a lid
                // closed overnight would otherwise not count.
                self.queue.asyncAfter(wallDeadline: .now() + self.timeout) { [weak self] in self?.finish(.failure(timedOut)) }
                // The page opens once the listener is ready (stateUpdateHandler): opened before,
                // a process already holding the port could still receive the browser's answer
                // while Wombat reports the port as busy (review NEW-10).
            }
        }
    }

    func openLoginPage() { open(request.loginURL) }

    func cancel() { queue.async { self.finish(.failure(CancellationError())) } }

    // MARK: On `queue`

    private func listen() throws {
        // 127.0.0.1 only. Tested 2026-10-16: a Network.framework listener on [::1] refuses
        // 127.0.0.1, and once either is bound the other fails with "Address already in use"
        // (address reuse would let another process share the port). The IPv4 loopback works for a
        // gateway that names 127.0.0.1, and a browser sent to "localhost" falls back to it after
        // [::1] refuses (quality-6 L9).
        for host in ["127.0.0.1"] {
            let parameters = NWParameters.tcp
            parameters.requiredLocalEndpoint = .hostPort(host: NWEndpoint.Host(host), port: Self.port)
            parameters.acceptLocalOnly = true
            if let ip = parameters.defaultProtocolStack.internetProtocol as? NWProtocolIP.Options {
                ip.version = host.contains(":") ? .v6 : .v4
            }
            let listener = try NWListener(using: parameters)
            listener.newConnectionHandler = { [weak self] connection in self?.accept(connection) }
            // Port taken (another VPN client) or loopback unavailable: fail now, not wait forever.
            listener.stateUpdateHandler = { [weak self] state in
                guard let self else { return }
                switch state {
                case .ready:
                    self.readyListeners += 1
                    if self.readyListeners == self.listeners.count, !self.openedLoginPage, !self.done {
                        self.openedLoginPage = true
                        self.open(self.request.loginURL)
                    }
                case .failed:
                    self.failedListeners += 1
                    if self.failedListeners >= self.listeners.count {
                        self.finish(.failure(Failure(errorDescription: Self.portBusy)))
                    }
                default: break
                }
            }
            listener.start(queue: queue)
            listeners.append(listener)
        }
    }

    private func accept(_ connection: NWConnection) {
        // A few at a time, each with a deadline: stray local connections can't pile up.
        guard !done, connections.count < Self.maxConnections else { connection.cancel(); return }
        let key = ObjectIdentifier(connection)
        connections[key] = connection
        connection.start(queue: queue)
        queue.asyncAfter(deadline: .now() + 10) { [weak self, weak connection] in
            guard let self, let connection else { return }
            connection.cancel()
            self.connections[ObjectIdentifier(connection)] = nil
        }
        read(connection, Data())
    }

    /// Reads until the end of the headers (a request can arrive in pieces), at most 8 KB.
    private func read(_ connection: NWConnection, _ received: Data) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 8192 - received.count) { [weak self] data, _, complete, error in
            guard let self else { connection.cancel(); return }
            let all = received + (data ?? Data())
            if all.range(of: Data("\r\n\r\n".utf8)) == nil && !complete && error == nil && all.count < 8192 {
                return self.read(connection, all)
            }
            guard let blob = self.handle(all, on: connection) else { return }
            self.finish(.success(blob))
        }
    }

    /// Returns the blob for a valid request (after answering it), nil otherwise (after a 404).
    private func handle(_ data: Data, on connection: NWConnection) -> Data? {
        let notFound = "HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
        let text = String(decoding: data.prefix(8192), as: UTF8.self)
        let lines = text.components(separatedBy: "\r\n")
        guard let line = lines.first, line.hasPrefix("GET /api/sso/"), line.hasSuffix(" HTTP/1.1") || line.hasSuffix(" HTTP/1.0") else {
            respond(connection, notFound)
            return nil
        }
        // The browser names localhost here; a page that rebinds its own name to 127.0.0.1 would
        // send its own host instead (DNS rebinding).
        let hostHeader = lines.dropFirst().first { $0.lowercased().hasPrefix("host:") }?
            .dropFirst(5).trimmingCharacters(in: .whitespaces).lowercased()
        let allowedHosts: Set<String> = ["localhost:29786", "127.0.0.1:29786", "[::1]:29786", "localhost", "127.0.0.1", "[::1]"]
        guard let hostHeader, allowedHosts.contains(hostHeader) else {
            respond(connection, notFound)
            return nil
        }
        let target = line.dropFirst("GET /api/sso/".count).dropLast(" HTTP/1.1".count)
        let parts = target.split(separator: "?", maxSplits: 1)
        guard let encoded = parts.first.map(String.init)?.removingPercentEncoding,
              let blob = Data(base64Encoded: Self.padded(encoded)), !blob.isEmpty, accepts(blob) else {
            respond(connection, notFound)
            return nil
        }
        // Back to the gateway's own success page, never anywhere else (an open redirect would let
        // a forged request send the browser to any site), and never a value that could inject a
        // header line.
        var location: String?
        if parts.count == 2 {
            for item in parts[1].split(separator: "&") where item.hasPrefix("return=") {
                if let value = String(item.dropFirst(7)).removingPercentEncoding,
                   // Scalars, not Characters: "\r\n" is one Character and would slip a Character
                   // equality check (project pitfall 1); a CR or LF must never reach the header.
                   !value.unicodeScalars.contains(where: { $0 == "\r" || $0 == "\n" }), let url = URL(string: value),
                   url.scheme == "https", url.host?.lowercased() == gatewayHost {
                    location = url.absoluteString
                }
            }
        }
        if let location {
            respond(connection, "HTTP/1.1 302 Found\r\nConnection: close\r\nContent-Length: 0\r\nLocation: \(location)\r\n\r\n")
        } else {
            let page = "<!doctype html><title>Signed in</title><p style=\"font-family:-apple-system;margin:3em\">Signed in. You can close this tab and return to Wombat.</p>"
            respond(connection, "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: \(page.utf8.count)\r\n\r\n\(page)")
        }
        return blob
    }

    private func respond(_ connection: NWConnection, _ response: String) {
        let key = ObjectIdentifier(connection)
        answering.insert(key)
        connection.send(content: Data(response.utf8), completion: .contentProcessed { [weak self] _ in
            connection.cancel()
            self?.queue.async {
                self?.connections[key] = nil
                self?.answering.remove(key)
            }
        })
    }

    static func padded(_ base64: String) -> String {
        let normalized = base64.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        return normalized + String(repeating: "=", count: (4 - normalized.count % 4) % 4)
    }

    private func finish(_ result: Result<Data, Error>) {
        guard !done else { return }
        done = true
        for listener in listeners { listener.cancel() }
        listeners = []
        // Idle and half-read connections go; one being answered closes itself after its send.
        for (key, connection) in connections where !answering.contains(key) { connection.cancel() }
        connections = connections.filter { answering.contains($0.key) }
        continuation?.resume(with: result)
        continuation = nil
    }
}
