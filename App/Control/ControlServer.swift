import Darwin
import Foundation
import os
import Security
import TunnelCore

/// Serves the `wombat` CLI over a Unix socket in the app group container.
///
/// Who may connect: the socket file is 0600 inside a per-user container, the peer's uid must be
/// ours, and the peer must be the Wombat CLI signed by our team (checked against its audit token,
/// so a process can't pass off another binary's identity). What it may do without asking:
/// read status and connect/disconnect. Adding a tunnel or exporting keys asks the user in the app.
final class ControlServer: @unchecked Sendable {
    typealias Handler = @MainActor (Control.Request) async -> Control.Response

    private let log = Logger(subsystem: AppIdentity.logSubsystem, category: "control")
    private let queue = DispatchQueue(label: "control-server")
    /// Each client is served on its own work item with one overall deadline, so a slow or
    /// stuck client can't hold up the others. At most `maxClients` at once.
    private let clients = DispatchSemaphore(value: 8)
    private static let requestDeadline: TimeInterval = 5
    private var listenFD: Int32 = -1
    private var source: DispatchSourceRead?
    private let handler: Handler
    let socketURL: URL

    init?(handler: @escaping Handler) {
        guard let container = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: AppIdentity.appGroup) else {
            return nil
        }
        socketURL = container.appendingPathComponent(Control.socketName)
        self.handler = handler
    }

    func start() {
        let path = socketURL.path
        guard path.utf8.count < MemoryLayout.size(ofValue: sockaddr_un().sun_path) else {
            log.error("Socket path too long: \(path, privacy: .public)")
            return
        }
        unlink(path)
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return }
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutableBytes(of: &address.sun_path) { buffer in
            _ = path.withCString { strlcpy(buffer.baseAddress!.assumingMemoryBound(to: CChar.self), $0, buffer.count) }
        }
        let oldMask = umask(0o077)  // the socket file is created 0600
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        umask(oldMask)
        guard bound == 0, listen(fd, 8) == 0 else {
            log.error("Control socket bind/listen failed: \(errno, privacy: .public)")
            close(fd)
            return
        }
        listenFD = fd
        let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
        source.setEventHandler { [weak self] in self?.acceptClient() }
        source.setCancelHandler { close(fd) }
        source.resume()
        self.source = source
        log.notice("Control socket listening")
    }

    func stop() {
        source?.cancel()
        source = nil
        unlink(socketURL.path)
    }

    private func acceptClient() {
        let client = accept(listenFD, nil, nil)
        guard client >= 0 else { return }
        // Before any write, so a client that already hung up can't raise SIGPIPE (Q2-L2).
        var on: Int32 = 1
        setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &on, socklen_t(MemoryLayout<Int32>.size))
        guard clients.wait(timeout: .now()) == .success else {
            reply(client, .failure("Too many concurrent requests"))
            return
        }
        DispatchQueue.global(qos: .userInitiated).async { self.serve(client) }
    }

    private func serve(_ client: Int32) {
        var released = false
        func done() { if !released { released = true; clients.signal() } }
        // Short per-read timeout; readRequest enforces the overall deadline between reads.
        var timeout = timeval(tv_sec: 1, tv_usec: 0)
        setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))

        if let reason = Self.rejectReason(client) {
            log.error("Rejected control client: \(reason, privacy: .public)")
            reply(client, .failure("Rejected: \(reason)"))
            return done()
        }
        guard let data = readRequest(client, deadline: Date().addingTimeInterval(Self.requestDeadline)) else {
            reply(client, .failure("Malformed, oversized or too slow request"))
            return done()
        }
        // The request is read: free the reading slot even if the handler waits for the user, but
        // cap requests still being handled, so waiting ones can't pile up sockets and work
        // without bound (audit WOM-12).
        done()
        guard Self.pending.enter() else {
            reply(client, .failure("Too many requests are waiting; try again"))
            return
        }
        guard let request = try? Control.decode(Control.Request.self, from: data) else {
            reply(client, .failure("Could not decode request"))
            return
        }
        guard request.v == Control.protocolVersion else {
            reply(client, .failure("Protocol version \(request.v) is not supported (app speaks \(Control.protocolVersion)); update the CLI or the app"))
            return
        }
        let handler = self.handler
        Task { @MainActor in
            let response = await handler(request)
            DispatchQueue.global(qos: .userInitiated).async {
                self.reply(client, response)
                Self.pending.leave()
            }
        }
    }

    private func readRequest(_ fd: Int32, deadline: Date) -> Data? {
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 16 * 1024)
        while data.count <= Control.maxMessageBytes {
            guard Date() < deadline else { return nil }
            let n = read(fd, &buffer, buffer.count)
            if n < 0 { if errno == EAGAIN || errno == EINTR { continue }; return nil }
            if n == 0 { break }
            data.append(buffer, count: n)
            if let newline = data.firstIndex(of: 0x0A) { return data.prefix(upTo: newline) }
        }
        return data.count <= Control.maxMessageBytes && !data.isEmpty ? data : nil
    }

    private func reply(_ fd: Int32, _ response: Control.Response) {
        if var data = try? Control.encode(response) {
            data.append(0x0A)
            data.withUnsafeBytes { raw in
                var offset = 0
                while offset < raw.count {
                    let n = write(fd, raw.baseAddress! + offset, raw.count - offset)
                    if n <= 0 { break }
                    offset += n
                }
            }
        }
        close(fd)
    }

    // MARK: Peer verification

    /// nil when the peer is our CLI running as this user.
    static func rejectReason(_ fd: Int32) -> String? {
        PeerCheck.rejectReason(fd, requirement: CodeSigning.cli, expected: "the \(AppIdentity.appBundleID) CLI")
    }
}

extension ControlServer {
    /// Requests being handled (after reading), across all clients.
    fileprivate static let pending = PendingCounter(limit: 16)
}

private final class PendingCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0
    private let limit: Int
    init(limit: Int) { self.limit = limit }
    func enter() -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard count < limit else { return false }
        count += 1
        return true
    }
    func leave() {
        lock.lock(); defer { lock.unlock() }
        count = max(0, count - 1)
    }
}
