import CryptoKit
import Foundation
import Security

/// What the sign-in hands to the tunnel. The token is a bearer credential for the VPN session:
/// it goes from the app to the OpenConnect extension over XPC and lives only in memory there.
public struct AnyConnectSession: Codable, Equatable, Sendable {
    /// The gateway's session token (the `webvpn` cookie).
    public var cookie: String
    /// The gateway host name, for TLS SNI and the certificate check.
    public var host: String
    public var port: Int
    /// The IP address the sign-in talked to. The tunnel connects to the same one, so a
    /// round-robin name can't land it on a gateway that doesn't know the session.
    public var address: String?
    /// SHA-256 (hex) of the gateway certificate seen during sign-in.
    public var serverCertificateSHA256: String
    public var issued: Date
    /// The STRAP signing key (SEC1, base64) when the sign-in used STRAP: libopenconnect proves
    /// with it, at CONNECT, that the tunnel belongs to this sign-in. A credential, like the token.
    public var strapKey: String?

    public init(cookie: String, host: String, port: Int, address: String?, serverCertificateSHA256: String, issued: Date = Date(), strapKey: String? = nil) {
        self.strapKey = strapKey
        self.cookie = cookie
        self.host = host
        self.port = port
        self.address = address
        self.serverCertificateSHA256 = serverCertificateSHA256
        self.issued = issued
    }

    /// The URL libopenconnect connects to.
    public var connectURL: String {
        let h = host.contains(":") ? "[\(host)]" : host
        return port == 443 ? "https://\(h)/" : "https://\(h):\(port)/"
    }

    public static let maxBytes = 16 * 1024

    /// Rejects anything that couldn't have come from a real sign-in, before the extension uses it.
    public func validate() -> String? {
        guard !cookie.isEmpty, cookie.utf8.count <= 4096,
              cookie.unicodeScalars.allSatisfy({ $0.value > 0x20 && $0.value < 0x7F && $0 != ";" }) else {
            return "Invalid session token"
        }
        guard case .success = OpenConnectFile.validateServer(connectURL) else { return "Invalid gateway" }
        guard (1...65535).contains(port) else { return "Invalid gateway port" }
        if let address, !address.isEmpty, IPAddressRange(address).map({ $0.prefixLength == $0.maxPrefix }) != true {
            return "Invalid gateway address"
        }
        guard OpenConnectFile.normalizeFingerprint(serverCertificateSHA256) == serverCertificateSHA256 else {
            return "Invalid gateway certificate fingerprint"
        }
        if let strapKey {
            guard strapKey.count <= 512, let der = Data(base64Encoded: strapKey), der.first == 0x30,
                  strapKey.unicodeScalars.allSatisfy({ $0.isASCII && $0 != ";" && $0 != " " }) else { return "Invalid STRAP key" }
        }
        return nil
    }
}

/// A sign-in form shown to the user.
public struct AnyConnectPrompt: Equatable, Sendable {
    public let server: String
    public let title: String?
    public let banner: String?
    public let message: String?
    public let error: String?
    public let form: AuthForm
    /// Initial values (the profile's username and group, the server's selections).
    public let prefilled: [String: String]
}

/// The user-facing side of a sign-in. `fill` returns answers by field name, or nil to cancel.
public struct AnyConnectPrompts: Sendable {
    public var fill: @Sendable (AnyConnectPrompt) async -> [String: String]?
    /// Runs SAML/SSO in a browser and returns the token cookie's value; throws to cancel or fail.
    public var singleSignOn: @Sendable (SSORequest) async throws -> String
    /// The system-browser mode: opens the login page in the default browser and returns the
    /// encrypted blob the browser hands to localhost:29786. nil: not available.
    public var externalBrowser: (@Sendable (SSORequest) async throws -> Data)?

    public init(fill: @escaping @Sendable (AnyConnectPrompt) async -> [String: String]?,
                singleSignOn: @escaping @Sendable (SSORequest) async throws -> String,
                externalBrowser: (@Sendable (SSORequest) async throws -> Data)? = nil) {
        self.fill = fill
        self.singleSignOn = singleSignOn
        self.externalBrowser = externalBrowser
    }
}

/// One HTTPS exchange with the gateway, as the sign-in needs it. Redirects are not followed by
/// the transport: the sign-in decides (a POST must stay a POST).
public struct GatewayReply: Sendable {
    public var status: Int
    public var location: String?
    public var body: Data
    /// The webvpn cookie, if the gateway set one (older gateways put the token only there).
    public var webvpnCookie: String?
    public var serverCertificateSHA256: String?
    public var remoteAddress: String?

    public init(status: Int, location: String? = nil, body: Data, webvpnCookie: String? = nil,
                serverCertificateSHA256: String? = nil, remoteAddress: String? = nil) {
        self.status = status
        self.location = location
        self.body = body
        self.webvpnCookie = webvpnCookie
        self.serverCertificateSHA256 = serverCertificateSHA256
        self.remoteAddress = remoteAddress
    }
}

public protocol GatewayTransport: Sendable {
    /// POSTs `body`. `freshConnection` asks for a new TLS connection (so the gateway can ask
    /// for the client certificate again).
    func post(_ url: URL, body: Data, freshConnection: Bool) async throws -> GatewayReply
    /// Ends the transport: connections, cookies and credentials go.
    func invalidate()
    /// The hosts the client certificate may be shown to (the profile's gateway, and where it
    /// redirected before any answer was sent). Others get none (S5B-L2).
    func allowCertificate(for host: String)
}

extension GatewayTransport {
    public func invalidate() {}
    public func allowCertificate(for host: String) {}
}

public enum AnyConnectSignInError: LocalizedError, Equatable {
    case canceled
    case server(String)
    case hostScanRequired
    case externalBrowserRequired
    case externalBrowserRequiredWithPin
    case multipleCertificatesRequired
    case clientCertificateRejected
    case clientCertificateRequired
    case notAnyConnect(String)
    case tooManySteps
    case insecureRedirect(String)
    case http(Int)
    case noSessionToken
    /// The gateway's certificate isn't trusted by macOS (and doesn't match a pin). The user can
    /// choose to pin it after checking the fingerprint with their IT department.
    case untrustedServer(host: String, sha256: String, reason: String)
    case pinMismatch(host: String, sha256: String)
    /// After your answers were sent, the gateway tried to move the sign-in to another host.
    case crossHostRedirect(String)

    public var errorDescription: String? {
        switch self {
        case .canceled: return "Sign-in was canceled"
        case .server(let message): return message
        case .hostScanRequired:
            return "This gateway requires a Cisco host scan (HostScan/CSD). Wombat never runs programs a VPN server sends, so it can't connect to this gateway."
        case .externalBrowserRequired:
            // Only thrown when this VPN's profile turned browser sign-in off (SingleSignOn =
            // window); otherwise Wombat uses the default browser (quality-6 M2).
            return "This gateway only allows single sign-on in your default browser, which is turned off for this VPN. Turn on “Single sign-on in my default browser” under Edit VPN › Advanced, then connect again."
        case .externalBrowserRequiredWithPin:
            // Browser sign-in is never offered with a pin: the browser can't check it (NEW-1).
            return "This gateway only allows single sign-on in your default browser, but this VPN pins the gateway's certificate, and a browser can't check a pin. Ask your IT department for a certificate macOS trusts, or for sign-in without the external browser."
        case .multipleCertificatesRequired:
            return "This gateway needs two certificates (machine and user), which Wombat doesn't support yet."
        case .clientCertificateRejected:
            return "The gateway rejected the client certificate (Certificate Validation Failure). Check that the right certificate is chosen in this VPN's settings."
        case .clientCertificateRequired:
            return "The gateway requires a client certificate. Choose one in this VPN's settings."
        case .notAnyConnect(let detail): return detail
        case .tooManySteps: return "The sign-in took too many steps; the gateway may be misconfigured"
        case .insecureRedirect(let to): return "The gateway redirected to \(to), which isn't https; Wombat stopped there"
        case .http(let status): return "The gateway answered HTTP \(status)"
        case .noSessionToken: return "The gateway accepted the sign-in but sent no session token"
        case .untrustedServer(let host, _, let reason): return "The certificate of \(host) isn't trusted by macOS: \(reason)"
        case .crossHostRedirect(let host):
            return "After you entered your answers, the gateway tried to continue the sign-in on \(host). Wombat stopped there, so nothing was sent to that host."
        case .pinMismatch(let host, let sha256):
            return "The certificate of \(host) (SHA-256 \(sha256.prefix(16))…) doesn't match the one pinned for this VPN. If the gateway's certificate changed, check with your IT department before trusting the new one."
        }
    }
}

/// The AnyConnect sign-in conversation (aggregate auth), independent of the network and UI.
public struct AnyConnectSignIn: Sendable {
    public let profile: OpenConnectProfile
    public let transport: any GatewayTransport
    public let prompts: AnyConnectPrompts
    /// The client certificate was configured, so a request for one can be answered.
    public let hasClientCertificate: Bool
    /// Set when the system browser may be offered to the gateway (the transport sends its keys).
    public let strap: AnyConnectStrap?

    public init(profile: OpenConnectProfile, transport: any GatewayTransport, prompts: AnyConnectPrompts, hasClientCertificate: Bool,
                strap: AnyConnectStrap? = nil) {
        self.profile = profile
        self.transport = transport
        self.prompts = prompts
        self.hasClientCertificate = hasClientCertificate
        // Never advertise the external browser with a pinned certificate (review NEW-1).
        self.strap = strap.flatMap { prompts.externalBrowser == nil || profile.serverCertificate != nil ? nil : $0 }
    }

    static let maxSteps = 24
    static let maxRedirects = 5
    static let maxGroupChanges = 5

    public func run() async throws -> AnyConnectSession {
        defer { transport.invalidate() }  // the cookie store and identity don't outlive the sign-in
        var url = profile.server
        // Once the user's answers have been sent, the sign-in stays on that host: a redirect or
        // form action elsewhere would hand the next answers to a host the user didn't see (S5-L1).
        var answered = false
        func move(to next: URL) throws {
            if answered, next.host(percentEncoded: false)?.lowercased() != url.host(percentEncoded: false)?.lowercased() || next.port != url.port {
                throw AnyConnectSignInError.crossHostRedirect(next.host(percentEncoded: false) ?? next.absoluteString)
            }
            url = next
            if let host = next.host(percentEncoded: false) { transport.allowCertificate(for: host) }
        }
        transport.allowCertificate(for: profile.host)
        var group = profile.group
        var groupChanges = 0
        var redirects = 0
        var body = AnyConnectXML.initRequest(groupAccess: profile.server.absoluteString, groupSelect: group, externalBrowser: strap != nil)
        var fresh = false
        var certificateRequests = 0

        for _ in 0..<Self.maxSteps {
            try Task.checkCancellation()
            let response = try await transport.post(url, body: body, freshConnection: fresh)
            fresh = false

            if (300...399).contains(response.status) {
                guard let location = response.location, let next = URL(string: location, relativeTo: url)?.absoluteURL else {
                    throw AnyConnectSignInError.http(response.status)
                }
                guard next.scheme?.lowercased() == "https" else { throw AnyConnectSignInError.insecureRedirect(next.absoluteString) }
                redirects += 1
                guard redirects <= Self.maxRedirects else { throw AnyConnectSignInError.tooManySteps }
                try move(to: next)
                continue
            }
            guard (200...299).contains(response.status) else { throw AnyConnectSignInError.http(response.status) }

            let reply: AnyConnectReply
            do { reply = try AnyConnectReply.parse(response.body) } catch let f as AnyConnectReply.Failure {
                throw AnyConnectSignInError.notAnyConnect(f.description)
            }
            if reply.hostScanRequested { throw AnyConnectSignInError.hostScanRequired }
            if reply.multipleCertRequested { throw AnyConnectSignInError.multipleCertificatesRequired }

            // The gateway wants a client certificate in the TLS handshake. Some gateways forget to
            // ask on the first connection, so with a certificate configured, try once more on a
            // fresh one; after that (or without one), tell the gateway it failed.
            if reply.clientCertRequested && !reply.certAuthenticated {
                certificateRequests += 1
                if hasClientCertificate && certificateRequests == 1 {
                    fresh = true
                    body = AnyConnectXML.initRequest(groupAccess: profile.server.absoluteString, groupSelect: group, externalBrowser: strap != nil)
                } else if certificateRequests <= (hasClientCertificate ? 2 : 1) {
                    // The gateway may offer another way in (a password form) once it knows.
                    body = AnyConnectXML.initRequest(groupAccess: profile.server.absoluteString, groupSelect: group, clientCertFailed: true, externalBrowser: strap != nil)
                } else {
                    throw hasClientCertificate ? AnyConnectSignInError.clientCertificateRejected : AnyConnectSignInError.clientCertificateRequired
                }
                continue
            }

            if reply.isSuccess {
                guard let token = reply.sessionToken ?? response.webvpnCookie else { throw AnyConnectSignInError.noSessionToken }
                guard let hash = response.serverCertificateSHA256 else { throw AnyConnectSignInError.noSessionToken }
                let host = url.host(percentEncoded: false) ?? profile.host
                return AnyConnectSession(cookie: token, host: host, port: url.port ?? 443,
                                         address: response.remoteAddress, serverCertificateSHA256: hash,
                                         strapKey: strap?.signingKeyForTunnel)
            }

            if let action = reply.form?.action, !action.isEmpty {
                guard let next = URL(string: action, relativeTo: url)?.absoluteURL, next.scheme?.lowercased() == "https" else {
                    throw AnyConnectSignInError.insecureRedirect(action)
                }
                try move(to: next)
            }

            guard let form = reply.form else {
                if reply.error == "Certificate Validation Failure" { throw AnyConnectSignInError.clientCertificateRejected }
                throw AnyConnectSignInError.server(reply.error ?? reply.message ?? "The gateway refused the sign-in")
            }

            // SAML/SSO: a browser produces the token for the form's sso field.
            if let sso = reply.sso, form.fields.contains(where: { $0.kind == .ssoToken }) {
                let external = sso.browserMode?.lowercased() == "external"
                if external && profile.serverCertificate != nil { throw AnyConnectSignInError.externalBrowserRequiredWithPin }
                if external && (strap == nil || prompts.externalBrowser == nil) { throw AnyConnectSignInError.externalBrowserRequired }
                // The flow must end on the gateway itself (ASA and FTD always do): the page that
                // ends it decides whose cookies count as the token, and a hostile gateway could
                // otherwise name the identity provider and collect its session cookie (S5B-H2).
                guard let final = URL(string: sso.finalURL), final.scheme?.lowercased() == "https",
                      final.host(percentEncoded: false)?.lowercased() == url.host(percentEncoded: false)?.lowercased(),
                      (final.port ?? 443) == (url.port ?? 443) else {
                    throw AnyConnectSignInError.notAnyConnect("The gateway's single sign-on doesn't end on the gateway itself (\(URL(string: sso.finalURL)?.host ?? "unknown host")); Wombat stopped")
                }
                let token: String
                do {
                    if external, let strap, let browser = prompts.externalBrowser {
                        // The browser brings back the token encrypted to our STRAP DH key.
                        do { token = try strap.decryptToken(try await browser(sso)) } catch let f as AnyConnectStrap.Failure {
                            throw AnyConnectSignInError.server(f.description)
                        }
                    } else {
                        token = try await prompts.singleSignOn(sso)
                    }
                } catch is CancellationError { throw AnyConnectSignInError.canceled }
                var answers: [(name: String, value: String)] = []
                for field in form.fields {
                    switch field.kind {
                    case .ssoToken: answers.append((field.name, token))
                    case .hidden(let value): answers.append((field.name, value))
                    case .select(let choices, let selected): answers.append((field.name, choices[selected].value))
                    case .text, .password: continue
                    }
                }
                body = AnyConnectXML.authReply(opaque: reply.opaque, answers: answers, externalBrowser: strap != nil)
                answered = true
                continue
            }

            let visible = form.fields.filter { if case .hidden = $0.kind { return false } else { return true } }
            var answers: [String: String] = [:]
            if visible.isEmpty {
                // Nothing to ask: only "authentication complete" may be posted as is.
                guard reply.authenticationComplete else {
                    if reply.error == "Certificate Validation Failure" { throw AnyConnectSignInError.clientCertificateRejected }
                    throw AnyConnectSignInError.server(reply.error ?? reply.message ?? "The gateway refused the sign-in")
                }
            } else {
                // The host this form really comes from (after a redirect it isn't the profile's).
                let shown = url.host(percentEncoded: false).map { h in url.port.map { "\(h):\($0)" } ?? h } ?? profile.displayServer
                let prompt = AnyConnectPrompt(server: shown, title: reply.title, banner: reply.banner,
                                              message: reply.message, error: reply.error, form: form,
                                              prefilled: Self.prefill(form, profile: profile, group: group))
                guard let filled = await prompts.fill(prompt) else { throw AnyConnectSignInError.canceled }
                answers = filled
            }

            // A different group changes the form: start over with that group, like OpenConnect.
            if let groupField = form.fields.first(where: \.isGroupList), case .select(let choices, let selected) = groupField.kind,
               let picked = answers[groupField.name], picked != choices[selected].value,
               choices.contains(where: { $0.value == picked }) {
                groupChanges += 1
                guard groupChanges <= Self.maxGroupChanges else { throw AnyConnectSignInError.tooManySteps }
                group = picked
                url = profile.server
                answered = false
                body = AnyConnectXML.initRequest(groupAccess: profile.server.absoluteString, groupSelect: picked, externalBrowser: strap != nil)
                continue
            }

            var ordered: [(name: String, value: String)] = []
            for field in form.fields {
                switch field.kind {
                case .hidden(let value): ordered.append((field.name, value))
                case .select(let choices, let selected):
                    let value = answers[field.name].flatMap { v in choices.contains { $0.value == v } ? v : nil } ?? choices[selected].value
                    ordered.append((field.name, value))
                case .text, .password, .ssoToken:
                    ordered.append((field.name, answers[field.name] ?? ""))
                }
            }
            body = AnyConnectXML.authReply(opaque: reply.opaque, answers: ordered, externalBrowser: strap != nil)
            answered = true
        }
        throw AnyConnectSignInError.tooManySteps
    }

    static func prefill(_ form: AuthForm, profile: OpenConnectProfile, group: String?) -> [String: String] {
        var values: [String: String] = [:]
        var usernameFilled = false
        for field in form.fields {
            switch field.kind {
            case .text where !usernameFilled && profile.username != nil && field.name.lowercased().contains("user"):
                values[field.name] = profile.username
                usernameFilled = true
            case .select(let choices, let selected):
                if field.isGroupList, let group, let match = choices.first(where: { $0.value == group || $0.label == group }) {
                    values[field.name] = match.value
                } else {
                    values[field.name] = choices[selected].value
                }
            default: continue
            }
        }
        return values
    }
}

// MARK: - URLSession transport

/// The real transport: URLSession with macOS trust evaluation, an optional certificate pin,
/// and the client identity from the keychain (its private key stays there; the TLS stack asks
/// the keychain to sign).
public final class URLSessionGatewayTransport: NSObject, GatewayTransport, URLSessionTaskDelegate, @unchecked Sendable {
    private let pin: String?
    private let identity: SecIdentity?
    private let userAgent: String
    private let cookies: HTTPCookieStorage
    private let lock = NSLock()
    private var session: URLSession!
    private var certificateHash: [String: String] = [:]
    private var untrusted: [String: (sha256: String, reason: String)] = [:]
    private var pinFailures: [String: String] = [:]
    private var remoteAddress: [Int: String] = [:]
    /// Hosts that asked for a client certificate when none is configured: a dropped connection
    /// from them means "certificate required", not a network problem.
    private var wantedCertificate = Set<String>()
    private var certificateHosts = Set<String>()

    /// Only the exact hosts the sign-in actually talks to (the profile gateway, and any host it
    /// redirected to before an answer was sent), so a client certificate is never offered to an
    /// unrelated host. Fuzzy domain matching is avoided: public suffixes (co.uk, github.io) and
    /// IP literals make "same parent domain" unsound (S5D-L2).
    public func allowCertificate(for host: String) {
        lock.withLock { _ = certificateHosts.insert(host.lowercased()) }
    }

    private let strapHeaders: (key: String, dh: String)?

    public init(profile: OpenConnectProfile, identity: SecIdentity?, strap: AnyConnectStrap? = nil) {
        strapHeaders = strap.map { ($0.publicKey, $0.dhPublicKey) }
        pin = profile.serverCertificate
        self.identity = identity
        userAgent = profile.userAgent ?? AnyConnectXML.defaultUserAgent
        let configuration = URLSessionConfiguration.ephemeral
        cookies = configuration.httpCookieStorage ?? HTTPCookieStorage()
        super.init()
        session = makeSession()
    }

    /// A URLSession keeps its delegate (this) alive until invalidated, so the sign-in ends it
    /// explicitly (Q5-M3).
    public func invalidate() {
        let current = lock.withLock { session! }
        current.invalidateAndCancel()
        cookies.removeCookies(since: .distantPast)
    }

    private func makeSession() -> URLSession {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpCookieStorage = cookies
        configuration.httpCookieAcceptPolicy = .always
        configuration.urlCache = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        configuration.timeoutIntervalForRequest = 30
        configuration.tlsMinimumSupportedProtocolVersion = .TLSv12
        configuration.httpMaximumConnectionsPerHost = 1
        // Straight to the gateway: through a proxy the address recorded for the tunnel would be
        // the proxy's (S5-I3), and the tunnel itself never uses one.
        configuration.connectionProxyDictionary = [
            kCFNetworkProxiesHTTPEnable: false, kCFNetworkProxiesHTTPSEnable: false,
            kCFNetworkProxiesSOCKSEnable: false, kCFNetworkProxiesProxyAutoConfigEnable: false,
        ] as [AnyHashable: Any]
        return URLSession(configuration: configuration, delegate: self, delegateQueue: nil)
    }

    public func post(_ url: URL, body: Data, freshConnection: Bool) async throws -> GatewayReply {
        if freshConnection {
            let old = lock.withLock { () -> URLSession in
                let old = session!
                session = makeSession()
                return old
            }
            old.finishTasksAndInvalidate()
        }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.httpBody = body
        request.setValue(userAgent, forHTTPHeaderField: "User-Agent")
        request.setValue("application/xml; charset=utf-8", forHTTPHeaderField: "Content-Type")
        request.setValue("*/*", forHTTPHeaderField: "Accept")
        request.setValue("identity", forHTTPHeaderField: "Accept-Encoding")
        request.setValue("1", forHTTPHeaderField: "X-Transcend-Version")
        request.setValue("1", forHTTPHeaderField: "X-Aggregate-Auth")
        request.setValue(AnyConnectXML.deviceID, forHTTPHeaderField: "X-AnyConnect-Platform")
        if let strapHeaders {
            request.setValue(strapHeaders.key, forHTTPHeaderField: "X-AnyConnect-STRAP-Pubkey")
            request.setValue(strapHeaders.dh, forHTTPHeaderField: "X-AnyConnect-STRAP-DH-Pubkey")
        }
        let host = url.host(percentEncoded: false) ?? ""

        let (bytes, response): (URLSession.AsyncBytes, URLResponse)
        do {
            do {
                (bytes, response) = try await lock.withLock({ session! }).bytes(for: request)
            } catch let error as URLError where error.code == .networkConnectionLost {
                // A kept-alive connection the gateway (or a NAT) closed meanwhile: once more, fresh.
                (bytes, response) = try await lock.withLock({ session! }).bytes(for: request)
            }
        } catch {
            if let pinned = lock.withLock({ pinFailures[host] }) { throw AnyConnectSignInError.pinMismatch(host: host, sha256: pinned) }
            if lock.withLock({ wantedCertificate.contains(host) }), let urlError = error as? URLError,
               [.networkConnectionLost, .secureConnectionFailed, .clientCertificateRequired, .clientCertificateRejected].contains(urlError.code) {
                throw AnyConnectSignInError.clientCertificateRequired
            }
            if let bad = lock.withLock({ untrusted[host] }) { throw AnyConnectSignInError.untrustedServer(host: host, sha256: bad.sha256, reason: bad.reason) }
            if (error as? URLError)?.code == .cancelled { throw CancellationError() }
            throw error
        }
        var data = Data()
        for try await byte in bytes {
            data.append(byte)
            if data.count > XMLTree.maxBytes { throw AnyConnectSignInError.notAnyConnect("The gateway's reply is larger than \(XMLTree.maxBytes / 1024) KB") }
        }
        guard let http = response as? HTTPURLResponse else { throw AnyConnectSignInError.http(0) }
        if http.statusCode == 401, lock.withLock({ wantedCertificate.contains(host) }) { throw AnyConnectSignInError.clientCertificateRequired }
        let webvpn = cookies.cookies(for: url)?.first { $0.name == "webvpn" }?.value
        return lock.withLock {
            GatewayReply(status: http.statusCode, location: http.value(forHTTPHeaderField: "Location"), body: data,
                         webvpnCookie: webvpn, serverCertificateSHA256: certificateHash[host],
                         remoteAddress: remoteAddress.removeValue(forKey: bytes.task.taskIdentifier) ?? Self.literal(host))
        }
    }

    // Redirects come back to the sign-in, which keeps POSTing (URLSession would turn a 302
    // into a GET).
    public func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                           newRequest request: URLRequest) async -> URLRequest? { nil }

    public func urlSession(_ session: URLSession, task: URLSessionTask, didFinishCollecting metrics: URLSessionTaskMetrics) {
        guard let address = metrics.transactionMetrics.last(where: { $0.remoteAddress != nil })?.remoteAddress else { return }
        lock.withLock { remoteAddress[task.taskIdentifier] = address }
    }

    public func urlSession(_ session: URLSession, task: URLSessionTask, didReceive challenge: URLAuthenticationChallenge) async
        -> (URLSession.AuthChallengeDisposition, URLCredential?) {
        let space = challenge.protectionSpace
        switch space.authenticationMethod {
        case NSURLAuthenticationMethodServerTrust:
            guard let trust = space.serverTrust else { return (.cancelAuthenticationChallenge, nil) }
            return evaluate(trust, host: space.host)
        case NSURLAuthenticationMethodClientCertificate:
            // No identity configured: continue without one. Default handling could pick an
            // identity preference and hand your certificate to a gateway you never chose (S5-NV1).
            guard let identity, lock.withLock({ certificateHosts.contains(space.host.lowercased()) }) else {
                lock.withLock { _ = wantedCertificate.insert(space.host) }
                return (.rejectProtectionSpace, nil)
            }
            return (.useCredential, URLCredential(identity: identity, certificates: nil, persistence: .forSession))
        default:
            // HTTP Basic/NTLM and the like: AnyConnect gateways don't use them for aggregate auth.
            return (.performDefaultHandling, nil)
        }
    }

    private func evaluate(_ trust: SecTrust, host: String) -> (URLSession.AuthChallengeDisposition, URLCredential?) {
        guard let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate], let leaf = chain.first else {
            return (.cancelAuthenticationChallenge, nil)
        }
        let hash = Self.sha256Hex(SecCertificateCopyData(leaf) as Data)
        if let pin {
            // A pin accepts exactly that certificate, trusted by macOS or not, and nothing else.
            guard hash == pin else {
                lock.withLock { pinFailures[host] = hash }
                return (.cancelAuthenticationChallenge, nil)
            }
        } else {
            SecTrustSetPolicies(trust, SecPolicyCreateSSL(true, host as CFString))
            var error: CFError?
            guard SecTrustEvaluateWithError(trust, &error) else {
                let reason = (error as Error?)?.localizedDescription ?? "not trusted"
                lock.withLock { untrusted[host] = (hash, reason) }
                return (.cancelAuthenticationChallenge, nil)
            }
        }
        lock.withLock { certificateHash[host] = hash }
        return (.useCredential, URLCredential(trust: trust))
    }

    /// The host itself when it's an IP literal (metrics can be missing; then this is still right).
    static func literal(_ host: String) -> String? {
        let bare = host.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        return IPAddressRange(bare).map { $0.prefixLength == $0.maxPrefix } == true ? bare : nil
    }

    public static func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}
