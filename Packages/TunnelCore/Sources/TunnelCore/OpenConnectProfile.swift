import Foundation

/// A Cisco AnyConnect (OpenConnect) VPN as Wombat stores it. Unlike a wg-quick file it holds no
/// secret: the user signs in each time (password, Duo, SAML/SSO or a client certificate), and
/// the server hands back a session token that only ever lives in memory.
///
///     [AnyConnect]
///     Server = https://vpn.example.edu/staff
///     Group = Staff
///     Username = jdoe
///     ClientCertificate = sha256:3f2a…
///     ServerCertificate = sha256:9b1c…
///     DTLS = on
public struct OpenConnectProfile: Equatable, Sendable {
    /// The gateway, https only. A path selects a group URL (`https://vpn.example.edu/staff`).
    public var server: URL
    /// The group (tunnel group) to pick when the server offers a list.
    public var group: String?
    /// Filled into the first username field, so only the password needs typing.
    public var username: String?
    /// SHA-256 of the client certificate (DER) to present, looked up among the login
    /// keychain's identities. Its private key never leaves the keychain.
    public var clientCertificate: String?
    /// SHA-256 of the server's certificate (DER), for a gateway whose certificate macOS doesn't
    /// trust (self-signed or a private CA). With a pin, only that exact certificate is accepted.
    public var serverCertificate: String?
    /// Some gateways only answer clients that call themselves AnyConnect.
    public var userAgent: String?
    /// DTLS (UDP) carries traffic faster; off forces TLS only, for networks that block UDP.
    public var dtls: Bool
    /// Single sign-on in the default browser when the gateway allows it (passkeys, password
    /// managers, an existing identity-provider session); off: always Wombat's sign-in window.
    public var ssoInBrowser: Bool

    /// Whether sign-in may go through the default browser. Never with a pinned certificate: the
    /// browser knows nothing of the pin, so it would post the SAML assertion to whoever answered
    /// (review NEW-1). Wombat's own sign-in view enforces the pin.
    public var usesBrowserSignIn: Bool { ssoInBrowser && serverCertificate == nil }

    public init(server: URL, group: String? = nil, username: String? = nil, clientCertificate: String? = nil,
                serverCertificate: String? = nil, userAgent: String? = nil, dtls: Bool = true, ssoInBrowser: Bool = true) {
        self.server = server
        self.group = group
        self.username = username
        self.clientCertificate = clientCertificate
        self.serverCertificate = serverCertificate
        self.userAgent = userAgent
        self.dtls = dtls
        self.ssoInBrowser = ssoInBrowser
    }

    /// The gateway's host name (or IP literal, without brackets).
    public var host: String { server.host(percentEncoded: false) ?? "" }
    public var port: Int { server.port ?? 443 }
    /// "vpn.example.edu" or "vpn.example.edu:8443", for lists and System Settings.
    public var displayServer: String { port == 443 ? host : "\(host):\(port)" }
}

/// Parses and writes the `[AnyConnect]` profile format.
public enum OpenConnectFile {
    public struct ParseResult: Sendable {
        public let profile: OpenConnectProfile?
        public let diagnostics: [Diagnostic]
        public var errors: [Diagnostic] { diagnostics.filter { $0.severity == .error } }
    }

    public static let section = "[AnyConnect]"
    /// Real profiles are a few hundred bytes.
    public static let maxBytes = 16 * 1024
    public static let maxFieldLength = 256
    public static let maxServerLength = 2048

    /// Keys of other clients' hooks. A profile must never make Wombat run a program (CLAUDE.md
    /// constraint 2), so these are refused by name rather than ignored as unknown.
    static let hookKeys: Set<String> = ["script", "vpncscript", "csdwrapper", "csd-wrapper", "csdwrapperscript", "hostscan", "postup", "preup", "postdown", "predown"]

    /// Whether `text` is meant to be an AnyConnect profile (its first section is `[AnyConnect]`),
    /// so importers can tell it from a wg-quick file before parsing either.
    public static func looksLikeProfile(_ text: String) -> Bool {
        for raw in text.split(whereSeparator: \.isNewline).prefix(200) {
            var line = Substring(raw)
            if let hash = line.firstIndex(of: "#") { line = line[..<hash] }
            let trimmed = line.trimmingCharacters(in: .whitespaces).replacingOccurrences(of: "\u{FEFF}", with: "")
            if trimmed.isEmpty { continue }
            return trimmed.lowercased() == section.lowercased()
        }
        return false
    }

    public static func parse(_ text: String) -> ParseResult {
        var diagnostics: [Diagnostic] = []
        func error(_ line: Int?, _ message: String) { diagnostics.append(Diagnostic(.error, line: line, message)) }
        guard text.utf8.count <= maxBytes else {
            error(nil, "Profile is larger than \(maxBytes / 1024) KB")
            return ParseResult(profile: nil, diagnostics: diagnostics)
        }

        var inSection = false
        var sections = 0
        var values: [String: (value: String, line: Int)] = [:]
        let known: Set<String> = ["server", "group", "username", "clientcertificate", "servercertificate", "useragent", "dtls", "singlesignon"]

        let text = text.hasPrefix("\u{FEFF}") ? String(text.dropFirst()) : text
        for (index, rawLine) in text.split(omittingEmptySubsequences: false, whereSeparator: \.isNewline).enumerated() {
            let lineNumber = index + 1
            var line = Substring(rawLine)
            if let hash = line.firstIndex(of: "#") { line = line[..<hash] }
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty { continue }
            if trimmed.unicodeScalars.contains(where: { ($0.value < 0x20 && $0 != "\t") || (0x7F...0x9F).contains($0.value) || $0.properties.generalCategory == .format }) {
                error(lineNumber, "Line contains control or invisible formatting characters")
                continue
            }
            if trimmed.hasPrefix("[") {
                if trimmed.lowercased() == section.lowercased() {
                    sections += 1
                    if sections > 1 { error(lineNumber, "Only one \(section) section is allowed") }
                    inSection = true
                } else {
                    error(lineNumber, "Unknown section \(trimmed)")
                    inSection = false
                }
                continue
            }
            guard let equals = trimmed.firstIndex(of: "=") else {
                error(lineNumber, "Expected \"Key = Value\"")
                continue
            }
            let key = trimmed[..<equals].trimmingCharacters(in: .whitespaces)
            let value = trimmed[trimmed.index(after: equals)...].trimmingCharacters(in: .whitespaces)
            let lowered = key.lowercased()
            guard inSection else { error(lineNumber, "\"\(key)\" is outside the \(section) section"); continue }
            if hookKeys.contains(lowered) {
                error(lineNumber, "\(key): Wombat never runs scripts or host-scan programs for a VPN")
                continue
            }
            guard known.contains(lowered) else { error(lineNumber, "Unknown key \"\(key)\""); continue }
            guard values[lowered] == nil else { error(lineNumber, "\(key) is given twice"); continue }
            guard !value.isEmpty else { error(lineNumber, "\(key) has no value"); continue }
            values[lowered] = (value, lineNumber)
        }
        if sections == 0 { error(nil, "Missing \(section) section") }

        var server: URL?
        if let (text, line) = values["server"] {
            switch validateServer(text) {
            case .success(let url): server = url
            case .failure(let problem): error(line, problem.message)
            }
        } else if sections > 0 {
            error(nil, "Server is required")
        }

        func field(_ key: String, _ name: String) -> String? {
            guard let (value, line) = values[key] else { return nil }
            guard value.count <= maxFieldLength else { error(line, "\(name) is longer than \(maxFieldLength) characters"); return nil }
            return value
        }
        func fingerprint(_ key: String, _ name: String) -> String? {
            guard let (value, line) = values[key] else { return nil }
            guard let normalized = normalizeFingerprint(value) else {
                error(line, "\(name) must be \"sha256:\" followed by 64 hex digits")
                return nil
            }
            return normalized
        }
        let group = field("group", "Group")
        let username = field("username", "Username")
        let userAgent = field("useragent", "UserAgent")
        let client = fingerprint("clientcertificate", "ClientCertificate")
        let pin = fingerprint("servercertificate", "ServerCertificate")
        var dtls = true
        if let (value, line) = values["dtls"] {
            switch value.lowercased() {
            case "on", "yes", "true", "1": dtls = true
            case "off", "no", "false", "0": dtls = false
            default: error(line, "DTLS must be on or off")
            }
        }

        var ssoInBrowser = true
        if let (value, line) = values["singlesignon"] {
            switch value.lowercased() {
            case "browser": ssoInBrowser = true
            case "window": ssoInBrowser = false
            default: error(line, "SingleSignOn must be browser or window")
            }
        }

        guard diagnostics.allSatisfy({ $0.severity != .error }), let server else {
            return ParseResult(profile: nil, diagnostics: diagnostics)
        }
        let profile = OpenConnectProfile(server: server, group: group, username: username, clientCertificate: client,
                                         serverCertificate: pin, userAgent: userAgent, dtls: dtls, ssoInBrowser: ssoInBrowser)
        return ParseResult(profile: profile, diagnostics: diagnostics)
    }

    public static func serialize(_ p: OpenConnectProfile) -> String {
        var lines = [section, "Server = \(p.server.absoluteString)"]
        if let v = p.group { lines.append("Group = \(v)") }
        if let v = p.username { lines.append("Username = \(v)") }
        if let v = p.clientCertificate { lines.append("ClientCertificate = sha256:\(v)") }
        if let v = p.serverCertificate { lines.append("ServerCertificate = sha256:\(v)") }
        if let v = p.userAgent { lines.append("UserAgent = \(v)") }
        if !p.dtls { lines.append("DTLS = off") }
        if !p.ssoInBrowser { lines.append("SingleSignOn = window") }
        return lines.joined(separator: "\n") + "\n"
    }

    public struct Problem: Error, Equatable, Sendable { public let message: String }

    /// The gateway URL: https, a host, no credentials, no fragment. A bare host name is taken as
    /// `https://host/`, the way people type it.
    public static func validateServer(_ raw: String) -> Result<URL, Problem> {
        let text = raw.trimmingCharacters(in: .whitespaces)
        guard !text.isEmpty else { return .failure(Problem(message: "Server is empty")) }
        guard text.count <= maxServerLength else { return .failure(Problem(message: "Server is longer than \(maxServerLength) characters")) }
        guard !text.contains(where: { $0.isWhitespace }) else { return .failure(Problem(message: "Server contains spaces")) }
        let lowered = text.lowercased()
        if lowered.hasPrefix("http://") { return .failure(Problem(message: "Server must use https://, never plain http")) }
        let withScheme = lowered.hasPrefix("https://") ? text : (text.contains("://") ? text : "https://" + text)
        guard let components = URLComponents(string: withScheme), components.scheme?.lowercased() == "https" else {
            return .failure(Problem(message: "Server must be an https:// address"))
        }
        guard components.user == nil, components.password == nil else {
            return .failure(Problem(message: "Server must not contain a user name or password"))
        }
        guard components.fragment == nil else { return .failure(Problem(message: "Server must not contain a #fragment")) }
        guard let host = components.host, !host.isEmpty else { return .failure(Problem(message: "Server has no host name")) }
        guard host.count <= 253, host.unicodeScalars.allSatisfy({ $0.isASCII }) else {
            return .failure(Problem(message: "Server host must be an ASCII host name or IP address (use the xn-- form for international names)"))
        }
        if let port = components.port, !(1...65535).contains(port) { return .failure(Problem(message: "Server port must be 1-65535")) }
        var normalized = components
        normalized.scheme = "https"
        normalized.host = host.lowercased()
        if normalized.path.isEmpty { normalized.path = "/" }
        guard let url = normalized.url else { return .failure(Problem(message: "Server is not a valid address")) }
        return .success(url)
    }

    /// "sha256:AB:CD…", "sha256:abcd…" or bare hex → 64 lowercase hex digits.
    public static func normalizeFingerprint(_ raw: String) -> String? {
        var text = raw.trimmingCharacters(in: .whitespaces).lowercased()
        if text.hasPrefix("sha256:") { text.removeFirst(7) }
        text = text.replacingOccurrences(of: ":", with: "")
        guard text.count == 64, text.allSatisfy({ $0.isASCII && $0.isHexDigit }) else { return nil }
        return text
    }
}
