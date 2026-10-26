import CryptoKit
import Foundation

/// A tailnet (Tailscale or Headscale) as Wombat stores it. It holds no secret: the node and
/// machine keys are made by the Tailnet extension and never leave its root-only container.
///
///     [Tailnet]
///     ControlURL = https://headscale.example.com
///     Hostname = laptop
///     AcceptDNS = yes
public struct TailnetProfile: Equatable, Sendable {
    /// Canonical coordination server URL (`TailnetControl.canonical`).
    public var controlURL: String
    public var hostname: String?
    /// MagicDNS names through the tailnet's resolver (split DNS: only the tailnet's domains).
    public var acceptDNS: Bool

    public init(controlURL: String = TailnetControl.defaultURL, hostname: String? = nil, acceptDNS: Bool = true) {
        self.controlURL = controlURL
        self.hostname = hostname
        self.acceptDNS = acceptDNS
    }

    /// "Tailscale" or the server's host, for lists and System Settings.
    public var displayServer: String {
        TailnetControl.isDefault(controlURL) ? "Tailscale" : (URLComponents(string: controlURL)?.host ?? controlURL)
    }
}

/// Parses and writes the `[Tailnet]` profile format. Spike scope: these three keys only; exit
/// nodes, subnet routes and ShieldsUp are fixed by code (spike design 2.6), and any other key is
/// refused by name rather than ignored.
public enum TailnetFile {
    public struct ParseResult: Sendable {
        public let profile: TailnetProfile?
        public let diagnostics: [Diagnostic]
        public var errors: [Diagnostic] { diagnostics.filter { $0.severity == .error } }
    }

    public static let section = "[Tailnet]"
    public static let maxBytes = 4 * 1024
    public static let maxHostnameLength = 63

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
        let known: Set<String> = ["controlurl", "hostname", "acceptdns"]
        var inSection = false
        var sections = 0
        var values: [String: (value: String, line: Int)] = [:]
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
            guard known.contains(lowered) else { error(lineNumber, "Unknown key \"\(key)\""); continue }
            guard values[lowered] == nil else { error(lineNumber, "\(key) is given twice"); continue }
            guard !value.isEmpty else { error(lineNumber, "\(key) has no value"); continue }
            values[lowered] = (value, lineNumber)
        }
        if sections == 0 { error(nil, "Missing \(section) section") }

        var control = TailnetControl.defaultURL
        if let (value, line) = values["controlurl"] {
            switch TailnetControl.canonical(value) {
            case .success(let url): control = url
            case .failure(let problem): error(line, problem.message)
            }
        }
        var hostname: String?
        if let (value, line) = values["hostname"] {
            if value.count <= maxHostnameLength, value.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-") }),
               !value.hasPrefix("-"), !value.hasSuffix("-") {
                hostname = value
            } else {
                error(line, "Hostname must be letters, digits and hyphens, at most \(maxHostnameLength) characters")
            }
        }
        var acceptDNS = true
        if let (value, line) = values["acceptdns"] {
            switch value.lowercased() {
            case "on", "yes", "true", "1": acceptDNS = true
            case "off", "no", "false", "0": acceptDNS = false
            default: error(line, "AcceptDNS must be yes or no")
            }
        }
        guard diagnostics.allSatisfy({ $0.severity != .error }) else { return ParseResult(profile: nil, diagnostics: diagnostics) }
        return ParseResult(profile: TailnetProfile(controlURL: control, hostname: hostname, acceptDNS: acceptDNS), diagnostics: diagnostics)
    }

    public static func serialize(_ p: TailnetProfile) -> String {
        var lines = [section, "ControlURL = \(p.controlURL)"]
        if let h = p.hostname { lines.append("Hostname = \(h)") }
        lines.append("AcceptDNS = \(p.acceptDNS ? "yes" : "no")")
        return lines.joined(separator: "\n") + "\n"
    }
}

/// Coordination server and sign-in URL rules (spike design 2.4, 2.5). The Go engine applies the
/// same rules with its own code (`node/control.go`); neither trusts the other.
public enum TailnetControl {
    public static let defaultURL = "https://controlplane.tailscale.com"
    public static let maxLength = 512

    public struct Problem: Error, Equatable, Sendable {
        public let message: String
    }

    public static func isDefault(_ canonical: String) -> Bool {
        canonical == defaultURL || canonical == "https://login.tailscale.com"
    }

    /// The canonical form: lowercase scheme and host, the port only when not 443, the path
    /// without a trailing slash. https only; no user, query or fragment; no ".."; the host must
    /// not be loopback, link-local, multicast, unspecified or inside the tailnet.
    public static func canonical(_ raw: String) -> Result<String, Problem> {
        func fail(_ m: String) -> Result<String, Problem> { .failure(Problem(message: m)) }
        if raw.isEmpty { return .success(defaultURL) }
        guard raw.count <= maxLength else { return fail("ControlURL is too long") }
        guard !raw.unicodeScalars.contains(where: { $0.value <= 0x20 || $0.value == 0x7F || !$0.isASCII }) else {
            return fail("ControlURL contains spaces, control or non-ASCII characters")
        }
        guard !raw.contains("#"), !raw.contains("?") else { return fail("ControlURL must not contain a query or fragment") }
        guard let c = URLComponents(string: raw), let scheme = c.scheme?.lowercased(), let rawHost = c.host, !rawHost.isEmpty else {
            return fail("ControlURL must be an https URL with a host")
        }
        guard scheme == "https" else { return fail("ControlURL must use https") }
        guard c.user == nil, c.password == nil else { return fail("ControlURL must not contain a user name or password") }
        guard !c.percentEncodedPath.contains(".."), !c.percentEncodedPath.lowercased().contains("%2e") else {
            return fail("ControlURL path must not contain \"..\"")
        }
        var host = rawHost.lowercased()
        if host.hasPrefix("["), host.hasSuffix("]") { host = String(host.dropFirst().dropLast()) }
        if let problem = hostProblem(host) { return fail(problem) }
        var port = ""
        if let p = c.port {
            guard (1...65535).contains(p) else { return fail("ControlURL has an invalid port") }
            if p != 443 { port = ":\(p)" }
        }
        var path = c.percentEncodedPath
        while path.hasSuffix("/") { path.removeLast() }
        let shownHost = host.contains(":") ? "[\(host)]" : host
        return .success("https://\(shownHost)\(port)\(path)")
    }

    /// The state directory name for a coordination server: 16 hex digits of SHA-256 of its
    /// canonical URL. A different server is a different node; keys never move between them.
    public static func key(_ canonical: String) -> String {
        SHA256.hash(data: Data(canonical.utf8)).prefix(8).map { String(format: "%02x", $0) }.joined()
    }

    /// Whether a sign-in URL from the coordination server may be offered to the user: https,
    /// the server's own host and port (Tailscale's own server: tailscale.com or a subdomain),
    /// no IP-literal host, no user, no control characters, at most 2048 characters.
    public static func isValidLoginURL(_ login: String, control canonicalControl: String) -> Bool {
        guard !login.isEmpty, login.count <= 2048,
              !login.unicodeScalars.contains(where: { $0.value <= 0x20 || $0.value == 0x7F }),
              let u = URLComponents(string: login), u.scheme?.lowercased() == "https",
              u.user == nil, u.password == nil, let host = u.host?.lowercased(), !host.isEmpty,
              let control = URLComponents(string: canonicalControl), let controlHost = control.host?.lowercased() else { return false }
        if isDefault(canonicalControl) {
            return u.port == nil && (host == "tailscale.com" || host.hasSuffix(".tailscale.com"))
        }
        guard !isIPLiteral(host), !host.contains(":") else { return false }
        return host == controlHost && (u.port ?? 443) == (control.port ?? 443)
    }

    static func hostProblem(_ host: String) -> String? {
        let bare = host.hasPrefix("[") && host.hasSuffix("]") ? String(host.dropFirst().dropLast()) : host
        if bare.contains(":") || isIPLiteral(bare) {
            guard bare.firstIndex(of: "%") == nil, let range = IPAddressRange(bare) else { return "ControlURL has an invalid address" }
            // IPv4-mapped IPv6 addresses hide an IPv4 address from these checks (security-7 L1).
            if mappedIPv4.contains(range) { return "ControlURL must not be an IPv4-mapped IPv6 address" }
            for blocked in blockedRanges where blocked.contains(range) {
                return blocked.description.hasPrefix("100.64") || blocked.description.hasPrefix("fd7a")
                    ? "The coordination server can't be inside the tailnet"
                    : "ControlURL must be a public or private network address"
            }
            return nil
        }
        if bare == "localhost" || bare.hasSuffix(".localhost") { return "ControlURL must be a public or private network address" }
        guard bare.count <= 253 else { return "ControlURL host name is too long" }
        // "127.1" or "2130706433": numeric forms that resolvers may turn into an address the
        // checks above refuse. No real host name ends in an all-digit label.
        if let last = bare.split(separator: ".").last, last.allSatisfy(\.isASCIIDigit) { return "ControlURL has an invalid address" }
        // A trailing dot names the same host, but the server's sign-in page never carries it,
        // so sign-in could never match (quality-9 L11).
        if bare.hasSuffix(".") { return "ControlURL host name must not end with a dot" }
        let labels = bare.split(separator: ".", omittingEmptySubsequences: false)
        // Hex forms too ("0x7f000001", "0x7f.0.0.1"): inet_aton reads them as addresses
        // (security-9-astra S9-3).
        if labels.contains(where: { $0.count > 2 && $0.hasPrefix("0x") && $0.dropFirst(2).allSatisfy(\.isHexDigit) }) {
            return "ControlURL has an invalid address"
        }
        for label in labels {
            guard !label.isEmpty, label.count <= 63, !label.hasPrefix("-"), !label.hasSuffix("-"),
                  label.allSatisfy({ ($0.isASCII && $0.isLetter) || ($0.isASCII && $0.isNumber) || $0 == "-" }) else {
                return "ControlURL host name isn't valid"
            }
        }
        return nil
    }

    static let blockedRanges: [IPAddressRange] = [
        "127.0.0.0/8", "0.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32", "100.64.0.0/10",
        "::/128", "::1/128", "fe80::/10", "ff00::/8", "fd7a:115c:a1e0::/48",
    ].map { IPAddressRange($0)! }
    static let mappedIPv4 = IPAddressRange("::ffff:0.0.0.0/96")!
}

/// Whether a host is an IP literal (no prefix allowed).
private func isIPLiteral(_ s: String) -> Bool { !s.contains("/") && IPAddressRange(s) != nil }

/// What the Tailnet extension applies, after this gate (spike design 2.6). The engine proposes
/// a plan from the coordination server's netmap; only tailnet space and the tailnet's own
/// resolver pass. A hostile server can't route the internet, the LAN or the control host into
/// the tunnel, or replace the Mac's DNS.
public struct TailnetNetworkPlan: Equatable, Sendable {
    public struct Proposal: Codable, Equatable, Sendable {
        public var addresses: [String] = []
        public var routes: [String] = []
        public var mtu: Int = 0
        public var dnsServers: [String] = []
        public var matchDomains: [String] = []
        public var searchDomains: [String] = []
        public init() {}
    }

    public enum Failure: Error, Equatable, LocalizedError {
        case invalid(String)
        public var errorDescription: String? { if case .invalid(let s) = self { return s }; return nil }
    }

    public static let tailnetIPv4 = IPAddressRange("100.64.0.0/10")!
    public static let tailnetIPv6 = IPAddressRange("fd7a:115c:a1e0::/48")!
    public static let quad100 = "100.100.100.100"
    public static let quad100v6 = "fd7a:115c:a1e0::53"
    public static let maxBytes = 256 * 1024
    public static let maxRoutes = 1024
    public static let maxDomains = 256
    public static let defaultMTU = 1280

    public var ipv4Address: IPAddressRange?
    public var ipv6Address: IPAddressRange?
    public var ipv4Routes: [IPAddressRange] = []
    public var ipv6Routes: [IPAddressRange] = []
    public var mtu = defaultMTU
    /// Empty when the tailnet's DNS was refused or turned off; the Mac's resolver stays.
    public var dnsServers: [String] = []
    /// Never empty when dnsServers isn't, and never [""]: only these names go to quad100.
    public var matchDomains: [String] = []
    /// Always empty since security-9: on macOS search domains (and match domains, unless
    /// matchDomainsNoSearch) apply to every single-label name typed on the Mac, so a server's
    /// suffix would capture `printer` or `intranet` (fable L1). MagicDNS names are used in full.
    public var searchDomains: [String] = []
    /// The MagicDNS suffix this plan accepted, for the provider to pin on first use.
    public var magicDNSSuffix: String?
    /// What the gate left out, for the Log tab.
    public var dropped: [String] = []

    public static func decode(_ data: Data) throws -> Proposal {
        guard data.count <= maxBytes else { throw Failure.invalid("The network plan is larger than \(maxBytes / 1024) KB") }
        return try JSONDecoder().decode(Proposal.self, from: data)
    }

    /// Validates a proposal. Throws when the node's own address is outside tailnet space (no
    /// tunnel with a foreign address); anything else outside the rules is dropped and listed.
    /// `pinnedSuffix` is the MagicDNS suffix this profile accepted first: a server that later names
    /// another one can't move the Mac's lookups to it without the tailnet being re-added
    /// (security-9-astra S9-1).
    public static func make(_ p: Proposal, acceptDNS: Bool, control: String, pinnedSuffix: String? = nil) throws -> TailnetNetworkPlan {
        var plan = TailnetNetworkPlan()
        guard p.addresses.count <= 4 else { throw Failure.invalid("The coordination server sent \(p.addresses.count) addresses for this node") }
        for text in p.addresses {
            guard let a = IPAddressRange(text) else { throw Failure.invalid("The coordination server sent an invalid address") }
            switch a.family {
            case .v4:
                guard a.prefixLength == 32, tailnetIPv4.contains(a), plan.ipv4Address == nil else {
                    throw Failure.invalid("The coordination server gave this node an address outside the tailnet (\(a))")
                }
                plan.ipv4Address = a
            case .v6:
                guard a.prefixLength == 128, tailnetIPv6.contains(a), plan.ipv6Address == nil else {
                    throw Failure.invalid("The coordination server gave this node an address outside the tailnet (\(a))")
                }
                plan.ipv6Address = a
            }
        }
        // No address at all is the engine before sign-in or after sign-out (quality-7 H2): an
        // empty plan, with nothing routed and no DNS. A foreign address still ends the tunnel.
        guard plan.ipv4Address != nil || plan.ipv6Address != nil else {
            if !p.routes.isEmpty || !p.dnsServers.isEmpty { plan.dropped.append("routes and DNS without an address for this node") }
            return plan
        }

        let quad100Routes = [IPAddressRange(quad100 + "/32")!, IPAddressRange(quad100v6 + "/128")!]
        for text in p.routes.prefix(maxRoutes) {
            guard let r = IPAddressRange(text) else { plan.dropped.append("invalid route"); continue }
            let allowed = tailnetIPv4.contains(r) || tailnetIPv6.contains(r) || quad100Routes.contains(r)
            guard allowed else { plan.dropped.append("route \(r)"); continue }
            if r.family == .v4, plan.ipv4Address != nil { plan.ipv4Routes.append(r.network) }
            if r.family == .v6, plan.ipv6Address != nil { plan.ipv6Routes.append(r.network) }
        }
        if p.routes.count > maxRoutes { plan.dropped.append("\(p.routes.count - maxRoutes) route(s) over the limit") }

        if (1280...1500).contains(p.mtu) { plan.mtu = p.mtu }

        guard acceptDNS, !p.dnsServers.isEmpty else { return plan }
        let allowedServers = Set([quad100, quad100v6])
        if let foreign = p.dnsServers.first(where: { !allowedServers.contains($0) }) {
            plan.dropped.append("DNS (server \(foreign) isn't the tailnet's resolver)")
            return plan
        }
        // Only the tailnet's own names go to quad100 (security-7 M1): the reverse zones of
        // tailnet space, and one MagicDNS suffix, which the server names as a search domain.
        // Any other split-DNS domain ("com", "github.com") would let the server answer for it.
        let proposed = p.matchDomains.prefix(maxDomains).compactMap(dnsName)
        var suffix = p.searchDomains.compactMap(dnsName).first { proposed.contains($0) && isMagicDNSSuffix($0, control: control) }
        if let s = suffix, let pinned = pinnedSuffix, s != pinned {
            plan.dropped.append("DNS name \(s): this tailnet first used \(pinned); remove and re-add the tailnet to accept a new one")
            suffix = nil
        }
        var domains: [String] = []
        for d in proposed where !domains.contains(d) {
            if isTailnetReverseZone(d) || d == suffix { domains.append(d) } else { plan.dropped.append("DNS domain \(d)") }
        }
        guard !domains.isEmpty else {
            // No match domains would make quad100 the Mac's only resolver: refused.
            plan.dropped.append("DNS (no tailnet domains to resolve)")
            return plan
        }
        // A resolver only counts when an accepted route takes it into the tunnel; otherwise the
        // Mac would ask it in clear text over the physical network (quality-9 L3).
        let q4 = IPAddressRange(quad100 + "/32")!, q6 = IPAddressRange(quad100v6 + "/128")!
        plan.dnsServers = p.dnsServers.filter {
            ($0 == quad100 && plan.ipv4Routes.contains { $0.contains(q4) })
                || ($0 == quad100v6 && plan.ipv6Routes.contains { $0.contains(q6) })
        }
        guard !plan.dnsServers.isEmpty else {
            plan.dropped.append("DNS (the tailnet's resolver isn't routed into the tunnel)")
            return plan
        }
        plan.matchDomains = domains
        plan.magicDNSSuffix = suffix
        if p.matchDomains.count > maxDomains { plan.dropped.append("\(p.matchDomains.count - maxDomains) DNS domain(s) over the limit") }
        return plan
    }

    /// Reverse-lookup zones inside tailnet space: 64-127.100.in-addr.arpa (100.64.0.0/10) and
    /// the ip6.arpa zone of fd7a:115c:a1e0::/48, or names below them.
    static func isTailnetReverseZone(_ d: String) -> Bool {
        let v6 = "0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa"
        if d == v6 || d.hasSuffix("." + v6) { return true }
        guard d.hasSuffix(".100.in-addr.arpa") else { return false }
        let labels = d.dropLast(".100.in-addr.arpa".count).split(separator: ".")
        guard let second = labels.last, let octet = Int(second), (64...127).contains(octet) else { return false }
        return labels.allSatisfy { Int($0).map { (0...255).contains($0) } ?? false }
    }

    /// A MagicDNS suffix the server may claim: Tailscale's own server only names under ts.net;
    /// a custom server any name of two labels or more (never a top-level domain). A hostile
    /// custom server can still claim one such name; the product gets an approval for it.
    static func isMagicDNSSuffix(_ d: String, control: String) -> Bool {
        if TailnetControl.isDefault(control) { return d.hasSuffix(".ts.net") }
        return d.split(separator: ".").count >= 2 && !d.hasSuffix(".arpa")
    }

    /// A lowercase DNS name without the trailing dot, or nil.
    public static func dnsName(_ s: String) -> String? {
        var name = s.lowercased()
        if name.hasSuffix(".") { name.removeLast() }
        guard !name.isEmpty, name.count <= 253 else { return nil }
        for label in name.split(separator: ".", omittingEmptySubsequences: false) {
            guard !label.isEmpty, label.count <= 63,
                  label.allSatisfy({ ($0.isASCII && ($0.isLetter || $0.isNumber)) || $0 == "-" || $0 == "_" }) else { return nil }
        }
        return name
    }
}

/// The Tailnet extension's status for the app (ProviderMessage.tailnetStatus): no keys.
public struct TailnetStatus: Codable, Equatable, Sendable {
    public struct Peer: Codable, Equatable, Sendable {
        public var name: String
        public var dnsName: String?
        public var os: String?
        public var addresses: [String]
        public var online: Bool
        public var active: Bool
        public var relay: String?
        public var direct: Bool
        public var rxBytes: Int64
        public var txBytes: Int64
        public var lastSeen: Date?
    }

    public static let maxBytes = 256 * 1024

    public var state: String
    public var authURL: String?
    public var control: String
    public var `self`: Peer?
    public var magicDNSSuffix: String?
    public var tailnet: String?
    public var health: [String]
    public var peers: [Peer]
    public var peersTruncated: Bool?

    // Made once: two formatters per date was ~512 a second with 256 peers at the 1 s poll
    // (quality-9 L10). ISO8601DateFormatter is thread-safe.
    nonisolated(unsafe) private static let fractionalDates: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()
    nonisolated(unsafe) private static let plainDates = ISO8601DateFormatter()

    public static func decode(_ data: Data) -> TailnetStatus? {
        guard data.count <= maxBytes else { return nil }
        let decoder = JSONDecoder()
        // Go writes RFC 3339 with nanoseconds, which .iso8601 refuses.
        decoder.dateDecodingStrategy = .custom { d in
            let text = try d.singleValueContainer().decode(String.self)
            if let date = fractionalDates.date(from: text) ?? plainDates.date(from: text) { return date }
            throw DecodingError.dataCorrupted(.init(codingPath: d.codingPath, debugDescription: "Invalid date"))
        }
        return try? decoder.decode(TailnetStatus.self, from: data)
    }

    /// The sign-in URL, only when it passes the app-side check against the profile's own
    /// server (not the server the engine reports; security-7 L2).
    public func validAuthURL(control profileControl: String) -> URL? {
        guard let authURL, control == profileControl, TailnetControl.isValidLoginURL(authURL, control: profileControl) else { return nil }
        return URL(string: authURL)
    }
}

/// The Tailnet extension's reply to `.tailnetLogin` and `.tailnetLogout`. The sign-in URL is a
/// bearer link for days, so it travels only here, to the click that asked for it, never in the
/// status every poll returns (security-9-fable NV2).
public struct TailnetCommandReply: Codable, Equatable, Sendable {
    public var error: String?
    public var authURL: String?

    public init(error: String? = nil, authURL: String? = nil) {
        self.error = error
        self.authURL = authURL
    }

    public var encoded: Data { (try? JSONEncoder().encode(self)) ?? Data() }

    public static func decode(_ data: Data) -> TailnetCommandReply? {
        guard data.count <= 16 * 1024 else { return nil }
        return try? JSONDecoder().decode(TailnetCommandReply.self, from: data)
    }
}
