import Foundation

/// Takes secrets out of log lines before anything stores them. Every extension runs each line
/// through `scrub` on its way into the app's Log tab, and the diagnostics file is built from
/// those lines, so a line the scrubber misses can end up attached to a public issue. It errs on
/// the side of hiding: a hidden value costs a little debugging, a leaked session costs an account.
///
/// libopenconnect at PRG_DEBUG prints every HTTP and CSTP header it receives (it hides only the
/// `webvpn` cookie and X-CSTP-Post-Auth-XML itself), so header values with secret-looking names
/// go, whatever the header. Wombat never turns on libopenconnect's HTTP dumps
/// (`openconnect_set_dump_http_traffic`), which would print the CONNECT request with the cookie
/// and the DTLS master secret.
///
/// Lines can be gateway text (attacker-chosen) and are scrubbed on libopenconnect's main-loop
/// thread: every pattern is bounded, so a hostile line can't make matching slow (security-10 L2).
public enum LogScrubber {
    public static let hidden = "<hidden>"
    public static let hiddenLogin = "<login>"

    /// Lines longer than this are cut: nothing useful is that long, and a gateway's text is
    /// attacker-chosen.
    public static let maxLineLength = 1024

    public static func scrub(_ line: String, maxLength: Int = maxLineLength) -> String {
        var text = String(TunnelName.line(line).prefix(maxLength))
        text = hideHeaderValue(in: text)
        text = replace(assignment, in: text, with: "$1=\(hidden)")
        // Tailscale logs the signed-in account ("active login: name@example.com", security-10 M1).
        text = replace(email, in: text, with: hiddenLogin)
        text = replaceOpaqueRuns(in: text)
        return text
    }

    /// Words in a header or key name that say its value is secret: Cookie, Set-Cookie,
    /// X-DTLS-Session-ID, X-DTLS-Master-Secret, X-AnyConnect-STRAP-*, Authorization, tokens…
    private static let secretWords = ["cookie", "secret", "session-id", "strap", "authorization", "authorisation",
                                      "token", "password", "passwd", "master", "app-id", "private", "preshared", "psk",
                                      "saml"]

    /// A "Name:" candidate: a bounded name right before a colon.
    private static let headerName = try! NSRegularExpression(pattern: #"(?<![A-Za-z0-9_-])([A-Za-z0-9_-]{1,64})[ \t]*:"#)

    /// "Name: value" where the name says it carries a secret: the value goes, up to the end of
    /// the line (header values can hold spaces and semicolons). The first such name wins.
    private static func hideHeaderValue(in text: String) -> String {
        let ns = text as NSString
        for match in headerName.matches(in: text, range: NSRange(location: 0, length: ns.length)) {
            let name = ns.substring(with: match.range(at: 1)).lowercased()
            guard secretWords.contains(where: name.contains) else { continue }
            let end = match.range.location + match.range.length
            let rest = ns.substring(from: end)
            guard rest.contains(where: { !$0.isWhitespace }) else { return text }
            return ns.substring(to: match.range.location) + ns.substring(with: match.range(at: 1)) + ": " + hidden
        }
        return text
    }

    /// key=value pairs that carry a secret: cookies (webvpn, webvpnc…), the STRAP key in
    /// libopenconnect's cookie format, wg(8)-style keys, and any name with token, secret,
    /// password, cookie, key or session in it (sso_token=, auth-token=…).
    private static let assignment = try! NSRegularExpression(
        pattern: #"(?i)(?<![A-Za-z0-9_-])(webvpn[A-Za-z0-9_]{0,32}|[A-Za-z0-9_-]{0,32}(?:token|secret|passw(?:or)?d|cookie|key|session|saml)[A-Za-z0-9_-]{0,32})[ \t]*=[ \t]*[^;,\s]+"#)

    private static let email = try! NSRegularExpression(
        pattern: #"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){0,8}\.[A-Za-z]{2,24}"#)

    /// Base64, base64url or hex runs of 32 characters or more: keys, tokens, cookies, session
    /// ids, hashes. Two kinds are kept: UUIDs (tunnel ids, in the world-readable NE plist
    /// anyway) and runs of letters and hyphens only, which are words (long Cisco header names
    /// like X-CSTP-Smartcard-Removal-Disconnect, seen on ocserv at debug level, 2026-11-05).
    /// A key or token with no digit, "+", "/", "_" or "=" in 32 characters is vanishingly rare.
    private static let opaque = try! NSRegularExpression(pattern: #"[A-Za-z0-9+/_-]{32,}={0,2}"#)
    private static let uuid = try! NSRegularExpression(
        pattern: #"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$"#)
    private static let lettersAndHyphens = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-")

    fileprivate static func replace(_ regex: NSRegularExpression, in text: String, with template: String) -> String {
        regex.stringByReplacingMatches(in: text, range: NSRange(text.startIndex..., in: text), withTemplate: template)
    }

    private static func replaceOpaqueRuns(in text: String) -> String {
        let ns = text as NSString
        var out = ""
        var last = 0
        for match in opaque.matches(in: text, range: NSRange(location: 0, length: ns.length)) {
            let run = ns.substring(with: match.range)
            out += ns.substring(with: NSRange(location: last, length: match.range.location - last))
            let keep = (run.contains("-") && run.unicodeScalars.allSatisfy(lettersAndHyphens.contains))
                || uuid.firstMatch(in: run, range: NSRange(location: 0, length: (run as NSString).length)) != nil
            out += keep ? run : hidden
            last = match.range.location + match.range.length
        }
        return out + ns.substring(from: last)
    }
}

/// Debug logging's deadline (Settings › Troubleshooting). Stored as seconds since
/// 1970; a stored value more than a day ahead (a hand-edited default, a clock set back) counts
/// as a day from now, so it can never stay on for longer.
public enum DebugLoggingDeadline {
    public static let hours = 24

    public static func effective(stored: Double, now: Date = Date()) -> Date? {
        guard stored > now.timeIntervalSince1970 else { return nil }
        return min(Date(timeIntervalSince1970: stored), now.addingTimeInterval(TimeInterval(hours * 3600)))
    }
}

/// Replaces server names, domain names, IP addresses and VPN names in a diagnostics report with
/// stable placeholders ("server-1", "domain-2", "address-3", "VPN 1"), for reports that will be
/// posted publicly. The same value always gets the same placeholder within one hider, so the
/// report still reads coherently.
public struct ServerHider {
    private var names: [(String, String)] = []
    private var vpnNames: [(NSRegularExpression, String)] = []
    private var addresses: [String: String] = [:]
    private var domains: [String: String] = [:]

    /// `servers`: host names to hide (gateways, endpoints, coordination servers); numbered by
    /// length, then alphabetically, so two reports of the same setup number them alike.
    /// `vpnNames`: in report order, shown as "VPN 1", "VPN 2"… wherever they stand as words.
    public init(servers: [String], vpnNames: [String] = []) {
        let unique = Set(servers.map { $0.lowercased() }.filter { !$0.isEmpty && !Self.isAddress($0) })
        names = unique.sorted { $0.count != $1.count ? $0.count > $1.count : $0 < $1 }.enumerated().map { ($1, "server-\($0 + 1)") }
        // Longest first, so "Work VPN" goes before "Work"; as words only, so "Home" leaves
        // "Homebrew" alone (quality-10 L).
        self.vpnNames = vpnNames.enumerated().filter { !$0.element.isEmpty }
            .sorted { $0.element.count > $1.element.count }
            .compactMap { index, name in
                (try? NSRegularExpression(pattern: "(?<![A-Za-z0-9])" + NSRegularExpression.escapedPattern(for: name) + "(?![A-Za-z0-9])"))
                    .map { ($0, "VPN \(index + 1)") }
            }
    }

    /// Not after "v" or a digit-dot (version numbers like v9.21.0.1 stay).
    private static let ipv4 = try! NSRegularExpression(pattern: #"(?<![0-9.vV])(?:\d{1,3}\.){3}\d{1,3}(?![0-9.])"#)
    /// Four or more colon-separated hex groups, or any "::" form: never a time like 10:22:33,
    /// and never C++'s std:: (no letter or digit right before it).
    private static let ipv6 = try! NSRegularExpression(
        pattern: #"(?i)(?<![0-9a-z:])(?:(?:[0-9a-f]{1,4}:){3,7}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,6}:(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,6})?|::[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,6})(?![0-9a-z:])"#)
    /// Domain names the gateway or tailnet hands out (default domain, split DNS, MagicDNS).
    private static let domain = try! NSRegularExpression(
        pattern: #"(?i)(?<![A-Za-z0-9@.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,8}[a-z]{2,24}(?![A-Za-z0-9.-])"#)
    /// Names ending in these are files and bundles, not domains.
    private static let notDomains: Set<String> = ["app", "txt", "plist", "conf", "anyconnect", "swift", "json", "log",
                                                  "dylib", "framework", "systemextension", "appex", "md", "zip", "dmg",
                                                  "local", "go", "c", "h"]

    private static func isAddress(_ s: String) -> Bool {
        let r = NSRange(s.startIndex..., in: s)
        return [ipv4, ipv6].contains { $0.firstMatch(in: s, range: r)?.range == r }
    }

    public mutating func hide(_ text: String) -> String {
        var out = text
        for (name, placeholder) in names {
            out = out.replacingOccurrences(of: name, with: placeholder, options: .caseInsensitive)
        }
        for (regex, label) in vpnNames {
            out = LogScrubber.replace(regex, in: out, with: NSRegularExpression.escapedTemplate(for: label))
        }
        out = replaceEach(Self.ipv4, in: out) { value in
            value == "127.0.0.1" || value == "0.0.0.0" ? value : Self.placeholder(value, in: &addresses, prefix: "address")
        }
        out = replaceEach(Self.ipv6, in: out) { value in
            value == "::1" ? value : Self.placeholder(value, in: &addresses, prefix: "address")
        }
        out = replaceEach(Self.domain, in: out) { value in
            // "server-1" and the like are ours; file names aren't domains.
            let tld = value.split(separator: ".").last.map { $0.lowercased() } ?? ""
            return Self.notDomains.contains(tld) ? value : Self.placeholder(value, in: &domains, prefix: "domain")
        }
        return out
    }

    private static func placeholder(_ value: String, in table: inout [String: String], prefix: String) -> String {
        let key = value.lowercased()
        if let known = table[key] { return known }
        let made = "\(prefix)-\(table.count + 1)"
        table[key] = made
        return made
    }

    private func replaceEach(_ regex: NSRegularExpression, in text: String, _ transform: (String) -> String) -> String {
        let ns = text as NSString
        var result = ""
        var last = 0
        for match in regex.matches(in: text, range: NSRange(location: 0, length: ns.length)) {
            result += ns.substring(with: NSRange(location: last, length: match.range.location - last))
            result += transform(ns.substring(with: match.range))
            last = match.range.location + match.range.length
        }
        return result + ns.substring(from: last)
    }
}

/// Whether the app should ask macOS why a tunnel went down (`fetchLastDisconnectError`): when it
/// ended without the app stopping it, from any live state and for every kind of tunnel (issue
/// #1: the gateway ended an AnyConnect session a second after connecting and nothing said why).
public enum DisconnectReasonRule {
    public enum Status: Sendable { case disconnected, connecting, connected, reasserting, disconnecting, other }

    public static func shouldFetch(before: Status, now: Status, stoppedByApp: Bool) -> Bool {
        now == .disconnected && !stoppedByApp && [.connecting, .connected, .reasserting, .disconnecting].contains(before)
    }
}

/// Files that hold a report: created 0600 before anything is written (no window at the default
/// mode), and an existing file is set to 0600 before it is truncated (security-10 hardening).
public enum PrivateFile {
    public struct Failure: Error, LocalizedError {
        public let errorDescription: String?
    }

    public static func write(_ data: Data, to path: String) throws {
        let fd = open(path, O_WRONLY | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw Failure(errorDescription: "Could not open \(path): \(String(cString: strerror(errno)))") }
        defer { close(fd) }
        guard fchmod(fd, 0o600) == 0, ftruncate(fd, 0) == 0 else {
            throw Failure(errorDescription: "Could not prepare \(path): \(String(cString: strerror(errno)))")
        }
        try data.withUnsafeBytes { buffer in
            var offset = 0
            while offset < buffer.count {
                let n = Darwin.write(fd, buffer.baseAddress! + offset, buffer.count - offset)
                guard n > 0 else { throw Failure(errorDescription: "Could not write \(path): \(String(cString: strerror(errno)))") }
                offset += n
            }
        }
    }
}

/// The newest log lines that fit a byte budget: CLI replies are capped (Control.maxMessageBytes),
/// and a debug session's log can be larger (security-10, "not security").
public enum LogBudget {
    /// For one CLI reply: room under the CLI's 1 MB limit for JSON escaping and the rest.
    public static let cliReplyBytes = 600 * 1024

    public static func newest(_ lines: [String], maxBytes: Int) -> (lines: [String], leftOut: Int) {
        var total = 0
        var kept = 0
        for line in lines.reversed() {
            total += line.utf8.count + 1
            if total > maxBytes { break }
            kept += 1
        }
        return (Array(lines.suffix(kept)), lines.count - kept)
    }
}
