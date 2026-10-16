import Foundation

/// AmneziaWG's obfuscation settings (protocol versions 1.0 through 2.0) from an [Interface]
/// section. They change the bytes on the wire, so a tunnel with any of them active must run
/// on the amneziawg-go engine and can only talk to an AmneziaWG peer.
///
/// The limits here are Wombat's own (amneziawg-tools is GPLv2, so none of its code is used).
/// They are stricter than the engine's: a downloaded config must not be able to make the
/// extension send megabytes before every handshake.
public struct AmneziaParameters: Equatable, Sendable {
    /// Junk packets sent before each handshake initiation (Jc), with random sizes in Jmin..<Jmax.
    public var junkCount: UInt32?
    public var junkMin: UInt32?
    public var junkMax: UInt32?
    /// Random bytes prepended to initiation, response, cookie and transport messages (S1-S4).
    public var paddings: [UInt16?] = [nil, nil, nil, nil]
    /// Message type values for the same four messages (H1-H4): one value or a range to pick from.
    public var headers: [HeaderRange?] = [nil, nil, nil, nil]
    /// Signature packets sent before each handshake (I1-I5), as tag specs like `<b 0x…><r 16>`.
    public var signaturePackets: [String?] = [nil, nil, nil, nil, nil]

    public init() {}

    public static let maxJunkCount: UInt32 = 128
    /// A junk packet larger than this would be fragmented on any common link.
    public static let maxJunkSize: UInt32 = 1500
    /// S1-S4 limits keep each padded handshake message within IPv6's minimum MTU of 1280.
    public static let maxPaddings: [UInt16] = [1132, 1188, 1216, 32]
    public static let maxSignaturePacketBytes = 4096
    /// Longest I1-I5 text. A <b> tag at the byte limit is about 8 KB of hex; the engine reads
    /// each UAPI line into a 64 KB buffer, and padding beyond it would fail the tunnel's start.
    public static let maxSignatureSpecLength = 10_000
    /// Junk and signature traffic for one round of handshakes, summed over every peer: the
    /// settings apply to each peer's handshake, so the per-handshake limits alone would let a
    /// file with thousands of peers send hundreds of MB at tunnel start (audit S4 M1).
    public static let maxBurstBytes = 1 << 20
    public static let maxBurstPackets = 1024

    /// The message types WireGuard itself uses, which the engine keeps for any H left unset.
    static let defaultHeaders: [UInt32] = [1, 2, 3, 4]

    public struct HeaderRange: Equatable, Sendable, CustomStringConvertible {
        public let lower: UInt32
        public let upper: UInt32

        public init?(_ text: String) {
            let parts = text.split(separator: "-", omittingEmptySubsequences: false)
            guard (1...2).contains(parts.count),
                  parts.allSatisfy({ !$0.isEmpty && $0.count <= 10 && $0.allSatisfy(\.isASCIIDigit) }),
                  let lower = UInt32(parts[0]), let upper = UInt32(parts.last!), lower <= upper
            else { return nil }
            self.lower = lower
            self.upper = upper
        }

        init(single value: UInt32) { lower = value; upper = value }

        public var description: String { lower == upper ? "\(lower)" : "\(lower)-\(upper)" }

        func overlaps(_ other: HeaderRange) -> Bool { lower <= other.upper && other.lower <= upper }
    }

    /// True when any setting differs from what plain WireGuard sends. All-default settings
    /// (Jc = 0, S = 0, H = 1, 2, 3, 4, no I-packets) describe plain WireGuard.
    public var isActive: Bool {
        (junkCount ?? 0) > 0
            || paddings.contains { ($0 ?? 0) > 0 }
            || headers.enumerated().contains { i, h in h.map { $0 != HeaderRange(single: Self.defaultHeaders[i]) } ?? false }
            || signaturePackets.contains { $0 != nil }
    }

    /// Device lines for amneziawg-go's UAPI, in a fixed order. Only keys that are set.
    public var uapiPairs: [(key: String, value: String)] {
        var out: [(String, String)] = []
        if let v = junkCount { out.append(("jc", "\(v)")) }
        if let v = junkMin { out.append(("jmin", "\(v)")) }
        if let v = junkMax { out.append(("jmax", "\(v)")) }
        for (i, v) in paddings.enumerated() { if let v { out.append(("s\(i + 1)", "\(v)")) } }
        for (i, v) in headers.enumerated() { if let v { out.append(("h\(i + 1)", v.description)) } }
        for (i, v) in signaturePackets.enumerated() { if let v { out.append(("i\(i + 1)", v)) } }
        return out
    }

    /// wg-quick lines, in the same order and with AmneziaWG's spelling.
    var configLines: [String] {
        uapiPairs.map { key, value in "\(key.prefix(1).uppercased())\(key.dropFirst()) = \(value)" }
    }
}

extension AmneziaParameters {
    /// [Interface] keys this parser accepts, lowercased.
    static let keys: Set<String> = ["jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4",
                                    "i1", "i2", "i3", "i4", "i5"]

    /// Keys from AmneziaWG 1.5 and 3.x that Wombat does not support yet, lowercased. Named so the
    /// error can say what they are instead of "Unknown key". Some of them (the timers) change
    /// how long session keys live, so they need limits of their own before they can be accepted.
    static let unsupportedKeys: Set<String> = [
        "j1", "j2", "j3", "itime",
        "headerprotectionkey", "contentpaddingaddition", "randomtrailers", "disablecookies",
        "rekeyaftertime", "rekeytimeout", "rejectaftertime", "keepalivetimeout", "maxhandshakeattempts",
    ]

    /// Parses the AmneziaWG keys of one [Interface]. `values` holds lowercased keys.
    /// The most bytes and packets one handshake initiation sends before the initiation itself.
    var handshakeBurst: (bytes: Int, packets: Int) {
        let junk = Int(junkCount ?? 0)
        let signatures = signaturePackets.compactMap { $0 }.map { (try? SignaturePacket.length(of: $0).get()) ?? 0 }
        return (junk * Int(junkMax ?? 0) + signatures.reduce(0, +), junk + signatures.count)
    }

    // Messages name the setting but never quote its value: `wombat check --json` output can end
    // up in CI logs, and the values identify the server to a censor (audit S4 L3).
    static func parse(_ values: [String: (value: String, line: Int)], mtu: UInt16?, peers: Int,
                      error: (Int?, String) -> Void, warning: (Int?, String) -> Void) -> AmneziaParameters? {
        guard values.keys.contains(where: keys.contains) else { return nil }
        var p = AmneziaParameters()

        func number(_ key: String, _ name: String, max: UInt32) -> UInt32? {
            guard let (value, line) = values[key] else { return nil }
            guard !value.isEmpty, value.count <= 10, value.allSatisfy(\.isASCIIDigit), let n = UInt32(value), n <= max else {
                error(line, "\(name) must be a number from 0 to \(max)")
                return nil
            }
            return n
        }

        p.junkCount = number("jc", "Jc", max: maxJunkCount)
        p.junkMin = number("jmin", "Jmin", max: maxJunkSize)
        p.junkMax = number("jmax", "Jmax", max: maxJunkSize)
        if let jmin = p.junkMin, jmin > (p.junkMax ?? 0) {
            if p.junkMax != nil { error(values["jmax"]!.line, "Jmax is smaller than Jmin") }
            else { error(values["jmin"]!.line, "Jmin is set but Jmax isn't") }
        }
        if let jc = p.junkCount, jc > 0, p.junkMax == nil || p.junkMax == 0 {
            error(values["jc"]!.line, "Jc sends junk packets, so Jmin and Jmax must give their size")
        }
        if let jmax = p.junkMax, jmax >= UInt32(mtu ?? 1420) {
            warning(values["jmax"]!.line, "Jmax is not below the MTU, so junk packets may be fragmented")
        }

        for i in 0..<4 {
            if let n = number("s\(i + 1)", "S\(i + 1)", max: UInt32(maxPaddings[i])) { p.paddings[i] = UInt16(n) }
        }
        // 148 + S1 == 92 + S2 makes the initiation and the response the same size; AmneziaWG 1.0
        // peers tell them apart by size, and its tools refuse the pair.
        // An omitted S is 0, as in the engine (S4b I2).
        if p.paddings[0] != nil || p.paddings[1] != nil, Int(p.paddings[0] ?? 0) + 56 == Int(p.paddings[1] ?? 0) {
            warning(values["s2"]!.line, "S2 = S1 + 56 makes the handshake initiation and response the same size; older AmneziaWG peers can't tell them apart")
        }

        for i in 0..<4 {
            guard let (value, line) = values["h\(i + 1)"] else { continue }
            if let range = HeaderRange(value) { p.headers[i] = range }
            else { error(line, "H\(i + 1) must be a number or a range like 100-200 (0 to 4294967295)") }
        }
        // The engine tells the four message types apart by these values, so no two may share one.
        // An H left unset keeps WireGuard's own value (1 to 4), which counts too.
        let effective = (0..<4).map { p.headers[$0] ?? HeaderRange(single: defaultHeaders[$0]) }
        for i in 0..<4 {
            for j in (i + 1)..<4 where effective[i].overlaps(effective[j]) {
                let line = values["h\(j + 1)"]?.line ?? values["h\(i + 1)"]?.line
                let what = { (k: Int) in p.headers[k] == nil ? "H\(k + 1) (unset, so \(defaultHeaders[k]))" : "H\(k + 1)" }
                error(line, "\(what(i)) and \(what(j)) overlap: each message type needs its own values")
            }
        }

        for i in 0..<5 {
            guard let (value, line) = values["i\(i + 1)"] else { continue }
            if value.isEmpty { continue }  // empty means "no packet", as in the engine
            // Bytes, not Characters: a grapheme can be many bytes, and the engine's limit is bytes.
            guard value.utf8.count <= maxSignatureSpecLength else {
                error(line, "I\(i + 1) is longer than \(maxSignatureSpecLength) bytes")
                continue
            }
            // ASCII only: Swift and Go disagree on what Unicode whitespace splits a tag, so a
            // spec this parser accepts could fail in the engine (S4b L2).
            guard value.unicodeScalars.allSatisfy({ $0.isASCII && ($0.value >= 0x20 || $0 == "\t") }) else {
                error(line, "I\(i + 1) may contain only ASCII characters")
                continue
            }
            switch SignaturePacket.length(of: value) {
            case .success(let length) where length > maxSignaturePacketBytes:
                error(line, "I\(i + 1) is longer than \(maxSignaturePacketBytes) bytes")
            case .success:
                p.signaturePackets[i] = value
            case .failure(let problem):
                error(line, "I\(i + 1): \(problem.message)")
            }
        }

        let burst = p.handshakeBurst
        if peers * burst.bytes > maxBurstBytes || peers * burst.packets > maxBurstPackets {
            let line = values["jc"]?.line ?? values.first { keys.contains($0.key) }?.value.line
            error(line, "Junk and signature packets for \(peers) peers would be more than \(maxBurstBytes >> 20) MB or \(maxBurstPackets) packets per round of handshakes; use fewer peers or smaller Jc, Jmax or I1-I5")
        }
        return p
    }
}

/// The tag language of AmneziaWG's I1-I5 signature packets.
enum SignaturePacket {
    struct Problem: Error, Equatable { let message: String }

    /// Checks a spec and returns the packet's length in bytes. Only the documented tags are
    /// accepted: `<b 0xHEX>` fixed bytes, `<t>` a 4-byte timestamp, `<r N>` random bytes,
    /// `<rc N>` random letters, `<rd N>` random digits. Text outside tags is refused (the engine
    /// silently skips it, which would hide a typo).
    static func length(of spec: String) -> Result<Int, Problem> {
        var total = 0
        var tags = 0
        var rest = Substring(spec)
        while let open = rest.firstIndex(where: { !$0.isWhitespace }) {
            rest = rest[open...]
            guard rest.first == "<" else { return .failure(Problem(message: "text outside a <tag>")) }
            guard let close = rest.firstIndex(of: ">") else { return .failure(Problem(message: "a tag is missing its closing >")) }
            let parts = rest[rest.index(after: rest.startIndex)..<close].split(whereSeparator: \.isWhitespace)
            rest = rest[rest.index(after: close)...]
            guard let tag = parts.first, parts.count <= 2 else { return .failure(Problem(message: "a tag is malformed")) }
            let argument = parts.count == 2 ? String(parts[1]) : nil

            let length: Int
            switch tag {
            case "b":
                var hex = argument ?? ""
                if hex.hasPrefix("0x") { hex.removeFirst(2) }
                // Character.isHexDigit also accepts fullwidth digits, which the engine doesn't.
                guard !hex.isEmpty, hex.count % 2 == 0, hex.allSatisfy({ $0.isASCII && $0.isHexDigit }) else {
                    return .failure(Problem(message: "<b> needs an even number of hex digits, like <b 0xc0ffee>"))
                }
                length = hex.count / 2
            case "t":
                guard argument == nil else { return .failure(Problem(message: "<t> takes no value")) }
                length = 4
            case "r", "rc", "rd":
                guard let argument, argument.count <= 5, argument.allSatisfy(\.isASCIIDigit), let n = Int(argument) else {
                    return .failure(Problem(message: "<\(tag)> needs a length, like <\(tag) 16>"))
                }
                length = n
            default:
                // Never named: the text comes from the file (S4b L1, S4b L3).
                return .failure(Problem(message: "a tag is not one of the supported tags (b, t, r, rc, rd)"))
            }
            total += length
            tags += 1
            if total > AmneziaParameters.maxSignaturePacketBytes { return .success(total) }
        }
        if tags == 0 { return .failure(Problem(message: "no tags")) }
        return total == 0 ? .failure(Problem(message: "the packet would be empty")) : .success(total)
    }
}
