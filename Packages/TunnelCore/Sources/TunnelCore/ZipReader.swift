import Compression
import Foundation

/// Reads `.conf` entries from a zip archive in memory, e.g. the official app's
/// "Export Tunnels to Zip". Built for untrusted input: nothing is written to disk, entry names
/// are reduced to their last path component, and sizes and counts are capped before inflating.
public enum ZipReader {
    public struct Entry: Equatable, Sendable {
        public let name: String     // last path component, e.g. "home.conf"
        public let text: String
    }

    public enum Failure: Error, Equatable, CustomStringConvertible {
        case notAZip, tooLarge, tooManyEntries, unsupported(String), corrupt(String)
        public var description: String {
            switch self {
            case .notAZip: return "Not a zip archive"
            case .tooLarge: return "Archive or entry is too large"
            case .tooManyEntries: return "Archive has too many entries"
            case .unsupported(let s): return "Unsupported zip feature: \(s)"
            case .corrupt(let s): return "Corrupt zip archive: \(s)"
            }
        }
    }

    public static let maxArchiveBytes = 16 * 1024 * 1024
    public static let maxEntries = 1024
    public static let maxEntryBytes = WgQuick.maxBytes
    /// Total inflated output across all entries: several entries pointing at the same compressed
    /// data (an "overlap" zip bomb) would otherwise multiply a small archive into hundreds of MB.
    public static let maxTotalBytes = 4 * 1024 * 1024

    public static func confEntries(_ data: Data) throws -> [Entry] {
        guard data.count <= maxArchiveBytes else { throw Failure.tooLarge }
        let bytes = [UInt8](data)
        guard bytes.count >= 22 else { throw Failure.notAZip }

        func u16(_ o: Int) throws -> Int {
            guard o >= 0, o + 2 <= bytes.count else { throw Failure.corrupt("truncated") }
            return Int(bytes[o]) | Int(bytes[o + 1]) << 8
        }
        func u32(_ o: Int) throws -> Int {
            guard o >= 0, o + 4 <= bytes.count else { throw Failure.corrupt("truncated") }
            return Int(bytes[o]) | Int(bytes[o + 1]) << 8 | Int(bytes[o + 2]) << 16 | Int(bytes[o + 3]) << 24
        }

        // End of central directory: scan back over at most a 64 KB comment.
        var eocd = -1
        var i = bytes.count - 22
        let floor = max(0, bytes.count - 22 - 0xFFFF)
        while i >= floor {
            if bytes[i] == 0x50, bytes[i + 1] == 0x4B, bytes[i + 2] == 0x05, bytes[i + 3] == 0x06 { eocd = i; break }
            i -= 1
        }
        guard eocd >= 0 else { throw Failure.notAZip }
        let count = try u16(eocd + 10)
        let cdOffset = try u32(eocd + 16)
        guard count != 0xFFFF, cdOffset != 0xFFFF_FFFF else { throw Failure.unsupported("ZIP64") }
        guard count <= maxEntries else { throw Failure.tooManyEntries }

        var entries: [Entry] = []
        var total = 0
        var dataRanges: [Range<Int>] = []
        var p = cdOffset
        for _ in 0..<count {
            guard try u32(p) == 0x0201_4B50 else { throw Failure.corrupt("central directory") }
            let flags = try u16(p + 8)
            let crc = UInt32(truncatingIfNeeded: try u32(p + 16))
            let method = try u16(p + 10)
            let compressedSize = try u32(p + 20)
            let size = try u32(p + 24)
            let nameLength = try u16(p + 28)
            let extraLength = try u16(p + 30)
            let commentLength = try u16(p + 32)
            let localOffset = try u32(p + 42)
            guard p + 46 + nameLength <= bytes.count else { throw Failure.corrupt("name") }
            let rawName = String(decoding: bytes[(p + 46)..<(p + 46 + nameLength)], as: UTF8.self)
            p += 46 + nameLength + extraLength + commentLength

            let name = rawName.split(whereSeparator: { $0 == "/" || $0 == "\\" }).last.map(String.init) ?? ""
            guard name.lowercased().hasSuffix(".conf"), !name.hasPrefix("."), name.count > 5 else { continue }
            guard flags & 0x1 == 0 else { throw Failure.unsupported("encrypted entries") }
            guard size <= maxEntryBytes, compressedSize <= maxEntryBytes else { throw Failure.tooLarge }

            guard try u32(localOffset) == 0x0403_4B50 else { throw Failure.corrupt("local header") }
            let start = localOffset + 30 + (try u16(localOffset + 26)) + (try u16(localOffset + 28))
            guard start >= 0, start + compressedSize <= bytes.count else { throw Failure.corrupt("entry data") }
            let range = start..<(start + max(compressedSize, 1))
            guard !dataRanges.contains(where: { $0.overlaps(range) }) else { throw Failure.corrupt("entries share data") }
            dataRanges.append(range)
            total += size
            guard total <= maxTotalBytes else { throw Failure.tooLarge }
            let payload = Array(bytes[start..<(start + compressedSize)])

            let content: [UInt8]
            switch method {
            case 0:
                guard compressedSize == size else { throw Failure.corrupt("stored size") }
                content = payload
            case 8:
                content = try inflate(payload, expected: size)
            default:
                throw Failure.unsupported("compression method \(method)")
            }
            guard CRC32.checksum(content) == crc else { throw Failure.corrupt("\(name) checksum mismatch") }
            guard let text = String(bytes: content, encoding: .utf8) else { throw Failure.corrupt("\(name) is not UTF-8") }
            entries.append(Entry(name: name, text: text))
        }
        return entries
    }

    /// Raw DEFLATE (COMPRESSION_ZLIB is RFC 1951 without a zlib header). The output buffer is
    /// exactly the declared size, so a zip bomb cannot expand past the per-entry cap.
    static func inflate(_ input: [UInt8], expected: Int) throws -> [UInt8] {
        if expected == 0 { return [] }
        var output = [UInt8](repeating: 0, count: expected + 1)
        let written = input.withUnsafeBufferPointer { src in
            output.withUnsafeMutableBufferPointer { dst in
                compression_decode_buffer(dst.baseAddress!, dst.count, src.baseAddress!, src.count, nil, COMPRESSION_ZLIB)
            }
        }
        guard written == expected else { throw Failure.corrupt("inflated size \(written) != \(expected)") }
        return Array(output.prefix(expected))
    }
}

enum CRC32 {
    static let table: [UInt32] = (0..<256).map { n in
        var c = UInt32(n)
        for _ in 0..<8 { c = c & 1 != 0 ? 0xEDB8_8320 ^ (c >> 1) : c >> 1 }
        return c
    }

    static func checksum(_ bytes: [UInt8]) -> UInt32 {
        var c: UInt32 = 0xFFFF_FFFF
        for b in bytes { c = table[Int((c ^ UInt32(b)) & 0xFF)] ^ (c >> 8) }
        return c ^ 0xFFFF_FFFF
    }
}

public enum TunnelName {
    public static let maxLength = 64

    /// A display name from a file name: "My VPN.conf" → "My VPN". Control and bidi characters
    /// are dropped (names appear in menus and the CLI), whitespace collapsed, length capped.
    public static func from(fileName: String) -> String {
        var base = fileName
        if base.lowercased().hasSuffix(".conf") { base = String(base.dropLast(5)) }
        return sanitize(base)
    }

    public static func sanitize(_ raw: String) -> String {
        let cleaned = raw.unicodeScalars.filter { s in
            !(s.properties.generalCategory == .control || s.properties.generalCategory == .format
              || s.properties.generalCategory == .lineSeparator || s.properties.generalCategory == .paragraphSeparator)
        }
        let collapsed = String(String.UnicodeScalarView(cleaned))
            .split(whereSeparator: \.isWhitespace).joined(separator: " ")
        let capped = String(collapsed.prefix(maxLength))
        return capped.isEmpty ? "Tunnel" : capped
    }

    /// "Home" → "Home 2" while the name is taken (case-insensitive).
    public static func unique(_ name: String, existing: [String]) -> String {
        let taken = Set(existing.map { $0.lowercased() })
        guard taken.contains(name.lowercased()) else { return name }
        var n = 2
        while taken.contains("\(name) \(n)".lowercased()) { n += 1 }
        return "\(name) \(n)"
    }
}
