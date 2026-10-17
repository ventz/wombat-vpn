import Foundation

/// Writes a zip of `.conf` files (stored, no compression: configs are tiny) in the layout the
/// official WireGuard app's "Import Tunnel(s) from File" accepts. Pure and in memory.
public enum ZipWriter {
    public struct File: Sendable {
        public let name: String
        public let text: String
        public init(name: String, text: String) {
            self.name = name
            self.text = text
        }
    }

    public static func archive(_ files: [File], date: Date = Date()) -> Data {
        var out = Data()
        var central = Data()
        let (dosTime, dosDate) = dosDateTime(date)
        var used = Set<String>()

        for file in files {
            let name = uniqueName(fileName(file.name), used: &used)
            let nameData = Data(name.utf8)
            // Checked, never trapping: fileName keeps names far below this (SEC-11).
            guard let nameLength = UInt16(exactly: nameData.count) else { continue }
            let content = [UInt8](file.text.utf8)
            let crc = CRC32.checksum(content)
            let offset = UInt32(out.count)

            out.append(le32: 0x0403_4B50)      // local file header
            out.append(le16: 20)               // version needed
            out.append(le16: 0x0800)           // flags: UTF-8 names
            out.append(le16: 0)                // stored
            out.append(le16: dosTime); out.append(le16: dosDate)
            out.append(le32: crc)
            out.append(le32: UInt32(content.count)); out.append(le32: UInt32(content.count))
            out.append(le16: nameLength); out.append(le16: 0)
            out.append(nameData)
            out.append(contentsOf: content)

            central.append(le32: 0x0201_4B50)  // central directory header
            central.append(le16: 0x031E)       // made by: Unix, 3.0
            central.append(le16: 20)
            central.append(le16: 0x0800)
            central.append(le16: 0)
            central.append(le16: dosTime); central.append(le16: dosDate)
            central.append(le32: crc)
            central.append(le32: UInt32(content.count)); central.append(le32: UInt32(content.count))
            central.append(le16: nameLength)
            central.append(le16: 0); central.append(le16: 0)  // extra, comment
            central.append(le16: 0); central.append(le16: 0)  // disk, internal attributes
            central.append(le32: UInt32(0o100600) << 16)      // -rw------- (keys inside)
            central.append(le32: offset)
            central.append(nameData)
        }

        let cdOffset = UInt32(out.count)
        out.append(central)
        out.append(le32: 0x0605_4B50)
        out.append(le16: 0); out.append(le16: 0)
        out.append(le16: UInt16(files.count)); out.append(le16: UInt16(files.count))
        out.append(le32: UInt32(central.count))
        out.append(le32: cdOffset)
        out.append(le16: 0)
        return out
    }

    /// "Home/Office" → "Home-Office.conf": names come from tunnel names, never paths.
    public static func fileName(_ tunnelName: String) -> String {
        let safe = TunnelName.sanitize(tunnelName)
            .map { "/\\:".contains($0) ? "-" : $0 }
        var base = String(safe).trimmingCharacters(in: CharacterSet(charactersIn: ". "))
        // Names are capped in characters, and one character can be dozens of UTF-8 bytes; a zip
        // name must fit in 16 bits (review SEC-11), and macOS file names in 255 bytes.
        while base.utf8.count > 200 { base.removeLast() }
        if base.isEmpty { base = "Tunnel" }
        return base + ".conf"
    }

    private static func uniqueName(_ name: String, used: inout Set<String>) -> String {
        var candidate = name
        var n = 2
        while used.contains(candidate.lowercased()) {
            candidate = String(name.dropLast(5)) + " \(n).conf"
            n += 1
        }
        used.insert(candidate.lowercased())
        return candidate
    }

    private static func dosDateTime(_ date: Date) -> (UInt16, UInt16) {
        let c = Calendar(identifier: .gregorian).dateComponents(in: .current, from: date)
        let time = UInt16((c.hour ?? 0) << 11 | (c.minute ?? 0) << 5 | (c.second ?? 0) / 2)
        let day = UInt16(max(0, (c.year ?? 1980) - 1980) << 9 | (c.month ?? 1) << 5 | (c.day ?? 1))
        return (time, day)
    }
}

private extension Data {
    mutating func append(le16 v: UInt16) { Swift.withUnsafeBytes(of: v.littleEndian) { append(contentsOf: $0) } }
    mutating func append(le32 v: UInt32) { Swift.withUnsafeBytes(of: v.littleEndian) { append(contentsOf: $0) } }
}
