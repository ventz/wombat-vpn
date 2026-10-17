import Foundation
import Testing
@testable import TunnelCore

/// Archives are made by /usr/bin/zip, an independent writer, not by code in this package.
private func makeZip(_ files: [String: String], options: [String] = []) throws -> Data {
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: dir) }
    for (name, text) in files {
        let url = dir.appendingPathComponent(name)
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try text.write(to: url, atomically: true, encoding: .utf8)
    }
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/zip")
    process.currentDirectoryURL = dir
    process.arguments = ["-q", "-r"] + options + ["out.zip"] + files.keys.sorted()
    try process.run()
    process.waitUntilExit()
    return try Data(contentsOf: dir.appendingPathComponent("out.zip"))
}

@Suite struct ZipReaderTests {
    @Test func readsDeflatedAndStoredConfs() throws {
        let big = String(repeating: "# padding so deflate kicks in\n", count: 50) + sample
        for options in [[], ["-0"]] {
            let data = try makeZip(["home.conf": big, "sub/work.conf": sample, "readme.txt": "x"], options: options)
            let entries = try ZipReader.confEntries(data).sorted { $0.name < $1.name }
            #expect(entries.map(\.name) == ["home.conf", "work.conf"])
            #expect(entries[0].text == big)
            #expect(WgQuick.parse(entries[1].text).configuration != nil)
        }
    }

    @Test func refusesNonZipAndTruncated() throws {
        #expect(throws: ZipReader.Failure.notAZip) { try ZipReader.confEntries(Data("hello".utf8)) }
        let data = try makeZip(["a.conf": sample])
        #expect(throws: (any Error).self) { try ZipReader.confEntries(data.prefix(data.count - 30)) }
    }

    @Test func refusesEncrypted() throws {
        let data = try makeZip(["a.conf": sample], options: ["-P", "pw"])
        #expect(throws: ZipReader.Failure.unsupported("encrypted entries")) { try ZipReader.confEntries(data) }
    }

    @Test func refusesOversizeEntries() throws {
        let data = try makeZip(["a.conf": String(repeating: "#", count: ZipReader.maxEntryBytes + 1)])
        #expect(throws: ZipReader.Failure.tooLarge) { try ZipReader.confEntries(data) }
    }

    @Test func pathTraversalNamesAreFlattened() throws {
        var data = try makeZip(["aaaaaaa.conf": sample])
        // Rewrite the stored name "aaaaaaa.conf" to "../xx/b.conf" (same length) in both headers.
        let from = Data("aaaaaaa.conf".utf8), replacement = Data("../xx/b.conf".utf8)
        while let r = data.range(of: from) { data.replaceSubrange(r, with: replacement) }
        let entries = try ZipReader.confEntries(data)
        #expect(entries.map(\.name) == ["b.conf"])
    }
}

@Suite struct ZipBombTests {
    // L-1: two central-directory entries pointing at one local entry.
    @Test func sharedDataIsRejected() throws {
        var data = try makeZipForBomb()
        // Duplicate the central directory record and bump the entry count.
        let cdSig = Data([0x50, 0x4B, 0x01, 0x02]), eocdSig = Data([0x50, 0x4B, 0x05, 0x06])
        let cd = data.range(of: cdSig)!.lowerBound, eocd = data.range(of: eocdSig)!.lowerBound
        let record = data[cd..<eocd]
        data.insert(contentsOf: record, at: eocd)
        let newEOCD = eocd + record.count
        data[newEOCD + 8] += 1; data[newEOCD + 10] += 1                       // entries on disk / total
        let size = UInt32(record.count * 2)
        for i in 0..<4 { data[newEOCD + 12 + i] = UInt8((size >> (8 * UInt32(i))) & 0xFF) }
        #expect(throws: ZipReader.Failure.corrupt("entries share data")) { try ZipReader.confEntries(data) }
    }

    @Test func corruptedContentFailsChecksum() throws {
        var data = try makeZipForBomb(stored: true)
        let r = data.range(of: Data("PrivateKey".utf8))!
        data[r.lowerBound] = UInt8(ascii: "Q")
        #expect(throws: (any Error).self) { try ZipReader.confEntries(data) }
    }

    @Test func crcMatchesKnownValue() {
        #expect(CRC32.checksum(Array("123456789".utf8)) == 0xCBF4_3926)
    }
}

private func makeZipForBomb(stored: Bool = false) throws -> Data {
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: dir) }
    try sample.write(to: dir.appendingPathComponent("a.conf"), atomically: true, encoding: .utf8)
    let p = Process()
    p.executableURL = URL(fileURLWithPath: "/usr/bin/zip")
    p.currentDirectoryURL = dir
    p.arguments = ["-q"] + (stored ? ["-0"] : []) + ["out.zip", "a.conf"]
    try p.run(); p.waitUntilExit()
    return try Data(contentsOf: dir.appendingPathComponent("out.zip"))
}

@Suite struct ZipWriterTests {
    /// A name of heavily combined characters is short in characters but huge in UTF-8; it used to
    /// trap in UInt16(nameData.count) (review SEC-11).
    @Test func combiningCharacterNamesDontTrap() throws {
        let zalgo = String(repeating: "a" + String(repeating: "\u{0301}", count: 1100), count: 64)
        #expect(TunnelName.sanitize(zalgo).utf8.count > 65_535)  // the case that trapped
        #expect(ZipWriter.fileName(zalgo).utf8.count <= 255)
        let data = ZipWriter.archive([ZipWriter.File(name: zalgo, text: "x")])
        #expect(!data.isEmpty)
    }

    /// Read back with /usr/bin/unzip, an independent implementation, and with our reader.
    @Test func roundTripsThroughUnzipAndReader() throws {
        let files = [ZipWriter.File(name: "Home", text: sample), ZipWriter.File(name: "Home", text: "# second\n"),
                     ZipWriter.File(name: "a/b\\c:d", text: "x")]
        let data = ZipWriter.archive(files)
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let zip = dir.appendingPathComponent("t.zip")
        try data.write(to: zip)
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/unzip")
        p.arguments = ["-q", zip.path, "-d", dir.appendingPathComponent("out").path]
        try p.run(); p.waitUntilExit()
        #expect(p.terminationStatus == 0)
        let names = try FileManager.default.contentsOfDirectory(atPath: dir.appendingPathComponent("out").path).sorted()
        #expect(names == ["Home 2.conf", "Home.conf", "a-b-c-d.conf"])
        #expect(try String(contentsOf: dir.appendingPathComponent("out/Home.conf"), encoding: .utf8) == sample)
        #expect(try ZipReader.confEntries(data).map(\.name).sorted() == names)
    }
}
