import Foundation
import Testing
@testable import TunnelCore

/// Debug logging and Save Diagnostics (issue #1, 2026-11-05): log lines end up in files people
/// attach to public issues, so nothing secret may survive the scrubber.
@Suite struct LogScrubberTests {
    /// What libopenconnect 9.21 prints at PRG_DEBUG for the headers of a CSTP CONNECT reply
    /// (cstp.c:447) and an HTTP reply (http.c:325, 340).
    @Test func secretHeadersLoseTheirValues() {
        let lines = [
            "X-DTLS-Session-ID: 6c1f0b2a9e4d7c8b5a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b",
            "X-DTLS-App-ID: 9f8e7d6c5b4a",
            "X-DTLS-Master-Secret: 0123",
            "Set-Cookie: webvpnc=bu:/&p:t&iu:1/&sh:ABCD",
            "Cookie: webvpn=ABCDEF",
            "X-AnyConnect-STRAP-Pubkey: MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE",
            "Authorization: Bearer abc",
        ]
        for line in lines {
            let out = LogScrubber.scrub(line)
            #expect(out.hasSuffix(": \(LogScrubber.hidden)"), "\(line) -> \(out)")
            #expect(!out.contains("bu:/") && !out.contains("ABCDEF") && !out.contains("abc") && !out.contains("0123"))
        }
    }

    @Test func usefulHeadersStay() {
        for line in ["X-CSTP-Session-Timeout: 43200", "X-CSTP-Smartcard-Removal-Disconnect: true", "X-CSTP-MTU: 1399", "X-CSTP-Rekey-Method: new-tunnel",
                     "X-CSTP-Address: 10.1.2.3", "X-DTLS-CipherSuite: ECDHE-RSA-AES256-GCM-SHA384",
                     "Got inappropriate HTTP CONNECT response: HTTP/1.1 401 Unauthorized",
                     "Received server disconnect: b0 'Posture Assessment Failed'"] {
            #expect(LogScrubber.scrub(line) == line)
        }
    }

    @Test func assignmentsLoseTheirValues() {
        let out = LogScrubber.scrub("cookie openconnect_strapkey=MHcCAQEE; webvpn=4C1D2E@12345@ABCD and private_key=yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=")
        #expect(!out.contains("MHcCAQEE") && !out.contains("4C1D2E") && !out.contains("yAnz5TF"))
        #expect(out.contains("openconnect_strapkey=\(LogScrubber.hidden)"))
        #expect(out.contains("webvpn=\(LogScrubber.hidden)"))
    }

    /// The wg(8) man page key: a base64 key anywhere in a line goes, even without a name.
    @Test func longOpaqueRunsGoButUUIDsStay() {
        let id = "6F9619FF-8B86-D011-B42D-00C04FC964FF"
        let out = LogScrubber.scrub("peer HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw= for \(id), sha256 \(String(repeating: "a1", count: 32))")
        #expect(!out.contains("HIgo9xNzJMWL"))
        #expect(!out.contains("a1a1a1a1"))
        #expect(out.contains(id))
    }

    @Test func controlCharactersAndLengthAreCut() {
        let out = LogScrubber.scrub("a\u{1B}[31mred\nnext" + String(repeating: "x ", count: 1000))
        #expect(!out.contains("\u{1B}") && !out.contains("\n"))
        #expect(out.count <= LogScrubber.maxLineLength)
    }

    @Test func serversAndAddressesGetStablePlaceholders() {
        var hider = ServerHider(servers: ["vpn.example.edu", "example.edu", "203.0.113.9"])
        let out = hider.hide("Connected to VPN.example.edu (203.0.113.9), DNS 10.0.0.53, 10.0.0.53 again, v6 2001:db8::1 at 10:22:33.123, home example.edu, loopback 127.0.0.1")
        #expect(out == "Connected to server-1 (address-1), DNS address-2, address-2 again, v6 address-3 at 10:22:33.123, home server-2, loopback 127.0.0.1")
        // The same hider keeps its numbering across sections of one report.
        #expect(hider.hide("again 203.0.113.9") == "again address-1")
    }

    @Test func fullIPv6AddressesAreHidden() {
        var hider = ServerHider(servers: [])
        #expect(hider.hide("route fd7a:115c:a1e0:ab12:4843:cd96:6258:b240/128") == "route address-1/128")
    }

    /// security-10 M1: Tailscale logs the signed-in account at its default level.
    @Test func loginNamesAreHidden() {
        #expect(LogScrubber.scrub("active login: jane.doe+vpn@example.co.uk") == "active login: \(LogScrubber.hiddenLogin)")
        #expect(LogScrubber.scrub("switching to profile \"ventz@github\"") == "switching to profile \"ventz@github\"")
    }

    @Test func compoundSecretNamesLoseTheirValues() {
        let out = LogScrubber.scrub("sso_token=abc123 auth-token=def456; mode=full")
        #expect(!out.contains("abc123") && !out.contains("def456"))
        #expect(out.hasSuffix("mode=full"))
    }

    /// security-10 L2: gateway text can't make matching slow (the old pattern backtracked on
    /// hyphenated runs of secret words).
    @Test func hostileLinesScrubQuickly() {
        let lines = [String(repeating: "token-", count: 200), String(repeating: "a-", count: 600) + ":",
                     String(repeating: "x", count: 5000), String(repeating: "secret-token=", count: 90)]
        let start = ContinuousClock.now
        for line in lines { _ = LogScrubber.scrub(line) }
        #expect(ContinuousClock.now - start < .milliseconds(200))
    }

    @Test func digitFreeKeysStillGo() {
        // Base64 with "+" or "/" but no digit is a key, not a word.
        #expect(LogScrubber.scrub("k abcdefghij+klmnopqrstuvwxyzABCDEFGH/IJ end") == "k \(LogScrubber.hidden) end")
    }

    @Test func hideModeCoversDomainsVPNNamesAndKeepsVersions() {
        var hider = ServerHider(servers: ["vpn.example.edu"], vpnNames: ["Home", "Work VPN"])
        let out = hider.hide("Home and Work VPN via vpn.example.edu, domain corp.example.edu, MagicDNS tail1234.ts.net, Homebrew, Wombat v9.21.0.1, std::string, Settings.app")
        #expect(out == "VPN 1 and VPN 2 via server-1, domain domain-1, MagicDNS domain-2, Homebrew, Wombat v9.21.0.1, std::string, Settings.app")
    }

    @Test func serverNumberingIsStable() {
        var a = ServerHider(servers: ["b.example.com", "a.example.com"])
        var b = ServerHider(servers: ["a.example.com", "b.example.com"])
        #expect(a.hide("a.example.com b.example.com") == b.hide("a.example.com b.example.com"))
    }

    @Test func debugDeadlineIsAtMostADay() {
        let now = Date(timeIntervalSince1970: 1_000_000)
        #expect(DebugLoggingDeadline.effective(stored: 0, now: now) == nil)
        #expect(DebugLoggingDeadline.effective(stored: 999_999, now: now) == nil)
        #expect(DebugLoggingDeadline.effective(stored: 1_003_600, now: now) == Date(timeIntervalSince1970: 1_003_600))
        #expect(DebugLoggingDeadline.effective(stored: 9_999_999, now: now) == now.addingTimeInterval(86_400))
    }

    @Test func disconnectReasonIsFetchedOnlyForUnaskedEnds() {
        #expect(DisconnectReasonRule.shouldFetch(before: .connected, now: .disconnected, stoppedByApp: false))
        #expect(DisconnectReasonRule.shouldFetch(before: .disconnecting, now: .disconnected, stoppedByApp: false))
        #expect(DisconnectReasonRule.shouldFetch(before: .connecting, now: .disconnected, stoppedByApp: false))
        #expect(!DisconnectReasonRule.shouldFetch(before: .connected, now: .disconnected, stoppedByApp: true))
        #expect(!DisconnectReasonRule.shouldFetch(before: .disconnected, now: .disconnected, stoppedByApp: false))
        #expect(!DisconnectReasonRule.shouldFetch(before: .connected, now: .disconnecting, stoppedByApp: false))
    }

    @Test func privateFilesAre0600EvenWhenTheyExisted() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = dir.appendingPathComponent("report.txt").path
        FileManager.default.createFile(atPath: path, contents: Data("old and longer".utf8), attributes: [.posixPermissions: 0o644])
        try PrivateFile.write(Data("new".utf8), to: path)
        let mode = try FileManager.default.attributesOfItem(atPath: path)[.posixPermissions] as? Int
        #expect(mode == 0o600)
        #expect(try String(contentsOfFile: path, encoding: .utf8) == "new")
        // A symlink planted at the path is refused, not followed.
        let link = dir.appendingPathComponent("link.txt").path
        try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: path)
        #expect(throws: PrivateFile.Failure.self) { try PrivateFile.write(Data("x".utf8), to: link) }
    }
}
