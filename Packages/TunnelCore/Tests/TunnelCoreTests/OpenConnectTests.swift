import Foundation
import Testing
@testable import TunnelCore

// Message shapes as Cisco ASA/FTD gateways send them (and as OpenConnect's auth.c reads them).

let ocOpaque = """
<opaque is-for="sg">
<tunnel-group>Staff</tunnel-group>
<auth-method>single-sign-on-v2</auth-method>
<group-alias>Staff</group-alias>
<config-hash>1595829378234</config-hash>
</opaque>
"""

let ocPasswordForm = """
<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
\(ocOpaque)
<auth id="main">
<title>Login</title>
<message>Please enter your username and password.</message>
<banner>Authorized users only &amp; monitored</banner>
<form>
<input type="text" name="username" label="Username:"></input>
<input type="password" name="password" label="Password:"></input>
<select name="group_list" label="GROUP:">
<option selected="true">Staff</option>
<option value="students">Students</option>
</select>
<input type="submit" name="Login" value="Login"></input>
</form>
</auth>
</config-auth>
"""

let ocDuoChallenge = """
<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
\(ocOpaque)
<auth id="challenge">
<message>Duo two-factor login for jdoe

Enter a passcode or select one of the following options:

 1. Duo Push to XXX-XXX-1234
 2. Phone call to XXX-XXX-1234

Passcode or option (1-2):</message>
<form>
<input type="password" name="answer" label="Response:"></input>
</form>
</auth>
</config-auth>
"""

let ocSSO = """
<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
<opaque is-for="sg"><tunnel-group>SAML</tunnel-group><config-hash>1</config-hash></opaque>
<auth id="main">
<title>Login</title>
<message>Please complete the authentication process in the AnyConnect Login window.</message>
<sso-v2-login>https://vpn.example.edu/+CSCOE+/saml/sp/login?ctx=3627392&amp;acsamlcap=v2</sso-v2-login>
<sso-v2-login-final>https://vpn.example.edu/+CSCOE+/saml_ac_login.html</sso-v2-login-final>
<sso-v2-token-cookie-name>acSamlv2Token</sso-v2-token-cookie-name>
<sso-v2-error-cookie-name>acSamlv2Error</sso-v2-error-cookie-name>
<form>
<input type="sso" name="sso-token"></input>
</form>
</auth>
</config-auth>
"""

let ocComplete = """
<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="complete" aggregate-auth-version="2">
<session-id>32768</session-id>
<session-token>ABCDEF@32768@1234@0123456789ABCDEF</session-token>
<auth id="success">
<banner>Authorized use only</banner>
<message id="0" param1="" param2=""></message>
</auth>
<config client="vpn" type="private"><vpn-base-config><server-cert-hash>AB12</server-cert-hash></vpn-base-config></config>
</config-auth>
"""

let ocHostScan = """
<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
<auth id="main"><title>Login</title><form><input type="text" name="username" label="Username:"/></form></auth>
<host-scan>
<host-scan-ticket>TICKET</host-scan-ticket>
<host-scan-token>TOKEN</host-scan-token>
<host-scan-base-uri>https://vpn.example.edu/+CSCOH+/</host-scan-base-uri>
<host-scan-wait-uri>/+CSCOE+/sdesktop/wait.html</host-scan-wait-uri>
</host-scan>
</config-auth>
"""

let ocCertRequest = """
<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
<client-cert-request/>
</config-auth>
"""

let testHash = String(repeating: "ab", count: 32)

@Suite struct OpenConnectProfileTests {
    @Test func parsesFullProfile() throws {
        let text = """
        # Work VPN
        [AnyConnect]
        Server = https://VPN.Example.edu/staff
        Group = Staff
        Username = jdoe
        ClientCertificate = sha256:\(String(repeating: "AB:", count: 31))AB
        ServerCertificate = \(testHash)
        UserAgent = AnyConnect Darwin_i386 4.10.08029
        DTLS = off
        """
        let result = OpenConnectFile.parse(text)
        #expect(result.errors.isEmpty)
        let p = try #require(result.profile)
        #expect(p.server.absoluteString == "https://vpn.example.edu/staff")
        #expect(p.host == "vpn.example.edu")
        #expect(p.port == 443)
        #expect(p.group == "Staff")
        #expect(p.username == "jdoe")
        #expect(p.clientCertificate == testHash)
        #expect(p.serverCertificate == testHash)
        #expect(p.userAgent == "AnyConnect Darwin_i386 4.10.08029")
        #expect(p.dtls == false)
        // Round trip.
        #expect(OpenConnectFile.parse(OpenConnectFile.serialize(p)).profile == p)
        #expect(OpenConnectFile.looksLikeProfile(text))
        #expect(!OpenConnectFile.looksLikeProfile("[Interface]\nPrivateKey = x"))
    }

    @Test func bareHostBecomesHTTPS() throws {
        let p = try #require(OpenConnectFile.parse("[AnyConnect]\nServer = vpn.example.edu:8443").profile)
        #expect(p.server.absoluteString == "https://vpn.example.edu:8443/")
        #expect(p.displayServer == "vpn.example.edu:8443")
    }

    /// A group URL works typed without https://, and a trailing slash (which an ASA treats as
    /// the web portal, not the group) is dropped.
    @Test func groupURLWithoutScheme() throws {
        let p = try #require(OpenConnectFile.parse("[AnyConnect]\nServer = vpn.example.edu/research").profile)
        #expect(p.server.absoluteString == "https://vpn.example.edu/research")
        let slash = try #require(OpenConnectFile.parse("[AnyConnect]\nServer = VPN.example.edu/research//").profile)
        #expect(slash.server.absoluteString == "https://vpn.example.edu/research")
        let bare = try #require(OpenConnectFile.parse("[AnyConnect]\nServer = vpn.example.edu/").profile)
        #expect(bare.server.absoluteString == "https://vpn.example.edu/")
    }

    @Test(arguments: [
        ("Server = http://vpn.example.edu", "never plain http"),
        ("Server = https://user:pw@vpn.example.edu", "user name or password"),
        ("Server = https://vpn.example.edu:0", "port"),
        ("Server = https://vpn.exämple.edu", "ASCII"),
        ("Server = ftp://vpn.example.edu", "https://"),
        ("Server = https://vpn.example.edu/a b", "spaces"),
    ])
    func rejectsBadServers(line: String, message: String) {
        let result = OpenConnectFile.parse("[AnyConnect]\n\(line)")
        #expect(result.profile == nil)
        #expect(result.errors.contains { $0.message.contains(message) }, "\(result.errors)")
    }

    @Test func refusesHooksAndUnknownKeys() {
        for key in ["CSDWrapper", "Script", "PostUp", "HostScan"] {
            let result = OpenConnectFile.parse("[AnyConnect]\nServer = vpn.example.edu\n\(key) = /tmp/x.sh")
            #expect(result.profile == nil)
            #expect(result.errors.contains { $0.message.contains("never runs") }, "\(key)")
        }
        #expect(OpenConnectFile.parse("[AnyConnect]\nServer = a.example\nColor = blue").errors.contains { $0.message.contains("Unknown key") })
        #expect(OpenConnectFile.parse("[AnyConnect]\nServer = a.example\nServer = b.example").errors.contains { $0.message.contains("twice") })
        #expect(OpenConnectFile.parse("Server = a.example").errors.contains { $0.message.contains("outside") })
        #expect(OpenConnectFile.parse("[AnyConnect]\nGroup = x").errors.contains { $0.message.contains("Server is required") })
        #expect(OpenConnectFile.parse("[AnyConnect]\nServer = a.example\nServerCertificate = sha1:abcd").errors.contains { $0.message.contains("64 hex") })
        #expect(OpenConnectFile.parse("[AnyConnect]\nServer = a.example\nDTLS = maybe").errors.contains { $0.message.contains("on or off") })
        // Invisible characters could make a line read differently than it is.
        #expect(OpenConnectFile.parse("[AnyConnect]\nServer = a.example\nGroup = St\u{202E}aff").errors.contains { $0.message.contains("invisible") })
        #expect(OpenConnectFile.parse(String(repeating: "#", count: OpenConnectFile.maxBytes + 1)).errors.contains { $0.message.contains("larger") })
    }

    @Test func fingerprintNormalization() {
        #expect(OpenConnectFile.normalizeFingerprint("SHA256:" + testHash.uppercased()) == testHash)
        #expect(OpenConnectFile.normalizeFingerprint(String(repeating: "０", count: 64)) == nil)  // fullwidth digits
        #expect(OpenConnectFile.normalizeFingerprint("abcd") == nil)
    }
}

@Suite struct AnyConnectXMLTests {
    @Test func parsesPasswordForm() throws {
        let reply = try AnyConnectReply.parse(Data(ocPasswordForm.utf8))
        #expect(reply.type == "auth-request")
        #expect(reply.authID == "main")
        #expect(reply.banner == "Authorized users only & monitored")
        #expect(reply.message == "Please enter your username and password.")
        let form = try #require(reply.form)
        // The group list comes first, submit buttons are dropped.
        #expect(form.fields.map(\.name) == ["group_list", "username", "password"])
        guard case .select(let choices, let selected) = form.fields[0].kind else { Issue.record("no select"); return }
        #expect(choices == [AuthField.Choice(value: "Staff", label: "Staff"), AuthField.Choice(value: "students", label: "Students")])
        #expect(selected == 0)
        #expect(form.fields[2].kind == .password)
        #expect(reply.opaque?.child("tunnel-group")?.allText == "Staff")
        #expect(!reply.isSuccess)
    }

    @Test func parsesSSOAndCompletion() throws {
        let sso = try #require(try AnyConnectReply.parse(Data(ocSSO.utf8)).sso)
        #expect(sso.loginURL.absoluteString == "https://vpn.example.edu/+CSCOE+/saml/sp/login?ctx=3627392&acsamlcap=v2")
        #expect(sso.finalURL == "https://vpn.example.edu/+CSCOE+/saml_ac_login.html")
        #expect(sso.tokenCookie == "acSamlv2Token")
        #expect(sso.errorCookie == "acSamlv2Error")

        let done = try AnyConnectReply.parse(Data(ocComplete.utf8))
        #expect(done.isSuccess)
        #expect(done.sessionToken == "ABCDEF@32768@1234@0123456789ABCDEF")
        #expect(done.banner == "Authorized use only")
    }

    @Test func flagsHostScanAndCertificateRequests() throws {
        #expect(try AnyConnectReply.parse(Data(ocHostScan.utf8)).hostScanRequested)
        let cert = try AnyConnectReply.parse(Data(ocCertRequest.utf8))
        #expect(cert.clientCertRequested && !cert.certAuthenticated)
    }

    @Test func refusesHostileDocuments() {
        let dtd = """
        <?xml version="1.0"?>
        <!DOCTYPE lol [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]>
        <config-auth type="auth-request"><auth id="main"><message>&b;</message></auth></config-auth>
        """
        #expect(throws: AnyConnectReply.Failure.self) { try AnyConnectReply.parse(Data(dtd.utf8)) }
        // A web page (a captive portal, or the wrong server) is not a sign-in reply.
        #expect(throws: AnyConnectReply.Failure.self) { try AnyConnectReply.parse(Data("<html><body>Hello</body></html>".utf8)) }
        // Field names become XML element names in the reply: only safe names are accepted.
        let badName = ocPasswordForm.replacingOccurrences(of: "name=\"username\"", with: "name=\"user&gt;&lt;x\"")
        #expect(throws: AnyConnectReply.Failure.self) { try AnyConnectReply.parse(Data(badName.utf8)) }
        let httpSSO = ocSSO.replacingOccurrences(of: "<sso-v2-login>https://", with: "<sso-v2-login>http://")
        #expect(throws: AnyConnectReply.Failure.self) { try AnyConnectReply.parse(Data(httpSSO.utf8)) }
        let deep = "<?xml version=\"1.0\"?><config-auth>" + String(repeating: "<a>", count: 100) + String(repeating: "</a>", count: 100) + "</config-auth>"
        #expect(throws: AnyConnectReply.Failure.self) { try AnyConnectReply.parse(Data(deep.utf8)) }
        #expect(throws: AnyConnectReply.Failure.self) { try AnyConnectReply.parse(Data(("<?xml version=\"1.0\"?>" + String(repeating: " ", count: XMLTree.maxBytes)).utf8)) }
    }

    @Test func refusesOtherEncodingsAndDuplicateFields() {
        // S5B-L1: whitespace pushes the declaration past any fixed-size check, and UTF-7 hides a
        // DTD ("+ADwAIQ-" is "<!"). The declaration is dropped, so the text is read as UTF-8 and
        // the hidden DTD stays inert text: no entity can expand.
        let padding = String(repeating: " ", count: 400)
        let hidden = padding + "<?xml version=\"1.0\" encoding=\"UTF-7\"?>+ADwAIQ-DOCTYPE x +AFs-+ADwAIQ-ENTITY a \"aaaa\"+AD4AXQA+-<config-auth type=\"auth-request\"><auth id=\"main\"><message>+ACY-a;</message></auth></config-auth>"
        // XMLTree.parse directly: AnyConnectReply.parse would refuse the padding before the guard
        // is reached, and the guard is what this tests (S5C-L1).
        if let tree = try? XMLTree.parse(Data(hidden.utf8)) {
            #expect(!tree.allText.contains("aaaa"))
        }
        let padded = padding + "<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY a \"b\">]><config-auth type=\"auth-request\"><auth id=\"main\"/></config-auth>"
        #expect(throws: XMLTree.ParseError.self) { try XMLTree.parse(Data(padded.utf8)) }
        // ASCII declaration, then UTF-16 without a BOM: the NUL bytes give it away.
        let utf16 = Data("<?xml version=\"1.0\"?>".utf8) + "<config-auth/>".data(using: .utf16LittleEndian)!
        #expect(throws: XMLTree.ParseError.self) { try XMLTree.parse(utf16) }
        let second = "<?xml version=\"1.0\"?><config-auth type=\"auth-request\"><?xml version=\"1.0\"?><auth id=\"main\"/></config-auth>"
        #expect(throws: AnyConnectReply.Failure.self) { try AnyConnectReply.parse(Data(second.utf8)) }
        let single = "<?xml version='1.0' encoding='utf-8'?><config-auth type=\"auth-request\"><auth id=\"main\"/></config-auth>"
        #expect(throws: Never.self) { try AnyConnectReply.parse(Data(single.utf8)) }
        let twice = ocPasswordForm.replacingOccurrences(of: "name=\"password\"", with: "name=\"username\"")
        #expect(throws: AnyConnectReply.Failure.self) { try AnyConnectReply.parse(Data(twice.utf8)) }
    }

    @Test func messagePlaceholders() throws {
        let tree = try XMLTree.parse(Data("<message param1=\"jdoe\" param2=\"3\">Hello %s, %s tries left</message>".utf8))
        #expect(AnyConnectReply.message(tree) == "Hello jdoe, 3 tries left")
    }

    @Test func buildsInitAndReply() throws {
        let initDoc = try XMLTree.parse(AnyConnectXML.initRequest(groupAccess: "https://vpn.example.edu/staff", groupSelect: "Staff", clientCertFailed: true))
        #expect(initDoc.name == "config-auth")
        #expect(initDoc.attribute("type") == "init")
        #expect(initDoc.attribute("aggregate-auth-version") == "2")
        #expect(initDoc.child("version")?.allText == AnyConnectXML.clientVersion)
        #expect(initDoc.child("device-id")?.allText == "mac-intel")
        #expect(initDoc.child("capabilities")?.child("auth-method")?.allText == "single-sign-on-v2")
        #expect(initDoc.child("group-access")?.allText == "https://vpn.example.edu/staff")
        #expect(initDoc.child("group-select")?.allText == "Staff")
        #expect(initDoc.child("client-cert-fail") != nil)

        let reply = try AnyConnectReply.parse(Data(ocPasswordForm.utf8))
        let body = AnyConnectXML.authReply(opaque: reply.opaque, answers: [
            ("group_list", "Staff"), ("username", "j<doe>&"), ("password", "p\"w"), ("answer", "push"), ("verify_password", "x"),
        ])
        let doc = try XMLTree.parse(body)
        #expect(doc.attribute("type") == "auth-reply")
        // The opaque block goes back exactly as received.
        #expect(doc.child("opaque") == reply.opaque)
        let auth = try #require(doc.child("auth"))
        #expect(auth.children.map(\.name) == ["username", "password", "password"])
        #expect(auth.children[0].allText == "j<doe>&")
        #expect(auth.children[1].allText == "p\"w")
        #expect(auth.children[2].allText == "push")
        #expect(doc.child("group-select")?.allText == "Staff")
    }
}

// MARK: - Sign-in state machine

/// A gateway that answers from a script and records what the client sent.
final class ScriptedGateway: GatewayTransport, @unchecked Sendable {
    var replies: [GatewayReply]
    var requests: [(url: URL, body: XMLTree, fresh: Bool)] = []
    let lock = NSLock()

    init(_ replies: [GatewayReply]) { self.replies = replies }

    func post(_ url: URL, body: Data, freshConnection: Bool) async throws -> GatewayReply {
        try lock.withLock {
            requests.append((url, try XMLTree.parse(body), freshConnection))
            guard !replies.isEmpty else { throw AnyConnectSignInError.tooManySteps }
            return replies.removeFirst()
        }
    }
}

func xmlReply(_ text: String, status: Int = 200) -> GatewayReply {
    GatewayReply(status: status, body: Data(text.utf8), serverCertificateSHA256: testHash, remoteAddress: "192.0.2.10")
}

let ocTestProfile = OpenConnectProfile(server: URL(string: "https://vpn.example.edu/staff")!, username: "jdoe")

func prompts(fill: @escaping @Sendable (AnyConnectPrompt) -> [String: String]?,
             sso: @escaping @Sendable (SSORequest) throws -> String = { _ in throw CancellationError() }) -> AnyConnectPrompts {
    AnyConnectPrompts(fill: { fill($0) }, singleSignOn: { try sso($0) })
}

@Suite struct AnyConnectSignInTests {
    @Test func passwordThenDuo() async throws {
        let gateway = ScriptedGateway([xmlReply(ocPasswordForm), xmlReply(ocDuoChallenge), xmlReply(ocComplete)])
        let seen = Recorder()
        let signIn = AnyConnectSignIn(profile: ocTestProfile, transport: gateway, prompts: prompts { prompt in
            seen.append(prompt)
            if prompt.form.fields.contains(where: { $0.name == "answer" }) { return ["answer": "push"] }
            return ["username": prompt.prefilled["username"] ?? "", "password": "hunter2", "group_list": "Staff"]
        }, hasClientCertificate: false)
        let session = try await signIn.run()
        #expect(session.cookie == "ABCDEF@32768@1234@0123456789ABCDEF")
        #expect(session.host == "vpn.example.edu")
        #expect(session.address == "192.0.2.10")
        #expect(session.serverCertificateSHA256 == testHash)
        #expect(session.validate() == nil)
        #expect(seen.prompts.first?.prefilled["username"] == "jdoe")  // from the profile
        #expect(seen.prompts.last?.message?.contains("Duo Push") == true)
        #expect(gateway.requests.map { $0.body.attribute("type") } == ["init", "auth-reply", "auth-reply"])
        #expect(gateway.requests[1].body.child("auth")?.child("password")?.allText == "hunter2")
        #expect(gateway.requests[2].body.child("auth")?.child("password")?.allText == "push")  // answer → password
    }

    @Test func choosingAnotherGroupStartsOver() async throws {
        let gateway = ScriptedGateway([xmlReply(ocPasswordForm), xmlReply(ocPasswordForm), xmlReply(ocComplete)])
        let count = Recorder()
        let signIn = AnyConnectSignIn(profile: ocTestProfile, transport: gateway, prompts: prompts { p in
            count.append(p)
            return ["username": "jdoe", "password": "x", "group_list": count.prompts.count == 1 ? "students" : "Staff"]
        }, hasClientCertificate: false)
        _ = try await signIn.run()
        #expect(gateway.requests[1].body.attribute("type") == "init")
        #expect(gateway.requests[1].body.child("group-select")?.allText == "students")
    }

    /// A gateway that hides its group list ignores a group-select of the alias, so the group is
    /// tried as the group URL, before single sign-on starts (seen on a university ASA, 2026-10-22).
    @Test func hiddenGroupListUsesTheGroupURL() async throws {
        let gateway = ScriptedGateway([xmlReply(ocSSO), xmlReply(ocSSO), xmlReply(ocComplete)])
        let profile = OpenConnectProfile(server: URL(string: "https://vpn.example.edu/")!, group: "research")
        let signIn = AnyConnectSignIn(profile: profile, transport: gateway, prompts: prompts(fill: { _ in nil }, sso: { _ in "SAML-TOKEN" }),
                                      hasClientCertificate: false)
        _ = try await signIn.run()
        #expect(gateway.requests.map { $0.body.attribute("type") } == ["init", "init", "auth-reply"])
        #expect(gateway.requests[0].body.child("group-select")?.allText == "research")
        #expect(gateway.requests[1].url.absoluteString == "https://vpn.example.edu/research")
        #expect(gateway.requests[1].body.child("group-access")?.allText == "https://vpn.example.edu/research")
        #expect(gateway.requests[1].body.child("group-select") == nil)
        #expect(gateway.requests[2].body.child("auth")?.child("sso-token")?.allText == "SAML-TOKEN")

        // No such group URL: say so instead of signing in to the default group.
        var missing = GatewayReply(status: 404, body: Data())
        missing.serverCertificateSHA256 = testHash
        let bad = AnyConnectSignIn(profile: profile, transport: ScriptedGateway([xmlReply(ocSSO), missing]),
                                   prompts: prompts(fill: { _ in nil }, sso: { _ in "x" }), hasClientCertificate: false)
        await #expect(throws: AnyConnectSignInError.unknownGroup("research", choices: [])) { try await bad.run() }

        // A root URL that answers 404 (as on one ASA with OpenConnect's user agent) still
        // gets the group URL.
        var rootMissing = GatewayReply(status: 404, body: Data())
        rootMissing.serverCertificateSHA256 = testHash
        let rooted = ScriptedGateway([rootMissing, xmlReply(ocSSO), xmlReply(ocComplete)])
        _ = try await AnyConnectSignIn(profile: profile, transport: rooted, prompts: prompts(fill: { _ in nil }, sso: { _ in "t" }),
                                       hasClientCertificate: false).run()
        #expect(rooted.requests.map(\.url.absoluteString) == ["https://vpn.example.edu/", "https://vpn.example.edu/research", "https://vpn.example.edu/research"])

        // Without a group, a 404 with the default user agent suggests "AnyConnect".
        var notFound = GatewayReply(status: 404, body: Data())
        notFound.serverCertificateSHA256 = testHash
        let plain = AnyConnectSignIn(profile: OpenConnectProfile(server: URL(string: "https://vpn.example.edu/")!), transport: ScriptedGateway([notFound]),
                                     prompts: prompts(fill: { _ in nil }), hasClientCertificate: false)
        await #expect(throws: AnyConnectSignInError.notFoundForUserAgent) { try await plain.run() }
        var agent = OpenConnectProfile(server: URL(string: "https://vpn.example.edu/")!)
        agent.userAgent = "AnyConnect"
        let named = AnyConnectSignIn(profile: agent, transport: ScriptedGateway([notFound]), prompts: prompts(fill: { _ in nil }), hasClientCertificate: false)
        await #expect(throws: AnyConnectSignInError.http(404)) { try await named.run() }

        // A server URL that already names a group is left alone.
        let pathed = OpenConnectProfile(server: URL(string: "https://vpn.example.edu/staff")!, group: "research")
        let kept = ScriptedGateway([xmlReply(ocSSO), xmlReply(ocComplete)])
        _ = try await AnyConnectSignIn(profile: pathed, transport: kept, prompts: prompts(fill: { _ in nil }, sso: { _ in "t" }),
                                       hasClientCertificate: false).run()
        #expect(kept.requests[1].url.absoluteString == "https://vpn.example.edu/staff")
    }

    /// A listed group is matched by value or label, ignoring case, and selected before the
    /// first prompt; a group the list doesn't have is an error naming the choices.
    @Test func listedGroupIsSelectedFirst() async throws {
        let gateway = ScriptedGateway([xmlReply(ocPasswordForm), xmlReply(ocPasswordForm), xmlReply(ocComplete)])
        let seen = Recorder()
        let profile = OpenConnectProfile(server: URL(string: "https://vpn.example.edu/")!, group: "STUDENTS", username: "jdoe")
        let signIn = AnyConnectSignIn(profile: profile, transport: gateway, prompts: prompts { p in
            seen.append(p)
            return ["username": "jdoe", "password": "x"]
        }, hasClientCertificate: false)
        _ = try await signIn.run()
        #expect(gateway.requests.map { $0.body.attribute("type") } == ["init", "init", "auth-reply"])
        #expect(gateway.requests[1].body.child("group-select")?.allText == "students")
        #expect(seen.prompts.count == 1)
        #expect(seen.prompts.first?.prefilled["group_list"] == "students")

        // Already the selected group (by its group-alias): no restart.
        let same = ScriptedGateway([xmlReply(ocPasswordForm), xmlReply(ocComplete)])
        let staff = OpenConnectProfile(server: URL(string: "https://vpn.example.edu/")!, group: "staff")
        _ = try await AnyConnectSignIn(profile: staff, transport: same, prompts: prompts { _ in ["password": "x"] }, hasClientCertificate: false).run()
        #expect(same.requests.map { $0.body.attribute("type") } == ["init", "auth-reply"])

        let unknown = OpenConnectProfile(server: URL(string: "https://vpn.example.edu/")!, group: "faculty")
        let bad = AnyConnectSignIn(profile: unknown, transport: ScriptedGateway([xmlReply(ocPasswordForm)]), prompts: prompts { _ in ["password": "x"] },
                                   hasClientCertificate: false)
        await #expect(throws: AnyConnectSignInError.unknownGroup("faculty", choices: ["Staff", "Students"])) { try await bad.run() }
    }

    @Test func singleSignOn() async throws {
        let gateway = ScriptedGateway([xmlReply(ocSSO), xmlReply(ocComplete)])
        let signIn = AnyConnectSignIn(profile: ocTestProfile, transport: gateway, prompts: prompts(fill: { _ in nil }, sso: { request in
            #expect(request.tokenCookie == "acSamlv2Token")
            return "SAML-TOKEN"
        }), hasClientCertificate: false)
        _ = try await signIn.run()
        #expect(gateway.requests[1].body.child("auth")?.child("sso-token")?.allText == "SAML-TOKEN")
    }

    /// SingleSignOn and DTLS survive a parse/serialize round trip, and defaults stay unwritten
    /// (quality-6 M5).
    @Test func singleSignOnAndDTLSRoundTrip() throws {
        let p = try #require(OpenConnectFile.parse("[AnyConnect]\nServer = vpn.example.edu\nSingleSignOn = window\nDTLS = off\n").profile)
        #expect(!p.ssoInBrowser && !p.dtls)
        let text = OpenConnectFile.serialize(p)
        #expect(text.contains("SingleSignOn = window") && text.contains("DTLS = off"))
        #expect(OpenConnectFile.parse(text).profile == p)
        let defaults = try #require(OpenConnectFile.parse("[AnyConnect]\nServer = vpn.example.edu").profile)
        #expect(defaults.ssoInBrowser && defaults.dtls)
        #expect(!OpenConnectFile.serialize(defaults).contains("SingleSignOn") && !OpenConnectFile.serialize(defaults).contains("DTLS"))
        #expect(!OpenConnectFile.parse("[AnyConnect]\nServer = vpn.example.edu\nSingleSignOn = sometimes").errors.isEmpty)
    }

    /// External-browser mode without a browser handler means the profile turned browser
    /// sign-in off (SingleSignOn = window); host scans are always refused.
    @Test func refusesExternalBrowserWhenOffAndHostScan() async {
        let external = ocSSO.replacingOccurrences(of: "<form>", with: "<sso-v2-browser-mode>external</sso-v2-browser-mode><form>")
        let cases: [(String, AnyConnectSignInError)] = [(external, .externalBrowserRequired), (ocHostScan, .hostScanRequired)]
        for (xml, expected) in cases {
            let signIn = AnyConnectSignIn(profile: ocTestProfile, transport: ScriptedGateway([xmlReply(xml)]),
                                          prompts: prompts(fill: { _ in [:] }, sso: { _ in "T" }), hasClientCertificate: false)
            await #expect(throws: expected) { try await signIn.run() }
        }
    }

    @Test func clientCertificateRetryOnFreshConnection() async throws {
        let gateway = ScriptedGateway([xmlReply(ocCertRequest), xmlReply(ocComplete)])
        let signIn = AnyConnectSignIn(profile: ocTestProfile, transport: gateway, prompts: prompts { _ in nil }, hasClientCertificate: true)
        _ = try await signIn.run()
        #expect(gateway.requests.map(\.fresh) == [false, true])
        #expect(gateway.requests[1].body.child("client-cert-fail") == nil)
    }

    @Test func noCertificateTellsTheGatewayThenGivesUp() async {
        let gateway = ScriptedGateway([xmlReply(ocCertRequest), xmlReply(ocCertRequest)])
        let signIn = AnyConnectSignIn(profile: ocTestProfile, transport: gateway, prompts: prompts { _ in nil }, hasClientCertificate: false)
        await #expect(throws: AnyConnectSignInError.clientCertificateRequired) { try await signIn.run() }
        #expect(gateway.requests[1].body.child("client-cert-fail") != nil)
    }

    @Test func redirectsStayHTTPSAndKeepPosting() async throws {
        var redirect = GatewayReply(status: 302, body: Data())
        redirect.location = "https://vpn2.example.edu/staff"
        let gateway = ScriptedGateway([redirect, xmlReply(ocPasswordForm), xmlReply(ocComplete)])
        let signIn = AnyConnectSignIn(profile: ocTestProfile, transport: gateway, prompts: prompts { _ in ["password": "x"] }, hasClientCertificate: false)
        let session = try await signIn.run()
        #expect(gateway.requests[1].url.host == "vpn2.example.edu")
        #expect(gateway.requests[1].body.attribute("type") == "init")
        #expect(session.host == "vpn2.example.edu")

        var downgrade = GatewayReply(status: 302, body: Data())
        downgrade.location = "http://evil.example/"
        let bad = AnyConnectSignIn(profile: ocTestProfile, transport: ScriptedGateway([downgrade]), prompts: prompts { _ in nil }, hasClientCertificate: false)
        await #expect(throws: AnyConnectSignInError.insecureRedirect("http://evil.example/")) { try await bad.run() }
    }

    @Test func ssoMustEndOnTheGateway() async {
        // A hostile gateway names the identity provider's page as "final" (S5B-H2).
        let foreign = ocSSO.replacingOccurrences(of: "<sso-v2-login-final>https://vpn.example.edu/", with: "<sso-v2-login-final>https://login.idp.example/")
        let gateway = ScriptedGateway([xmlReply(foreign)])
        let signIn = AnyConnectSignIn(profile: OpenConnectProfile(server: URL(string: "https://vpn.example.edu/")!), transport: gateway,
                                      prompts: prompts(fill: { _ in nil }, sso: { _ in Issue.record("SSO opened"); return "x" }), hasClientCertificate: false)
        await #expect(throws: AnyConnectSignInError.self) { try await signIn.run() }
    }

    @Test func noHostChangeAfterAnswers() async {
        // The password went to vpn.example.edu; a redirect to another host must not get the next answer.
        var redirect = GatewayReply(status: 302, body: Data())
        redirect.location = "https://collector.example/"
        let gateway = ScriptedGateway([xmlReply(ocPasswordForm), redirect])
        let signIn = AnyConnectSignIn(profile: ocTestProfile, transport: gateway, prompts: prompts { _ in ["password": "x"] }, hasClientCertificate: false)
        await #expect(throws: AnyConnectSignInError.crossHostRedirect("collector.example")) { try await signIn.run() }
        #expect(gateway.requests.count == 2)
    }

    @Test func cancelAndServerErrors() async {
        let cancel = AnyConnectSignIn(profile: ocTestProfile, transport: ScriptedGateway([xmlReply(ocPasswordForm)]), prompts: prompts { _ in nil }, hasClientCertificate: false)
        await #expect(throws: AnyConnectSignInError.canceled) { try await cancel.run() }
        let failed = """
        <?xml version="1.0" encoding="UTF-8"?>
        <config-auth client="vpn" type="auth-request"><auth id="main"><error id="98" param1="" param2="">Login failed.</error></auth></config-auth>
        """
        let refused = AnyConnectSignIn(profile: ocTestProfile, transport: ScriptedGateway([xmlReply(failed)]), prompts: prompts { _ in [:] }, hasClientCertificate: false)
        await #expect(throws: AnyConnectSignInError.server("Login failed.")) { try await refused.run() }
        let html = AnyConnectSignIn(profile: ocTestProfile, transport: ScriptedGateway([xmlReply("<html>portal</html>")]), prompts: prompts { _ in [:] }, hasClientCertificate: false)
        await #expect(throws: AnyConnectSignInError.self) { try await html.run() }
    }

    @Test func sessionValidation() {
        var s = AnyConnectSession(cookie: "ABC@1", host: "vpn.example.edu", port: 443, address: "192.0.2.1", serverCertificateSHA256: testHash)
        #expect(s.validate() == nil)
        #expect(s.connectURL == "https://vpn.example.edu/")
        s.cookie = "a; b"
        #expect(s.validate() != nil)
        s.cookie = "ok"
        s.address = "10.0.0.0/8"
        #expect(s.validate() != nil)
        s.address = nil
        s.serverCertificateSHA256 = "nothex"
        #expect(s.validate() != nil)
    }
}

final class Recorder: @unchecked Sendable {
    private let lock = NSLock()
    private var items: [AnyConnectPrompt] = []
    func append(_ p: AnyConnectPrompt) { lock.withLock { items.append(p) } }
    var prompts: [AnyConnectPrompt] { lock.withLock { items } }
}

@Suite struct OpenConnectNetworkTests {
    @Test func fullTunnelIPv4BlocksIPv6() throws {
        var info = OpenConnectIPInfo()
        info.address = "10.8.0.5"
        info.netmask = "255.255.255.0"
        info.dns = ["10.8.0.1", "not-an-ip"]
        info.domain = "corp.example.edu example.edu"
        info.mtu = 1406
        let plan = try OpenConnectNetworkPlan.make(info)
        #expect(plan.ipv4Address == .init(address: "10.8.0.5", mask: "255.255.255.0", prefixLength: 24))
        #expect(plan.isFullTunnelIPv4)
        #expect(plan.blockedIPv6)
        #expect(plan.ipv6Address?.address == OpenConnectNetworkPlan.placeholderIPv6)
        #expect(plan.isFullTunnelIPv6)
        #expect(plan.dnsServers == ["10.8.0.1"])
        #expect(plan.searchDomains == ["corp.example.edu", "example.edu"])
        #expect(plan.matchDomains == nil)
        #expect(plan.mtu == 1406)
    }

    @Test func splitTunnelWithSplitDNS() throws {
        var info = OpenConnectIPInfo()
        info.address = "10.8.0.5"
        info.address6 = "fd00:8::5"
        info.netmask6 = "fd00:8::5/64"
        info.splitIncludes = ["10.0.0.0/255.0.0.0", "172.16.5.7/16", "fd00::/8", "garbage", "10.0.0.0/255.0.255.0"]
        info.splitExcludes = ["10.9.0.0/16", "0.0.0.0/0"]
        info.splitDNS = ["corp.example.edu", "-bad-.example"]
        let plan = try OpenConnectNetworkPlan.make(info)
        #expect(plan.ipv4Included.map(\.address) == ["10.0.0.0", "172.16.0.0"])  // host bits cleared, holey mask dropped
        #expect(plan.ipv4Included.map(\.prefixLength) == [8, 16])
        #expect(plan.ipv4Excluded.map(\.address) == ["10.9.0.0"])  // excluding everything is ignored
        #expect(plan.ipv6Included.map(\.address) == ["fd00::"])
        #expect(plan.ipv6Address?.prefixLength == 64)
        #expect(!plan.blockedIPv6 && !plan.blockedIPv4)
        #expect(plan.matchDomains == ["corp.example.edu"])
    }

    @Test func rejectsMissingOrBadAddress() {
        #expect(throws: OpenConnectNetworkPlan.Failure.self) { try OpenConnectNetworkPlan.make(OpenConnectIPInfo()) }
        var bad = OpenConnectIPInfo()
        bad.address = "10.0.0.1/8"
        #expect(throws: OpenConnectNetworkPlan.Failure.self) { try OpenConnectNetworkPlan.make(bad) }
    }

    @Test func halfRoutesCountAsFullTunnel() throws {
        // vpnc-script style: two /1 routes instead of /0, and no IPv6 (CLAUDE.md #10).
        var info = OpenConnectIPInfo()
        info.address = "10.8.0.5"
        info.splitIncludes = ["0.0.0.0/128.0.0.0", "128.0.0.0/128.0.0.0"]
        info.splitDNS = ["corp.example.edu"]
        info.dns = ["10.8.0.1"]
        let plan = try OpenConnectNetworkPlan.make(info)
        #expect(plan.isFullTunnelIPv4)
        #expect(plan.blockedIPv6)
        #expect(plan.matchDomains == nil)  // a full tunnel's DNS answers everything
    }

    @Test func ipv6OnlyFullTunnelBlocksIPv4() throws {
        var info = OpenConnectIPInfo()
        info.netmask6 = "fd00:8::5/64"
        let plan = try OpenConnectNetworkPlan.make(info)
        #expect(plan.isFullTunnelIPv6)
        #expect(plan.blockedIPv4)
        #expect(plan.ipv4Address?.address == OpenConnectNetworkPlan.placeholderIPv4)
        #expect(plan.isFullTunnelIPv4)
    }

    @Test func dnsServersOutsideSplitRoutesGoThroughTheTunnel() throws {
        var info = OpenConnectIPInfo()
        info.address = "10.8.0.5"
        info.splitIncludes = ["10.98.0.0/255.255.255.0"]
        info.dns = ["192.0.2.53", "10.98.0.1"]
        let plan = try OpenConnectNetworkPlan.make(info)
        #expect(plan.ipv4Included.map { "\($0.address)/\($0.prefixLength)" } == ["10.98.0.0/24", "192.0.2.53/32"])
    }

    @Test func excludesCountAndThePartialFamilyIsForcedIn() throws {
        var info = OpenConnectIPInfo()
        info.address = "10.8.0.5"
        info.netmask6 = "fd00:8::5/64"
        info.splitIncludes = ["0.0.0.0/0.0.0.0", "fd00::/8"]          // IPv4 full, IPv6 only partly
        info.dns = ["10.8.0.1", "2001:db8::53"]
        var plan = try OpenConnectNetworkPlan.make(info)
        #expect(plan.isFullTunnelIPv6)                                // forced: no IPv6 outside it
        #expect(plan.ipv6Included.map(\.prefixLength) == [0, 128] || plan.ipv6Included.first?.prefixLength == 0)
        info.splitExcludes = ["0.0.0.0/128.0.0.0", "128.0.0.0/128.0.0.0"]
        info.netmask6 = nil
        plan = try OpenConnectNetworkPlan.make(info)
        #expect(!plan.isFullTunnelIPv4)                               // everything excluded: not "full"
        // An IPv6 DNS server with no IPv6 in the tunnel would be asked outside it: dropped.
        var v4only = OpenConnectIPInfo()
        v4only.address = "10.8.0.5"
        v4only.splitIncludes = ["10.0.0.0/255.0.0.0"]
        v4only.dns = ["10.8.0.1", "2001:db8::53"]
        #expect(try OpenConnectNetworkPlan.make(v4only).dnsServers == ["10.8.0.1"])
    }

    @Test func coverageIsSetArithmetic() throws {
        func r(_ a: String, _ p: UInt8) -> OpenConnectNetworkPlan.Route {
            .init(address: a, mask: OpenConnectNetworkPlan.maskString(p), prefixLength: p)
        }
        typealias Plan = OpenConnectNetworkPlan
        // S5C-M4: include the lower half, exclude the (disjoint) upper half: still half the space.
        #expect(Plan.netShare([r("0.0.0.0", 1)], minus: [r("128.0.0.0", 1)], bits: 32) == 0.5)
        #expect(Plan.netShare([r("0.0.0.0", 0)], minus: [r("0.0.0.0", 1), r("128.0.0.0", 1)], bits: 32) == 0)
        #expect(Plan.netShare([r("0.0.0.0", 0)], minus: [r("10.0.0.0", 8)], bits: 32) == 1 - 1.0 / 256)
        #expect(Plan.netShare([r("10.0.0.0", 8), r("10.0.0.0", 9)], minus: [], bits: 32) == 1.0 / 256)  // overlap counted once
        var info = OpenConnectIPInfo()
        info.address = "10.8.0.5"
        info.splitIncludes = ["0.0.0.0/128.0.0.0"]
        info.splitExcludes = ["128.0.0.0/128.0.0.0"]
        let plan = try OpenConnectNetworkPlan.make(info)
        #expect(plan.isFullTunnelIPv4 && plan.blockedIPv6)  // half the space: IPv6 kept inside
    }

    /// Review NEW-7: IPv6 is measured the way WireGuard's RouteCoverage measures it.
    @Test func ipv6IsMeasuredAgainstInternetIPv6() throws {
        func plan(_ includes: [String], v4: Bool = true) throws -> OpenConnectNetworkPlan {
            var info = OpenConnectIPInfo()
            if v4 { info.address = "10.8.0.5" }
            info.netmask6 = "fd00:8::5/64"
            info.splitIncludes = includes
            return try OpenConnectNetworkPlan.make(info)
        }
        // Full IPv4 plus 8000::/1: half the space but no internet address, so IPv6 goes in.
        var p = try plan(["0.0.0.0/0.0.0.0", "8000::/1"])
        #expect(p.ipv6Included.first?.prefixLength == 0)
        // Full IPv4 plus 2000::/3: all internet IPv6, but NAT64's 64:ff9b::/96 would stay
        // outside, so IPv6 still goes in whole (security-6 L2).
        p = try plan(["0.0.0.0/0.0.0.0", "2000::/3"])
        #expect(p.isFullTunnelIPv6)
        #expect(p.ipv6Included.first?.prefixLength == 0)
        // Full IPv4 and all of IPv6: left as the gateway sent it.
        p = try plan(["0.0.0.0/0.0.0.0", "::/0"])
        #expect(p.ipv6Included.first?.prefixLength == 0 && !p.blockedIPv6)
        // An IPv6-only gateway pushing 2000::/3: IPv4 is blocked, not left outside.
        p = try plan(["2000::/3"], v4: false)
        #expect(p.isFullTunnelIPv6 && p.blockedIPv4)
        #expect(p.ipv4Included.first?.prefixLength == 0)
    }

    @Test func maskHelpers() {
        #expect(OpenConnectNetworkPlan.prefixLength(ofMask: "255.255.240.0") == 20)
        #expect(OpenConnectNetworkPlan.prefixLength(ofMask: "0.0.0.0") == 0)
        #expect(OpenConnectNetworkPlan.prefixLength(ofMask: "255.255.255.255") == 32)
        #expect(OpenConnectNetworkPlan.prefixLength(ofMask: "255.0.255.0") == nil)
        #expect(OpenConnectNetworkPlan.maskString(20) == "255.255.240.0")
        #expect(OpenConnectNetworkPlan.maskString(0) == "0.0.0.0")
    }
}
