import Foundation

// Cisco AnyConnect "aggregate auth": the sign-in conversation is XML posted to the gateway. The
// shapes here follow OpenConnect's auth.c (v9.21, LGPL; reimplemented, not copied), which has
// interoperated with ASA and FTD gateways for over a decade:
//
//   client: <config-auth type="init">            → server: <config-auth type="auth-request">
//   client: <config-auth type="auth-reply">      → server: another auth-request (MFA, Duo)…
//                                                → server: <config-auth type="complete"> + session token
//
// Everything the server sends is untrusted: sizes are capped, DTDs refused, and nothing it
// says is ever run (host scan requests make the sign-in fail).

/// A small XML tree: just enough to read AnyConnect replies and echo their `<opaque>` block back.
public struct XMLTree: Equatable, Sendable {
    public enum Content: Equatable, Sendable { case element(XMLTree), text(String) }
    public var name: String
    public var attributes: [(name: String, value: String)]
    public var content: [Content]

    public init(name: String, attributes: [(name: String, value: String)] = [], content: [Content] = []) {
        self.name = name
        self.attributes = attributes
        self.content = content
    }

    public static func == (a: XMLTree, b: XMLTree) -> Bool {
        a.name == b.name && a.content == b.content
            && a.attributes.map(\.name) == b.attributes.map(\.name) && a.attributes.map(\.value) == b.attributes.map(\.value)
    }

    public var children: [XMLTree] { content.compactMap { if case .element(let e) = $0 { e } else { nil } } }
    /// All text inside this element, children included (libxml2's xmlNodeGetContent).
    public var allText: String {
        content.map { switch $0 { case .text(let t): t; case .element(let e): e.allText } }.joined()
    }
    public func attribute(_ name: String) -> String? { attributes.first { $0.name == name }?.value }
    public func child(_ name: String) -> XMLTree? { children.first { $0.name == name } }

    mutating func append(_ child: XMLTree) { content.append(.element(child)) }

    public func serialized() -> String {
        var out = "<\(name)"
        for (key, value) in attributes { out += " \(key)=\"\(XMLTree.escape(value, attribute: true))\"" }
        if content.isEmpty { return out + "/>" }
        out += ">"
        for item in content {
            switch item {
            case .text(let t): out += XMLTree.escape(t, attribute: false)
            case .element(let e): out += e.serialized()
            }
        }
        return out + "</\(name)>"
    }

    static func escape(_ s: String, attribute: Bool) -> String {
        var out = ""
        out.reserveCapacity(s.count)
        for scalar in s.unicodeScalars {
            switch scalar {
            case "&": out += "&amp;"
            case "<": out += "&lt;"
            case ">": out += "&gt;"
            case "\"" where attribute: out += "&quot;"
            case "\n" where attribute: out += "&#10;"
            case "\r": out += "&#13;"
            case "\t" where attribute: out += "&#9;"
            default:
                // Characters XML 1.0 can't carry at all are dropped rather than producing a
                // document the gateway would reject.
                let v = scalar.value
                if v == 0x9 || v == 0xA || v >= 0x20 && v != 0xFFFE && v != 0xFFFF && !(0xD800...0xDFFF).contains(v) {
                    out.unicodeScalars.append(scalar)
                }
            }
        }
        return out
    }

    /// XML element names Wombat will write (field names come from the server).
    static func isSafeName(_ s: String) -> Bool {
        guard let first = s.unicodeScalars.first, s.count <= 64 else { return false }
        let letters = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_")
        let rest = letters.union(CharacterSet(charactersIn: "0123456789-."))
        return letters.contains(first) && s.unicodeScalars.allSatisfy(rest.contains)
            && !s.lowercased().hasPrefix("xml")
    }

    // MARK: Parsing

    public struct ParseError: Error, Equatable, Sendable, CustomStringConvertible {
        public let description: String
    }

    public static let maxBytes = 512 * 1024
    static let maxDepth = 32
    static let maxNodes = 10_000

    /// Parses a document from the network. Refuses DTDs and entity declarations outright: no
    /// AnyConnect message has one, and they are how XML parsers get attacked (billion laughs,
    /// external entities).
    public static func parse(_ data: Data) throws -> XMLTree {
        guard data.count <= maxBytes else { throw ParseError(description: "The server's reply is larger than \(maxBytes / 1024) KB") }
        // UTF-8 only: another declared encoding (UTF-7, UTF-16) would hide a DTD from the byte
        // check below. The reply must also decode as UTF-8.
        guard var text = String(data: data, encoding: .utf8) else {
            throw ParseError(description: "The server's reply is not UTF-8 text")
        }
        // NUL can't occur in XML; with it, libxml2 might guess UTF-16 after all (S5C-L1).
        if text.utf8.contains(0) { throw ParseError(description: "The server's reply contains NUL bytes") }
        // The XML declaration is removed, wherever whitespace puts it, so libxml2 can only read
        // the text as UTF-8: a declared UTF-7 or UTF-16 could otherwise hide a DTD from the check
        // below (S5-L2, S5B-L1). Only one declaration, at the start, is accepted.
        text = String(text.drop { $0.isWhitespace || $0 == "\u{FEFF}" })
        if text.hasPrefix("<?xml") {
            guard let end = text.range(of: "?>") else { throw ParseError(description: "The server's reply has a broken XML declaration") }
            text.removeSubrange(text.startIndex..<end.upperBound)
        }
        if text.range(of: "<?xml", options: .caseInsensitive) != nil {
            throw ParseError(description: "The server's reply has a misplaced XML declaration")
        }
        if text.range(of: "<!DOCTYPE", options: .caseInsensitive) != nil || text.range(of: "<!ENTITY", options: .caseInsensitive) != nil {
            throw ParseError(description: "The server's reply declares a DTD, which AnyConnect never does")
        }
        let data = Data(text.utf8)
        let builder = Builder()
        let parser = XMLParser(data: data)
        parser.shouldResolveExternalEntities = false
        parser.shouldProcessNamespaces = false
        parser.delegate = builder
        let ok = parser.parse()
        if let problem = builder.problem { throw ParseError(description: problem) }
        guard ok, let root = builder.root else {
            throw ParseError(description: "The server's reply is not valid XML (\(parser.parserError?.localizedDescription ?? "unknown error"))")
        }
        return root
    }

    private final class Builder: NSObject, XMLParserDelegate {
        var stack: [XMLTree] = []
        var root: XMLTree?
        var nodes = 0
        var problem: String?

        func parser(_ parser: XMLParser, didStartElement name: String, namespaceURI: String?, qualifiedName: String?, attributes: [String: String] = [:]) {
            nodes += 1
            if nodes > XMLTree.maxNodes || stack.count >= XMLTree.maxDepth {
                problem = "The server's reply is too deeply nested or too large"
                parser.abortParsing()
                return
            }
            // XMLParser hands attributes over as a dictionary: sort for a stable order.
            stack.append(XMLTree(name: name, attributes: attributes.sorted { $0.key < $1.key }.map { ($0.key, $0.value) }))
        }

        func parser(_ parser: XMLParser, didEndElement name: String, namespaceURI: String?, qualifiedName: String?) {
            guard let done = stack.popLast() else { return }
            if stack.isEmpty { root = done } else { stack[stack.count - 1].append(done) }
        }

        func parser(_ parser: XMLParser, foundCharacters string: String) {
            guard !stack.isEmpty else { return }
            if case .text(let previous)? = stack[stack.count - 1].content.last {
                stack[stack.count - 1].content[stack[stack.count - 1].content.count - 1] = .text(previous + string)
            } else {
                stack[stack.count - 1].content.append(.text(string))
            }
        }

        func parser(_ parser: XMLParser, foundCDATA block: Data) {
            self.parser(parser, foundCharacters: String(decoding: block, as: UTF8.self))
        }

        func parser(_ parser: XMLParser, resolveExternalEntityName name: String, systemID: String?) -> Data? { nil }
    }
}

// MARK: - Messages

public enum AnyConnectXML {
    /// The client version reported to the gateway, the same one libopenconnect reports when it
    /// connects the tunnel: some gateways tie the session to it.
    public static let clientVersion = "v9.21"
    public static let defaultUserAgent = "Open AnyConnect VPN Agent v9.21"
    /// AnyConnect's name for macOS. Also selects the (never run) host-scan binary on the server.
    public static let deviceID = "mac-intel"

    /// The first message: which group URL we want, and that we can do SAML in an embedded browser.
    public static func initRequest(groupAccess: String, groupSelect: String? = nil, clientCertFailed: Bool = false, externalBrowser: Bool = false) -> Data {
        var root = query(type: "init", externalBrowser: externalBrowser)
        root.append(XMLTree(name: "group-access", content: [.text(groupAccess)]))
        if clientCertFailed { root.append(XMLTree(name: "client-cert-fail")) }
        if let groupSelect { root.append(XMLTree(name: "group-select", content: [.text(groupSelect)])) }
        return document(root)
    }

    /// The answer to a form. `answers` are in the form's own order (name, value), hidden fields
    /// included; the server's `<opaque>` block goes back unchanged.
    public static func authReply(opaque: XMLTree?, answers: [(name: String, value: String)], externalBrowser: Bool = false) -> Data {
        var root = query(type: "auth-reply", externalBrowser: externalBrowser)
        if let opaque { root.append(opaque) }
        var auth = XMLTree(name: "auth")
        var groupSelects: [XMLTree] = []
        for (name, value) in answers {
            switch name {
            case "group_list": groupSelects.append(XMLTree(name: "group-select", content: [.text(value)]))
            // RSA/OTP challenge fields are all "password" to the gateway.
            case "answer", "whichpin", "new_password": auth.append(XMLTree(name: "password", content: [.text(value)]))
            case "verify_pin", "verify_password": continue
            default:
                guard XMLTree.isSafeName(name) else { continue }  // AuthForm already refused it
                auth.append(XMLTree(name: name, content: [.text(value)]))
            }
        }
        root.append(auth)
        for g in groupSelects { root.append(g) }
        return document(root)
    }

    private static func query(type: String, externalBrowser: Bool) -> XMLTree {
        var root = XMLTree(name: "config-auth", attributes: [("client", "vpn"), ("type", type), ("aggregate-auth-version", "2")])
        root.append(XMLTree(name: "version", attributes: [("who", "vpn")], content: [.text(clientVersion)]))
        root.append(XMLTree(name: "device-id", content: [.text(deviceID)]))
        // The embedded browser always; the system browser ("external") only with STRAP keys in
        // the request headers (a gateway answers "internal error" otherwise).
        var capabilities = XMLTree(name: "capabilities", content: [.element(XMLTree(name: "auth-method", content: [.text("single-sign-on-v2")]))])
        if externalBrowser {
            capabilities.append(XMLTree(name: "auth-method", content: [.text("single-sign-on-external-browser")]))
        }
        root.append(capabilities)
        return root
    }

    private static func document(_ root: XMLTree) -> Data {
        Data(("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" + root.serialized() + "\n").utf8)
    }
}

/// One field of a sign-in form.
public struct AuthField: Equatable, Sendable {
    public enum Kind: Equatable, Sendable {
        case text, password
        case hidden(String)
        /// Choices as (value, label); `selected` is an index into them.
        case select(choices: [Choice], selected: Int)
        /// Filled with the token the SSO browser flow produces.
        case ssoToken
    }
    public struct Choice: Equatable, Sendable {
        public let value: String
        public let label: String
    }
    public let name: String
    public let label: String
    public let kind: Kind
    /// Part of a second authentication (the gateway's "second-auth" flag).
    public let secondAuth: Bool

    public var isGroupList: Bool { name == "group_list" }
}

public struct AuthForm: Equatable, Sendable {
    /// Where the answer goes, if not the current URL.
    public let action: String?
    public let fields: [AuthField]
}

/// The gateway asks for SAML/SSO in a browser.
public struct SSORequest: Equatable, Sendable {
    public let loginURL: URL
    /// The page that ends the flow; the token is in a cookie by then.
    public let finalURL: String
    public let tokenCookie: String
    public let errorCookie: String?
    /// "external": the gateway lets the default browser sign in (Wombat's browser sign-in,
    /// with STRAP keys and a local listener).
    public let browserMode: String?

    public init(loginURL: URL, finalURL: String, tokenCookie: String, errorCookie: String? = nil, browserMode: String? = nil) {
        self.loginURL = loginURL
        self.finalURL = finalURL
        self.tokenCookie = tokenCookie
        self.errorCookie = errorCookie
        self.browserMode = browserMode
    }
}

/// What one gateway reply says.
public struct AnyConnectReply: Equatable, Sendable {
    public var type: String?
    public var authID: String?
    public var title: String?
    public var banner: String?
    public var message: String?
    public var error: String?
    public var form: AuthForm?
    public var sso: SSORequest?
    public var opaque: XMLTree?
    public var sessionToken: String?
    public var clientCertRequested = false
    public var certAuthenticated = false
    public var multipleCertRequested = false
    /// The gateway wants a host scan (CSD/HostScan) run first. Wombat never runs one.
    public var hostScanRequested = false
    public var authenticationComplete = false

    public var isSuccess: Bool { authID == "success" || (sessionToken != nil && type == "complete") }

    public struct Failure: Error, Equatable, Sendable, CustomStringConvertible {
        public let description: String
    }

    public static func parse(_ data: Data) throws -> AnyConnectReply {
        let head = String(decoding: data.prefix(64), as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        guard head.hasPrefix("<?xml") || head.hasPrefix("<config-auth") else {
            throw Failure(description: "The server didn't answer like a Cisco AnyConnect gateway (it sent a web page, not an XML reply). Check the server address.")
        }
        let tree: XMLTree
        do { tree = try XMLTree.parse(data) } catch let e as XMLTree.ParseError { throw Failure(description: e.description) }
        var reply = AnyConnectReply()
        var nodes: [XMLTree]
        if tree.name == "config-auth" {
            reply.type = tree.attribute("type")
            nodes = tree.children
        } else {
            nodes = [tree]  // the legacy shape: a bare <auth> element
        }
        while !nodes.isEmpty {
            let node = nodes.removeFirst()
            switch node.name {
            case "client-cert-request": reply.clientCertRequested = true
            case "multiple-client-cert-request": reply.multipleCertRequested = true
            case "cert-authenticated": reply.certAuthenticated = true
            case "auth":
                reply.authID = node.attribute("id")
                try parseAuth(node, into: &reply)
            case "opaque": reply.opaque = node
            case "host-scan":
                if node.children.contains(where: { ["host-scan-ticket", "host-scan-token", "host-scan-base-uri", "host-scan-wait-uri"].contains($0.name) }) {
                    reply.hostScanRequested = true
                }
            case "session-token":
                let token = node.allText.trimmingCharacters(in: .whitespacesAndNewlines)
                if !token.isEmpty { reply.sessionToken = token }
            case "error": reply.error = message(node) ?? reply.error
            default: continue
            }
        }
        if reply.authID == nil, !reply.clientCertRequested, !reply.multipleCertRequested, reply.sessionToken == nil {
            throw Failure(description: reply.error ?? "The server's reply has no sign-in step")
        }
        return reply
    }

    private static func parseAuth(_ auth: XMLTree, into reply: inout AnyConnectReply) throws {
        var login: URL?, final: String?, cookie: String?, errorCookie: String?, mode: String?
        for node in auth.children {
            switch node.name {
            case "title": reply.title = message(node)
            case "banner": reply.banner = message(node)
            case "message": reply.message = message(node)
            case "error": reply.error = message(node)
            case "sso-v2-login": login = message(node).flatMap(URL.init(string:))
            case "sso-v2-login-final": final = message(node)
            case "sso-v2-token-cookie-name": cookie = message(node)
            case "sso-v2-error-cookie-name": errorCookie = message(node)
            case "sso-v2-browser-mode": mode = message(node)
            case "authentication-complete": reply.authenticationComplete = true
            case "csd", "csdMac", "csdLinux":
                if node.attribute("token") != nil || node.attribute("ticket") != nil || node.attribute("stuburl") != nil
                    || node.attribute("starturl") != nil {
                    reply.hostScanRequested = true
                }
            case "form": reply.form = try parseForm(node)
            default: continue
            }
        }
        if let login, let final, let cookie {
            guard login.scheme?.lowercased() == "https" else {
                throw Failure(description: "The server's single sign-on page isn't https (\(login.scheme ?? "no scheme")); Wombat won't open it")
            }
            reply.sso = SSORequest(loginURL: login, finalURL: final, tokenCookie: cookie, errorCookie: errorCookie, browserMode: mode)
        }
    }

    static let maxFields = 64
    static let maxChoices = 512

    private static func parseForm(_ form: XMLTree) throws -> AuthForm {
        let method = form.attribute("method") ?? "POST"
        let action = form.attribute("action")
        guard method.uppercased() == "POST", action.map({ !$0.isEmpty }) ?? true else {
            throw Failure(description: "The server sent a sign-in form Wombat can't submit (method \(method))")
        }
        var fields: [AuthField] = []
        var names = Set<String>()
        for node in form.children {
            // Answers are keyed by name: a repeated name would merge two fields (Q5-L6).
            if let name = node.attribute("name"), ["input", "select"].contains(node.name) {
                guard names.insert(name).inserted else { throw Failure(description: "The server's sign-in form has two fields named \(name)") }
            }
            guard fields.count < maxFields else { throw Failure(description: "The server's sign-in form has more than \(maxFields) fields") }
            let secondAuth = node.attribute("second-auth") == "1"
            if node.name == "select" {
                guard let name = node.attribute("name") else { throw Failure(description: "A choice in the sign-in form has no name") }
                var choices: [AuthField.Choice] = []
                var selected = 0
                for option in node.children where option.name == "option" {
                    guard choices.count < maxChoices else { break }
                    let label = option.allText.trimmingCharacters(in: .whitespacesAndNewlines)
                    let value = option.attribute("value") ?? label
                    if option.attribute("selected")?.lowercased() == "true" { selected = choices.count }
                    choices.append(AuthField.Choice(value: value, label: label.isEmpty ? value : label))
                }
                if choices.isEmpty { continue }  // an empty <select/> is ignored, as by OpenConnect
                guard XMLTree.isSafeName(name) || name == "group_list" else { throw Failure(description: "The sign-in form has a field with an invalid name") }
                // Shown first, like OpenConnect does: the group decides the rest of the form.
                fields.insert(AuthField(name: name, label: node.attribute("label") ?? "Group", kind: .select(choices: choices, selected: selected), secondAuth: secondAuth), at: 0)
                continue
            }
            guard node.name == "input", let type = node.attribute("type")?.lowercased() else { continue }
            if type == "submit" || type == "reset" { continue }
            guard let name = node.attribute("name") else { continue }
            guard XMLTree.isSafeName(name) else { throw Failure(description: "The sign-in form has a field with an invalid name") }
            let label = node.attribute("label") ?? "\(name):"
            let kind: AuthField.Kind
            switch type {
            case "text": kind = .text
            case "password": kind = .password
            case "hidden": kind = .hidden(node.attribute("value") ?? "")
            case "sso": kind = .ssoToken
            default: continue  // unknown input types are skipped, as by OpenConnect
            }
            fields.append(AuthField(name: name, label: label, kind: kind, secondAuth: secondAuth))
        }
        return AuthForm(action: action, fields: fields)
    }

    /// Element text with AnyConnect's `%s` placeholders filled from param1/param2.
    static func message(_ node: XMLTree) -> String? {
        var text = node.allText
        guard !text.isEmpty else { return nil }
        var params = [node.attribute("param1"), node.attribute("param2")]
        var result = ""
        var index = text.startIndex
        var used = 0
        while let pct = text[index...].firstIndex(of: "%") {
            let next = text.index(after: pct)
            guard next < text.endIndex, text[next] == "s", used < 2 else { break }
            result += text[index..<pct]
            result += params[used] ?? "%s"
            params[used] = nil
            used += 1
            index = text.index(after: next)
        }
        result += text[index...]
        text = result.trimmingCharacters(in: .whitespacesAndNewlines)
        return text.isEmpty ? nil : String(text.prefix(4096))
    }
}
