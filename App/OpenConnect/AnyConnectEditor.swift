import SwiftUI
import TunnelCore

/// Adds or edits a Cisco AnyConnect VPN. The fields become an `[AnyConnect]` profile, checked by
/// the same parser the extension uses; nothing secret is entered here (you sign in at connect).
struct AnyConnectEditor: View {
    /// nil: a new VPN.
    let tunnel: Tunnel?
    @EnvironmentObject private var model: AppModel
    @EnvironmentObject private var store: TunnelStore
    @Environment(\.dismiss) private var dismiss

    @State private var name = "Work VPN"
    @State private var server = ""
    @State private var group = ""
    @State private var username = ""
    @State private var certificate = ""
    @State private var pin = ""
    @State private var userAgent = ""
    @State private var dtls = true
    @State private var ssoInBrowser = true
    @State private var identities: [ClientIdentities.Item] = []
    @State private var showAdvanced = false
    @State private var error: String?
    @State private var saving = false

    private var text: String {
        var lines = [OpenConnectFile.section, "Server = \(server.trimmingCharacters(in: .whitespaces))"]
        func add(_ key: String, _ value: String) {
            let v = value.trimmingCharacters(in: .whitespaces)
            if !v.isEmpty { lines.append("\(key) = \(v)") }
        }
        add("Group", group)
        add("Username", username)
        if !certificate.isEmpty { lines.append("ClientCertificate = sha256:\(certificate)") }
        add("ServerCertificate", pin)
        add("UserAgent", userAgent)
        if !dtls { lines.append("DTLS = off") }
        if !ssoInBrowser { lines.append("SingleSignOn = window") }
        return lines.joined(separator: "\n") + "\n"
    }

    private var result: OpenConnectFile.ParseResult { OpenConnectFile.parse(text) }

    /// The profile's key names as the fields call them.
    private static let labels = ["Server": "Server", "Group": "Group", "Username": "Username", "ClientCertificate": "Client certificate",
                                 "ServerCertificate": "Pinned server certificate", "UserAgent": "User agent", "DTLS": "DTLS"]

    /// Each parse error belongs to the field its line came from (the text is generated one key
    /// per line), worded with the field's label rather than the profile's key (A5-M3).
    private var fieldErrors: [String: String] {
        let lines = text.split(separator: "\n", omittingEmptySubsequences: false)
        var errors: [String: String] = [:]
        // "#" starts a comment in a profile, so the rest of the value would be lost without a
        // word (quality-6 L8).
        for (key, value) in [("Server", server), ("Group", group), ("Username", username), ("ServerCertificate", pin), ("UserAgent", userAgent)]
        where value.contains("#") {
            errors[key] = "\(Self.labels[key] ?? key) can't contain “#”"
        }
        for d in result.errors {
            guard let line = d.line, line >= 1, line <= lines.count else {
                if d.message.contains("Server") { errors["Server"] = d.message }
                continue
            }
            let key = String(lines[line - 1].split(separator: "=").first ?? "").trimmingCharacters(in: .whitespaces)
            guard let label = Self.labels[key], errors[key] == nil else { continue }
            var message = d.message.replacingOccurrences(of: key, with: label)
            if message.contains("control or invisible") { message = "\(label) contains invisible or control characters" }
            errors[key] = message
        }
        return errors
    }

    private var nameError: String? { tunnel == nil && TunnelName.sanitize(name).isEmpty ? "A name is required" : nil }

    @ViewBuilder
    private func fieldError(_ key: String) -> some View {
        if let error = fieldErrors[key] { ErrorLabel(error).font(.caption) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(tunnel == nil ? "Add AnyConnect VPN" : "Edit “\(tunnel!.name)”")
                .font(.title2.weight(.semibold))
                .accessibilityAddTraits(.isHeader)
            Text("For Cisco AnyConnect and Secure Client gateways (ASA, Firepower) and ocserv. You sign in each time you connect: password, Duo, single sign-on or a certificate.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Form {
                if tunnel == nil {
                    TextField("Name", text: $name)
                        .accessibilityHint(nameError ?? "")
                    if let nameError { ErrorLabel(nameError).font(.caption) }
                }
                TextField("Server", text: $server, prompt: Text("vpn.example.edu or https://vpn.example.edu/group"))
                    .textContentType(.URL)
                    .accessibilityHint(fieldErrors["Server"] ?? "")
                if !server.trimmingCharacters(in: .whitespaces).isEmpty { fieldError("Server") }
                TextField("Group", text: $group, prompt: Text("Optional"))
                    .accessibilityHint(fieldErrors["Group"] ?? "")
                fieldError("Group")
                TextField("Username", text: $username, prompt: Text("Optional, filled in at sign-in"))
                    .textContentType(.username)
                    .accessibilityHint(fieldErrors["Username"] ?? "")
                fieldError("Username")
                Picker("Client certificate", selection: $certificate) {
                    Text("None").tag("")
                    ForEach(identities) { item in
                        Text(label(item)).tag(item.id).accessibilityLabel(label(item).replacingOccurrences(of: " · ", with: ", "))
                    }
                    if !certificate.isEmpty, !identities.contains(where: { $0.id == certificate }) {
                        Text("Missing (\(String(certificate.prefix(16)))…)").tag(certificate)
                    }
                }
                DisclosureGroup("Advanced", isExpanded: $showAdvanced) {
                    TextField("Pinned server certificate", text: $pin, prompt: Text("sha256:… (only for an untrusted gateway)"))
                        .font(.body.monospaced())
                        .accessibilityHint(fieldErrors["ServerCertificate"] ?? "")
                    fieldError("ServerCertificate")
                    TextField("User agent", text: $userAgent, prompt: Text(AnyConnectXML.defaultUserAgent))
                        .accessibilityHint(fieldErrors["UserAgent"] ?? "")
                    fieldError("UserAgent")
                    Toggle("Use DTLS (faster; turn off if UDP is blocked)", isOn: $dtls)
                    Toggle("Single sign-on in my default browser when the gateway allows it", isOn: $ssoInBrowser)
                        .help("Passkeys, password managers and your identity provider's session work there. Off: always Wombat's sign-in window.")
                        .disabled(!pin.trimmingCharacters(in: .whitespaces).isEmpty)
                    if !pin.trimmingCharacters(in: .whitespaces).isEmpty {
                        Text("With a pinned certificate, sign-in always uses Wombat's window: a browser can't check the pin.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
            .formStyle(.grouped)
            if result.profile != nil {
                SuccessLabel("Valid. You sign in each time you connect.")
            }
            if let error { ErrorLabel(error) }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button(tunnel == nil ? "Add VPN" : "Save") { Task { await save() } }
                    .keyboardShortcut(.defaultAction)
                    .disabled(saving || result.profile == nil || !fieldErrors.isEmpty || (tunnel == nil && TunnelName.sanitize(name).isEmpty))
            }
        }
        .padding(20)
        .frame(width: 560)
        .onAppear(perform: load)
    }

    private func label(_ item: ClientIdentities.Item) -> String {
        var parts = [item.name]
        if let issuer = item.issuer { parts.append("issued by \(issuer)") }
        if item.isExpired { parts.append("expired") }
        return parts.joined(separator: " · ")
    }

    private func load() {
        identities = ClientIdentities.all()
        guard let tunnel, let profile = tunnel.profile else { return }
        server = profile.server.absoluteString
        group = profile.group ?? ""
        username = profile.username ?? ""
        certificate = profile.clientCertificate ?? ""
        pin = profile.serverCertificate.map { "sha256:" + $0 } ?? ""
        userAgent = profile.userAgent ?? ""
        dtls = profile.dtls
        ssoInBrowser = profile.ssoInBrowser
        showAdvanced = !pin.isEmpty || !userAgent.isEmpty || !dtls || !ssoInBrowser
    }

    private func save() async {
        saving = true
        defer { saving = false }
        do {
            if let tunnel {
                let wasActive = tunnel.isActive
                try await store.update(tunnel, text: text)
                if wasActive { await store.reconnect(tunnel) }
            } else {
                model.selection = try await store.addOpenConnect(name: name, text: text).id
            }
            dismiss()
        } catch {
            self.error = error.localizedDescription
            NSAccessibility.post(element: NSApp as Any, notification: .announcementRequested, userInfo: [
                .announcement: "Couldn't save: \(error.localizedDescription)",
                .priority: NSAccessibilityPriorityLevel.high.rawValue,
            ])
        }
    }
}
