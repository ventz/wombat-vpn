import SwiftUI
import TunnelCore

/// Review step for every import: what parses, what doesn't, and what each tunnel would do with
/// your traffic. Nothing reaches the keychain until "Import".
struct ImportSheet: View {
    @EnvironmentObject private var model: AppModel
    @EnvironmentObject private var store: TunnelStore
    @Environment(\.dismiss) private var dismiss
    @State private var importing = false
    @State private var errors: [String] = []

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(model.pendingImport.count == 1 ? "Import Tunnel" : "Import \(model.pendingImport.count) Tunnels")
                .font(.title2.weight(.semibold))
                .accessibilityAddTraits(.isHeader)
                .padding(20)
            Divider()
            ScrollView {
                VStack(spacing: 12) {
                    ForEach($model.pendingImport) { $candidate in
                        CandidateRow(candidate: $candidate)
                    }
                }
                .padding(20)
            }
            if !errors.isEmpty {
                VStack(alignment: .leading) {
                    ForEach(errors, id: \.self) { ErrorLabel($0) }
                }
                .padding(.horizontal, 20)
            }
            Divider()
            HStack {
                Text("Keys are stored in your login keychain. Scripts in the files (PostUp, host scans) are never run.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                Button("Cancel") { model.pendingImport = [] }
                    .keyboardShortcut(.cancelAction)
                // No Return shortcut: any process can open a file in Wombat (`open -a`), so the
                // sheet can appear unasked, and a stray Return must not add a tunnel (S2-M3, F-7).
                Button(importing ? "Importing…" : "Import") { Task { await runImport() } }
                    .disabled(importing || importable.isEmpty)
            }
            .padding(16)
        }
        .frame(width: 640, height: 520)
    }

    private var importable: [ImportCandidate] {
        model.pendingImport.filter { $0.include && $0.readError == nil && $0.isValid }
    }

    private func runImport() async {
        importing = true
        defer { importing = false }
        errors = []
        var lastID: UUID?
        for candidate in importable {
            do {
                lastID = try await store.add(name: candidate.name, text: candidate.text).id
            } catch {
                errors.append("\(candidate.name): \(error.localizedDescription)")
            }
        }
        if let lastID { model.selection = lastID }
        let added = importable.count - errors.count
        if added > 0 {
            let cleared = errors.isEmpty && model.clearClipboardAfterImport(importable)
            NSAccessibility.post(element: NSApp as Any, notification: .announcementRequested, userInfo: [
                .announcement: "Imported \(added) tunnel\(added == 1 ? "" : "s")" + (cleared ? ". The clipboard was cleared, since it held the private key." : ""),
                .priority: NSAccessibilityPriorityLevel.high.rawValue,
            ])
        }
        if errors.isEmpty { model.pendingImport = [] }
    }
}

private struct CandidateRow: View {
    @Binding var candidate: ImportCandidate

    var body: some View {
        let result = candidate.parse
        let config = result.configuration
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Toggle("", isOn: $candidate.include)
                    .labelsHidden()
                    .disabled(!candidate.isValid)
                    .accessibilityLabel("Import \(candidate.name)")
                TextField("Name", text: $candidate.name)
                    .accessibilityLabel("Tunnel name for \(candidate.source)")
                    .textFieldStyle(.roundedBorder)
                    .font(.headline)
                Text(candidate.source).font(.caption).foregroundStyle(.secondary)
            }
            if let error = candidate.readError {
                ErrorLabel(error)
            } else if let profileResult = candidate.profile {
                if let profile = profileResult.profile {
                    Group {
                        Text("Cisco AnyConnect VPN: \(profile.server.absoluteString)")
                        if let group = profile.group { Text("Group: \(group)") }
                        if let user = profile.username { Text("Username: \(user)") }
                        if profile.clientCertificate != nil {
                            Text("Client certificate: \(candidate.certificateName ?? "not in your keychain") (sent to this gateway)")
                        }
                    }
                    .font(.callout.monospaced())
                    .foregroundStyle(.secondary)
                    // Same warning as the CLI prompt: a pin replaces macOS trust, so a profile
                    // with a real hostname and someone else's pin is not harmless (review NEW-3).
                    if let pin = profile.serverCertificate {
                        Label {
                            VStack(alignment: .leading, spacing: 2) {
                                Text("It pins a server certificate instead of using macOS trust. Only import it if you expected this.")
                                Text(pin).font(.caption.monospaced()).foregroundStyle(.secondary).textSelection(.enabled)
                            }
                        } icon: {
                            Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                        }
                    }
                    SuccessLabel("Valid profile. You sign in each time you connect.")
                } else {
                    ProfileDiagnostics(result: profileResult)
                }
            } else if let config {
                Group {
                    if config.isAmnezia { Text("Protocol: AmneziaWG (needs an AmneziaWG server)") }
                    Text("Endpoint: \(config.peers.compactMap { $0.endpoint?.description }.joined(separator: ", ").ifEmpty("none"))")
                    Text("Routes: \(config.isFullTunnel ? "\(RouteCoverage.describe(config.coverage.ipv4)) of IPv4, \(RouteCoverage.describe(config.coverage.ipv6)) of IPv6" : config.peers.flatMap(\.allowedIPs).prefix(8).map(\.description).joined(separator: ", ").ifEmpty("none"))")
                }
                .font(.callout.monospaced())
                .foregroundStyle(.secondary)
                DiagnosticsList(result: result, findings: candidate.findings)
            } else {
                DiagnosticsList(result: result, findings: [])
            }
        }
        .padding(14)
        .background(.background.secondary, in: RoundedRectangle(cornerRadius: 10))
    }
}

struct NewTunnelSheet: View {
    @EnvironmentObject private var model: AppModel
    @EnvironmentObject private var store: TunnelStore
    @Environment(\.dismiss) private var dismiss
    @State private var name = "New Tunnel"
    @State private var text = ""
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("New Tunnel").font(.title2.weight(.semibold)).accessibilityAddTraits(.isHeader)
            TextField("Name", text: $name).textFieldStyle(.roundedBorder).accessibilityLabel("Tunnel name")
            Text("A fresh key pair was generated. Give your server this public key, then fill in the peer.")
                .font(.callout)
                .foregroundStyle(.secondary)
            ConfigTextEditor(text: $text)
            DiagnosticsList(result: WgQuick.parse(text))
            if let error { ErrorLabel(error) }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Create") {
                    Task {
                        do {
                            model.selection = try await store.add(name: name, text: text).id
                            dismiss()
                        } catch {
                            self.error = error.localizedDescription
                        }
                    }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(!WgQuick.parse(text).errors.isEmpty)
            }
        }
        .padding(20)
        .frame(width: 600, height: 520)
        .onAppear {
            let key = KeyPair.generatePrivateKey()
            text = """
            [Interface]
            PrivateKey = \(key.base64)
            # PublicKey = \(KeyPair.publicKey(for: key).base64)
            Address = 10.0.0.2/32
            DNS = 1.1.1.1

            [Peer]
            PublicKey =
            AllowedIPs = 0.0.0.0/0, ::/0
            Endpoint = vpn.example.com:51820
            """
        }
    }
}

extension String {
    func ifEmpty(_ fallback: String) -> String { isEmpty ? fallback : self }
}

/// Errors in an AnyConnect profile, by line.
struct ProfileDiagnostics: View {
    let result: OpenConnectFile.ParseResult

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            if result.diagnostics.isEmpty { SuccessLabel("Valid profile") }
            ForEach(Array(result.diagnostics.prefix(30).enumerated()), id: \.offset) { _, d in
                Label {
                    Text((d.line.map { "Line \($0): " } ?? "") + d.message)
                } icon: {
                    Image(systemName: "xmark.octagon.fill").foregroundStyle(.red)
                }
                .accessibilityLabel("Error: " + (d.line.map { "line \($0), " } ?? "") + d.message)
            }
        }
        .font(.callout)
        .textSelection(.enabled)
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}
