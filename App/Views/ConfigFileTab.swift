import SwiftUI
import TunnelCore

/// The Config File tab: the wg-quick text with secrets masked. Editing (which needs the real keys) unlocks
/// with Touch ID or the login password, and the unlocked text is dropped when editing ends.
struct ConfigFileTab: View {
    @ObservedObject var tunnel: Tunnel
    @EnvironmentObject private var store: TunnelStore
    @EnvironmentObject private var model: AppModel
    @State private var editing = false
    @State private var name = ""
    @State private var text = ""
    @State private var saveError: String?
    @State private var saving = false

    var body: some View {
        VStack(spacing: 0) {
            if editing {
                editor
            } else {
                ScrollView {
                    Text(tunnel.configuration.map { WgQuick.serialize($0, includePrivateKey: false) } ?? "")
                        .font(.body.monospaced())
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(20)
                }
            }
            Divider()
            HStack {
                if editing {
                    Button("Cancel") { endEditing() }
                        .keyboardShortcut(.cancelAction)
                    Spacer()
                    if let saveError {
                        Label { Text(saveError).lineLimit(2) } icon: { Image(systemName: "xmark.octagon.fill").foregroundStyle(.red) }
                            .accessibilityLabel("Error: \(saveError)")
                    }
                    Button("Save") { Task { await save() } }
                        .keyboardShortcut("s")
                        .disabled(saving || !WgQuick.parse(text).errors.isEmpty)
                } else {
                    Spacer()
                    if let saveError {
                        Label { Text(saveError).lineLimit(2) } icon: { Image(systemName: "xmark.octagon.fill").foregroundStyle(.red) }
                    }
                    Text("Keys are hidden").font(.caption).foregroundStyle(.secondary)
                    Menu("Export") {
                        Button("Export .conf File…") { model.run { try await Exporter.exportOne($0) } }
                        Button("Show QR Code…") { model.showingQR = true }
                    }
                    .fixedSize()
                    Button("Edit…") { Task { await beginEditing() } }
                        .keyboardShortcut("e")
                }
            }
            .padding(12)
        }
    }

    private var editor: some View {
        VStack(alignment: .leading, spacing: 8) {
            LabeledContent("Name") {
                TextField("Name", text: $name)
                    .textFieldStyle(.roundedBorder)
                    .font(.title3)
            }
            ConfigTextEditor(text: $text)
            DiagnosticsList(result: WgQuick.parse(text))
        }
        .padding(16)
    }

    private func beginEditing() async {
        guard await Authenticator.confirm(reason: "edit the keys of “\(tunnel.name)”") else {
            saveError = "Authentication was canceled"
            return
        }
        guard let reference = tunnel.proto?.passwordReference, let full = try? ConfigKeychain.read(reference) else {
            saveError = "The keychain item for this tunnel is missing"
            return
        }
        name = tunnel.name
        text = full
        saveError = nil
        editing = true
    }

    private func endEditing() {
        text = ""
        editing = false
    }

    private func save() async {
        saving = true
        defer { saving = false }
        do {
            let wasActive = tunnel.isActive
            try await store.update(tunnel, name: name == tunnel.name ? nil : name, text: text)
            endEditing()
            if wasActive { await store.reconnect(tunnel) }  // apply the new configuration
        } catch {
            saveError = error.localizedDescription
        }
    }
}

/// A monospaced plain-text editor without smart quotes, dashes or spelling correction, which
/// would corrupt keys and addresses.
struct ConfigTextEditor: NSViewRepresentable {
    @Binding var text: String

    func makeNSView(context: Context) -> NSScrollView {
        let scroll = NSTextView.scrollableTextView()
        let view = scroll.documentView as! NSTextView
        view.font = .monospacedSystemFont(ofSize: NSFont.systemFontSize, weight: .regular)
        view.isAutomaticQuoteSubstitutionEnabled = false
        view.isAutomaticDashSubstitutionEnabled = false
        view.isAutomaticTextReplacementEnabled = false
        view.isAutomaticSpellingCorrectionEnabled = false
        view.isContinuousSpellCheckingEnabled = false
        view.isRichText = false
        view.allowsUndo = true
        view.textContainerInset = NSSize(width: 6, height: 8)
        view.delegate = context.coordinator
        view.string = text
        view.setAccessibilityLabel("Tunnel configuration")
        scroll.borderType = .bezelBorder
        // The editor appears after Touch ID: put the keyboard focus in it (A-M7).
        DispatchQueue.main.async { view.window?.makeFirstResponder(view) }
        return scroll
    }

    func updateNSView(_ scroll: NSScrollView, context: Context) {
        let view = scroll.documentView as! NSTextView
        if view.string != text { view.string = text }
    }

    func makeCoordinator() -> Coordinator { Coordinator(text: $text) }

    final class Coordinator: NSObject, NSTextViewDelegate {
        var text: Binding<String>
        init(text: Binding<String>) { self.text = text }
        func textDidChange(_ notification: Notification) {
            guard let view = notification.object as? NSTextView else { return }
            text.wrappedValue = view.string
        }

        /// Tab and Shift-Tab move focus (configs don't need tab characters), so keyboard users
        /// aren't trapped in the editor.
        func textView(_ textView: NSTextView, doCommandBy selector: Selector) -> Bool {
            if selector == #selector(NSResponder.insertTab(_:)) { textView.window?.selectNextKeyView(nil); return true }
            if selector == #selector(NSResponder.insertBacktab(_:)) { textView.window?.selectPreviousKeyView(nil); return true }
            return false
        }
    }
}

struct DiagnosticsList: View {
    let result: WgQuick.ParseResult
    var findings: [Finding]

    /// Editor use: reviews the text being typed (bounded cost since the review is O(n log n)
    /// and capped).
    init(result: WgQuick.ParseResult) {
        self.result = result
        findings = result.configuration.map(ConfigReview.review) ?? []
    }

    init(result: WgQuick.ParseResult, findings: [Finding]) {
        self.result = result
        self.findings = findings
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            if result.diagnostics.isEmpty && findings.isEmpty {
                SuccessLabel("Valid configuration")
            }
            // Risks first, then parse errors and warnings; the review's script-hook finding repeats
            // the parser's line-numbered warning, so it's left out here.
            ForEach(Array(findings.filter { $0.level == .risk && $0.code != "script-hook" }.enumerated()), id: \.offset) { _, f in
                Label {
                    Text(f.message)
                } icon: {
                    Image(systemName: "exclamationmark.octagon").foregroundStyle(.red)
                }
                .accessibilityLabel("Risk: \(f.message)")
            }
            ForEach(Array(result.diagnostics.prefix(30).enumerated()), id: \.offset) { _, d in
                Label {
                    Text((d.line.map { "Line \($0): " } ?? "") + d.message)
                } icon: {
                    Image(systemName: d.severity == .error ? "xmark.octagon.fill" : "exclamationmark.triangle.fill")
                        .foregroundStyle(d.severity == .error ? .red : .orange)
                }
                // The symbol's color is the only visual difference, so say it (A-M5).
                .accessibilityLabel("\(d.severity == .error ? "Error" : "Warning"): " + (d.line.map { "line \($0), " } ?? "") + d.message)
            }
            ForEach(Array(findings.filter { $0.level == .warning }.enumerated()), id: \.offset) { _, f in
                Label {
                    Text(f.message)
                } icon: {
                    Image(systemName: "exclamationmark.triangle").foregroundStyle(.orange)
                }
                .accessibilityLabel("Warning: \(f.message)")
            }
        }
        .font(.callout)
        .textSelection(.enabled)
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}
