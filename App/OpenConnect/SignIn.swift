import AppKit
import SwiftUI
import TunnelCore
import WebKit

/// Runs an AnyConnect sign-in with the user: a small window shows the gateway's forms
/// (password, Duo, group) or its single sign-on page. One sign-in at a time.
@MainActor
final class SignInCoordinator: ObservableObject {
    static let shared = SignInCoordinator()

    enum Step {
        case working(String)
        case form(AnyConnectPrompt)
        case sso(SSORequest, store: UUID)
        /// The login page is open in the default browser.
        case browser(SSORequest)
    }

    @Published private(set) var step: Step = .working("Contacting the gateway…")
    /// The embedded sign-in page needs the whole detail column (A6-H1).
    var showsPage: Bool { if case .sso = step { return true } else { return false } }
    /// Changes with every step, so the Overview can scroll the sign-in into view (A6-H1).
    var stepKey: String {
        switch step {
        case .working(let text): return "working:" + text
        case .form(let prompt): return "form:" + prompt.form.fields.map(\.name).joined() + (prompt.error ?? "")
        case .sso(let request, _): return "sso:" + request.loginURL.absoluteString
        case .browser(let request): return "browser:" + request.loginURL.absoluteString
        }
    }
    @Published private(set) var tunnelName = ""
    @Published private(set) var server = ""
    /// The VPN being signed in to: its Overview shows the sign-in.
    @Published private(set) var activeTunnelID: UUID?
    private var lastPrompt: AnyConnectPrompt?
    /// The profile's certificate pin, for the gateway's pages in the SSO browser (S5-I4).
    private(set) var gatewayPin: String?
    /// Brings the main window forward with this VPN's Overview, where the sign-in is shown
    /// (set by AppModel). The sign-in used to be a floating panel; the user found it confusing
    /// and in the way (2026-10-16), so it lives in the main window now.
    var reveal: ((UUID) -> Void)?
    private var formContinuation: CheckedContinuation<[String: String]?, Never>?
    private var ssoContinuation: CheckedContinuation<String, Error>?
    private var browserSignIn: BrowserSignIn?
    private var task: Task<AnyConnectSession, Error>?
    private(set) var busy = false

    struct Busy: LocalizedError {
        var errorDescription: String? { "Another sign-in is in progress; finish or cancel it first" }
    }

    struct MissingCertificate: LocalizedError {
        var errorDescription: String? {
            "The client certificate chosen for this VPN is no longer in your keychain. Choose another one in Edit VPN."
        }
    }

    func signIn(tunnelID: UUID, name: String, profile: OpenConnectProfile) async throws -> AnyConnectSession {
        guard !busy else {
            // The sign-in may be out of sight: bring it back rather than only failing.
            showPanel()
            throw Busy()
        }
        busy = true
        activeTunnelID = tunnelID
        defer {
            busy = false
            activeTunnelID = nil
            lastPrompt = nil
        }
        var identity: SecIdentity?
        if let sha = profile.clientCertificate {
            guard let found = ClientIdentities.identity(sha256: sha) else { throw MissingCertificate() }
            identity = found
        }
        tunnelName = name
        server = profile.displayServer
        gatewayPin = profile.serverCertificate
        step = .working("Contacting \(profile.displayServer)…")
        show()
        // A CLI `wombat up` starts a sign-in while another app is in front: say so (A5-L7).
        say("Wombat: sign in to \(name)", .high)
        // STRAP keys let the gateway offer the default browser; only when the profile allows it
        // and pins no certificate, which a browser can't check (review NEW-1).
        let strap = profile.usesBrowserSignIn ? AnyConnectStrap() : nil
        var browser: (@Sendable (SSORequest) async throws -> Data)?
        if strap != nil {
            browser = { request in try await SignInCoordinator.shared.runBrowser(request, accepts: { (try? strap?.decryptToken($0)) != nil }) }
        }
        let prompts = AnyConnectPrompts(
            fill: { prompt in await SignInCoordinator.shared.askForm(prompt) },
            singleSignOn: { request in try await SignInCoordinator.shared.runSSO(request, store: tunnelID) },
            externalBrowser: browser)
        let signIn = AnyConnectSignIn(profile: profile, transport: URLSessionGatewayTransport(profile: profile, identity: identity, strap: strap),
                                      prompts: prompts, hasClientCertificate: identity != nil, strap: strap)
        let task = Task { try await signIn.run() }
        self.task = task
        defer { self.task = nil }
        do {
            return try await task.value
        } catch is CancellationError {
            throw AnyConnectSignInError.canceled
        }
    }

    private func askForm(_ prompt: AnyConnectPrompt) async -> [String: String]? {
        if task?.isCancelled == true { return nil }
        return await withCheckedContinuation { continuation in
            formContinuation = continuation
            lastPrompt = prompt
            step = .form(prompt)
            bringForward()
            // Each step replaces the sign-in's content: say what changed (A5-H1).
            if let error = prompt.error {
                say("Sign-in failed: \(error)" + (prompt.message.map { ". \($0)" } ?? ""), .high)
            } else if let message = prompt.message {
                say(message)
            }
        }
    }

    func submit(_ answers: [String: String]) {
        // A different group restarts the sign-in, often with the same fields: say it (A5-H1).
        if let prompt = lastPrompt ?? currentPrompt,
           let field = prompt.form.fields.first(where: \.isGroupList), case .select(let choices, let selected) = field.kind,
           let picked = answers[field.name], picked != choices[selected].value,
           let label = choices.first(where: { $0.value == picked })?.label {
            say("Group changed to \(label). Sign in for that group.")
        } else {
            say("Signing in")
        }
        lastPrompt = nil
        step = .working("Signing in…")
        formContinuation?.resume(returning: answers)
        formContinuation = nil
    }

    private var currentPrompt: AnyConnectPrompt? {
        if case .form(let prompt) = step { return prompt }
        return nil
    }

    /// Shows the sign-in: the main window, this VPN, its Overview.
    func showPanel() {
        guard let id = activeTunnelID else { return }
        NSApp.activate()
        reveal?(id)
    }

    /// For later steps: only the window comes forward. Switching tunnel or tab under the user
    /// could drop an open Config File edit (accessibility-6 M1); the sidebar row and the header's
    /// "Show Sign-In" lead back.
    private func bringForward() {
        NSApp.activate()
        MainWindow.show()
    }

    private func say(_ text: String, _ priority: NSAccessibilityPriorityLevel = .medium) {
        NSAccessibility.post(element: NSApp as Any, notification: .announcementRequested, userInfo: [
            .announcement: text, .priority: priority.rawValue,
        ])
    }

    private func runSSO(_ request: SSORequest, store: UUID) async throws -> String {
        if task?.isCancelled == true { throw CancellationError() }  // canceled before the page opened (Q5-L5)
        return try await withCheckedThrowingContinuation { continuation in
            ssoContinuation = continuation
            step = .sso(request, store: store)
            bringForward()
            say("Single sign-on page opened. Sign in with your organization's account.")
        }
    }

    private func runBrowser(_ request: SSORequest, accepts: @escaping @Sendable (Data) -> Bool) async throws -> Data {
        if task?.isCancelled == true { throw CancellationError() }
        let browser = BrowserSignIn(request: request, accepts: accepts)
        browserSignIn = browser
        defer { browserSignIn = nil }
        step = .browser(request)
        say("The sign-in page opened in your default browser. Finish signing in there.")
        let blob = try await browser.run()
        step = .working("Signing in…")
        // Back to Wombat from the browser.
        NSApp.activate()
        return blob
    }

    func openBrowserAgain() { browserSignIn?.openLoginPage() }

    #if DEBUG
    /// Demo mode (screenshots) only: shows a sign-in step without a gateway.
    func setDemo(tunnelID: UUID?, name: String, server: String, step: Step) {
        activeTunnelID = tunnelID
        tunnelName = name
        self.server = server
        self.step = step
    }
    #endif

    func ssoFinished(_ token: String) {
        step = .working("Signing in…")
        ssoContinuation?.resume(returning: token)
        ssoContinuation = nil
    }

    func ssoFailed(_ message: String) {
        ssoContinuation?.resume(throwing: AnyConnectSignInError.server(message))
        ssoContinuation = nil
    }

    func cancel() {
        // Typed answers and the SSO page go from the screen at once, not when the network
        // round trip ends (S5B-L3).
        step = .working("Canceling…")
        task?.cancel()
        formContinuation?.resume(returning: nil)
        formContinuation = nil
        ssoContinuation?.resume(throwing: CancellationError())
        ssoContinuation = nil
        browserSignIn?.cancel()
    }

    private func show() { showPanel() }

    /// The gateway's certificate isn't trusted by macOS. Pinning it is a security decision, so
    /// the fingerprint is shown and Cancel is the default.
    /// Persisted like the CLI approvals' cool-down, so `wombat stop` (quitting the app) doesn't
    /// reset it (review NEW-10).
    private var trustDeclinedUntil: Date {
        get {
            let saved = Date(timeIntervalSince1970: UserDefaults.standard.double(forKey: "trustDeclinedUntil"))
            // A clock set back must not leave a long lockout.
            return saved.timeIntervalSinceNow > 10 ? .distantPast : saved
        }
        set { UserDefaults.standard.set(newValue.timeIntervalSince1970, forKey: "trustDeclinedUntil") }
    }
    private var trustAccepted = false

    func confirmTrust(host: String, sha256: String, reason: String) -> Bool {
        // Like the CLI approvals: after a decline, no new prompt for a few seconds, so a script
        // running `wombat up` in a loop can't keep asking until a stray click accepts (S5B-L5).
        guard Date() >= trustDeclinedUntil else { return false }
        trustAccepted = false
        defer { if !trustAccepted { trustDeclinedUntil = Date().addingTimeInterval(10) } }
        let alert = NSAlert()
        alert.messageText = "Trust the certificate of “\(host)”?"
        let grouped = stride(from: 0, to: sha256.count, by: 4).map { i -> String in
            let start = sha256.index(sha256.startIndex, offsetBy: i)
            return String(sha256[start..<sha256.index(start, offsetBy: min(4, sha256.count - i))])
        }.joined(separator: " ")
        alert.informativeText = """
        macOS doesn't trust this gateway's certificate (\(reason)). Only continue if your IT department confirmed this SHA-256 fingerprint:

        \(grouped)

        Wombat will then accept exactly this certificate for this VPN, and warn you if it ever changes.
        """
        alert.alertStyle = .warning
        alert.addButton(withTitle: "Cancel")
        let trust = alert.addButton(withTitle: "Trust and Connect")
        trust.hasDestructiveAction = true
        trust.keyEquivalent = ""
        NSApp.activate()
        // Declined after two minutes, with a run-loop timer in the modal mode: this runs inside a
        // main-actor job, where a queued timeout would never fire (pitfall 17; Q5-M4).
        let timeout = Timer(timeInterval: 120, repeats: false) { _ in MainActor.assumeIsolated { NSApp.abortModal() } }
        RunLoop.main.add(timeout, forMode: .modalPanel)
        defer { timeout.invalidate() }
        trustAccepted = alert.runModal() == .alertSecondButtonReturn
        return trustAccepted
    }

}

// MARK: - Views

struct SignInView: View {
    @EnvironmentObject private var coordinator: SignInCoordinator

    var body: some View {
        Card(title: "Sign in to \(coordinator.tunnelName)", systemImage: "person.badge.key") {
            switch coordinator.step {
            case .working(let text):
                HStack(spacing: 12) {
                    ProgressView().controlSize(.small).accessibilityHidden(true)  // the text says it (A6-L3)
                    Text(text)
                    Spacer()
                    // No Escape: it would cancel from anywhere in the main window (A6-L1).
                    Button("Cancel") { coordinator.cancel() }
                }
                .accessibilityElement(children: .contain)
            case .form(let prompt):
                SignInForm(prompt: prompt)
                    .id(prompt.form.fields.map(\.name).joined() + (prompt.message ?? ""))
            case .sso(let request, let store):
                // Fills the detail column (OverviewTab shows it alone), so the page and its
                    // focused field stay on screen (A6-H1).
                SSOView(request: request, store: store)
                    .frame(minHeight: 320, maxHeight: .infinity)
                    .clipShape(RoundedRectangle(cornerRadius: 8))
                    .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(.separator))
            case .browser(let request):
                // Said plainly (user, 2026-10-16): what Wombat waits for, where, and that this
                // goes away by itself.
                VStack(alignment: .leading, spacing: 10) {
                    HStack(spacing: 10) {
                        ProgressView().controlSize(.small).accessibilityHidden(true)
                        Text("Waiting for you to sign in…").font(.title3.weight(.semibold)).accessibilityAddTraits(.isHeader)
                    }
                    Text("The sign-in page for \(request.loginURL.host() ?? coordinator.server) opened in your default browser. Finish signing in there.")
                        .fixedSize(horizontal: false, vertical: true)
                    Text("This stays here until you're signed in. Then Wombat connects, and it goes away on its own.")
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    HStack {
                        Button("Open Sign-In Page Again") { coordinator.openBrowserAgain() }
                            .help("If you closed the browser tab, or it opened in the wrong window")
                        Button("Cancel") { coordinator.cancel() }
                    }
                }
            }
        }
    }
}

/// The gateway's form: whatever fields it asks for (username, password, a Duo passcode or
/// "push", a group), in its order.
struct SignInForm: View {
    let prompt: AnyConnectPrompt
    @EnvironmentObject private var coordinator: SignInCoordinator
    @State private var values: [String: String] = [:]
    @FocusState private var focused: String?

    private var visible: [AuthField] {
        prompt.form.fields.filter { if case .hidden = $0.kind { return false } else { return true } }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            // The Overview around it scrolls, so a long banner is readable by keyboard too (A5-M4).
            Group {
                VStack(alignment: .leading, spacing: 14) {
                    HStack(spacing: 10) {
                        Image(systemName: "lock.shield").font(.title).foregroundStyle(.tint).accessibilityHidden(true)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(prompt.title ?? "Sign In").font(.headline).accessibilityAddTraits(.isHeader)
                            Text(prompt.server).font(.callout)
                        }
                    }
                    if let banner = prompt.banner {
                        Text(banner)
                            .font(.callout)
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(8)
                            .background(.background.secondary, in: RoundedRectangle(cornerRadius: 8))
                            .accessibilityElement(children: .contain)
                            .accessibilityLabel("Message from the gateway")
                    }
                    if let message = prompt.message {
                        Text(message).font(.callout).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                    }
                    if let error = prompt.error {
                        ErrorLabel(error).font(.callout)
                    }
                    Form {
                        ForEach(visible, id: \.name) { field in
                            row(field)
                        }
                    }
                    .formStyle(.columns)
                }
            }
            HStack {
                Spacer()
                Button("Cancel") { coordinator.cancel() }.keyboardShortcut(.cancelAction)
                Button("Sign In") { coordinator.submit(values) }.keyboardShortcut(.defaultAction)
            }
        }
        .onAppear {
            values = prompt.prefilled
            // The first empty field gets the cursor (the password, when the username is known).
            focused = visible.first { field in
                switch field.kind {
                case .text, .password: return (values[field.name] ?? "").isEmpty
                default: return false
                }
            }?.name ?? visible.first?.name
        }
    }

    @ViewBuilder
    private func row(_ field: AuthField) -> some View {
        let trimmed = field.label.trimmingCharacters(in: CharacterSet(charactersIn: ": "))
        let label = trimmed.isEmpty ? (field.secondAuth ? "Passcode" : field.name.capitalized) : trimmed
        // The instructions and the error, again on the field that has focus (A5-H1).
        let hint = (prompt.error.map { "Error: \($0). " } ?? "") + (prompt.message ?? "")
        switch field.kind {
        case .text:
            TextField(label, text: binding(field.name))
                .textContentType(field.name.lowercased().contains("user") ? .username : nil)
                .focused($focused, equals: field.name)
                .accessibilityHint(hint)
        case .password:
            SecureField(label, text: binding(field.name))
                .textContentType(field.secondAuth || prompt.form.fields.contains(where: { $0.name == "answer" }) ? .oneTimeCode : .password)
                .focused($focused, equals: field.name)
                .accessibilityHint(hint)
        case .select(let choices, let selected):
            Picker(label, selection: Binding(get: { values[field.name] ?? choices[selected].value }, set: { values[field.name] = $0 })) {
                ForEach(choices, id: \.value) { Text($0.label).tag($0.value) }
            }
        case .hidden, .ssoToken:
            EmptyView()
        }
    }

    private func binding(_ name: String) -> Binding<String> {
        Binding(get: { values[name] ?? "" }, set: { values[name] = $0 })
    }
}

/// The gateway's single sign-on page (SAML: Okta, Entra ID, Duo…) in an embedded browser with
/// its own cookie store per VPN, so Safari's cookies are neither used nor touched. The bar shows
/// which site the page is on: sign in only where you expect to.
struct SSOView: View {
    let request: SSORequest
    let store: UUID
    @EnvironmentObject private var coordinator: SignInCoordinator
    @State private var host = ""
    @State private var secure = true
    @State private var loading = true
    @State private var loadError: String?

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 8) {
                Image(systemName: secure ? "lock.fill" : "lock.open.trianglebadge.exclamationmark")
                    .foregroundStyle(secure ? Color.secondary : Color.red)
                    .accessibilityHidden(true)
                Text(host.isEmpty ? "Loading…" : host)
                    .font(.callout.monospaced())
                    .lineLimit(1)
                    .truncationMode(.head)
                    .accessibilityLabel(host.isEmpty ? "Loading" : "Page on \(host)\(secure ? "" : ", not secure")")
                if !secure && !host.isEmpty {
                    Text("Not secure").font(.callout.weight(.semibold)).accessibilityHidden(true)
                }
                if loading { ProgressView().controlSize(.small).accessibilityLabel("Loading page") }
                Spacer()
                // No Escape here: inside the identity provider's page it closes their popovers,
                // and must not cancel the whole sign-in (A5-M5).
                Button("Cancel") { coordinator.cancel() }
            }
            .padding(10)
            if let loadError {
                ErrorLabel("Couldn't load the sign-in page: \(loadError)").font(.callout).padding(.horizontal, 10).padding(.bottom, 8)
            }
            Divider()
            SSOWebView(request: request, store: store, host: $host, secure: $secure, loading: $loading, loadError: $loadError)
        }
    }
}

struct SSOWebView: NSViewRepresentable {
    let request: SSORequest
    let store: UUID
    @Binding var host: String
    @Binding var secure: Bool
    @Binding var loading: Bool
    @Binding var loadError: String?

    func makeCoordinator() -> Delegate { Delegate(self) }

    func makeNSView(context: Context) -> WKWebView {
        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = SSODataStore.store(for: store)
        let view = WKWebView(frame: .zero, configuration: configuration)
        view.navigationDelegate = context.coordinator
        view.load(URLRequest(url: request.loginURL))
        context.coordinator.watch(view)
        return view
    }

    func updateNSView(_ view: WKWebView, context: Context) {}

    static func dismantleNSView(_ view: WKWebView, coordinator: Delegate) {
        view.stopLoading()
        coordinator.stop()
    }

    @MainActor
    final class Delegate: NSObject, WKNavigationDelegate {
        let parent: SSOWebView
        private var done = false
        private var focusedOnce = false
        private var observation: NSKeyValueObservation?
        private let gatewayHost: String?

        init(_ parent: SSOWebView) {
            self.parent = parent
            gatewayHost = URL(string: parent.request.finalURL)?.host?.lowercased()
        }

        func watch(_ view: WKWebView) {
            observation = view.observe(\.url, options: [.new]) { [weak self] view, _ in
                MainActor.assumeIsolated { self?.update(view) }
            }
        }

        func stop() { observation = nil; done = true }

        private func update(_ view: WKWebView) {
            parent.host = view.url?.host ?? ""
            parent.secure = view.url?.scheme == "https" && view.hasOnlySecureContent
            check(view)
        }

        func webView(_ webView: WKWebView, decidePolicyFor action: WKNavigationAction) async -> WKNavigationActionPolicy {
            // Sign-in pages are https only; anything else (http, custom schemes, files) is refused.
            guard let url = action.request.url else { return .cancel }
            if url.scheme == "https" || url.absoluteString == "about:blank" { return .allow }
            return .cancel
        }

        func webView(_ webView: WKWebView, didStartProvisionalNavigation navigation: WKNavigation!) {
            parent.loading = true
            parent.loadError = nil
        }
        func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
            parent.loading = false
            // The page gets the keyboard, so the user can type at once (A5-M5).
            if !focusedOnce {
                focusedOnce = true
                webView.window?.makeFirstResponder(webView)
            }
            update(webView)
        }
        func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) { parent.loading = false }
        func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
            parent.loading = false
            if (error as NSError).code != NSURLErrorCancelled {
                parent.loadError = error.localizedDescription
                NSAccessibility.post(element: NSApp as Any, notification: .announcementRequested, userInfo: [
                    .announcement: "Couldn't load the sign-in page: \(error.localizedDescription)",
                    .priority: NSAccessibilityPriorityLevel.high.rawValue,
                ])
            }
        }
        func webView(_ webView: WKWebView, didReceiveServerRedirectForProvisionalNavigation navigation: WKNavigation!) { update(webView) }

        /// Done when the page is the gateway's final page and its token cookie is set (the rule
        /// OpenConnect uses). Cookies count only from the gateway's own domain.
        private func check(_ view: WKWebView) {
            guard !done, let url = view.url else { return }
            let final = parent.request.finalURL
            let atFinal = url.absoluteString == final || Self.samePage(url, URL(string: final))
            view.configuration.websiteDataStore.httpCookieStore.getAllCookies { [weak self] cookies in
                MainActor.assumeIsolated {
                    guard let self, !self.done else { return }
                    let fromGateway = cookies.filter { self.matchesGateway($0.domain) }
                    if let name = self.parent.request.errorCookie, let error = fromGateway.first(where: { $0.name == name && !$0.value.isEmpty }) {
                        self.done = true
                        SignInCoordinator.shared.ssoFailed("Single sign-on failed: \(error.value.removingPercentEncoding ?? error.value)")
                        return
                    }
                    guard atFinal, let token = fromGateway.first(where: { $0.name == self.parent.request.tokenCookie && !$0.value.isEmpty }) else { return }
                    self.done = true
                    // The token is single use: it doesn't stay in the cookie store.
                    view.configuration.websiteDataStore.httpCookieStore.delete(token)
                    SignInCoordinator.shared.ssoFinished(token.value)
                }
            }
        }

        /// The gateway's own host only: a parent-domain cookie could come from a sibling site
        /// such as the identity provider (S5-I5).
        private func matchesGateway(_ domain: String) -> Bool {
            guard let gatewayHost else { return false }
            return domain.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: ".")) == gatewayHost
        }

        /// The gateway's pages use the profile's pin when it has one (exactly that certificate),
        /// like the sign-in; every other site gets macOS trust.
        func webView(_ webView: WKWebView, respondTo challenge: URLAuthenticationChallenge) async -> (URLSession.AuthChallengeDisposition, URLCredential?) {
            let space = challenge.protectionSpace
            // No site in the sign-in browser gets a client certificate unasked: default handling
            // could pick an identity preference (S5B-I5, like the sign-in's S5-NV1).
            if space.authenticationMethod == NSURLAuthenticationMethodClientCertificate { return (.rejectProtectionSpace, nil) }
            guard space.authenticationMethod == NSURLAuthenticationMethodServerTrust, let trust = space.serverTrust,
                  space.host.lowercased() == gatewayHost, let pin = SignInCoordinator.shared.gatewayPin else {
                return (.performDefaultHandling, nil)
            }
            guard let leaf = (SecTrustCopyCertificateChain(trust) as? [SecCertificate])?.first,
                  ClientIdentities.hash(leaf) == pin else { return (.cancelAuthenticationChallenge, nil) }
            return (.useCredential, URLCredential(trust: trust))
        }

        static func samePage(_ a: URL, _ b: URL?) -> Bool {
            guard let b else { return false }
            return a.scheme == b.scheme && a.host?.lowercased() == b.host?.lowercased() && a.port == b.port && a.path == b.path
        }
    }
}

/// Each VPN's single sign-on cookies live in their own store, so an identity provider's
/// "remember me" works across connects without sharing anything with Safari or another VPN.
enum SSODataStore {
    @MainActor static func store(for id: UUID) -> WKWebsiteDataStore { WKWebsiteDataStore(forIdentifier: id) }

    /// Deletes a VPN's sign-in cookies (on delete, or when the user asks) and reports whether
    /// that worked. WebKit refuses to remove a store a web view still uses, so this VPN's
    /// sign-in is canceled first, and the removal tried again once (review NEW-10).
    @MainActor static func remove(_ id: UUID) async -> Bool {
        let coordinator = SignInCoordinator.shared
        if coordinator.activeTunnelID == id {
            coordinator.cancel()
            var waited = 0
            while coordinator.activeTunnelID == id, waited < 20 {
                try? await Task.sleep(for: .milliseconds(100))
                waited += 1
            }
        }
        for attempt in 0..<2 {
            do {
                try await WKWebsiteDataStore.remove(forIdentifier: id)
                return true
            } catch {
                if attempt == 0 { try? await Task.sleep(for: .milliseconds(500)) }
            }
        }
        return false
    }
}
