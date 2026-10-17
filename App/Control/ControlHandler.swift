import AppKit
import Foundation
import LocalAuthentication
import TunnelCore

/// Answers CLI requests. Read-only and connect/disconnect requests run directly; adding a tunnel
/// and exporting keys need the user, in the app, every time.
@MainActor
final class ControlHandler {
    private let store: TunnelStore

    init(store: TunnelStore) { self.store = store }

    func handle(_ request: Control.Request) async -> Control.Response {
        if !store.loaded { await store.reload() }
        switch request.command {
        case .version:
            var r = Control.Response(ok: true)
            r.version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String
            return r

        case .list, .status:
            var tunnels = store.tunnels
            if let name = request.name {
                guard let t = store.tunnel(named: name) else { return .failure("No tunnel named \"\(name)\"") }
                tunnels = [t]
            }
            var r = Control.Response(ok: true)
            r.tunnels = tunnels.map(summary)
            return r

        case .down where request.name == nil:
            // Disconnecting drops on-demand and kill-switch protection, so the user approves it
            // (review SEC-1: a full tunnel has its kill switch on and on-demand off by default).
            let protected = store.tunnels.filter { $0.isActive && ($0.hasOnDemandSetting || $0.isKillSwitchActive) }
            if !protected.isEmpty, !confirm(
                title: "Disconnect \(protected.map { "“\($0.name)”" }.joined(separator: ", "))?",
                detail: "The wombat command asked to disconnect. \(Self.protectionLoss(protected))",
                action: "Disconnect") {
                return declinedFailure("Disconnect")
            }
            var failures: [String] = []
            for t in store.tunnels where t.isActive {
                do { try await store.disconnect(t) } catch { failures.append("\(t.name): \(error.localizedDescription)") }
            }
            var r = Control.Response(ok: failures.isEmpty)
            if !failures.isEmpty { r.error = failures.joined(separator: "; ") }
            r.tunnels = store.tunnels.map(summary)
            return r

        case .up, .down:
            guard let name = request.name, let t = store.tunnel(named: name) else {
                return .failure("No tunnel named \"\(request.name ?? "")\"")
            }
            // Disconnecting an on-demand tunnel turns its rules off: that weakens protection, so
            // the user approves it (any process running as the user can invoke the CLI).
            // The kill switch counts too: without it, traffic leaves outside the tunnel (SEC-1).
            if request.command == .down, t.hasOnDemandSetting || t.isKillSwitchActive, !confirm(
                title: "Disconnect “\(t.name)”?",
                detail: "The wombat command asked to disconnect this tunnel. \(Self.protectionLoss([t]))",
                action: "Disconnect") {
                return declinedFailure("Disconnect")
            }
            // Connecting stops our other tunnels and turns their on-demand off (one at a time).
            // When that drops another tunnel's on-demand or kill switch, the user approves it,
            // like `down` (audits S2-M1, F-1, WOM-01, Q2-H1).
            var approved = Set<UUID>()
            if request.command == .up, !t.isActive {
                let affected = store.tunnels.filter { $0 !== t && ($0.hasOnDemandSetting || $0.isKillSwitchActive) }
                approved = Set(affected.map(\.id))
                if !affected.isEmpty, !confirm(
                    title: "Connect “\(t.name)” instead of \(affected.map { "“\($0.name)”" }.joined(separator: ", "))?",
                    detail: "The wombat command asked to connect “\(t.name)”. Wombat runs one tunnel at a time, so this disconnects \(affected.map { "“\($0.name)”" }.joined(separator: ", ")) and turns off its on-demand rules and kill switch protection.",
                    action: "Connect") {
                    return declinedFailure("Connect")
                }
            }
            do {
                if request.command == .up { try await store.connect(t, source: "the wombat CLI", approved: approved) }
                else { try await store.disconnect(t) }
                // Report the state the request leads to once it settles (up to 10 s).
                let target: Set<String> = request.command == .up ? ["connected"] : ["disconnected"]
                for _ in 0..<100 where !target.contains(t.cliStatus) {
                    try? await Task.sleep(for: .milliseconds(100))
                    t.refreshStatus()
                }
                var r = Control.Response(ok: target.contains(t.cliStatus))
                if !r.ok { r.error = t.lastError ?? "Tunnel is \(t.cliStatus)" }
                r.tunnels = [summary(t)]
                return r
            } catch {
                return .failure(error.localizedDescription)
            }

        case .stats:
            guard let name = request.name, let t = store.tunnel(named: name) else {
                return .failure("No tunnel named \"\(request.name ?? "")\"")
            }
            guard let stats = await store.fetchStats(t) else { return .failure("\(t.name) is not connected") }
            var r = Control.Response(ok: true)
            r.stats = stats
            r.tunnels = [summary(t)]
            return r

        case .import:
            guard let text = request.config else { return .failure("No configuration given") }
            if OpenConnectFile.looksLikeProfile(text) {
                let parsed = OpenConnectFile.parse(text)
                guard let profile = parsed.profile else { return .failure(parsed.errors.map(\.description).joined(separator: "\n")) }
                let name = TunnelName.sanitize(request.name ?? "VPN")
                // Anyone able to run the CLI could add a VPN that later receives your sign-in, so
                // the user sees which gateway it is.
                var detail = ["The wombat command wants to add a Cisco AnyConnect VPN.", "", "Gateway: \(String(profile.server.absoluteString.prefix(200)))"]
                if let group = profile.group { detail.append("Group: \(String(group.prefix(80)))") }
                if let user = profile.username { detail.append("Username: \(String(user.prefix(80)))") }
                if let sha = profile.clientCertificate {
                    // It would present your certificate to this gateway (S5-L4).
                    let name = ClientIdentities.item(sha256: sha)?.name ?? "a certificate that isn't in your keychain"
                    detail.append("⚠︎ It signs in with your client certificate “\(String(name.prefix(80)))”. Only accept if this gateway should receive it.")
                }
                if profile.serverCertificate != nil { detail.append("⚠︎ It pins a server certificate instead of using macOS trust. Only accept if you expected this.") }
                detail += ["", "You will sign in to this gateway when you connect it: make sure it's your organization's."]
                guard confirm(title: "Add VPN “\(name)”?", detail: detail.joined(separator: "\n"), action: "Add VPN") else {
                    return declinedFailure("Import")
                }
                do {
                    let t = try await store.addOpenConnect(name: name, text: text)
                    var r = Control.Response(ok: true)
                    r.tunnels = [summary(t)]
                    return r
                } catch {
                    return .failure(error.localizedDescription)
                }
            }
            let parsed = WgQuick.parse(text)
            guard let config = parsed.configuration else {
                return .failure(parsed.errors.map(\.description).joined(separator: "\n"))
            }
            let name = TunnelName.sanitize(request.name ?? "Tunnel")
            let findings = ConfigReview.review(config)
            guard approveImport(name: name, config: config, findings: findings) else {
                return declinedFailure("Import")
            }
            do {
                let t = try await store.add(name: name, text: text)
                var r = Control.Response(ok: true)
                r.tunnels = [summary(t)]
                r.findings = findings
                return r
            } catch {
                return .failure(error.localizedDescription)
            }

        case .export:
            if let name = request.name, let t = store.tunnel(named: name), t.isOpenConnect {
                guard let profile = t.profile else { return .failure("The keychain item for \(t.name) is missing") }
                var r = Control.Response(ok: true)
                r.config = OpenConnectFile.serialize(profile)  // no secrets in a profile
                return r
            }
            guard let name = request.name, let t = store.tunnel(named: name), let config = t.configuration else {
                return .failure("No tunnel named \"\(request.name ?? "")\"")
            }
            let withSecrets = request.includeSecrets == true
            if withSecrets {
                guard await authenticate(reason: "export the private key of “\(t.name)” to the wombat command") else {
                    return declinedFailure(nil)
                }
            }
            var r = Control.Response(ok: true)
            r.config = WgQuick.serialize(config, includePrivateKey: withSecrets)
            return r

        case .rename:
            guard let name = request.name, let t = store.tunnel(named: name) else {
                return .failure("No tunnel named \"\(request.name ?? "")\"")
            }
            guard let newName = request.newName, !TunnelName.sanitize(newName).isEmpty else { return .failure("No new name given") }
            // A rename can disguise one tunnel as another ("Work"), so the user approves it (S2-L8).
            guard confirm(title: "Rename “\(t.name)” to “\(TunnelName.sanitize(newName))”?",
                          detail: "The wombat command asked to rename this tunnel.", action: "Rename") else {
                return declinedFailure("Rename")
            }
            do {
                try await store.rename(t, to: newName)
                var r = Control.Response(ok: true)
                r.tunnels = [summary(t)]
                return r
            } catch {
                return .failure(error.localizedDescription)
            }

        case .onDemand, .protection:
            guard let name = request.name, let t = store.tunnel(named: name) else {
                return .failure("No tunnel named \"\(request.name ?? "")\"")
            }
            do {
                if request.command == .onDemand {
                    guard let rules = request.onDemand else { return .failure("No on-demand settings given") }
                    // Refused before any approval prompt: AnyConnect can't connect on demand (Q5-L4).
                    if t.isOpenConnect {
                        return .failure("AnyConnect VPNs can't connect on demand: each connect needs a sign-in")
                    }
                    let current = Control.OnDemand(manager: t.manager)
                    var changes = Self.weakening(from: current, to: rules).map { [$0] } ?? []
                    // Turning this tunnel's on-demand on turns the others' off.
                    // Turning this tunnel's on-demand on enables its configuration, which stops a
                    // running tunnel and its kill switch too (docs/CLI.md; review SEC-1).
                    let others = store.tunnels.filter { $0 !== t && ($0.hasOnDemandSetting || $0.isKillSwitchActive) }
                    if rules.enabled, !others.isEmpty {
                        changes.append("turn off on-demand and kill switch protection for \(others.map { "“\($0.name)”" }.joined(separator: ", ")) (one tunnel at a time)")
                    }
                    if !changes.isEmpty,
                       !confirm(title: "Change on-demand for “\(t.name)”?", detail: "The wombat command asked to \(changes.joined(separator: " and ")).", action: "Allow") {
                        return declinedFailure("Change")
                    }
                    try await store.setOnDemand(t, rules)
                } else {
                    guard let protection = request.protection else { return .failure("No protection settings given") }
                    let current = Control.Protection(proto: t.proto)
                    if current.killSwitch && !protection.killSwitch {
                        guard await authenticate(reason: "turn off the kill switch for “\(t.name)” (asked by the wombat command)") else {
                            return declinedFailure(nil)
                        }
                    } else if protection.killSwitch, !current.allowLAN, protection.allowLAN,
                              !confirm(title: "Allow the local network for “\(t.name)”?", detail: "The wombat command asked to let local-network traffic bypass the kill switch.", action: "Allow") {
                        return declinedFailure("Change")
                    }
                    try await store.setProtection(t, protection)
                }
                var r = Control.Response(ok: true)
                r.tunnels = [summary(t)]
                return r
            } catch {
                return .failure(error.localizedDescription)
            }

        case .log:
            guard let name = request.name, let t = store.tunnel(named: name) else {
                return .failure("No tunnel named \"\(request.name ?? "")\"")
            }
            var r = Control.Response(ok: true)
            r.log = await store.fetchRecentLog(t)
            return r

        case .delete:
            guard let name = request.name, let t = store.tunnel(named: name) else {
                return .failure("No tunnel named \"\(request.name ?? "")\"")
            }
            guard confirm(title: "Delete “\(t.name)”?", detail: "The wombat command asked to delete this tunnel and its keys. This cannot be undone.", action: "Delete") else {
                return declinedFailure("Delete")
            }
            do {
                try await store.delete(t)
                return Control.Response(ok: true)
            } catch {
                return .failure(error.localizedDescription)
            }
        }
    }

    private func summary(_ t: Tunnel) -> Control.TunnelSummary {
        var s = Control.TunnelSummary(
            name: t.name,
            status: t.cliStatus,
            onDemand: t.isOnDemand,
            endpoint: t.isOpenConnect ? t.profile?.displayServer : t.configuration?.peers.first?.endpoint?.description,
            addresses: t.isOpenConnect ? [t.stats?.openConnect?.ipv4, t.stats?.openConnect?.ipv6].compactMap { $0 }
                : t.configuration?.interface.addresses.map(\.description) ?? [],
            connectedSince: t.connectedSince)
        s.onDemandRules = Control.OnDemand(manager: t.manager)
        s.protection = Control.Protection(proto: t.proto)
        s.protocol = t.isOpenConnect ? "anyconnect" : t.configuration?.protocolName
        return s
    }

    /// Imports from the CLI could come from any process able to run our CLI, and a tunnel that
    /// routes 0.0.0.0/0 to a stranger's server sees all traffic. So the user approves each one,
    /// seeing where the traffic would go.
    private func approveImport(name: String, config: TunnelConfiguration, findings: [Finding]) -> Bool {
        var lines = ["The wombat command wants to add \(config.isAmnezia ? "an AmneziaWG" : "a") tunnel with \(config.peers.count) peer\(config.peers.count == 1 ? "" : "s").", ""]
        // Where most traffic would go comes first, naming every peer that carries a default
        // route, so a long peer list can't hide one (audit WOM-13).
        // Lists are capped and long hostnames shortened, so what follows always fits in the
        // alert's 1500 characters (S4b L1).
        // Long names keep their end (domain and port), where a lookalike would differ.
        func list(_ items: [String]) -> String {
            let shown = items.prefix(6).map { $0.count > 48 ? "…" + $0.suffix(47) : $0 }
            return shown.joined(separator: ", ") + (items.count > 6 ? " (+\(items.count - 6) more)" : "")
        }
        // The peers that actually receive most of the internet, computed the way WireGuard
        // routes (longest prefix; an identical prefix goes to the later peer). A peer whose
        // routes are all shadowed gets nothing and isn't named (S4c L1, S4d/S4e L1).
        let heavy = config.internetPeers
        if !heavy.isEmpty {
            lines.append("Internet traffic goes to (largest share first): \(list(heavy.map { $0.endpoint?.description ?? "a peer with no endpoint" }))")
        }
        // Then risks, so a long route list can't push them out of view.
        // The file-chosen packets first: six generic warnings must not push them out (S4 L1).
        // The AmneziaWG traffic warnings come first (S4c L1).
        let first: Set<String> = ["amneziawg-signature-packets", "amneziawg-amplification"]
        let risks = findings.filter { first.contains($0.code) } + findings.filter { $0.level != .info && !first.contains($0.code) }
        var tail: [String] = []
        let endpoints = config.peers.compactMap { $0.endpoint?.description }
        tail.append("Endpoints: \(endpoints.isEmpty ? "none" : list(endpoints))")
        let coverage = config.coverage
        if coverage.isFullTunnel {
            tail.append("Routes: \(RouteCoverage.describe(coverage.ipv4)) of IPv4 and \(RouteCoverage.describe(coverage.ipv6)) of IPv6 traffic")
        } else {
            let routes = config.peers.flatMap(\.allowedIPs).map(\.description)
            tail.append("Routes: \(routes.prefix(8).joined(separator: ", "))\(routes.count > 8 ? " (+\(routes.count - 8) more)" : "")")
        }
        // Risks get what the alert's 1500 characters leave after the header and the
        // endpoint/route lines, so neither side can push the other out (S4c L1). The
        // first risk always fits: the header and tail are capped well below the limit.
        var budget = 1500 - (lines + tail).joined(separator: "\n").count - 40
        var shown = 0
        for risk in risks.prefix(6) {
            let line = "⚠︎ " + (risk.message.count > 150 ? risk.message.prefix(149) + "…" : risk.message)
            guard line.count + 1 <= budget || shown == 0 else { break }
            lines.append(line)
            budget -= line.count + 1
            shown += 1
        }
        if risks.count > shown { lines.append("…and \(risks.count - shown) more") }
        if !risks.isEmpty { lines.append("") }
        lines += tail
        return confirm(title: "Add tunnel “\(name)”?", detail: lines.joined(separator: "\n"), action: "Add Tunnel")
    }

    /// A description of how `new` lowers protection compared to `old`, or nil if it doesn't.
    static func weakening(from old: Control.OnDemand, to new: Control.OnDemand) -> String? {
        var parts: [String] = []
        if old.enabled && !new.enabled { parts.append("turn on-demand off") }
        if new.enabled {
            if old.onWiFi && !new.onWiFi { parts.append("stop connecting automatically on Wi-Fi") }
            if old.onEthernet && !new.onEthernet { parts.append("stop connecting automatically on Ethernet") }
        }
        // Trusted networks count even while on-demand is off: they take effect when it is turned
        // on later, which isn't checked again (audit F-6).
        do {
            let added = Set(new.trustedSSIDs).subtracting(old.trustedSSIDs)
            if !added.isEmpty { parts.append("trust the Wi-Fi network\(added.count == 1 ? "" : "s") \(added.sorted().map { "“\(TunnelName.sanitize($0))”" }.joined(separator: ", ")) (the tunnel disconnects there)") }
        }
        return parts.isEmpty ? nil : parts.joined(separator: " and ")
    }

    /// What disconnecting these tunnels gives up, for an approval prompt.
    static func protectionLoss(_ tunnels: [Tunnel]) -> String {
        var parts: [String] = []
        let onDemand = tunnels.filter(\.hasOnDemandSetting)
        let killSwitch = tunnels.filter(\.isKillSwitchActive)
        if !onDemand.isEmpty {
            parts.append("macOS would reconnect \(onDemand.count == 1 ? "it" : "them") at once, so \(onDemand.count == 1 ? "its" : "their") on-demand rules are turned off too.")
        }
        if !killSwitch.isEmpty {
            parts.append("The kill switch stops protecting you: traffic goes out without the VPN.")
        }
        return parts.joined(separator: " ")
    }

    /// Touch ID requests from the CLI follow the same rules as the approval prompts: one at a
    /// time, and refused for a while after a cancel, so a script can't re-ask in a loop (SEC-1).
    private func authenticate(reason: String) async -> Bool {
        notShownReason = promptBlocked()
        guard notShownReason == nil else { return false }
        approvalOpen = true
        defer { approvalOpen = false }
        let ok = await Authenticator.confirm(reason: reason)
        if !ok { declined() }
        return ok
    }

    /// Why the last prompt wasn't shown at all, so the CLI doesn't report a decline the user
    /// never saw (quality-6 L6).
    private var notShownReason: String?

    private func declinedFailure(_ action: String?) -> Control.Response {
        defer { notShownReason = nil }
        if let notShownReason { return .failure(notShownReason) }
        return .failure(action.map { "\($0) was declined in the app" } ?? "Authentication failed or was canceled")
    }

    /// Nil when a prompt may be shown now.
    private func promptBlocked() -> String? {
        if approvalOpen { return "Another approval is open in Wombat; answer it, then try again" }
        let wait = declinedUntil.timeIntervalSinceNow
        if wait > 0 { return "A request was just declined; try again in \(Int(wait.rounded(.up))) s" }
        return nil
    }

    private var approvalOpen = false
    /// After a decline, further prompts are refused for a few seconds, so a script can't keep
    /// re-asking until the user clicks the wrong button (audit F-14).
    /// Kept in the defaults too, so `wombat stop` and a relaunch don't clear it (SEC-1).
    private var declinedUntil: Date {
        get {
            let saved = Date(timeIntervalSince1970: UserDefaults.standard.double(forKey: "cliDeclinedUntil"))
            // A clock set back must not leave a long lockout.
            return saved.timeIntervalSinceNow > Self.coolDown ? .distantPast : saved
        }
        set { UserDefaults.standard.set(newValue.timeIntervalSince1970, forKey: "cliDeclinedUntil") }
    }
    private static let coolDown: TimeInterval = 10

    private func declined() { declinedUntil = Date().addingTimeInterval(Self.coolDown) }

    /// Asks the user. Cancel is the default button (a stray Return must not approve), only one
    /// approval is shown at a time, and an unanswered one is declined after two minutes.
    private func confirm(title: String, detail: String, action: String) -> Bool {
        notShownReason = promptBlocked()
        guard notShownReason == nil else { return false }
        approvalOpen = true
        defer { approvalOpen = false }
        // The app is usually in the background when the CLI asks: bounce the Dock icon too, so
        // the request is noticed (and VoiceOver users hear it) before it times out (A-M8).
        let attention = NSApp.isActive ? nil : NSApp.requestUserAttention(.criticalRequest)
        defer { if let attention { NSApp.cancelUserAttentionRequest(attention) } }
        NSApp.activate()
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = String(detail.prefix(1500))
        alert.alertStyle = .warning
        alert.addButton(withTitle: "Cancel")
        let approve = alert.addButton(withTitle: action)
        approve.hasDestructiveAction = true
        approve.keyEquivalent = ""
        alert.window.level = .floating  // a background app can't take focus (cooperative activation)
        // A run-loop timer in the modal mode, not DispatchQueue.main.asyncAfter: this runs inside
        // a main-actor job, and the main queue isn't drained again until that job returns, so a
        // queued timeout never fired. The alert stayed up and the app answered nothing (2026-10-16).
        let timeout = Timer(timeInterval: 120, repeats: false) { _ in
            MainActor.assumeIsolated { NSApp.abortModal() }
        }
        RunLoop.main.add(timeout, forMode: .modalPanel)
        defer { timeout.invalidate() }
        let approved = alert.runModal() == .alertSecondButtonReturn
        if !approved { declined() }
        return approved
    }
}

enum Authenticator {
    /// Touch ID, Apple Watch or the login password.
    @MainActor
    static func confirm(reason: String) async -> Bool {
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else { return false }
        return (try? await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)) ?? false
    }
}
