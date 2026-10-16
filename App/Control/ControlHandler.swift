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
            let onDemand = store.tunnels.filter { $0.isActive && $0.isOnDemand }
            if !onDemand.isEmpty, !confirm(
                title: "Turn off on-demand for \(onDemand.map { "“\($0.name)”" }.joined(separator: ", "))?",
                detail: "The wombat command asked to disconnect. macOS would reconnect these tunnels at once, so disconnecting also turns their on-demand rules off.",
                action: "Disconnect") {
                return .failure("Disconnect was declined in the app")
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
            if request.command == .down, t.isOnDemand, !confirm(
                title: "Disconnect “\(t.name)” and turn off on-demand?",
                detail: "The wombat command asked to disconnect this tunnel. Its on-demand rules would reconnect it at once, so they are turned off too.",
                action: "Disconnect") {
                return .failure("Disconnect was declined in the app")
            }
            // Connecting stops our other tunnels and turns their on-demand off (one at a time).
            // When that drops another tunnel's on-demand or kill switch, the user approves it,
            // like `down` (audits S2-M1, F-1, WOM-01, Q2-H1).
            if request.command == .up, !t.isActive {
                let affected = store.tunnels.filter { $0 !== t && ($0.isOnDemand || ($0.isActive && $0.proto?.includeAllNetworks == true)) }
                if !affected.isEmpty, !confirm(
                    title: "Connect “\(t.name)” instead of \(affected.map { "“\($0.name)”" }.joined(separator: ", "))?",
                    detail: "The wombat command asked to connect “\(t.name)”. Wombat runs one tunnel at a time, so this disconnects \(affected.map { "“\($0.name)”" }.joined(separator: ", ")) and turns off its on-demand rules and kill switch protection.",
                    action: "Connect") {
                    return .failure("Connect was declined in the app")
                }
            }
            do {
                if request.command == .up { try await store.connect(t, source: "the wombat CLI") }
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
            let parsed = WgQuick.parse(text)
            guard let config = parsed.configuration else {
                return .failure(parsed.errors.map(\.description).joined(separator: "\n"))
            }
            let name = TunnelName.sanitize(request.name ?? "Tunnel")
            let findings = ConfigReview.review(config)
            guard approveImport(name: name, config: config, findings: findings) else {
                return .failure("Import was declined in the app")
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
            guard let name = request.name, let t = store.tunnel(named: name), let config = t.configuration else {
                return .failure("No tunnel named \"\(request.name ?? "")\"")
            }
            let withSecrets = request.includeSecrets == true
            if withSecrets {
                guard await Authenticator.confirm(reason: "export the private key of “\(t.name)” to the wombat command") else {
                    return .failure("Authentication failed or was canceled")
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
                return .failure("Rename was declined in the app")
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
                    let current = Control.OnDemand(manager: t.manager)
                    var changes = Self.weakening(from: current, to: rules).map { [$0] } ?? []
                    // Turning this tunnel's on-demand on turns the others' off.
                    let others = store.tunnels.filter { $0 !== t && $0.isOnDemand }
                    if rules.enabled, !others.isEmpty {
                        changes.append("turn off on-demand for \(others.map { "“\($0.name)”" }.joined(separator: ", ")) (one tunnel at a time)")
                    }
                    if !changes.isEmpty,
                       !confirm(title: "Change on-demand for “\(t.name)”?", detail: "The wombat command asked to \(changes.joined(separator: " and ")).", action: "Allow") {
                        return .failure("Change was declined in the app")
                    }
                    try await store.setOnDemand(t, rules)
                } else {
                    guard let protection = request.protection else { return .failure("No protection settings given") }
                    let current = Control.Protection(proto: t.proto)
                    if current.killSwitch && !protection.killSwitch {
                        guard await Authenticator.confirm(reason: "turn off the kill switch for “\(t.name)” (asked by the wombat command)") else {
                            return .failure("Authentication failed or was canceled")
                        }
                    } else if protection.killSwitch, !current.allowLAN, protection.allowLAN,
                              !confirm(title: "Allow the local network for “\(t.name)”?", detail: "The wombat command asked to let local-network traffic bypass the kill switch.", action: "Allow") {
                        return .failure("Change was declined in the app")
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
                return .failure("Delete was declined in the app")
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
            endpoint: t.configuration?.peers.first?.endpoint?.description,
            addresses: t.configuration?.interface.addresses.map(\.description) ?? [],
            connectedSince: t.connectedSince)
        s.onDemandRules = Control.OnDemand(manager: t.manager)
        s.protection = Control.Protection(proto: t.proto)
        s.protocol = t.configuration?.protocolName
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
            lines.append("All traffic goes to: \(list(heavy.map { $0.endpoint?.description ?? "a peer with no endpoint" }))")
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

    private var approvalOpen = false
    /// After a decline, further prompts are refused for a few seconds, so a script can't keep
    /// re-asking until the user clicks the wrong button (audit F-14).
    private var declinedUntil = Date.distantPast

    /// Asks the user. Cancel is the default button (a stray Return must not approve), only one
    /// approval is shown at a time, and an unanswered one is declined after two minutes.
    private func confirm(title: String, detail: String, action: String) -> Bool {
        guard !approvalOpen, Date() >= declinedUntil else { return false }
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
        if !approved { declinedUntil = Date().addingTimeInterval(10) }
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
