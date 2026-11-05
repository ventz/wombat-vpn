import AppKit
import Foundation
import NetworkExtension
import TunnelCore
import UniformTypeIdentifiers

/// Save Diagnostics (issue #1, 2026-11-05): one text file a user can attach to a problem report.
/// Versions, the extensions' state, each VPN's settings and its last log, and no secret: no keys,
/// no AmneziaWG values (they fingerprint the server to a censor), no cookies, no user names. Every
/// log line already went through `LogScrubber` in the extension and goes through it again here.
/// With `hideServers`, server names, addresses and VPN names become placeholders, for a public post.
@MainActor
enum Diagnostics {
    /// `logBytes`: a budget for all the logs together (the CLI's reply is capped); the newest
    /// lines of each VPN are kept.
    static func report(_ store: TunnelStore, tunnel only: Tunnel? = nil, hideServers: Bool, logBytes: Int? = nil) async -> String {
        let tunnels = only.map { [$0] } ?? store.tunnels
        for t in tunnels where t.isActive { await store.keepRecentLog(t) }
        var hider = ServerHider(servers: tunnels.flatMap(servers), vpnNames: tunnels.map(\.name))
        let perTunnel = logBytes.map { $0 / max(tunnels.count, 1) }
        let info = Bundle.main.infoDictionary
        let os = ProcessInfo.processInfo.operatingSystemVersion
        let model = AppModel.shared
        var out: [String] = []
        out.append("Wombat diagnostics")
        out.append("Created: \(ISO8601DateFormatter().string(from: Date()))")
        out.append("Wombat \(info?["CFBundleShortVersionString"] as? String ?? "?") (\(info?["CFBundleVersion"] as? String ?? "?")), macOS \(os.majorVersion).\(os.minorVersion).\(os.patchVersion), \(Self.machine)")
        out.append("Debug logging: \(Preferences.debugLoggingUntil.map { "on until \(ISO8601DateFormatter().string(from: $0))" } ?? "off")")
        out.append("Server names and addresses: \(hideServers ? "hidden" : "shown")")
        out.append("")
        out.append("Network extensions")
        out.append("  WireGuard: \(state(model.installer.state))")
        out.append("  AnyConnect (OpenConnect): \(state(model.openConnectInstaller.state))")
        out.append("  Tailnet: \(state(model.tailnetInstaller.state))")
        if let problem = store.extensionProblem { out.append("  Problem: \(problem)") }
        for (index, t) in tunnels.enumerated() {
            out.append("")
            out.append(contentsOf: section(t, label: hideServers ? "VPN \(index + 1)" : t.name, hideServers: hideServers, logBytes: perTunnel))
        }
        let text = out.map { LogScrubber.scrub($0, maxLength: 8192) }.joined(separator: "\n") + "\n"
        return hideServers ? hider.hide(text) : text
    }

    /// Asks where to save, then writes the report (0600: it names your servers unless hidden).
    static func save(_ store: TunnelStore, tunnel: Tunnel? = nil) {
        let panel = NSSavePanel()
        // Which VPNs it covers, in the panel itself: the Settings button saves all, the Log tab's
        // only that one (accessibility-10 L4).
        panel.title = tunnel.map { "Save Diagnostics for “\($0.name)”" } ?? "Save Diagnostics for All VPNs"
        panel.message = "A text file for a problem report\(tunnel == nil ? ", covering every VPN" : ""). It holds no keys, passwords or session cookies."
        panel.nameFieldStringValue = "Wombat Diagnostics \(Self.fileDate).txt"
        panel.allowedContentTypes = [.plainText]
        let hide = NSButton(checkboxWithTitle: "Hide server names, addresses and VPN names (for posting publicly)", target: nil, action: nil)
        hide.state = .on
        panel.accessoryView = hide
        guard panel.runModal() == .OK, let url = panel.url else { return }
        let hideServers = hide.state == .on
        Task {
            let text = await report(store, tunnel: tunnel, hideServers: hideServers)
            do {
                try PrivateFile.write(Data(text.utf8), to: url.path)
                NSAccessibility.post(element: NSApp as Any, notification: .announcementRequested,
                                     userInfo: [.announcement: "Diagnostics saved", .priority: NSAccessibilityPriorityLevel.medium.rawValue])
                NSWorkspace.shared.activateFileViewerSelecting([url])
            } catch {
                AppModel.shared.actionError = "Could not save the diagnostics: \(error.localizedDescription)"
            }
        }
    }

    private static var fileDate: String {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd HH.mm"
        return f.string(from: Date())
    }

    private static var machine: String {
        var size = 0
        // "Mac15,6": the model, which "hw.machine" ("arm64") doesn't say.
        sysctlbyname("hw.model", nil, &size, nil, 0)
        var bytes = [CChar](repeating: 0, count: max(size, 1))
        sysctlbyname("hw.model", &bytes, &size, nil, 0)
        return String(cString: bytes)
    }

    static func serverNames(_ tunnels: [Tunnel]) -> [String] { tunnels.flatMap(servers) }

    private static func servers(_ t: Tunnel) -> [String] {
        var names: [String] = []
        if let host = t.profile?.host { names.append(host) }
        if let control = t.tailnetProfile?.controlURL, let host = URL(string: control)?.host() { names.append(host) }
        names += t.configuration?.peers.compactMap { $0.endpoint?.hostString } ?? []
        return names
    }

    private static func state(_ state: ExtensionInstaller.State) -> String {
        switch state {
        case .active: "active"
        case .activating: "activating"
        case .needsApproval: "waiting for approval in System Settings"
        case .requiresApplicationsFolder: "the app isn't in /Applications"
        case .failed(let message): "failed: \(message)"
        case .unknown: "not activated (no VPN of this kind, or not checked yet)"
        }
    }

    private static func section(_ t: Tunnel, label: String, hideServers: Bool, logBytes: Int?) -> [String] {
        var out = ["VPN: \(label)"]
        // Using AmneziaWG at all can matter to someone hiding from a censor: not in a public report.
        out.append("  Protocol: \(hideServers && t.protocolName == "AmneziaWG" ? "WireGuard or AmneziaWG" : t.protocolName)")
        out.append("  Status: \(t.statusText)\(t.connectedSince.map { ", since \(ISO8601DateFormatter().string(from: $0))" } ?? "")")
        if let error = t.lastError { out.append("  Last error: \(error)") }
        let protection = Control.Protection(proto: t.proto)
        out.append("  On demand: \(t.hasOnDemandSetting ? "on" : "off"); kill switch: \(protection.killSwitch ? "on" : "off"); local network: \(protection.allowLAN ? "allowed" : "blocked")")
        if t.isOpenConnect, let p = t.profile {
            out.append("  Gateway: \(p.displayServer)\(p.server.path.isEmpty || p.server.path == "/" ? "" : " (group URL \(hideServers ? "set" : p.server.path))")")
            out.append("  Group: \(p.group == nil ? "not set" : "set"); user name: \(p.username == nil ? "not set" : "set"); client certificate: \(p.clientCertificate == nil ? "no" : "yes")")
            out.append("  Pinned server certificate: \(p.serverCertificate == nil ? "no" : "yes"); DTLS: \(p.dtls ? "on" : "off"); sign-in in the browser: \(p.usesBrowserSignIn ? "yes" : "no")")
            out.append("  User agent: \(p.userAgent ?? "default (\(AnyConnectXML.defaultUserAgent))")")
            if let s = t.stats?.openConnect {
                out.append("  Transport: \(s.transport ?? "?")\(s.cipher.map { ", \($0)" } ?? ""); full tunnel: \(s.fullTunnel ? "yes" : "no"); \(s.routes.count) route(s), \(s.dnsServers.count) DNS server(s)")
            }
        } else if t.isTailnet, let p = t.tailnetProfile {
            out.append("  Coordination server: \(p.displayServer); MagicDNS: \(p.acceptDNS ? "on" : "off")")
            if let state = t.tailnetStatus?.state { out.append("  Node state: \(state)") }
        } else if let c = t.configuration {
            let i = c.interface
            out.append("  Addresses: \(i.addresses.map(\.description).joined(separator: ", "))")
            out.append("  DNS: \(i.dnsServers.isEmpty ? "none" : i.dnsServers.joined(separator: ", ")); MTU: \(i.mtu.map(String.init) ?? "automatic"); AmneziaWG settings: \(hideServers ? "not shown" : c.isAmnezia ? "yes (values not included)" : "no")")
            for (n, peer) in c.peers.enumerated() {
                let ips = peer.allowedIPs.map(\.description)
                out.append("  Peer \(n + 1): endpoint \(peer.endpoint?.description ?? "none"); allowed IPs \(ips.prefix(20).joined(separator: ", "))\(ips.count > 20 ? " and \(ips.count - 20) more" : ""); keepalive \(peer.persistentKeepalive.map { "\($0) s" } ?? "off"); preshared key: \(peer.presharedKey == nil ? "no" : "yes")")
            }
        }
        let fit = LogBudget.newest(t.recentLog, maxBytes: logBytes ?? .max)
        out.append("  Log (last run, \(t.recentLog.count) line(s)\(fit.leftOut > 0 ? ", the \(fit.leftOut) oldest left out here; Save Diagnostics in the app has them all" : "")):")
        out.append(contentsOf: t.recentLog.isEmpty ? ["    (none: the extension hasn't run this VPN since Wombat started)"] : fit.lines.map { "    \($0)" })
        return out
    }
}
