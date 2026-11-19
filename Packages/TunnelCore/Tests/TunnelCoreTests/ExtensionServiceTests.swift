import Testing
@testable import TunnelCore

/// An extension whose launchd job lost its Mach service (2026-11-18/19, pitfall 43).
@Suite struct ExtensionServiceTests {
    /// Turning the extension off and on removes its VPNs (pitfall 41), and the app can't
    /// re-install the same build: the only advice is a restart or the next update.
    @Test func adviceIsRestartOrUpdate() {
        for engine in ["WireGuard", "OpenConnect", "Tailnet"] {
            let text = ExtensionService.missingMessage(engine: engine)
            #expect(text.contains("Wombat \(engine) extension"))
            #expect(text.lowercased().contains("restart the mac"))
            #expect(!text.contains("off and on"))
            #expect(!text.contains("reopen"))
        }
    }

    /// Every message the extensions or the app give for an unreachable extension stays clear
    /// of "turn it off and on" now (it removes the VPNs) and of "reopen Wombat" (fixes nothing).
    @Test func handOffAdviceNeverTogglesTheExtension() {
        for text in HandOffReport.adviceTexts {
            #expect(!text.contains("off and on"))
            #expect(!text.contains("reopen"))
            #expect(text.lowercased().contains("restart the mac"))
        }
    }
}
