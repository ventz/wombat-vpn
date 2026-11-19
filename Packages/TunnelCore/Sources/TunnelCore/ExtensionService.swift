import Foundation

/// Whether an extension's launchd job still has its Mach service (CLAUDE.md pitfall 43). When
/// macOS replaces a system extension it can create the new job WITHOUT its service; then nothing
/// the app sends reaches the extension until a restart or the next update with a higher build
/// number. The app can't repair it: sysextd answers a same-version activation with "already
/// active" and never offers a replacement (device test 2026-11-19), and turning the extension off
/// and on removes its VPNs (pitfall 41). So the app only says what still works and what fixes it.
public enum ExtensionService {
    public enum Lookup: Equatable, Sendable {
        case registered
        /// launchd's definite "unknown service".
        case missing
        /// The lookup failed some other way (a sandbox refusal, say): proves nothing.
        case unknown
    }

    /// The banner for an extension whose service is missing. `engine` is "WireGuard",
    /// "OpenConnect" or "Tailnet".
    public static func missingMessage(engine: String) -> String {
        let works: String
        switch engine {
        case "WireGuard": works = "Tunnels you haven't changed still connect, but new or edited tunnels can't reach it"
        case "OpenConnect": works = "AnyConnect VPNs still connect, but other changes can't reach it"
        default: works = "Changes can't reach it"
        }
        return "macOS didn't finish updating the Wombat \(engine) extension. \(works) until you restart the Mac or install the next Wombat update."
    }
}
