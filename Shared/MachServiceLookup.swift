import Darwin
import TunnelCore

// <servers/bootstrap.h> isn't in Swift's Darwin module; declared here so every target can use it
// without a bridging header. `@_silgen_name` uses Swift's calling convention, which matches C's
// for these plain integer/pointer arguments on arm64 and x86_64 (security-12 L4). Never also
// include <servers/bootstrap.h> in a bridging header: the two declarations conflict.
@_silgen_name("bootstrap_look_up")
private func wombat_bootstrap_look_up(_ bp: mach_port_t, _ serviceName: UnsafePointer<CChar>, _ sp: UnsafeMutablePointer<mach_port_t>) -> kern_return_t

/// Whether launchd has a Mach service, without connecting to it. A lookup of an on-demand
/// service doesn't launch its process; only a message would.
///
/// Why (2026-11-18): when macOS replaces a system extension it SIGKILLs the old process and
/// creates the new launchd job without waiting for the old one to exit. If the old process is
/// slow to die, the new job is created WITHOUT its Mach service ("The endpoint ... already exists
/// and is owned by" the old job) and stays that way until the Mac restarts (CLAUDE.md pitfall 43).
/// Seen on 1.4.6 → 1.4.8 (OpenConnect, busy) and 1.4.8/54 → 55 (WireGuard, idle).
/// The app can only report it (`ExtensionService`).
enum MachServiceLookup {
    /// launchd's BOOTSTRAP_UNKNOWN_SERVICE.
    static let unknownService: kern_return_t = 1102

    static func state(of name: String) -> ExtensionService.Lookup {
        var port: mach_port_t = 0
        let result = name.withCString { wombat_bootstrap_look_up(bootstrap_port, $0, &port) }
        if result == KERN_SUCCESS {
            mach_port_deallocate(mach_task_self_, port)
            return .registered
        }
        // Only launchd's definite answer counts; a sandbox refusal (1100) or anything else proves
        // nothing.
        return result == unknownService ? .missing : .unknown
    }
}
