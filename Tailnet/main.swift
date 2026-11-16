import Foundation
import NetworkExtension
import os
import TunnelCore

// SIGPIPE: ignored here too. Go's c-archive runtime (libwg-go / libts-go) installs a process-wide
// SIGPIPE handler and, on darwin, ignores every SIGPIPE whatever thread it lands on
// (runtime/signal_unix.go sigfwdgo, golang.org/issue/33384). That handler is usually in place
// before this line (the archive starts its runtime from a load-time initializer), so this line
// mostly swaps it for a plain ignore; it keeps us safe if Go's behavior or its start order ever
// changes. In either order a write to a reset socket fails with EPIPE instead of killing the
// process and every tunnel in it (the OpenConnect extension, which links no Go, did die of
// exactly that on a 1.4.5 Mac).
signal(SIGPIPE, SIG_IGN)

// The tailnet extension: Tailscale's node (control plane, DERP, peers) in its own process and
// sandbox container, so none of it shares memory with WireGuard keys (spike design 3).
SecretStore.shared = TailnetStore()
TailnetEngine.installCallbacks()
// Lines from Go's standard logger (no tunnel token), already redacted in Go.
let processLogger = Logger(subsystem: AppIdentity.logSubsystem, category: "tailnet")
TailnetEngine.processLog = { line in processLogger.debug("engine: \(line, privacy: .private)") }

// The app hands profiles over this Mach service (NEMachServiceName in Info.plist). Only our
// app, signed by our team, may connect. Write-only, like the other two: there is no read.
let listener = NSXPCListener(machServiceName: AppIdentity.tailnetMachService)
listener.setConnectionCodeSigningRequirement(CodeSigning.app)
listener.delegate = SecretStore.shared
listener.resume()

autoreleasepool {
    NEProvider.startSystemExtensionMode()
}
dispatchMain()
