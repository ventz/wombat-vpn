import Foundation
import NetworkExtension
import os
import TunnelCore

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
