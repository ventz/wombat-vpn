import Foundation
import NetworkExtension
import TunnelCore

// The OpenConnect (Cisco AnyConnect) extension: its own process and sandbox container, so a
// bug in the OpenConnect C code can't reach the WireGuard extension's keys.
SecretStore.shared = OpenConnectStore()

// The app hands profiles and sign-in sessions over this Mach service (NEMachServiceName in
// Info.plist). Only our app, signed by our team, may connect.
let listener = NSXPCListener(machServiceName: AppIdentity.openConnectMachService)
listener.setConnectionCodeSigningRequirement(CodeSigning.app)
listener.delegate = SecretStore.shared
listener.resume()

autoreleasepool {
    NEProvider.startSystemExtensionMode()
}
dispatchMain()
