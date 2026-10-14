import Foundation
import NetworkExtension

// The app hands tunnel configurations to the extension over this Mach service (NEMachServiceName
// in Info.plist). Only our app, signed by our team, may connect.
let listener = NSXPCListener(machServiceName: AppIdentity.extensionMachService)
listener.setConnectionCodeSigningRequirement(CodeSigning.app)
listener.delegate = SecretStore.shared
listener.resume()

// A Network Extension packaged as a system extension hands control to the framework here;
// the framework instantiates PacketTunnelProvider (named in Info.plist) per connection.
autoreleasepool {
    NEProvider.startSystemExtensionMode()
}
dispatchMain()
