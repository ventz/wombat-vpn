import Foundation
import NetworkExtension
import TunnelCore

// The WireGuard extension's store: wg-quick texts, checked by the same parser the app uses.
SecretStore.shared = SecretStore(maxBytes: WgQuick.maxBytes, interface: NSXPCInterface(with: TunnelSecretStoreProtocol.self)) { text in
    let parsed = WgQuick.parse(text)
    return parsed.configuration == nil ? parsed.errors.map(\.description).joined(separator: "; ") : nil
}
SecretStore.shared.onForget = { EndpointAddresses.forget(tunnelID: $0) }

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
