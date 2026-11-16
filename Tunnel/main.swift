import Foundation
import NetworkExtension
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
