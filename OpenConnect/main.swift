import Foundation
import NetworkExtension
import os
import TunnelCore

// The OpenConnect (Cisco AnyConnect) extension: its own process and sandbox container, so a
// bug in the OpenConnect C code can't reach the WireGuard extension's keys.

// libopenconnect and OpenSSL write to the gateway's sockets with plain send()/write(), without
// MSG_NOSIGNAL or SO_NOSIGPIPE, and the openconnect CLI ignores SIGPIPE in its own main.c, which
// we don't link. So a write to a connection the gateway has already reset (likely after a sleep
// or a network change) raises SIGPIPE, whose default action kills this whole process, every
// tunnel and the XPC listener in it, with no "Tunnel ended" reason. Seen on a 1.4.5 Mac: launchd
// "last terminating signal = Broken pipe: 13". Ignored, such a write fails with EPIPE instead,
// an error libopenconnect already handles.
signal(SIGPIPE, SIG_IGN)

SecretStore.shared = OpenConnectStore()

// The app hands profiles and sign-in sessions over this Mach service (NEMachServiceName in
// Info.plist). Only our app, signed by our team, may connect.
let listener = NSXPCListener(machServiceName: AppIdentity.openConnectMachService)
listener.setConnectionCodeSigningRequirement(CodeSigning.app)
listener.delegate = SecretStore.shared
listener.resume()
// Said once in the system log, publicly (no secrets): the one line that tells this state apart.
// Logged either way (review security-11 L6: shows whether the check sees the broken state).
if ServiceCheck.ownServiceMissing() {
    Logger(subsystem: AppIdentity.logSubsystem, category: "openconnect")
        .error("This extension's XPC service is missing from launchd (macOS replaced the extension while the old one was exiting); connects use the backup hand-off until the Mac restarts")
} else {
    Logger(subsystem: AppIdentity.logSubsystem, category: "openconnect").notice("This extension's XPC service is registered")
}

autoreleasepool {
    NEProvider.startSystemExtensionMode()
}
dispatchMain()
