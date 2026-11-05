import Foundation

/// Errors handed to NetworkExtension (a start's completion handler, `cancelTunnelWithError`).
/// NE carries them to the app as NSError: a Swift `LocalizedError` arrives as "<Type> error N",
/// its text lost (pitfall 31, seen with the Tailnet extension), so the reason a tunnel didn't
/// start or was ended never reached the app's Overview (quality-10 H1, issue #1). The text names
/// no secret: callers pass the same messages the Log tab shows.
enum ProviderError {
    static func ns(_ error: Error) -> NSError {
        let original = error as NSError
        return NSError(domain: AppIdentity.appBundleID + ".provider", code: original.code,
                       userInfo: [NSLocalizedDescriptionKey: error.localizedDescription])
    }
}
