import Foundation

/// Where a Wombat.app runs from, for `wombat completion install`, which links into the app.
public enum BuildLocation {
    /// An Xcode build folder: it goes away on the next clean, and the completion links would
    /// dangle wherever they are synced (a dotfiles repository, say). Matched by whole path
    /// components, ignoring case (APFS usually does): a `DerivedData…` folder (also
    /// `-derivedDataPath DerivedDataRelease`), an `.xcarchive`, a `.noindex` folder (Xcode's
    /// convention, and this repo's `build.noindex/signed/export`), Xcode's install staging folder,
    /// or Xcode's layout `…/Build/Products/<Configuration>/<Name>.app/…`, so a folder merely
    /// called "Build" or "Products" (`~/Build/Products/Wombat.app`) doesn't count.
    /// Expects a path with symlinks resolved (the CLI resolves its own executable first).
    public static func isDevelopmentBuild(_ path: String) -> Bool {
        let parts = path.split(separator: "/").map { $0.lowercased() }
        if parts.contains(where: { $0.hasPrefix("deriveddata") || $0.hasSuffix(".xcarchive") || $0.hasSuffix(".noindex") || $0 == "installationbuildproductslocation" }) {
            return true
        }
        guard parts.count >= 4 else { return false }
        for i in 0...(parts.count - 4)
        where parts[i] == "build" && parts[i + 1] == "products" && parts[i + 3].hasSuffix(".app") {
            return true
        }
        return false
    }
}
