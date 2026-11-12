import Foundation

/// A file error as text that names the cause: Cocoa's "You don't have permission to save the
/// file" is the same for EACCES, EPERM and a sandbox denial, so the POSIX error underneath is
/// appended ("… (EPERM 1: Operation not permitted)"). No paths: the text reaches the app and
/// Save Diagnostics.
enum FileErrorDetail {
    static func describe(_ error: Error) -> String {
        let text = error.localizedDescription
        guard let code = posixCode(error) else { return text }
        let name = names[code].map { "\($0) " } ?? ""
        return "\(text) (\(name)\(code): \(String(cString: strerror(code))))"
    }

    static func posixCode(_ error: Error) -> Int32? {
        var current: NSError? = error as NSError
        for _ in 0..<4 {
            guard let nsError = current else { return nil }
            if nsError.domain == NSPOSIXErrorDomain { return Int32(truncatingIfNeeded: nsError.code) }
            current = nsError.userInfo[NSUnderlyingErrorKey] as? NSError
        }
        return nil
    }

    private static let names: [Int32: String] = [
        EPERM: "EPERM", EACCES: "EACCES", EROFS: "EROFS", ENOSPC: "ENOSPC",
        ENOENT: "ENOENT", EEXIST: "EEXIST", ENOTDIR: "ENOTDIR", EISDIR: "EISDIR", EDQUOT: "EDQUOT",
    ]
}
