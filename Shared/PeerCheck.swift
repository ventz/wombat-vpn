import Foundation
import Security

/// Identifies the process at the other end of a Unix socket: same user, and signed with the
/// given code-signing requirement (checked through its audit token, so a reused pid can't fool
/// it). The app uses it on CLI clients; the CLI uses it on the app before sending anything,
/// since a configuration being imported carries a private key (audits S2-L3, F-4, WOM-05).
enum PeerCheck {
    static func rejectReason(_ fd: Int32, requirement text: String, expected: String) -> String? {
        var cred = xucred()
        var credLength = socklen_t(MemoryLayout<xucred>.size)
        guard getsockopt(fd, SOL_LOCAL, LOCAL_PEERCRED, &cred, &credLength) == 0, cred.cr_version == XUCRED_VERSION else {
            return "no peer credentials"
        }
        guard cred.cr_uid == getuid() else { return "different user (uid \(cred.cr_uid))" }

        var token = audit_token_t()
        var tokenLength = socklen_t(MemoryLayout<audit_token_t>.size)
        guard getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &tokenLength) == 0 else { return "no audit token" }
        let tokenData = withUnsafeBytes(of: &token) { Data($0) }

        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributeAudit: tokenData] as CFDictionary, [], &code) == errSecSuccess,
              let code else { return "cannot identify the process" }
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess, let requirement else {
            return "bad requirement"
        }
        let status = SecCodeCheckValidity(code, [], requirement)
        return status == errSecSuccess ? nil : "not \(expected) signed by this team (\(status))"
    }
}
