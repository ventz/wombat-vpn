import Testing
@testable import TunnelCore

/// Sign-in labels (user, 2026-11-05): ocserv's code step is a field labeled "Password" under
/// "Please enter your OTP password.", which read exactly like the password step.
@Suite struct AuthFieldLabelTests {
    private func field(_ name: String, _ label: String, _ kind: AuthField.Kind = .password, second: Bool = false) -> AuthField {
        AuthField(name: name, label: label, kind: kind, secondAuth: second)
    }

    @Test func ocservCodeStepIsLabeledAsACode() {
        let f = field("password", "Password:")
        let form = AuthForm(action: nil, fields: [f])
        #expect(form.asksForCode(f, message: "Please enter your OTP password."))
        #expect(form.label(for: f, message: "Please enter your OTP password.") == "One-time code")
        #expect(form.label(for: f, message: "Please enter your password.") == "Password")
    }

    @Test func passwordNextToUsernameStaysPassword() {
        let pw = field("password", "Password:")
        let form = AuthForm(action: nil, fields: [field("username", "Username:", .text), pw])
        #expect(!form.asksForCode(pw, message: "Enter your password and then your OTP"))
        #expect(form.label(for: pw, message: "Enter your password and then your OTP") == "Password")
    }

    @Test func duoAloneIsNotACode() {
        let pw = field("password", "Password:")
        #expect(!AuthForm(action: nil, fields: [pw]).asksForCode(pw, message: "Duo push will follow"))
    }

    @Test func gatewayLabelsAndSecondAuthAreKept() {
        let second = field("secondary_password", "Duo Passcode:", second: true)
        let form = AuthForm(action: nil, fields: [field("username", "Username:", .text), field("password", "Password:"), second])
        #expect(form.asksForCode(second, message: nil))
        #expect(form.label(for: second, message: nil) == "Duo Passcode")
        let answer = field("answer", "")
        #expect(AuthForm(action: nil, fields: [answer]).label(for: answer, message: "Enter the code") == "One-time code")
    }
}
