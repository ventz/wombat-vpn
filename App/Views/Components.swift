import SwiftUI

/// An error message in the label color with a red symbol: red text on the window background is
/// below 4.5:1 in light mode (audit A-H1), and VoiceOver hears "Error:" first.
struct ErrorLabel: View {
    let message: String
    init(_ message: String) { self.message = message }

    var body: some View {
        Label {
            Text(message).foregroundStyle(.primary).textSelection(.enabled)
        } icon: {
            Image(systemName: "xmark.octagon.fill").foregroundStyle(.red)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Error: \(message)")
    }
}

/// A positive status in the label color with a green symbol (green text is about 2:1).
struct SuccessLabel: View {
    let message: String
    init(_ message: String) { self.message = message }

    var body: some View {
        Label {
            Text(message).foregroundStyle(.primary)
        } icon: {
            Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
        }
    }
}
