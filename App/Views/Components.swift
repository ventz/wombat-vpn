import SwiftUI
import TunnelCore

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

/// What an AmneziaWG tunnel disguises, in words: which settings are on, not their values.
enum AmneziaSummary {
    static func text(_ a: AmneziaParameters) -> String {
        var parts: [String] = []
        if let jc = a.junkCount, jc > 0 { parts.append("\(jc) junk packet\(jc == 1 ? "" : "s")") }
        if a.paddings.contains(where: { ($0 ?? 0) > 0 }) { parts.append("padding") }
        if a.headers.contains(where: { $0 != nil }) { parts.append("custom headers") }
        let signatures = a.signaturePackets.compactMap { $0 }.count
        if signatures > 0 { parts.append("\(signatures) signature packet\(signatures == 1 ? "" : "s")") }
        return parts.joined(separator: ", ")
    }
}
