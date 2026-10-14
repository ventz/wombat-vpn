import AppKit
import CoreImage
import SwiftUI
import TunnelCore
import UniformTypeIdentifiers

/// Exports that reveal keys (.conf files, a zip of all tunnels, a QR code) ask for Touch ID or
/// the login password every time, and written files are readable by you only (0600).
@MainActor
enum Exporter {
    enum Failure: LocalizedError {
        case canceled, missing(String)
        var errorDescription: String? {
            switch self {
            case .canceled: return "Authentication was canceled"
            case .missing(let name): return "The keychain item for “\(name)” is missing"
            }
        }
    }

    static func fullText(_ tunnel: Tunnel) throws -> String {
        guard let reference = tunnel.proto?.passwordReference, let text = try? ConfigKeychain.read(reference) else {
            throw Failure.missing(tunnel.name)
        }
        // Re-serialize: drops comments and ignored PostUp-style lines from what leaves the app.
        return WgQuick.parse(text).configuration.map { WgQuick.serialize($0) } ?? text
    }

    static func exportOne(_ tunnel: Tunnel) async throws {
        guard await Authenticator.confirm(reason: "export “\(tunnel.name)” with its private key") else { throw Failure.canceled }
        let text = try fullText(tunnel)
        let panel = NSSavePanel()
        panel.nameFieldStringValue = ZipWriter.fileName(tunnel.name)
        panel.allowedContentTypes = [UTType(filenameExtension: "conf") ?? .plainText]
        panel.message = "The file contains the tunnel's private key."
        guard panel.runModal() == .OK, let url = panel.url else { return }
        try write(Data(text.utf8), to: url)
    }

    /// All tunnels in one zip, in the layout the official app (and Wombat) imports.
    static func exportAll(_ tunnels: [Tunnel]) async throws {
        guard !tunnels.isEmpty else { return }
        guard await Authenticator.confirm(reason: "export all \(tunnels.count) tunnels with their private keys") else { throw Failure.canceled }
        let files = try tunnels.map { ZipWriter.File(name: $0.name, text: try fullText($0)) }
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "Wombat Tunnels.zip"
        panel.allowedContentTypes = [.zip]
        panel.message = "The archive contains every tunnel's private key."
        guard panel.runModal() == .OK, let url = panel.url else { return }
        try write(ZipWriter.archive(files), to: url)
    }

    /// The file is 0600 before a single byte is written, and inherited ACLs (a shared folder
    /// granting a group read) are stripped, so no other user can open it in between (audits
    /// WOM-04, S2-L5). The sandbox only grants the chosen file, so it's written in place.
    private static func write(_ data: Data, to url: URL) throws {
        let fd = open(url.path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw CocoaError(.fileWriteNoPermission, userInfo: [NSFilePathErrorKey: url.path]) }
        defer { close(fd) }
        guard fchmod(fd, 0o600) == 0 else { throw CocoaError(.fileWriteNoPermission) }
        if let empty = acl_init(0) {
            _ = acl_set_fd(fd, empty)
            acl_free(UnsafeMutableRawPointer(empty))
        }
        try data.withUnsafeBytes { raw in
            var offset = 0
            while offset < raw.count {
                let n = Darwin.write(fd, raw.baseAddress! + offset, raw.count - offset)
                guard n > 0 else { throw CocoaError(.fileWriteUnknown) }
                offset += n
            }
        }
        guard fsync(fd) == 0 else { throw CocoaError(.fileWriteUnknown) }
    }

    /// A QR code for the WireGuard apps on iOS and Android ("Create from QR code").
    static func qrImage(_ text: String) -> NSImage? {
        guard let filter = CIFilter(name: "CIQRCodeGenerator") else { return nil }
        filter.setValue(Data(text.utf8), forKey: "inputMessage")
        filter.setValue("M", forKey: "inputCorrectionLevel")
        guard let output = filter.outputImage?.transformed(by: CGAffineTransform(scaleX: 10, y: 10)) else { return nil }
        let rep = NSCIImageRep(ciImage: output)
        let image = NSImage(size: rep.size)
        image.addRepresentation(rep)
        return image
    }
}

/// Shows a tunnel as a QR code after authentication. The code carries the private key, so the
/// sheet says so, and the image is dropped when the sheet closes.
struct QRCodeSheet: View {
    let tunnel: Tunnel
    @Environment(\.dismiss) private var dismiss
    @State private var image: NSImage?
    @State private var error: String?

    var body: some View {
        VStack(spacing: 16) {
            Text("“\(tunnel.name)” as a QR code").font(.title2.weight(.semibold)).accessibilityAddTraits(.isHeader)
            if let image {
                Image(nsImage: image)
                    .interpolation(.none)
                    .resizable()
                    .frame(width: 320, height: 320)
                    .accessibilityLabel("QR code containing the tunnel configuration")
                Label("Anyone who sees this code can use your tunnel. Scan it with the WireGuard app on your phone, then close this window.",
                      systemImage: "exclamationmark.triangle.fill")
                    .font(.callout)
                    .frame(maxWidth: 360)
            } else if let error {
                Text(error)
            } else {
                ProgressView().accessibilityLabel("Waiting for authentication")
            }
            Button("Done") { dismiss() }
                .keyboardShortcut(.defaultAction)
        }
        .padding(24)
        .task {
            guard await Authenticator.confirm(reason: "show the private key of “\(tunnel.name)” as a QR code") else {
                error = "Authentication was canceled"
                return
            }
            do {
                image = Exporter.qrImage(try Exporter.fullText(tunnel))
                // A QR code holds about 2.3 KB at this error-correction level (Q2-M8).
                if image == nil { error = "This configuration is too large for a QR code. Export it as a .conf file instead." }
            } catch { self.error = error.localizedDescription }
        }
        .onExitCommand { dismiss() }  // Escape closes it too
        .onDisappear { image = nil }
    }
}
