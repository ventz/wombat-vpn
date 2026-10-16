import AVFoundation
import AppKit
import SwiftUI
import TunnelCore
import UniformTypeIdentifiers
import Vision

/// Reads WireGuard configurations from QR codes: in an image (a file, a drop, the clipboard) or from
/// a camera. A decoded configuration goes through the same import review as a .conf file, so its
/// leak checks, PostUp warnings and AmneziaWG validation all apply; nothing is saved here.
enum QRReader {
    /// Far above any QR screenshot or photo; keeps a hostile file from being read whole.
    static let maxImageBytes = 25 * 1024 * 1024
    /// Pixel limits checked from the header before decoding: a small file can claim a huge
    /// image (40k × 40k is 6.4 GB decoded; security-5 M1). A 5K screenshot is 5120 × 2880.
    static let maxSide = 8192
    static let maxPixels = 40_000_000
    /// Decoded no larger than this on the long side, which still reads a QR in a screenshot.
    static let decodeSide = 4096
    /// Only the formats a QR picture comes in. ImageIO reads many more (RAW, EXR, PSD...), each
    /// more parser exposed to a file another app can hand us (security-5 N1).
    static let allowedTypes: Set<String> = [UTType.png, .jpeg, .heic, .heif, .tiff].map(\.identifier).reduce(into: []) { $0.insert($1) }

    static func isImage(_ url: URL) -> Bool {
        UTType(filenameExtension: url.pathExtension)?.conforms(to: .image) == true
    }

    /// Every QR payload Vision finds in the image.
    static func payloads(in image: CGImage) -> [String] {
        let request = VNDetectBarcodesRequest()
        request.symbologies = [.qr]
        try? VNImageRequestHandler(cgImage: image).perform([request])
        return (request.results ?? []).compactMap(\.payloadStringValue)
    }

    static func payloads(in pixelBuffer: CVPixelBuffer) -> [String] {
        let request = VNDetectBarcodesRequest()
        request.symbologies = [.qr]
        try? VNImageRequestHandler(cvPixelBuffer: pixelBuffer).perform([request])
        return (request.results ?? []).compactMap(\.payloadStringValue)
    }

    /// Payloads that look like a wg-quick configuration. A QR code can carry anything (a URL,
    /// Wi-Fi details), and only configurations go on to the import review.
    static func configurations(in payloads: [String]) -> [String] {
        var seen = Set<String>()
        return payloads.filter {
            $0.utf8.count <= WgQuick.maxBytes
                && $0.range(of: "[Interface]", options: .caseInsensitive) != nil
                && seen.insert($0).inserted
        }
    }

    /// Decodes the image and reads its QR codes off the main thread (a slow decode must not
    /// freeze the window and the CLI; pitfall 17), throwing a readable reason when there's no
    /// configuration.
    static func configurations(inImageData data: Data, source: String) async throws -> [String] {
        try await Task.detached(priority: .userInitiated) {
            try configurations(in: try cgImage(from: data, source: source), source: source)
        }.value
    }

    /// The configurations in an image's QR codes; throws a readable reason when there are none.
    static func configurations(in image: CGImage, source: String) throws -> [String] {
        let found = payloads(in: image)
        guard !found.isEmpty else { throw StoreError.invalid("No QR code found in \(source).") }
        let configs = configurations(in: found)
        guard !configs.isEmpty else { throw StoreError.invalid("The QR code in \(source) isn't a WireGuard configuration.") }
        return configs
    }

    /// Checks the format and the size the header claims, then decodes at most `decodeSide`
    /// pixels on the long side.
    static func cgImage(from data: Data, source: String) throws -> CGImage {
        let unreadable = StoreError.invalid("\(source) is not a PNG, JPEG, HEIC or TIFF picture.")
        guard let image = CGImageSourceCreateWithData(data as CFData, [kCGImageSourceShouldCache: false] as CFDictionary),
              let type = CGImageSourceGetType(image) as String?, allowedTypes.contains(type) else { throw unreadable }
        guard let properties = CGImageSourceCopyPropertiesAtIndex(image, 0, nil) as? [CFString: Any],
              let width = properties[kCGImagePropertyPixelWidth] as? Int,
              let height = properties[kCGImagePropertyPixelHeight] as? Int,
              width > 0, height > 0 else { throw unreadable }
        guard width <= maxSide, height <= maxSide, width * height <= maxPixels else {
            throw StoreError.invalid("\(source) is too large (\(width) × \(height) pixels). Crop it to the QR code.")
        }
        let options: [CFString: Any] = [
            kCGImageSourceCreateThumbnailFromImageAlways: true,
            kCGImageSourceThumbnailMaxPixelSize: decodeSide,
            kCGImageSourceCreateThumbnailWithTransform: true,
            kCGImageSourceShouldCacheImmediately: true,
        ]
        guard let decoded = CGImageSourceCreateThumbnailAtIndex(image, 0, options as CFDictionary) else { throw unreadable }
        return decoded
    }

    /// The image data on the clipboard, if any (a screenshot copied with ⌃⇧⌘4, an image copied
    /// from a browser or Preview). PNG or TIFF data only, and size-capped: not NSImage(pasteboard:),
    /// which also takes PDFs and file links, unbounded (security-5 L3).
    static func clipboardImageData() -> Data? {
        let board = NSPasteboard.general
        for type in [NSPasteboard.PasteboardType.png, .tiff] {
            if let data = board.data(forType: type) { return data.count <= maxImageBytes ? data : nil }
        }
        return nil
    }
}

// MARK: Camera

/// The capture session and frame reading, off the main thread. Frames are only handed to Vision
/// to look for a QR code; none is stored or leaves the process.
final class QRCamera: NSObject, AVCaptureVideoDataOutputSampleBufferDelegate, @unchecked Sendable {
    let session = AVCaptureSession()
    private let queue = DispatchQueue(label: "net.vpetkov.wombat.qr-camera")
    private let output = AVCaptureVideoDataOutput()
    private var lastScan = Date.distantPast
    /// Set by `finish()` and `stop()`; never cleared, so no frame is read after either.
    private var done = false
    /// Set by `stop()`; a start queued before it, or after it (the permission prompt answered
    /// once the sheet had closed), never turns the camera on (security-5 L1).
    private var stopped = false
    /// Called on the capture queue with the QR payloads of a frame (at most ~5 frames a second).
    var onPayloads: (([String]) -> Void)?

    static func devices() -> [AVCaptureDevice] {
        AVCaptureDevice.DiscoverySession(deviceTypes: [.builtInWideAngleCamera, .continuityCamera, .external],
                                         mediaType: .video, position: .unspecified).devices
    }

    func start(_ device: AVCaptureDevice, completion: @escaping (Error?) -> Void) {
        queue.async { [self] in
            guard !stopped else { return }
            do {
                session.beginConfiguration()
                session.sessionPreset = .high
                session.inputs.forEach { session.removeInput($0) }
                let input = try AVCaptureDeviceInput(device: device)
                guard session.canAddInput(input) else { throw StoreError.invalid("This camera can't be used.") }
                session.addInput(input)
                if session.outputs.isEmpty {
                    output.alwaysDiscardsLateVideoFrames = true
                    output.setSampleBufferDelegate(self, queue: queue)
                    guard session.canAddOutput(output) else { throw StoreError.invalid("This camera can't be used.") }
                    session.addOutput(output)
                }
                session.commitConfiguration()
                if !session.isRunning { session.startRunning() }
                completion(nil)
            } catch {
                session.commitConfiguration()
                completion(error)
            }
        }
    }

    /// Stops reading frames at once, then the camera (its light goes off).
    func stop() {
        queue.async { [self] in
            stopped = true
            done = true
            if session.isRunning { session.stopRunning() }
        }
    }

    deinit {
        if session.isRunning { session.stopRunning() }
    }

    func captureOutput(_ output: AVCaptureOutput, didOutput sampleBuffer: CMSampleBuffer, from connection: AVCaptureConnection) {
        guard !done, Date().timeIntervalSince(lastScan) > 0.2,
              let buffer = CMSampleBufferGetImageBuffer(sampleBuffer) else { return }
        lastScan = Date()
        let found = QRReader.payloads(in: buffer)
        if !found.isEmpty { onPayloads?(found) }
    }

    /// After a configuration is found: no further frames are read.
    func finish() { queue.async { [self] in done = true } }
}

@MainActor
final class QRScanner: ObservableObject {
    enum State: Equatable { case starting, running, denied, noCamera, failed(String) }

    @Published var state: State = .starting
    @Published var devices: [AVCaptureDevice] = []
    @Published var deviceID = ""
    @Published var note: String?
    @Published var found: String?
    let camera = QRCamera()
    private var stopped = false

    var mirrored: Bool {
        devices.first { $0.uniqueID == deviceID }?.deviceType == .builtInWideAngleCamera
    }

    func start() async {
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized: break
        case .notDetermined:
            guard await AVCaptureDevice.requestAccess(for: .video) else { state = .denied; return }
            // The sheet may have closed while macOS asked.
            guard !stopped else { return }
        default:
            state = .denied; return
        }
        devices = QRCamera.devices()
        guard let device = AVCaptureDevice.default(for: .video).flatMap({ d in devices.first { $0.uniqueID == d.uniqueID } }) ?? devices.first else {
            state = .noCamera; return
        }
        camera.onPayloads = { [weak self] payloads in
            Task { @MainActor in self?.handle(payloads) }
        }
        use(device.uniqueID)
    }

    func use(_ id: String) {
        guard !stopped, let device = devices.first(where: { $0.uniqueID == id }) else { return }
        deviceID = id
        state = .starting
        camera.start(device) { [weak self] error in
            Task { @MainActor in
                self?.state = error.map { .failed($0.localizedDescription) } ?? .running
            }
        }
    }

    func stop() {
        stopped = true
        camera.stop()
    }

    private func handle(_ payloads: [String]) {
        guard found == nil else { return }
        let configs = QRReader.configurations(in: payloads)
        if configs.count > 1 {
            note = "Several WireGuard QR codes are in view. Show one at a time."
        } else if let config = configs.first {
            camera.finish()
            found = config
        } else {
            note = "That QR code isn't a WireGuard configuration."
        }
    }
}

/// "Scan QR Code…": a live camera view that closes on the first WireGuard configuration it reads
/// and hands it to the import review.
struct QRScannerSheet: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @StateObject private var scanner = QRScanner()

    var body: some View {
        VStack(spacing: 14) {
            Text("Scan a QR Code").font(.title2.weight(.semibold)).accessibilityAddTraits(.isHeader)
            Text("Hold the code up to the camera, such as the one your router's app shows for a new WireGuard client. Nothing is saved until you review the configuration.")
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
            ZStack {
                RoundedRectangle(cornerRadius: 10).fill(.black)
                switch scanner.state {
                case .starting:
                    ProgressView().controlSize(.large)
                case .running:
                    CameraPreview(session: scanner.camera.session, mirrored: scanner.mirrored)
                        .clipShape(RoundedRectangle(cornerRadius: 10))
                        .accessibilityLabel("Camera view")
                case .denied:
                    message("Wombat doesn't have access to the camera.") {
                        Button("Open Privacy Settings") {
                            NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_Camera")!)
                        }
                    }
                case .noCamera:
                    message("No camera found. Connect one, or use an iPhone as a Continuity Camera.") { EmptyView() }
                case .failed(let reason):
                    message(reason) { EmptyView() }
                }
            }
            .frame(width: 480, height: 360)

            if scanner.devices.count > 1 {
                Picker("Camera", selection: Binding(get: { scanner.deviceID }, set: { scanner.use($0) })) {
                    ForEach(scanner.devices, id: \.uniqueID) { Text($0.localizedName).tag($0.uniqueID) }
                }
                .frame(maxWidth: 360)
            }
            if let note = scanner.note {
                Label(note, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                    .accessibilityAddTraits(.updatesFrequently)
            }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
            }
        }
        .padding(24)
        .frame(width: 528)
        .task { await scanner.start() }
        .onDisappear { scanner.stop() }
        .onChange(of: scanner.found) { _, text in
            guard let text else { return }
            scanner.stop()
            // Staged by the sheet's onDismiss (ContentView), once this sheet has closed: one
            // sheet at a time, with no timer to race (security-5 L2).
            model.scannedConfig = text
            dismiss()
        }
    }

    private func message<Actions: View>(_ text: String, @ViewBuilder actions: () -> Actions) -> some View {
        VStack(spacing: 12) {
            Text(text).foregroundStyle(.white).multilineTextAlignment(.center)
            actions()
        }
        .padding(24)
    }
}

private struct CameraPreview: NSViewRepresentable {
    let session: AVCaptureSession
    let mirrored: Bool

    func makeNSView(context: Context) -> NSView {
        let view = NSView()
        let layer = AVCaptureVideoPreviewLayer(session: session)
        layer.videoGravity = .resizeAspectFill
        view.layer = layer
        view.wantsLayer = true
        apply(to: layer)
        return view
    }

    func updateNSView(_ view: NSView, context: Context) {
        if let layer = view.layer as? AVCaptureVideoPreviewLayer { apply(to: layer) }
    }

    /// A built-in camera faces you, so its picture is mirrored like a mirror; only the preview is,
    /// the frames Vision reads are not.
    private func apply(to layer: AVCaptureVideoPreviewLayer) {
        guard let connection = layer.connection, connection.isVideoMirroringSupported else { return }
        connection.automaticallyAdjustsVideoMirroring = false
        connection.isVideoMirrored = mirrored
    }
}
