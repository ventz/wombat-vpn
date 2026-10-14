import AppKit
import Darwin
import Foundation
import TunnelCore

// wombat: command-line control for Wombat. Tunnel commands go to the running app over its
// control socket (the app owns the VPN configurations); key and lint commands run offline.

setvbuf(stdout, nil, _IOLBF, 0)

enum Exit: Int32 {
    case ok = 0, failure = 1, usage = 2, unreachable = 3
}

struct Usage: Error { let message: String }

let usage = """
wombat: control Wombat tunnels from the terminal

Tunnels (talk to the app; it starts in the background if needed):
  wombat status [name] [--json]        Show tunnels and their state (alias: list, ls)
  wombat up <name>                     Connect (alias: connect)
  wombat down [name]                   Disconnect one tunnel, or all (alias: disconnect)
  wombat toggle <name>                 Connect or disconnect
  wombat show [name] [--json]          Live peers, handshakes and transfer, like `wg show`
  wombat import <file|-> [--name N]    Add a tunnel (asks for approval in the app)
  wombat export <name> [--with-keys]   Print the config; keys need Touch ID or your password
  wombat rename <name> <new-name>
  wombat delete <name>                 Asks for approval in the app
  wombat ondemand <name> on|off [--no-wifi] [--no-ethernet]
  wombat ondemand <name> trust|untrust <wifi-name>
  wombat killswitch <name> on|off [--allow-lan]
  wombat log <name>                    Recent log lines from the running tunnel

Diagnostics:
  wombat logs [-f] [--last 1h]         Unified log for the app and extension (log stream/show)
  wombat routes                        Routes through tunnel interfaces (utun*)
  wombat dns                           Which resolvers macOS uses now, and whether they're tunneled
  wombat doctor                        Check the install, extension, app and socket

Offline tools (no app needed):
  wombat check <file>... [--strict] [--json]   Lint wg-quick files; exit 1 on errors
  wombat genkey | wombat pubkey | wombat genpsk Key tools, compatible with `wg`
  wombat completion zsh|bash                   Shell completion script
  wombat install-skill [--dir DIR]             Teach coding agents (Claude Code) to use wombat

App:
  wombat start | stop                  Launch or quit the app (tunnels keep running when it quits)
  wombat version

Exit codes: 0 ok, 1 failed, 2 usage error, 3 cannot reach the app.
"""

// MARK: Arguments

struct Args {
    var positional: [String] = []
    var flags: Set<String> = []
    var options: [String: String] = [:]

    init(_ raw: [String], valueOptions: Set<String> = ["--name", "--last", "--dir"]) throws {
        var i = 0
        while i < raw.count {
            let a = raw[i]
            if valueOptions.contains(a) {
                guard i + 1 < raw.count else { throw Usage(message: "\(a) needs a value") }
                options[a] = raw[i + 1]
                i += 2
                continue
            }
            if a.hasPrefix("-"), a != "-" { flags.insert(a) } else { positional.append(a) }
            i += 1
        }
    }

    var json: Bool { flags.contains("--json") }
    func has(_ f: String...) -> Bool { f.contains { flags.contains($0) } }
}

// MARK: Output

func printErr(_ s: String) { FileHandle.standardError.write(Data((s + "\n").utf8)) }

let useColor = isatty(STDOUT_FILENO) != 0 && ProcessInfo.processInfo.environment["NO_COLOR"] == nil
func paint(_ s: String, _ code: String) -> String { useColor ? "\u{1B}[\(code)m\(s)\u{1B}[0m" : s }
func bold(_ s: String) -> String { paint(s, "1") }
func dim(_ s: String) -> String { paint(s, "2") }

func statusMark(_ status: String) -> String {
    switch status {
    case "connected": return paint("●", "32")
    case "connecting", "reasserting", "disconnecting": return paint("◐", "33")
    case "invalid": return paint("✕", "31")
    default: return dim("○")
    }
}

func printJSON<T: Encodable>(_ value: T) {
    let encoder = JSONEncoder()
    encoder.dateEncodingStrategy = .iso8601
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
    if let data = try? encoder.encode(value) { print(String(decoding: data, as: UTF8.self)) }
}

/// Strips control and bidi characters from names before printing: a tunnel name came from a
/// file somebody else may have written, and must not move the cursor or recolor the terminal.
func safe(_ s: String) -> String { TunnelName.sanitize(s) }

// MARK: Talking to the app

enum Client {
    static var socketPath: String {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        return "\(home)/Library/Group Containers/\(AppIdentity.appGroup)/\(Control.socketName)"
    }

    /// Retries only when the app couldn't be reached at all. Once a request was sent it is never
    /// sent again: it may already be waiting for the user's approval or have run (Q2-H2).
    static func send(_ request: Control.Request, timeout: Int = 15, launch: Bool = true) throws -> Control.Response {
        do { return try once(request, timeout: timeout) } catch is NotListening {}
        guard launch else { throw Unreachable() }
        try startApp()
        for _ in 0..<50 {
            usleep(200_000)
            do { return try once(request, timeout: timeout) } catch is NotListening { continue }
        }
        throw Unreachable()
    }

    /// Nothing accepted the connection (the app isn't running yet).
    struct NotListening: Error {}
    /// The socket's owner is not the Wombat app; nothing was sent.
    struct NotWombat: Error, CustomStringConvertible {
        let reason: String
        var description: String { "The control socket is not served by Wombat (\(reason)); nothing was sent" }
    }

    struct Unreachable: Error {}
    /// Sent, but no answer in time (an approval left open, or a stuck app). Not retried.
    struct NoReply: Error, CustomStringConvertible {
        var description: String { "Wombat did not answer in time (an approval may still be open in the app); the request was not sent again" }
    }

    static func startApp() throws {
        guard NSWorkspace.shared.urlForApplication(withBundleIdentifier: AppIdentity.appBundleID) != nil else {
            printErr("Wombat.app is not installed (bundle \(AppIdentity.appBundleID)).")
            throw Unreachable()
        }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/open")
        p.arguments = ["-g", "-b", AppIdentity.appBundleID]
        try p.run()
        p.waitUntilExit()
    }

    private static func once(_ request: Control.Request, timeout: Int) throws -> Control.Response {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw Unreachable() }
        defer { close(fd) }
        var tv = timeval(tv_sec: timeout, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        var on: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, socklen_t(MemoryLayout<Int32>.size))
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let path = socketPath
        guard path.utf8.count < MemoryLayout.size(ofValue: address.sun_path) else { throw Unreachable() }
        withUnsafeMutableBytes(of: &address.sun_path) { buffer in
            _ = path.withCString { strlcpy(buffer.baseAddress!.assumingMemoryBound(to: CChar.self), $0, buffer.count) }
        }
        let connected = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        guard connected == 0 else { throw NotListening() }
        // Whoever owns the socket would receive the request, which can carry a private key.
        if let reason = PeerCheck.rejectReason(fd, requirement: CodeSigning.app, expected: "the Wombat app") {
            throw NotWombat(reason: reason)
        }
        var data = try Control.encode(request)
        data.append(0x0A)
        try data.withUnsafeBytes { raw in
            var offset = 0
            while offset < raw.count {
                let n = write(fd, raw.baseAddress! + offset, raw.count - offset)
                guard n > 0 else { throw Unreachable() }
                offset += n
            }
        }
        var reply = Data()
        var buffer = [UInt8](repeating: 0, count: 16 * 1024)
        while reply.count <= Control.maxMessageBytes * 2 {
            let n = read(fd, &buffer, buffer.count)
            if n <= 0 { break }
            reply.append(buffer, count: n)
            if reply.last == 0x0A { break }
        }
        guard !reply.isEmpty else { throw NoReply() }
        return try Control.decode(Control.Response.self, from: reply)
    }
}

/// Sends a request and turns a failed response into an error message + exit code.
/// The default covers the app's 120 s approval window: down, up, ondemand, killswitch, rename,
/// import and delete can all wait for the user. Read-only requests answer at once anyway.
func call(_ request: Control.Request, timeout: Int = 135) throws -> Control.Response {
    let response = try Client.send(request, timeout: timeout)
    guard response.ok else {
        printErr("wombat: \(response.error.map(safe) ?? "request failed")")
        exit(Exit.failure.rawValue)
    }
    return response
}

func requireName(_ args: Args, _ index: Int = 0, _ what: String = "tunnel name") throws -> String {
    guard args.positional.count > index else { throw Usage(message: "missing \(what)") }
    return args.positional[index]
}

// MARK: Commands

func printTunnels(_ tunnels: [Control.TunnelSummary]) {
    if tunnels.isEmpty { print("No tunnels. Import one with: wombat import wg0.conf"); return }
    let width = min(32, tunnels.map { safe($0.name).count }.max() ?? 8)
    for t in tunnels {
        var line = "\(statusMark(t.status)) \(bold(safe(t.name).padding(toLength: width, withPad: " ", startingAt: 0)))  \(t.status)"
        if let since = t.connectedSince { line += dim("  since \(since.formatted(date: .omitted, time: .shortened))") }
        if t.onDemand { line += dim("  on-demand") }
        if t.protection?.killSwitch == true { line += dim("  kill-switch") }
        if let e = t.endpoint { line += dim("  \(e)") }
        print(line)
    }
}

func cmdStatus(_ args: Args) throws {
    let r = try call(Control.Request(.status, name: args.positional.first))
    if args.json { printJSON(r.tunnels ?? []) } else { printTunnels(r.tunnels ?? []) }
}

func cmdUpDown(_ args: Args, up: Bool) throws {
    let name = up ? try requireName(args) : args.positional.first
    let r = try call(Control.Request(up ? .up : .down, name: name))
    if args.json { printJSON(r.tunnels ?? []) } else { printTunnels(r.tunnels ?? []) }
}

func cmdToggle(_ args: Args) throws {
    let name = try requireName(args)
    let status = try call(Control.Request(.status, name: name)).tunnels?.first?.status ?? "disconnected"
    try cmdUpDown(args, up: !["connected", "connecting", "reasserting"].contains(status))
}

func cmdShow(_ args: Args) throws {
    var names = args.positional
    if names.isEmpty {
        names = (try call(Control.Request(.status)).tunnels ?? []).filter { $0.status == "connected" }.map(\.name)
        if names.isEmpty { print("No connected tunnels."); return }
    }
    var all: [String: RuntimeStats] = [:]
    for name in names {
        let r = try call(Control.Request(.stats, name: name))
        guard let stats = r.stats else { continue }
        if args.json { all[name] = stats; continue }
        print("\(paint("tunnel", "32;1")): \(bold(safe(name)))")
        if let port = stats.listenPort { print("  \(bold("listening port")): \(port)") }
        for p in stats.peers {
            print("")
            print("\(paint("peer", "33;1")): \(paint(p.publicKey, "33"))")
            if let e = p.endpoint { print("  \(bold("endpoint")): \(e)") }
            print("  \(bold("allowed ips")): \(p.allowedIPs.isEmpty ? "(none)" : p.allowedIPs.joined(separator: ", "))")
            print("  \(bold("latest handshake")): \(Format.handshakeAge(p.lastHandshake))")
            print("  \(bold("transfer")): \(Format.bytes(p.rxBytes)) received, \(Format.bytes(p.txBytes)) sent")
            if let k = p.persistentKeepalive { print("  \(bold("persistent keepalive")): every \(k) seconds") }
        }
        print("")
    }
    if args.json { printJSON(all) }
}

/// Reads at most maxBytes + 1, whatever the file claims its size is (it can grow between a
/// size check and the read), and only from regular files or stdin (audit WOM-11).
func readInput(_ path: String) throws -> String {
    let limit = WgQuick.maxBytes
    let handle: FileHandle
    if path == "-" {
        handle = .standardInput
    } else {
        let expanded = (path as NSString).expandingTildeInPath
        var info = stat()
        guard stat(expanded, &info) == 0 else { throw Usage(message: "\(path): no such file") }
        guard (info.st_mode & S_IFMT) == S_IFREG else { throw Usage(message: "\(path) is not a regular file") }
        guard let h = FileHandle(forReadingAtPath: expanded) else { throw Usage(message: "\(path): cannot open") }
        handle = h
    }
    defer { if path != "-" { try? handle.close() } }
    var data = Data()
    while data.count <= limit, let chunk = try handle.read(upToCount: 64 * 1024), !chunk.isEmpty {
        data.append(chunk)
    }
    guard data.count <= limit, let text = String(data: data, encoding: .utf8) else {
        throw Usage(message: "\(path) is not a UTF-8 text file under \(limit / 1024) KB")
    }
    return text
}

func cmdImport(_ args: Args) throws {
    let path = try requireName(args, 0, "file (or - for stdin)")
    let text = try readInput(path)
    let parsed = WgQuick.parse(text)
    guard parsed.configuration != nil else {
        for d in parsed.diagnostics { printErr("\(path): \(d)") }
        exit(Exit.failure.rawValue)
    }
    let name = args.options["--name"] ?? (path == "-" ? "Tunnel" : TunnelName.from(fileName: (path as NSString).lastPathComponent))
    printErr("Waiting for approval in Wombat…")
    let r = try call(Control.Request(.import, name: name, config: text), timeout: 300)
    if args.json { printJSON(r) ; return }
    printTunnels(r.tunnels ?? [])
    for f in r.findings ?? [] where f.level != .info { printErr("\(f.level.rawValue): \(f.message)") }
}

func cmdExport(_ args: Args) throws {
    let name = try requireName(args)
    let withKeys = args.has("--with-keys")
    if withKeys { printErr("Confirm with Touch ID or your password in Wombat…") }
    var request = Control.Request(.export, name: name)
    request.includeSecrets = withKeys
    let r = try call(request, timeout: withKeys ? 120 : 15)
    print(r.config ?? "", terminator: "")
}

func cmdRename(_ args: Args) throws {
    var request = Control.Request(.rename, name: try requireName(args))
    request.newName = try requireName(args, 1, "new name")
    printTunnels(try call(request).tunnels ?? [])
}

func cmdDelete(_ args: Args) throws {
    let name = try requireName(args)
    printErr("Waiting for approval in Wombat…")
    _ = try call(Control.Request(.delete, name: name), timeout: 300)
    print("Deleted \(safe(name)).")
}

func cmdOnDemand(_ args: Args) throws {
    let name = try requireName(args)
    let action = try requireName(args, 1, "on, off, trust or untrust")
    let current = try call(Control.Request(.status, name: name)).tunnels?.first
    var rules = current?.onDemandRules ?? Control.OnDemand(enabled: false)
    switch action {
    case "on":
        rules.enabled = true
        if args.has("--no-wifi") { rules.onWiFi = false }
        if args.has("--no-ethernet") { rules.onEthernet = false }
        if args.has("--wifi") { rules.onWiFi = true }
        if args.has("--ethernet") { rules.onEthernet = true }
    case "off":
        rules.enabled = false
    case "trust":
        let ssid = try requireName(args, 2, "Wi-Fi name")
        if !rules.trustedSSIDs.contains(ssid) { rules.trustedSSIDs.append(ssid) }
    case "untrust":
        let ssid = try requireName(args, 2, "Wi-Fi name")
        rules.trustedSSIDs.removeAll { $0 == ssid }
    default:
        throw Usage(message: "ondemand: expected on, off, trust or untrust")
    }
    var request = Control.Request(.onDemand, name: name)
    request.onDemand = rules
    let r = try call(request)
    if args.json { printJSON(r.tunnels ?? []); return }
    let t = r.tunnels?.first?.onDemandRules ?? rules
    print("on-demand: \(t.enabled ? "on" : "off")  wifi: \(t.onWiFi ? "yes" : "no")  ethernet: \(t.onEthernet ? "yes" : "no")")
    if !t.trustedSSIDs.isEmpty { print("trusted wi-fi: \(t.trustedSSIDs.map(safe).joined(separator: ", "))") }
}

func cmdKillSwitch(_ args: Args) throws {
    let name = try requireName(args)
    let state = try requireName(args, 1, "on or off")
    guard state == "on" || state == "off" else { throw Usage(message: "killswitch: expected on or off") }
    var request = Control.Request(.protection, name: name)
    // Same default as the app for full tunnels: the local network stays blocked unless asked
    // for (TunnelVision / LocalNet; audit Q2-M3). --block-lan is still accepted.
    request.protection = Control.Protection(killSwitch: state == "on", allowLAN: state == "on" && args.has("--allow-lan"))
    let r = try call(request)
    let p = r.tunnels?.first?.protection
    print("kill switch: \(p?.killSwitch == true ? "on" : "off")  local network: \(p?.allowLAN == false ? "blocked" : "allowed")")
}

func cmdLog(_ args: Args) throws {
    let r = try call(Control.Request(.log, name: try requireName(args)))
    for line in r.log ?? [] { print(line) }
}

// MARK: Offline

func cmdCheck(_ args: Args) throws {
    guard !args.positional.isEmpty else { throw Usage(message: "check: give one or more files (or -)") }
    struct FileReport: Encodable {
        let file: String
        let valid: Bool
        let diagnostics: [String]
        let findings: [Finding]
    }
    var reports: [FileReport] = []
    var failed = false
    for path in args.positional {
        let text: String
        do { text = try readInput(path) } catch let e as Usage {
            reports.append(FileReport(file: path, valid: false, diagnostics: [e.message], findings: []))
            failed = true
            continue
        }
        let result = WgQuick.parse(text)
        let findings = result.configuration.map(ConfigReview.review) ?? []
        let valid = result.configuration != nil
        if !valid || (args.has("--strict") && findings.contains { $0.level == .risk }) { failed = true }
        reports.append(FileReport(file: path, valid: valid, diagnostics: result.diagnostics.map(\.description), findings: findings))
    }
    if args.json {
        printJSON(reports)
    } else {
        for r in reports {
            print("\(r.valid ? paint("✓", "32") : paint("✕", "31")) \(bold(r.file))")
            for d in r.diagnostics { print("  \(d.hasPrefix("error") ? paint(d, "31") : paint(d, "33"))") }
            for f in r.findings {
                let label = f.level == .risk ? paint("risk", "31") : f.level == .warning ? paint("warning", "33") : dim("info")
                print("  \(label): \(f.message)")
            }
        }
    }
    if failed { exit(Exit.failure.rawValue) }
}

func cmdPubkey() throws {
    let input = String(decoding: FileHandle.standardInput.readDataToEndOfFile(), as: UTF8.self)
        .trimmingCharacters(in: .whitespacesAndNewlines)
    guard let key = WireGuardKey(base64: input) else {
        printErr("wombat pubkey: expected a base64 private key on stdin")
        exit(Exit.failure.rawValue)
    }
    print(KeyPair.publicKey(for: key).base64)
}

// MARK: Diagnostics

@discardableResult
func run(_ path: String, _ arguments: [String], capture: Bool = true) -> (status: Int32, output: String) {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: path)
    p.arguments = arguments
    let pipe = Pipe()
    if capture { p.standardOutput = pipe; p.standardError = pipe }
    do { try p.run() } catch { return (127, "") }
    let data = capture ? pipe.fileHandleForReading.readDataToEndOfFile() : Data()
    p.waitUntilExit()
    return (p.terminationStatus, String(decoding: data, as: UTF8.self))
}

func cmdLogs(_ args: Args) -> Never {
    let predicate = "subsystem == \"\(AppIdentity.logSubsystem)\""
    var arguments: [String]
    if args.has("-f", "--follow") {
        arguments = ["stream", "--level", "debug", "--style", "compact", "--predicate", predicate]
    } else {
        arguments = ["show", "--last", args.options["--last"] ?? "1h", "--debug", "--style", "compact", "--predicate", predicate]
    }
    let p = Process()
    p.executableURL = URL(fileURLWithPath: "/usr/bin/log")
    p.arguments = arguments
    do { try p.run() } catch { printErr("wombat: cannot run /usr/bin/log"); exit(Exit.failure.rawValue) }
    signal(SIGINT, SIG_IGN)  // let `log` handle Ctrl-C and exit cleanly
    p.waitUntilExit()
    exit(p.terminationStatus)
}

func cmdRoutes() {
    let out = run("/usr/sbin/netstat", ["-rn"]).output
    let lines = out.split(separator: "\n")
    var printed = false
    for line in lines {
        let s = String(line)
        if s.hasPrefix("Internet") || s.hasPrefix("Destination") { print(bold(s)); continue }
        if s.split(separator: " ", omittingEmptySubsequences: true).last?.hasPrefix("utun") == true {
            print(s)
            printed = true
        }
    }
    if !printed { print(dim("No routes through utun interfaces. Is a tunnel connected?")) }
}

/// Reads `scutil --dns` and reports which resolvers are bound to tunnel interfaces. With a full
/// tunnel, the first resolver should be the tunnel's; a non-tunnel default resolver is a leak.
func cmdDNS() {
    let out = run("/usr/sbin/scutil", ["--dns"]).output
    let sections = out.components(separatedBy: "\nresolver #").dropFirst()
    var defaultResolver: (servers: [String], interface: String?)?
    print(bold("Resolvers (scutil --dns, first section):"))
    for section in sections {
        if section.contains("DNS configuration (for scoped queries)") { break }
        let lines = section.split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces) }
        let servers = lines.filter { $0.hasPrefix("nameserver[") }.compactMap { $0.split(separator: ":", maxSplits: 1).last.map { $0.trimmingCharacters(in: .whitespaces) } }
        let domain = lines.first { $0.hasPrefix("domain ") }?.split(separator: ":", maxSplits: 1).last.map { $0.trimmingCharacters(in: .whitespaces) }
        let interface = lines.first { $0.hasPrefix("if_index") }.flatMap { $0.split(separator: "(").last?.dropLast().description }
        guard !servers.isEmpty else { continue }
        let tunneled = interface?.hasPrefix("utun") == true
        print("  \(tunneled ? paint("tunnel", "32") : dim("local "))  \(servers.joined(separator: ", "))\(domain.map { "  for \($0)" } ?? "  (default)")\(interface.map { "  via \($0)" } ?? "")")
        if domain == nil, defaultResolver == nil { defaultResolver = (servers, interface) }
    }
    let netstat = run("/usr/sbin/netstat", ["-rn", "-f", "inet"]).output
    let defaultViaTunnel = netstat.split(separator: "\n").contains { $0.hasPrefix("default") && $0.contains("utun") }
        || netstat.split(separator: "\n").contains { ($0.hasPrefix("0/1") || $0.hasPrefix("128.0/1")) && $0.contains("utun") }
    print("")
    if defaultViaTunnel {
        print("Default route goes through a tunnel. DNS queries to the servers above leave through it too, unless a resolver is scoped to another interface.")
    } else {
        print("Default route does not go through a tunnel (split tunnel or disconnected): only queries for tunnel-scoped domains use the tunnel.")
    }
}

func cmdDoctor() {
    func line(_ ok: Bool?, _ title: String, _ detail: String = "") {
        let mark = ok == nil ? paint("–", "33") : ok! ? paint("✓", "32") : paint("✕", "31")
        print("\(mark) \(title)\(detail.isEmpty ? "" : dim("  \(detail)"))")
    }
    let appURL = NSWorkspace.shared.urlForApplication(withBundleIdentifier: AppIdentity.appBundleID)
    line(appURL != nil, "App installed", appURL?.path ?? "bundle \(AppIdentity.appBundleID) not found")
    if let appURL { line(appURL.path.hasPrefix("/Applications/"), "App is in /Applications", "network extensions only activate from there") }
    let running = !NSRunningApplication.runningApplications(withBundleIdentifier: AppIdentity.appBundleID).isEmpty
    line(running, "App running", running ? "" : "wombat start")
    let ext = run("/usr/bin/systemextensionsctl", ["list"]).output
    // After an update the old build stays listed ("terminated waiting to uninstall on reboot")
    // next to the new one, so prefer the active line.
    let extLines = ext.split(separator: "\n").filter { $0.contains(AppIdentity.extensionBundleID) }
    let extLine = (extLines.first { $0.contains("activated enabled") } ?? extLines.first).map(String.init)
    line(extLine?.contains("activated enabled"), "Network extension", extLine?.trimmingCharacters(in: .whitespaces) ?? "not installed; open the app")
    line(FileManager.default.fileExists(atPath: Client.socketPath), "Control socket", Client.socketPath)
    // macOS's VPN daemon can run out of file descriptors after weeks of uptime; it then fails
    // extension validation with a misleading "NetworkExtension key must be a non-empty
    // dictionary" and breaks other VPNs' on-demand too. Only restarting it helps.
    let recent = run("/usr/bin/log", ["show", "--last", "10m", "--style", "compact", "--predicate",
                                      "process == \"nesessionmanager\" AND eventMessage CONTAINS \"Too many open files\""]).output
    let exhausted = recent.split(separator: "\n").filter { $0.contains("Too many open files") }.count
    line(exhausted == 0, "macOS VPN daemon (nesessionmanager)",
         exhausted == 0 ? "healthy" : "out of file descriptors (\(exhausted) errors in 10 min): run `sudo killall nesessionmanager` (VPNs reconnect) or restart the Mac")
    if let r = try? Client.send(Control.Request(.version), launch: false) {
        let mine = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "?"
        line(r.version == mine, "App answers", "app \(r.version ?? "?"), cli \(mine)")
    } else {
        line(false, "App answers", "no reply on the socket")
    }
}

func cmdCompletion(_ args: Args) throws {
    let commands = "status list up down toggle show import export rename delete ondemand killswitch log logs routes dns doctor check genkey pubkey genpsk completion install-skill start stop version help"
    switch args.positional.first {
    case "zsh":
        print("""
        #compdef wombat
        _wombat() {
          local -a cmds; cmds=(\(commands))
          if (( CURRENT == 2 )); then _describe 'command' cmds; return; fi
          case $words[2] in
            up|down|toggle|show|export|rename|delete|ondemand|killswitch|log|status)
              local -a names; names=(${(f)"$(wombat _names 2>/dev/null)"}); names=(${names//:/\\:})
              (( CURRENT == 3 )) && _describe 'tunnel' names ;;
            check|import) _files ;;
          esac
        }
        compdef _wombat wombat
        """)
    case "bash":
        print("""
        _wombat() {
          local cur=${COMP_WORDS[COMP_CWORD]}
          if [ $COMP_CWORD -eq 1 ]; then COMPREPLY=($(compgen -W "\(commands)" -- "$cur")); return; fi
          case ${COMP_WORDS[1]} in
            check|import) COMPREPLY=($(compgen -f -- "$cur")) ;;
            *) COMPREPLY=()
               # Names are compared and quoted, never passed to compgen -W, which would expand
               # $(...) inside a name taken from a downloaded file (audits S2-M2, F-2).
               local n; while IFS= read -r n; do
                 [[ $n == "$cur"* ]] && COMPREPLY+=("$(printf '%q' "$n")")
               done < <(wombat _names 2>/dev/null) ;;
          esac
        }
        complete -F _wombat wombat
        """)
    default:
        throw Usage(message: "completion: expected zsh or bash")
    }
}

func cmdInstallSkill(_ args: Args) throws {
    let dir = URL(fileURLWithPath: ((args.options["--dir"] ?? "~/.claude/skills/wombat") as NSString).expandingTildeInPath)
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    let skill = """
    ---
    name: wombat
    description: Control WireGuard tunnels on this Mac with the `wombat` CLI (Wombat app). Use when asked to connect/disconnect a VPN or WireGuard tunnel, check VPN status, inspect handshakes/transfer, lint a wg-quick .conf, generate WireGuard keys, or debug routing/DNS through a tunnel.
    ---

    # wombat CLI

    - `wombat status --json`: tunnels with status (connected, disconnected, …), on-demand, kill switch.
    - `wombat up <name>` / `wombat down [name]`: connect / disconnect (no name = all). Exit 0 on success.
    - `wombat show <name> --json`: peers, endpoints, latest handshake, rx/tx bytes.
    - `wombat check <file> [--strict] [--json]`: lint wg-quick files offline; exit 1 on errors (and on risks with --strict).
    - `wombat genkey | tee priv | wombat pubkey`: key pair; `wombat genpsk` for a preshared key.
    - `wombat logs --last 10m` (or `-f`): app and tunnel logs. `wombat routes`, `wombat dns`, `wombat doctor` for debugging.

    Rules:
    - Never ask for or print private keys. `wombat export <name>` prints a config with keys hidden; `--with-keys` requires the user's Touch ID, so only use it when the user asks.
    - `wombat import` and `wombat delete` wait for the user to approve in the app; tell the user to look for the dialog.
    - Exit codes: 0 ok, 1 failed, 2 usage error, 3 the app is unreachable (`wombat start`, then `wombat doctor`).
    """
    let file = dir.appendingPathComponent("SKILL.md")
    try skill.write(to: file, atomically: true, encoding: .utf8)
    print("Wrote \(file.path)")
}

func cmdStop() {
    for app in NSRunningApplication.runningApplications(withBundleIdentifier: AppIdentity.appBundleID) { app.terminate() }
    print("Wombat quit. Connected tunnels and on-demand rules keep running in the system.")
}

// MARK: Dispatch

var raw = Array(CommandLine.arguments.dropFirst())
let command = raw.isEmpty ? "status" : raw.removeFirst()
do {
    let args = try Args(raw)
    switch command {
    case "status", "list", "ls": try cmdStatus(args)
    case "up", "connect": try cmdUpDown(args, up: true)
    case "down", "disconnect": try cmdUpDown(args, up: false)
    case "toggle": try cmdToggle(args)
    case "show": try cmdShow(args)
    case "import": try cmdImport(args)
    case "export": try cmdExport(args)
    case "rename": try cmdRename(args)
    case "delete", "rm": try cmdDelete(args)
    case "ondemand": try cmdOnDemand(args)
    case "killswitch": try cmdKillSwitch(args)
    case "log": try cmdLog(args)
    case "logs": cmdLogs(args)
    case "routes": cmdRoutes()
    case "dns", "dnsleak": cmdDNS()
    case "doctor": cmdDoctor()
    case "check", "lint": try cmdCheck(args)
    case "genkey": print(KeyPair.generatePrivateKey().base64)
    case "genpsk": print(KeyPair.generatePresharedKey().base64)
    case "pubkey": try cmdPubkey()
    case "completion": try cmdCompletion(args)
    case "install-skill", "install-skills": try cmdInstallSkill(args)
    case "start": try Client.startApp(); print("Wombat started.")
    case "_names":
        // For shell completion: one sanitized name per line, and never launches the app (Q2-L1).
        if let r = try? Client.send(Control.Request(.list), timeout: 2, launch: false) {
            for t in r.tunnels ?? [] { print(safe(t.name)) }
        }
    case "stop", "quit": cmdStop()
    case "version", "--version", "-v":
        print("wombat \(Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "dev")")
    case "help", "--help", "-h": print(usage)
    default: throw Usage(message: "unknown command \"\(command)\"")
    }
} catch let error as Usage {
    printErr("wombat: \(error.message)\nRun `wombat help` for usage.")
    exit(Exit.usage.rawValue)
} catch is Client.Unreachable {
    printErr("wombat: cannot reach the Wombat app. Try `wombat start`, then `wombat doctor`.")
    exit(Exit.unreachable.rawValue)
} catch let error as CustomStringConvertible & Error {
    printErr("wombat: \(error.description)")
    exit(Exit.failure.rawValue)
} catch {
    printErr("wombat: \(error.localizedDescription)")
    exit(Exit.failure.rawValue)
}
