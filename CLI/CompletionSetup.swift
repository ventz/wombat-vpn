import Darwin
import Foundation
import TunnelCore

// `wombat completion install|uninstall|status`: puts the completion scripts that ship in the app
// where each shell looks for them, for this user only.
//
// Files are symlinks to the scripts inside Wombat.app, so they follow Sparkle updates (a copy
// would go stale after an update). Nothing that isn't Wombat's is replaced without --force, and
// what --force replaces is kept as a backup. Shell startup files are only edited when no folder
// the shell already reads will do, and only after the user saw the lines and said yes (or passed
// --yes). Those lines sit between markers, so uninstall removes exactly them. Startup files are
// read as text, never run: a .zshrc can do anything.

enum CompletionShell: String, CaseIterable {
    case zsh, bash, fish

    var scriptName: String {
        switch self {
        case .zsh: return "_wombat"
        case .bash: return "wombat"
        case .fish: return "wombat.fish"
        }
    }

    /// The file's name inside Wombat.app/Contents/Resources/completions.
    var bundledName: String {
        switch self {
        case .zsh: return "_wombat"
        case .bash: return "wombat.bash"
        case .fish: return "wombat.fish"
        }
    }
}

/// Where this binary's app keeps the scripts: Contents/Helpers/wombat → Contents/Resources/completions.
func bundledCompletionURL(_ name: String) -> URL {
    let executable = (Bundle.main.executableURL ?? URL(fileURLWithPath: CommandLine.arguments[0])).resolvingSymlinksInPath()
    return executable.deletingLastPathComponent()
        .appendingPathComponent("../Resources/completions/\(name)").standardizedFileURL
}

struct CompletionSetup {
    static let blockBegin = "# >>> wombat completion >>>"
    static let blockEnd = "# <<< wombat completion <<<"
    static let blockNote = "# Added by `wombat completion install`; `wombat completion uninstall` removes it."

    let env = ProcessInfo.processInfo.environment
    let home: String
    let dryRun: Bool
    let force: Bool
    let yes: Bool
    let dir: String?
    let stamp: String
    var failed = false

    init(_ args: Args) {
        // $HOME first: it's what the shells use (and what a test sandbox sets).
        if let h = ProcessInfo.processInfo.environment["HOME"], h.hasPrefix("/") { home = h }
        else { home = FileManager.default.homeDirectoryForCurrentUser.path }
        dryRun = args.has("--dry-run", "-n")
        force = args.has("--force")
        yes = args.has("--yes", "-y")
        dir = args.options["--dir"]
        let f = DateFormatter()
        f.dateFormat = "yyyyMMdd-HHmmss"
        f.locale = Locale(identifier: "en_US_POSIX")
        stamp = f.string(from: Date())
    }

    // MARK: Entry

    static func run(_ action: String, _ args: Args) throws -> Never {
        // Under sudo, $HOME is still the user's: the links and edits would belong to root.
        if action != "status", getuid() == 0 { throw Usage(message: "completion \(action) sets up your own shells: run it without sudo") }
        var setup = CompletionSetup(args)
        var shells: [CompletionShell] = []
        for name in args.positional.dropFirst() {
            guard let s = CompletionShell(rawValue: name) else { throw Usage(message: "completion \(action): unknown shell \"\(name)\" (zsh, bash or fish)") }
            if !shells.contains(s) { shells.append(s) }
        }
        if setup.dir != nil, shells.count != 1 || action != "install" {
            throw Usage(message: "--dir works with `completion install` and one shell, like: wombat completion install zsh --dir ~/.zfunc")
        }
        switch action {
        case "install": setup.install(shells.isEmpty ? setup.detectedShells() : shells, auto: shells.isEmpty)
        case "uninstall": setup.uninstall(shells.isEmpty ? CompletionShell.allCases : shells)
        default: setup.status(shells.isEmpty ? CompletionShell.allCases : shells)
        }
        exit(setup.failed ? Exit.failure.rawValue : Exit.ok.rawValue)
    }

    // MARK: Detection

    var loginShell: String { ((env["SHELL"] ?? "") as NSString).lastPathComponent }
    var zdotdir: String { env["ZDOTDIR"].flatMap { $0.hasPrefix("/") ? $0 : nil } ?? home }
    var zshrc: String { zdotdir + "/.zshrc" }
    var dataHome: String { env["XDG_DATA_HOME"].flatMap { $0.hasPrefix("/") ? $0 : nil } ?? home + "/.local/share" }
    var configHome: String { env["XDG_CONFIG_HOME"].flatMap { $0.hasPrefix("/") ? $0 : nil } ?? home + "/.config" }

    /// The login shell first, then every other shell that is installed and has a startup file.
    func detectedShells() -> [CompletionShell] {
        var found: [CompletionShell] = []
        if let s = CompletionShell(rawValue: loginShell) { found.append(s) }
        if !found.contains(.zsh), exists(zshrc) { found.append(.zsh) }
        if !found.contains(.bash), [".bash_profile", ".bashrc"].contains(where: { exists(home + "/" + $0) }) { found.append(.bash) }
        if !found.contains(.fish), fishBinary() != nil, exists(configHome + "/fish") { found.append(.fish) }
        return found
    }

    func fishBinary() -> String? {
        let dirs = (env["PATH"] ?? "").split(separator: ":").map(String.init) + brewPrefixes.map { $0 + "/bin" }
        return dirs.map { $0 + "/fish" }.first { FileManager.default.isExecutableFile(atPath: $0) }
    }

    var brewPrefixes: [String] {
        var p: [String] = []
        if let e = env["HOMEBREW_PREFIX"], e.hasPrefix("/") { p.append(e) }
        for d in ["/opt/homebrew", "/usr/local"] where !p.contains(d) && FileManager.default.isExecutableFile(atPath: d + "/bin/brew") { p.append(d) }
        return p
    }

    /// A Homebrew-made link to Wombat's script, if the cask installed one.
    func brewLink(_ shell: CompletionShell) -> String? {
        let rel: String
        switch shell {
        case .zsh: rel = "/share/zsh/site-functions/_wombat"
        case .bash: rel = "/etc/bash_completion.d/wombat"
        case .fish: rel = "/share/fish/vendor_completions.d/wombat.fish"
        }
        for p in brewPrefixes {
            let path = p + rel
            if case .link(_, true, false) = classify(path) { return path }
        }
        return nil
    }

    // MARK: Files

    enum Existing { case none, link(to: String, wombat: Bool, dangling: Bool), wombatCopy, foreign }

    func exists(_ path: String) -> Bool { var st = stat(); return lstat(path, &st) == 0 }

    func classify(_ path: String) -> Existing {
        var st = stat()
        guard lstat(path, &st) == 0 else { return .none }
        if (st.st_mode & S_IFMT) == S_IFLNK {
            let dest = (try? FileManager.default.destinationOfSymbolicLink(atPath: path)) ?? ""
            return .link(to: dest, wombat: dest.contains("/Contents/Resources/completions/"), dangling: !FileManager.default.fileExists(atPath: path))
        }
        guard (st.st_mode & S_IFMT) == S_IFREG, let h = FileHandle(forReadingAtPath: path) else { return .foreign }
        defer { try? h.close() }
        let head = String(decoding: (try? h.read(upToCount: 4096)) ?? Data(), as: UTF8.self)
        // Our scripts, or one saved by hand from an older `wombat completion` (1.2 and before).
        if head.contains("the command line of Wombat") || (head.contains("_wombat") && head.contains("wombat _names")) { return .wombatCopy }
        return .foreign
    }

    func shown(_ path: String) -> String { path == home ? "~" : path.hasPrefix(home + "/") ? "~" + path.dropFirst(home.count) : path }

    func lines(_ path: String) -> [String] {
        guard let text = try? String(contentsOfFile: path, encoding: .utf8) else { return [] }
        return text.components(separatedBy: "\n")
    }

    func isComment(_ line: String) -> Bool { line.trimmingCharacters(in: .whitespaces).hasPrefix("#") }

    /// Expands ~, $HOME and the given variables in a path taken from a startup file. Anything
    /// else ($(...), other variables) can't be known without running the file: nil.
    func expand(_ raw: String, _ vars: [String: String] = [:]) -> String? {
        var s = raw.trimmingCharacters(in: .whitespaces)
        if s.count >= 2, let f = s.first, f == "\"" || f == "'", s.last == f { s = String(s.dropFirst().dropLast()) }
        if s == "~" || s.hasPrefix("~/") { s = home + s.dropFirst() }
        var all = vars
        all["HOME"] = home
        for (k, v) in all {
            // $HOME must not eat the start of $HOMEBREW_PREFIX.
            let re = try! NSRegularExpression(pattern: "\\$(\\{\(k)\\}|\(k)(?![A-Za-z0-9_]))")
            s = re.stringByReplacingMatches(in: s, range: NSRange(location: 0, length: (s as NSString).length),
                                            withTemplate: NSRegularExpression.escapedTemplate(for: v))
        }
        guard !s.contains("$"), !s.contains("`"), s.hasPrefix("/") else { return nil }
        return (s as NSString).standardizingPath
    }

    /// The value of `NAME=...` (or `export NAME=...`) on the last plain assignment in the file.
    func assignment(_ name: String, in text: [String]) -> String? {
        var value: String?
        for line in text where !isComment(line) {
            var t = line.trimmingCharacters(in: .whitespaces)
            if t.hasPrefix("export ") { t = String(t.dropFirst(7)).trimmingCharacters(in: .whitespaces) }
            guard t.hasPrefix(name + "=") else { continue }
            var v = String(t.dropFirst(name.count + 1))
            // Drop a trailing comment or a following command (`ZSH=~/.oh-my-zsh; ...`).
            if let r = v.range(of: " #") { v = String(v[..<r.lowerBound]) }
            if let r = v.range(of: ";") { v = String(v[..<r.lowerBound]) }
            value = v.trimmingCharacters(in: .whitespaces)
        }
        return value
    }

    // MARK: Install

    struct Plan {
        var target: String?           // where the link goes
        var why: String               // one line: why there
        var rc: String?               // startup file to edit, if any
        var rcBody: [String] = []     // lines between the markers
        var rcAtTop = false
        var skip: String?             // nothing to do, and why
        var guidance: [String] = []   // what the user has to do instead
        var after: [String] = []      // what to do once it's in place
    }

    mutating func install(_ shells: [CompletionShell], auto: Bool) {
        if dryRun { print("Dry run: nothing is changed.\n") }
        if auto { print("Shells found: \(shells.map(\.rawValue).joined(separator: ", ")) (name one to set up only that shell)\n") }
        var after: [String] = []
        for shell in shells {
            let source = bundledCompletionURL(shell.bundledName).path
            guard FileManager.default.fileExists(atPath: source) else {
                printErr("wombat: no completion script at \(source); use the wombat inside Wombat.app")
                failed = true
                return
            }
            if source.hasPrefix("/Volumes/") || source.contains("/AppTranslocation/") {
                printErr("wombat: this wombat runs from \(source.hasPrefix("/Volumes/") ? "a disk image" : "a temporary copy macOS made"); move Wombat to /Applications and run its wombat")
                failed = true
                return
            }
            // A development build's bundle goes away on the next clean, and the link would
            // dangle wherever the completions folder is synced (a dotfiles repository, say).
            if BuildLocation.isDevelopmentBuild(source) {
                printErr("wombat: this wombat is a development build (\(source)); run the wombat inside the installed Wombat.app (/Applications)")
                failed = true
                return
            }
            let plan: Plan
            switch shell {
            case .zsh: plan = planZsh()
            case .bash: plan = planBash()
            case .fish: plan = planFish()
            }
            print(bold(shell.rawValue))
            if let skip = plan.skip { print("  \(skip)\n"); continue }
            guard let target = plan.target else {
                for g in plan.guidance { print("  \(g)") }
                print("")
                failed = true
                continue
            }
            print("  \(plan.why)")
            guard place(source, at: target) else { print(""); continue }
            if let rc = plan.rc, !editBlock(rc, body: plan.rcBody, atTop: plan.rcAtTop) {
                print("  Without that change \(shell.rawValue) won't find the file. Add the lines yourself, or rerun with --yes.")
            }
            for g in plan.guidance { print("  \(g)") }
            after += plan.after
            print("")
        }
        if !dryRun, !after.isEmpty { print(after.joined(separator: "\n")) }
    }

    func planZsh() -> Plan {
        let rc = lines(zshrc)
        if let dir { return Plan(target: expandArg(dir) + "/_wombat", why: "Into \(shown(expandArg(dir))) (--dir); it must be on $fpath before compinit runs.", after: ["zsh: open a new terminal, or run `exec zsh`."]) }
        if let link = brewLink(.zsh), brewZshWired(rc), !force {
            return Plan(why: "", skip: "Homebrew already installed it (\(shown(link))) and zsh reads that folder: nothing to do. --force adds a second copy.")
        }
        let code = rc.filter { !isComment($0) }
        func uses(_ needle: String) -> Bool { code.contains { $0.contains(needle) } }
        if uses("oh-my-zsh.sh") {
            let zshDir = [env["ZSH"], assignment("ZSH", in: rc).flatMap { expand($0) }, home + "/.oh-my-zsh"]
                .compactMap { $0 }.first { FileManager.default.fileExists(atPath: $0 + "/oh-my-zsh.sh") }
            guard let zshDir else {
                return Plan(why: "", guidance: ["Found oh-my-zsh in \(shown(zshrc)) but not its folder.", "Run: wombat completion install zsh --dir \"$ZSH_CUSTOM/completions\""])
            }
            var custom = zshDir + "/custom"
            if let e = env["ZSH_CUSTOM"], e.hasPrefix("/") { custom = e }
            else if let raw = assignment("ZSH_CUSTOM", in: rc) {
                guard let c = expand(raw, ["ZSH": zshDir]) else {
                    return Plan(why: "", guidance: ["\(shown(zshrc)) sets ZSH_CUSTOM to \(raw), which needs the shell to work out.",
                                                    "Run: wombat completion install zsh --dir \"$ZSH_CUSTOM/completions\""])
                }
                custom = c
            }
            // oh-my-zsh.sh puts $ZSH_CUSTOM/completions on $fpath before it runs compinit, and
            // custom/ is outside its git checkout (.gitignore), so `omz update` leaves it alone.
            return Plan(target: custom + "/completions/_wombat",
                        why: "oh-my-zsh: into \(shown(custom))/completions, which oh-my-zsh reads before compinit. \(shown(zshrc)) stays as it is.",
                        after: ["zsh: open a new terminal, or run `exec zsh`."])
        }
        let frameworks = [("zprezto", "prezto"), ("zinit", "zinit"), ("antidote", "antidote"), ("antigen", "antigen"),
                          ("zimfw", "Zim"), ("zim/init", "Zim"), ("zplug", "zplug"), ("znap", "znap"), ("zgenom", "zgenom")]
        if let name = frameworks.first(where: { uses($0.0) })?.1 {
            return Plan(why: "", guidance: [
                "\(shown(zshrc)) uses \(name), which runs compinit its own way, so Wombat doesn't guess where it reads completions.",
                "Pick a folder, add it to $fpath in \(shown(zshrc)) before \(name) loads, for example:",
                "  fpath=(~/.zsh/completions $fpath)",
                "then run: wombat completion install zsh --dir ~/.zsh/completions",
            ])
        }
        // Plain zsh: a usual per-user folder that the startup files already put on $fpath before
        // compinit, or ~/.zsh/completions plus a marked line at the top of .zshrc.
        let known = [home + "/.zsh/completions", home + "/.zsh/completion", home + "/.zsh/functions", home + "/.zfunc",
                     home + "/.zfunctions", dataHome + "/zsh/site-functions", configHome + "/zsh/completions"]
        let compinitLine = rc.firstIndex(where: callsCompinit)
        var early: [String] = []
        for file in [zdotdir + "/.zshenv", zdotdir + "/.zprofile"] { early += lines(file) }
        early += rc.prefix(compinitLine ?? rc.count)
        let onFpath = fpathEntries(early)
        let usesCacheOnly = rc.contains { !isComment($0) && $0.contains("compinit -C") }
        var after = ["zsh: open a new terminal, or run `exec zsh`."]
        if usesCacheOnly { after.append("     \(shown(zshrc)) runs `compinit -C`, which doesn't look for new files: run `rm -f \(shown(zdotdir))/.zcompdump*` once, then `exec zsh`.") }
        if let d = known.first(where: { onFpath.contains($0) }) {
            return Plan(target: d + "/_wombat", why: "Into \(shown(d)), which \(shown(zshrc)) already puts on $fpath.", after: after)
        }
        let d = home + "/.zsh/completions"
        if compinitLine != nil {
            return Plan(target: d + "/_wombat", why: "Into \(shown(d)), added to $fpath at the top of \(shown(zshrc)) (before compinit).",
                        rc: zshrc, rcBody: ["fpath=(\"$HOME/.zsh/completions\" $fpath)"], rcAtTop: true, after: after)
        }
        return Plan(target: d + "/_wombat", why: "Into \(shown(d)). \(shown(zshrc)) doesn't turn on zsh's completion system (compinit), so the lines below do both.",
                    rc: zshrc, rcBody: ["fpath=(\"$HOME/.zsh/completions\" $fpath)", "autoload -Uz compinit && compinit"], after: after)
    }

    /// Homebrew's zsh reads its site-functions on its own; macOS's zsh does once `brew shellenv`
    /// (it adds them), oh-my-zsh's brew plugin, or a line of the user's adds the folder.
    func brewZshWired(_ rc: [String]) -> Bool {
        if brewPrefixes.contains(where: { (env["SHELL"] ?? "").hasPrefix($0 + "/") }) { return true }
        let all = (lines(zdotdir + "/.zshenv") + lines(zdotdir + "/.zprofile") + rc).filter { !isComment($0) }
        if all.contains(where: { $0.contains("brew shellenv") || $0.contains("share/zsh/site-functions") }) { return true }
        return all.contains { l in
            let t = l.trimmingCharacters(in: .whitespaces)
            return t.hasPrefix("plugins=(") && t.dropFirst(9).split(whereSeparator: { $0 == " " || $0 == ")" }).contains("brew")
        }
    }

    /// A line that runs compinit (not just `autoload -Uz compinit`).
    func callsCompinit(_ line: String) -> Bool {
        guard !isComment(line) else { return false }
        let segments = line.replacingOccurrences(of: "&&", with: ";").replacingOccurrences(of: "||", with: ";").split(separator: ";")
        return segments.contains { seg in
            var words = seg.split(separator: " ").map(String.init)
            while let w = words.first, ["then", "else", "do", "{", "(", "if", "!"].contains(w) { words.removeFirst() }
            return words.first == "compinit"
        }
    }

    /// Folders that `fpath=(...)`, `fpath+=...` or `FPATH=...` lines add, as far as they can be read.
    func fpathEntries(_ text: [String]) -> Set<String> {
        var out = Set<String>()
        let pattern = try! NSRegularExpression(pattern: #"(~|\$\{?HOME\}?|\$\{?XDG_[A-Z_]+\}?|/)[^\s()"':;]*"#)
        for line in text where !isComment(line) && (line.contains("fpath") || line.contains("FPATH")) {
            let ns = line as NSString
            for m in pattern.matches(in: line, range: NSRange(location: 0, length: ns.length)) {
                let token = ns.substring(with: m.range)
                if let p = expand(token, ["XDG_DATA_HOME": dataHome, "XDG_CONFIG_HOME": configHome]) { out.insert(p) }
            }
        }
        return out
    }

    func planBash() -> Plan {
        if let dir { return Plan(target: expandArg(dir) + "/wombat", why: "Into \(shown(expandArg(dir))) (--dir); your bash setup must load it.") }
        let loaded = bashCompletionLoaded()
        if let link = brewLink(.bash), let loaded, brewPrefixes.contains(where: { loaded.hasPrefix($0 + "/") }), !force {
            return Plan(why: "", skip: "Homebrew already installed it (\(shown(link))) and your bash-completion loads it: nothing to do. --force adds a second copy.")
        }
        let after = ["bash: open a new terminal, or run `exec bash -l`."]
        if let loaded {
            let d = dataHome + "/bash-completion/completions"
            return Plan(target: d + "/wombat", why: "bash-completion (\(shown(loaded))) loads it from \(shown(d)) when you first press Tab after `wombat`.", after: after)
        }
        let d = home + "/.bash_completion.d"
        let rc = bashStartupFile()
        return Plan(target: d + "/wombat", why: "No bash-completion 2 is loaded, so a line in \(shown(rc)) loads it from \(shown(d)) (works in macOS's bash 3.2 too).",
                    rc: rc, rcBody: ["[ -n \"$BASH_VERSION\" ] && [ -r \"$HOME/.bash_completion.d/wombat\" ] && . \"$HOME/.bash_completion.d/wombat\""],
                    after: after)
    }

    /// The bash-completion 2 script the startup files load, if it exists.
    func bashCompletionLoaded() -> String? {
        let files = [".bash_profile", ".bash_login", ".profile", ".bashrc"].map { home + "/" + $0 }
        let prefix = brewPrefixes.first ?? "/opt/homebrew"
        for line in files.flatMap(lines) where !isComment(line) && line.contains("bash_completion") {
            let l = line.replacingOccurrences(of: "$(brew --prefix)", with: prefix)
            for token in l.split(whereSeparator: { " \t;&|[]".contains($0) }) {
                guard token.contains("bash_completion"), let p = expand(String(token), ["HOMEBREW_PREFIX": prefix]) else { continue }
                // bash-completion 2's entry points; version 1 has no per-user folder.
                if (p.hasSuffix("/profile.d/bash_completion.sh") || p.hasSuffix("/share/bash-completion/bash_completion")),
                   FileManager.default.fileExists(atPath: p) { return p }
            }
        }
        return nil
    }

    /// macOS terminals start login shells, which read ~/.bash_profile (or .bash_login, or
    /// .profile), and only those. When ~/.bash_profile reads ~/.bashrc, .bashrc covers both.
    func bashStartupFile() -> String {
        let profile = home + "/.bash_profile", bashrc = home + "/.bashrc"
        if exists(profile) {
            let readsRc = lines(profile).contains { !isComment($0) && $0.contains(".bashrc") }
            return readsRc && exists(bashrc) ? bashrc : profile
        }
        for f in [".bash_login", ".profile"] where exists(home + "/" + f) { return home + "/" + f }
        return profile
    }

    func planFish() -> Plan {
        if let dir { return Plan(target: expandArg(dir) + "/wombat.fish", why: "Into \(shown(expandArg(dir))) (--dir).") }
        if let link = brewLink(.fish), let fish = fishBinary(), brewPrefixes.contains(where: { fish.hasPrefix($0 + "/") }), !force {
            return Plan(why: "", skip: "Homebrew already installed it (\(shown(link))) and Homebrew's fish reads it: nothing to do. --force adds a second copy.")
        }
        let d = configHome + "/fish/completions"
        return Plan(target: d + "/wombat.fish", why: "Into \(shown(d)), which fish reads on its own.", after: ["fish: new fish shells have it."])
    }

    func expandArg(_ path: String) -> String {
        let p = (path as NSString).expandingTildeInPath
        return (p.hasPrefix("/") ? p : FileManager.default.currentDirectoryPath + "/" + p).replacingOccurrences(of: "//", with: "/")
    }

    // MARK: Changes

    /// Links target → source. True when the link is (or would be) in place.
    mutating func place(_ source: String, at target: String) -> Bool {
        let fm = FileManager.default
        switch classify(target) {
        case .link(let dest, _, _) where dest == source:
            print("  ok    \(shown(target)) already links to \(shown(source))")
            return true
        case .link(_, true, _):
            print("  link  \(shown(target)) -> \(shown(source)) (replacing Wombat's old link)")
            if !dryRun { try? fm.removeItem(atPath: target) }
        case .wombatCopy:
            let backup = target + ".wombat-backup-" + stamp
            print("  link  \(shown(target)) -> \(shown(source)) (the copy there now moves to \(shown(backup)))")
            if !dryRun, !move(target, backup) { return false }
        case .link(_, false, _), .foreign:
            guard force else {
                print("  skip  \(shown(target)) exists and isn't Wombat's. --force replaces it and keeps it as a backup.")
                failed = true
                return false
            }
            let backup = target + ".wombat-backup-" + stamp
            print("  link  \(shown(target)) -> \(shown(source)) (--force: the file there now moves to \(shown(backup)))")
            if !dryRun, !move(target, backup) { return false }
        case .none:
            print("  link  \(shown(target)) -> \(shown(source))")
        }
        guard !dryRun else { return true }
        do {
            try fm.createDirectory(atPath: (target as NSString).deletingLastPathComponent, withIntermediateDirectories: true,
                                   attributes: [.posixPermissions: 0o755])
            try fm.createSymbolicLink(atPath: target, withDestinationPath: source)
            return true
        } catch {
            printErr("wombat: cannot create \(shown(target)): \(error.localizedDescription)")
            failed = true
            return false
        }
    }

    mutating func move(_ from: String, _ to: String) -> Bool {
        do { try FileManager.default.moveItem(atPath: from, toPath: to); return true } catch {
            printErr("wombat: cannot move \(shown(from)) aside: \(error.localizedDescription)")
            failed = true
            return false
        }
    }

    /// Adds (or updates) the marked block. True when it is (or would be) in place.
    mutating func editBlock(_ rc: String, body: [String], atTop: Bool) -> Bool {
        let block = [Self.blockBegin, Self.blockNote] + body + [Self.blockEnd]
        let old = exists(rc) ? lines(rc) : []
        var new: [String]
        if let b = old.firstIndex(of: Self.blockBegin), let e = old[b...].firstIndex(of: Self.blockEnd) {
            if Array(old[b...e]) == block { print("  ok    \(shown(rc)) already has Wombat's lines"); return true }
            new = old
            new.replaceSubrange(b...e, with: block)
            print("  edit  \(shown(rc)): update Wombat's lines to")
        } else if atTop {
            new = block + [""] + old
            print("  edit  \(shown(rc)): add at the top")
        } else {
            new = old
            while new.last == "" { new.removeLast() }
            new += (new.isEmpty ? [] : [""]) + block + [""]
            print("  edit  \(shown(rc)): add at the end")
        }
        for l in block { print("        \(l)") }
        if dryRun { return true }
        guard confirm("  Change \(shown(rc))?") else { print("  skip  \(shown(rc)) left as it is"); return false }
        return writeRC(rc, new, existed: !old.isEmpty || exists(rc))
    }

    /// Writes through a symlinked dotfile (into the user's dotfiles repository, say) instead of
    /// replacing the link, after a backup copy next to the name the shell reads.
    mutating func writeRC(_ rc: String, _ new: [String], existed: Bool) -> Bool {
        do {
            if existed {
                let backup = rc + ".wombat-backup-" + stamp
                try Data(contentsOf: URL(fileURLWithPath: rc)).write(to: URL(fileURLWithPath: backup))
                print("        (backup: \(shown(backup)))")
            }
            let real = URL(fileURLWithPath: rc).resolvingSymlinksInPath()
            try Data(new.joined(separator: "\n").utf8).write(to: real)
            return true
        } catch {
            printErr("wombat: cannot change \(shown(rc)): \(error.localizedDescription)")
            failed = true
            return false
        }
    }

    func confirm(_ question: String) -> Bool {
        if yes { return true }
        guard isatty(STDIN_FILENO) != 0 else {
            print("  Not asked (no terminal): rerun with --yes to make this change.")
            return false
        }
        print("\(question) [y/N] ", terminator: "")
        fflush(stdout)
        return readLine()?.trimmingCharacters(in: .whitespaces).lowercased().hasPrefix("y") == true
    }

    // MARK: Uninstall and status

    /// Every place install may have used, per shell.
    func candidates(_ shell: CompletionShell) -> [String] {
        switch shell {
        case .zsh:
            var dirs = [home + "/.zsh/completions", home + "/.zsh/completion", home + "/.zsh/functions", home + "/.zfunc",
                        home + "/.zfunctions", dataHome + "/zsh/site-functions", configHome + "/zsh/completions"]
            let rc = lines(zshrc)
            let zshDir = env["ZSH"] ?? assignment("ZSH", in: rc).flatMap { expand($0) } ?? home + "/.oh-my-zsh"
            let custom = env["ZSH_CUSTOM"] ?? assignment("ZSH_CUSTOM", in: rc).flatMap { expand($0, ["ZSH": zshDir]) } ?? zshDir + "/custom"
            dirs.insert(custom + "/completions", at: 0)
            return dirs.map { $0 + "/_wombat" }
        case .bash: return [dataHome + "/bash-completion/completions/wombat", home + "/.bash_completion.d/wombat"]
        case .fish: return [configHome + "/fish/completions/wombat.fish"]
        }
    }

    func rcFiles(_ shell: CompletionShell) -> [String] {
        switch shell {
        case .zsh: return [zshrc]
        case .bash: return [".bash_profile", ".bashrc", ".bash_login", ".profile"].map { home + "/" + $0 }
        case .fish: return []
        }
    }

    mutating func uninstall(_ shells: [CompletionShell]) {
        if dryRun { print("Dry run: nothing is changed.\n") }
        var changed = false
        for shell in shells {
            for path in candidates(shell) {
                switch classify(path) {
                case .link(_, true, _):
                    print("  remove \(shown(path))")
                    changed = true
                    if !dryRun { try? FileManager.default.removeItem(atPath: path) }
                case .wombatCopy:
                    print("  left   \(shown(path)): a copy saved by hand, not by install; delete it yourself if you don't want it")
                default: break
                }
            }
            for rc in rcFiles(shell) {
                let old = lines(rc)
                guard let b = old.firstIndex(of: Self.blockBegin), let e = old[b...].firstIndex(of: Self.blockEnd) else { continue }
                var new = old
                new.removeSubrange(b...e)
                // The blank line install put next to the block.
                if b < new.count, new[b] == "", b == 0 || (b > 0 && new[b - 1] == "") { new.remove(at: b) }
                print("  edit   \(shown(rc)): remove Wombat's lines")
                changed = true
                if !dryRun { _ = writeRC(rc, new, existed: true) }
            }
        }
        if !changed { print("Nothing to remove: no completion set up by `wombat completion install`.") }
    }

    func status(_ shells: [CompletionShell]) {
        let source = bundledCompletionURL("").path
        print("Scripts in the app: \(FileManager.default.fileExists(atPath: source) ? shown(source) : "missing (\(source))")")
        for shell in shells {
            var found: [String] = []
            for path in candidates(shell) {
                switch classify(path) {
                case .link(let dest, true, let dangling): found.append("\(shown(path)) -> \(shown(dest))\(dangling ? " (broken: run `wombat completion install`)" : "")")
                case .wombatCopy: found.append("\(shown(path)) (a copy; `wombat completion install` replaces it with a link)")
                default: break
                }
            }
            if let b = brewLink(shell) { found.append("\(shown(b)) (Homebrew)") }
            for rc in rcFiles(shell) where lines(rc).contains(Self.blockBegin) { found.append("\(shown(rc)) has Wombat's lines") }
            print("\(bold(shell.rawValue.padding(toLength: 5, withPad: " ", startingAt: 0))) \(found.isEmpty ? "not set up" : found.joined(separator: "\n      "))")
        }
    }
}
