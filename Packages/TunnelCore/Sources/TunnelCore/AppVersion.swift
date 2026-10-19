import Foundation

/// Version checks between Wombat's parts (the CLI and the app it drives).
public enum AppVersion {
    /// "1.2.0" < "1.10.0", numerically per part; "1.2" equals "1.2.0". A pre-release suffix
    /// ("1.3.0-beta") is ignored, and an unparsable version counts as oldest.
    public static func isOlder(_ a: String, than b: String) -> Bool {
        func parts(_ s: String) -> [Int]? {
            let core = s.split(separator: "-", maxSplits: 1).first.map(String.init) ?? ""
            let numbers = core.split(separator: ".").map { Int($0) }
            return numbers.isEmpty || numbers.contains(nil) ? nil : numbers.map { $0! }
        }
        guard let y = parts(b) else { return false }
        guard let x = parts(a) else { return true }
        for i in 0..<max(x.count, y.count) {
            let l = i < x.count ? x[i] : 0, r = i < y.count ? y[i] : 0
            if l != r { return l < r }
        }
        return false
    }
}

/// How long CLI approvals are refused after declines in a row: 10 s, doubling, at most 320 s.
public enum DeclineBackoff {
    public static func wait(afterDeclines count: Int) -> TimeInterval {
        10 * pow(2, Double(min(max(count, 1), 6) - 1))
    }
}
