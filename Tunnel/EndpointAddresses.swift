import Foundation
import Network
import os

/// Endpoint hostname -> IP addresses for one tunnel, from the app's start options or, failing
/// that, the last ones that completed a handshake. Needed because with the kill switch on, macOS blocks the
/// system resolver for this process as soon as the tunnel starts (verified 2026-10-14: "Could not
/// resolve endpoint" while the same name resolved fine outside).
///
/// The cache is this root-only extension's own defaults. Addresses aren't secret, but they are
/// only ever taken for hostnames that appear in the tunnel's own configuration, and only as
/// numeric IP literals, so a bad options dictionary can't point a peer somewhere unrelated.
enum EndpointAddresses {
    private static let log = Logger(subsystem: AppIdentity.logSubsystem, category: "tunnel")
    private static let defaults = UserDefaults.standard
    private static func key(_ id: String) -> String { "endpoints.\(id)" }

    /// Returns the address to use per hostname. Fresh answers from the app are used now but only
    /// cached once a handshake proves them (`confirm`), so one spoofed DNS answer on a hostile
    /// network can't stick in the cache (audits S2-L1, F-5, WOM-08).
    static func resolve(tunnelID id: String, hosts: Set<String>, options: [String: NSObject]?, killSwitch: Bool) -> (chosen: [String: String], pending: [String: [String]]) {
        guard !hosts.isEmpty else { return ([:], [:]) }
        let fresh = validated(options?[StartOption.endpoints] as? [String: [String]], hosts: hosts)
        var chosen = fresh.compactMapValues(\.first)
        // Without the kill switch the engine's own lookup works and gives current answers, so the
        // cache is only a fallback when the resolver is blocked.
        if killSwitch {
            let cached = validated(defaults.dictionary(forKey: key(id)) as? [String: [String]], hosts: hosts)
            for (host, addresses) in cached where chosen[host] == nil {
                chosen[host] = addresses.first
                log.notice("Using the last confirmed address for an endpoint (kill switch blocks lookups)")
            }
        }
        return (chosen, fresh)
    }

    /// Called after the first handshake: the addresses in use are known good.
    static func confirm(tunnelID id: String, _ addresses: [String: [String]], hosts: Set<String>) {
        guard !addresses.isEmpty else { return }
        var cached = validated(defaults.dictionary(forKey: key(id)) as? [String: [String]], hosts: hosts)
        cached.merge(addresses) { _, new in new }
        defaults.set(cached, forKey: key(id))
        // No hostnames or addresses: the count is enough to see the cache work in `wombat logs`.
        log.notice("Saved \(addresses.count, privacy: .public) confirmed endpoint address(es) for kill-switch starts")
    }

    static func forget(tunnelID id: String) { defaults.removeObject(forKey: key(id)) }

    private static func validated(_ raw: [String: [String]]?, hosts: Set<String>) -> [String: [String]] {
        guard let raw else { return [:] }
        var result: [String: [String]] = [:]
        for (host, addresses) in raw where hosts.contains(host) {
            let ips = addresses.prefix(8).filter { !$0.contains("%") && (IPv4Address($0) != nil || IPv6Address($0) != nil) }
            if !ips.isEmpty { result[host] = Array(ips) }
        }
        return result
    }
}
