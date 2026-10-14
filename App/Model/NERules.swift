import Foundation
import NetworkExtension
import TunnelCore

/// Maps the on-demand choices the app and CLI offer (`Control.OnDemand`) to NEOnDemandRules.
/// The system evaluates the rules, so they work while the app is closed.
extension Control.OnDemand {
    init(manager: NETunnelProviderManager) {
        let rules = manager.onDemandRules ?? []
        let connects = rules.compactMap { $0 as? NEOnDemandRuleConnect }
        self.init(
            enabled: manager.isOnDemandEnabled,
            onWiFi: rules.isEmpty || connects.contains { $0.interfaceTypeMatch == .wiFi || $0.interfaceTypeMatch == .any },
            onEthernet: rules.isEmpty || connects.contains { $0.interfaceTypeMatch == .ethernet || $0.interfaceTypeMatch == .any },
            trustedSSIDs: rules.compactMap { $0 as? NEOnDemandRuleDisconnect }.flatMap { $0.ssidMatch ?? [] })
    }

    func neRules() -> [NEOnDemandRule] {
        var rules: [NEOnDemandRule] = []
        let trusted = trustedSSIDs.map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        if !trusted.isEmpty {
            let rule = NEOnDemandRuleDisconnect()
            rule.interfaceTypeMatch = .wiFi
            rule.ssidMatch = trusted
            rules.append(rule)
        }
        if onWiFi {
            let rule = NEOnDemandRuleConnect()
            rule.interfaceTypeMatch = .wiFi
            rules.append(rule)
        }
        if onEthernet {
            let rule = NEOnDemandRuleConnect()
            rule.interfaceTypeMatch = .ethernet
            rules.append(rule)
        }
        // Anything not matched above (other interface types) leaves the tunnel as it is.
        rules.append(NEOnDemandRuleIgnore())
        return rules
    }
}

extension Control.Protection {
    init(proto: NETunnelProviderProtocol?) {
        self.init(killSwitch: proto?.includeAllNetworks ?? false, allowLAN: proto?.excludeLocalNetworks ?? true)
    }
}
