// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation
import Network

/// Wombat: one AmneziaWG device line for amneziawg-go's UAPI, e.g. `jc=4`.
public struct AmneziaSetting: Equatable {
    public let key: String
    public let value: String

    /// The AmneziaWG 1.0 to 2.0 device keys; nothing else (fwmark, private_key, ...) passes.
    public static let keys: Set<String> = ["jc", "jmin", "jmax", "s1", "s2", "s3", "s4",
                                           "h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5"]

    /// Nil unless the key is an AmneziaWG key and the value is one line of UAPI (no line breaks
    /// or NULs), so a setting can never inject another key (such as a peer or private_key).
    public init?(key: String, value: String) {
        guard Self.keys.contains(key), !value.contains(where: { $0.isNewline || $0 == "\0" }) else { return nil }
        self.key = key
        self.value = value
    }
}

public struct InterfaceConfiguration {
    public var privateKey: PrivateKey
    public var addresses = [IPAddressRange]()
    public var listenPort: UInt16?
    public var mtu: UInt16?
    public var dns = [DNSServer]()
    public var dnsSearch = [String]()
    /// Wombat: AmneziaWG device settings as UAPI key/value pairs, already validated by
    /// TunnelCore. Non-empty selects the amneziawg-go engine (`awgTurnOn`).
    public var amneziaSettings = [AmneziaSetting]()

    public init(privateKey: PrivateKey) {
        self.privateKey = privateKey
    }
}

extension InterfaceConfiguration: Equatable {
    public static func == (lhs: InterfaceConfiguration, rhs: InterfaceConfiguration) -> Bool {
        let lhsAddresses = lhs.addresses.filter { $0.address is IPv4Address } + lhs.addresses.filter { $0.address is IPv6Address }
        let rhsAddresses = rhs.addresses.filter { $0.address is IPv4Address } + rhs.addresses.filter { $0.address is IPv6Address }

        return lhs.privateKey == rhs.privateKey &&
            lhsAddresses == rhsAddresses &&
            lhs.listenPort == rhs.listenPort &&
            lhs.mtu == rhs.mtu &&
            lhs.dns == rhs.dns &&
            lhs.dnsSearch == rhs.dnsSearch &&
            lhs.amneziaSettings == rhs.amneziaSettings
    }
}
