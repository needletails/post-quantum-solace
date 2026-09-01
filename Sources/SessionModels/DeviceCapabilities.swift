//
//  DeviceCapabilities.swift
//  post-quantum-solace
//
//  Additive capability bitmask for published device key bundles.
//  Bit 0 = sealed sender. Absence of the field means incapable.
//

import Foundation

/// Bitmask advertised on `UserConfiguration.DeviceKeyBundle`.
///
/// Encoded as `UInt32`. A lone `Bool` is forbidden so future capabilities
/// do not require another schema bump.
public struct DeviceCapabilities: OptionSet, Sendable, Hashable, Codable {
    public let rawValue: UInt32

    public init(rawValue: UInt32) {
        self.rawValue = rawValue
    }

    /// Device can send and receive sealed-sender DMs.
    public static let sealedSender = DeviceCapabilities(rawValue: 1 << 0)
}
