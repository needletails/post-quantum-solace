//
//  DeviceKeys.swift
//  needletail-crypto
//
//  Created by Cole M on 9/14/24.
//
import Foundation
import DoubleRatchetKit

/// A struct representing the cryptographic keys associated with a device.
public struct DeviceKeys: Codable, Sendable, Equatable {
    /// Coding keys for encoding and decoding the struct.
    enum CodingKeys: String, CodingKey, Codable & Sendable {
        case deviceId = "a"             // Key for the device identity
        case privateSigningKey = "b"    // Key for the private signing key
        case privateLongTermKey = "c"   // Key for the long term private key
        case privateOneTimeKeys = "d"   // Key for the one time private key
        case kyber1024PrivateKey = "e"  //Post Quatum Private Key
    }
    
    /// Unique identifier for the device.
    public let deviceId: UUID
    /// Data representing the private signing identity of the device.
    public let privateSigningKey: Data
    /// Data representing the private key of the device.
    public let privateLongTermKey: Data
    
    public var privateOneTimeKeys: [Curve25519PrivateKeyRepresentable]
    
    public let kyber1024PrivateKey: Data
    
    public init(
        deviceId: UUID,
        privateSigningKey: Data,
        privateLongTermKey: Data,
        privateOneTimeKeys: [Curve25519PrivateKeyRepresentable],
        kyber1024PrivateKey: Data) {
        self.deviceId = deviceId
        self.privateSigningKey = privateSigningKey
        self.privateLongTermKey = privateLongTermKey
        self.privateOneTimeKeys = privateOneTimeKeys
        self.kyber1024PrivateKey = kyber1024PrivateKey
    }
}
