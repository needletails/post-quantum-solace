//
//  DeviceKeys.swift
//  post-quantum-solace
//
//  Created by Cole M on 9/14/24.
//
import Foundation
import SwiftKyber
import DoubleRatchetKit

/// A struct representing the cryptographic keys associated with a device.
public struct DeviceKeys: Codable, Sendable, Equatable {
    /// Coding keys for encoding and decoding the struct.
    enum CodingKeys: String, CodingKey {
        case deviceId = "a"                     // Key for the device identity
        case privateSigningKey = "b"            // Key for the private signing key
        case privateLongTermKey = "c"           // Key for the long-term private key
        case privateOneTimeKeys = "d"           // Key for the one-time private keys
        case privateKyberOneTimeKeys = "e"      // Post-Quantum private keys
        case finalKyberPrivateKey = "f"         // Final Post-Quantum private key
        case rotateKeysDate = "g"         // Date to rotate the signing key
    }
    
    /// Unique identifier for the device.
    public let deviceId: UUID
    
    /// Data representing the private signing identity of the device.
    public var privateSigningKey: Data
    
    /// Data representing the private long-term key of the device.
    public var privateLongTermKey: Data
    
    /// Array of private one-time keys for the device.
    public var privateOneTimeKeys: [Curve25519PrivateKeyRepresentable]
    
    /// Array of private Kyber one-time keys for the device.
    public var privateKyberOneTimeKeys: [Kyber1024PrivateKeyRepresentable]
    
    /// Final private Kyber key for the device.
    public var finalKyberPrivateKey: Kyber1024PrivateKeyRepresentable
    
    /// Date to rotate the key, if applicable.
    public var rotateKeysDate: Date?
    
    
    /// Initializes a new instance of `DeviceKeys`.
    /// - Parameters:
    ///   - deviceId: Unique identifier for the device.
    ///   - privateSigningKey: Data representing the private signing key.
    ///   - privateLongTermKey: Data representing the private long-term key.
    ///   - privateOneTimeKeys: Array of private one-time keys.
    ///   - privateKyberOneTimeKeys: Array of private Kyber one-time keys.
    ///   - finalKyberPrivateKey: Final private Kyber key.
    ///   - rotateSigningKeyDate: Optional date to rotate the key.
    public init(
        deviceId: UUID,
        privateSigningKey: Data,
        privateLongTermKey: Data,
        privateOneTimeKeys: [Curve25519PrivateKeyRepresentable],
        privateKyberOneTimeKeys: [Kyber1024PrivateKeyRepresentable],
        finalKyberPrivateKey: Kyber1024PrivateKeyRepresentable,
        rotateKeysDate: Date? = nil
    ) {
        self.deviceId = deviceId
        self.privateSigningKey = privateSigningKey
        self.privateLongTermKey = privateLongTermKey
        self.privateOneTimeKeys = privateOneTimeKeys
        self.privateKyberOneTimeKeys = privateKyberOneTimeKeys
        self.finalKyberPrivateKey = finalKyberPrivateKey
        self.rotateKeysDate = rotateKeysDate
    }
    
    public mutating func updateRotateKeysDate(_ date: Date) async {
        self.rotateKeysDate = date
    }
}
