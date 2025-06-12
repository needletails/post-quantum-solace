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
    enum CodingKeys: String, CodingKey, Codable & Sendable {
        case deviceId = "a"             // Key for the device identity
        case privateSigningKey = "b"    // Key for the private signing key
        case privateLongTermKey = "c"   // Key for the long term private key
        case privateOneTimeKeys = "d"   // Key for the one time private key
        case privateKyberOneTimeKeys = "e" //Post Quatum Private Keys
        case finalKyberPrivateKey = "f"  //Final Post Quatum Private Key
        case rotateKeyDate = "g" // Date to rotate long term keys
    }
    
    /// Unique identifier for the device.
    public let deviceId: UUID
    /// Data representing the private signing identity of the device.
    public let privateSigningKey: Data
    /// Data representing the private key of the device.
    public var privateLongTermKey: Data
    
    public var privateOneTimeKeys: [Curve25519PrivateKeyRepresentable]
    
    public var privateKyberOneTimeKeys: [Kyber1024PrivateKeyRepresentable]
    
    public var finalKyberPrivateKey: Kyber1024PrivateKeyRepresentable
    
    public var rotateKeyDate: Date?
    
    public init(
        deviceId: UUID,
        privateSigningKey: Data,
        privateLongTermKey: Data,
        privateOneTimeKeys: [Curve25519PrivateKeyRepresentable],
        privateKyberOneTimeKeys: [Kyber1024PrivateKeyRepresentable],
        finalKyberPrivateKey: Kyber1024PrivateKeyRepresentable,
        rotateKeyDate: Date? = nil
    ) {
        self.deviceId = deviceId
        self.privateSigningKey = privateSigningKey
        self.privateLongTermKey = privateLongTermKey
        self.privateOneTimeKeys = privateOneTimeKeys
        self.privateKyberOneTimeKeys = privateKyberOneTimeKeys
        self.finalKyberPrivateKey = finalKyberPrivateKey
        self.rotateKeyDate = rotateKeyDate
    }
}
