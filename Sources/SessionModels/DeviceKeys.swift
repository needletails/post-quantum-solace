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
        case signingPrivateKey = "b"            // Key for the private signing key
        case longTermPrivateKey = "c"           // Key for the long-term private key
        case oneTimePrivateKeys = "d"           // Key for the one-time private keys
        case pqKemOneTimePrivateKeys = "e"      // Post-Quantum private keys
        case finalPQKemPrivateKey = "f"         // Final Post-Quantum private key
        case rotateKeysDate = "g"         // Date to rotate the signing key
    }
    
    /// Unique identifier for the device.
    public let deviceId: UUID
    
    /// Data representing the private signing identity of the device.
    public var signingPrivateKey: Data
    
    /// Data representing the private long-term key of the device.
    public var longTermPrivateKey: Data
    
    /// Array of private one-time keys for the device.
    public var oneTimePrivateKeys: [CurvePrivateKey]
    
    /// Array of private Kyber one-time keys for the device.
    public var pqKemOneTimePrivateKeys: [PQKemPrivateKey]
    
    /// Final private Kyber key for the device.
    public var finalPQKemPrivateKey: PQKemPrivateKey
    
    /// Date to rotate the key, if applicable.
    public var rotateKeysDate: Date?
    
    
    /// Initializes a new instance of `DeviceKeys`.
    /// - Parameters:
    ///   - deviceId: Unique identifier for the device.
    ///   - signingPrivateKey: Data representing the private signing key.
    ///   - longTermPrivateKey: Data representing the private long-term key.
    ///   - oneTimePrivateKeys: Array of private one-time keys.
    ///   - pqKemOneTimePrivateKeys: Array of private Kyber one-time keys.
    ///   - finalPQKemPrivateKey: Final private Kyber key.
    ///   - rotateSigningKeyDate: Optional date to rotate the key.
    public init(
        deviceId: UUID,
        signingPrivateKey: Data,
        longTermPrivateKey: Data,
        oneTimePrivateKeys: [CurvePrivateKey],
        pqKemOneTimePrivateKeys: [PQKemPrivateKey],
        finalPQKemPrivateKey: PQKemPrivateKey,
        rotateKeysDate: Date? = nil
    ) {
        self.deviceId = deviceId
        self.signingPrivateKey = signingPrivateKey
        self.longTermPrivateKey = longTermPrivateKey
        self.oneTimePrivateKeys = oneTimePrivateKeys
        self.pqKemOneTimePrivateKeys = pqKemOneTimePrivateKeys
        self.finalPQKemPrivateKey = finalPQKemPrivateKey
        self.rotateKeysDate = rotateKeysDate
    }
    
    public mutating func updateRotateKeysDate(_ date: Date) async {
        self.rotateKeysDate = date
    }
}
