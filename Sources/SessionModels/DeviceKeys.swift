//
//  DeviceKeys.swift
//  post-quantum-solace
//
//  Created by Cole M on 9/14/24.
//
import Foundation
import SwiftKyber
import DoubleRatchetKit

/// A struct representing the cryptographic keys associated with a device in the post-quantum secure messaging system.
///
/// `DeviceKeys` encapsulates all the cryptographic material needed for a device to participate in secure
/// communications, including both classical and post-quantum cryptographic keys. This struct supports
/// the hybrid approach combining traditional elliptic curve cryptography with post-quantum Kyber KEM.
///
/// ## Key Components:
/// - **Device Identity**: Unique identifier for the device
/// - **Signing Keys**: For message authentication and digital signatures
/// - **Long-term Keys**: For establishing persistent secure channels
/// - **One-time Keys**: For forward secrecy and ephemeral key exchange
/// - **Post-Quantum Keys**: Kyber KEM keys for quantum-resistant encryption
///
/// ## Conformance:
/// - `Codable`: Supports serialization for storage and transmission
/// - `Sendable`: Safe for concurrent access
/// - `Equatable`: Supports equality comparison
///
/// ## Security Considerations:
/// - All private keys should be stored securely and never exposed
/// - Keys should be rotated according to the `rotateKeysDate` schedule
/// - One-time keys should be consumed and replaced regularly
public struct DeviceKeys: Codable, Sendable, Equatable {
    /// Coding keys for encoding and decoding the struct.
    ///
    /// Uses single-letter keys to minimize serialized data size while maintaining
    /// readability in the code. This is particularly important for cryptographic
    /// data that may be transmitted frequently.
    enum CodingKeys: String, CodingKey {
        case deviceId = "a"                     // Device identifier
        case signingPrivateKey = "b"            // Private signing key
        case longTermPrivateKey = "c"           // Private long-term key
        case oneTimePrivateKeys = "d"           // Private one-time keys
        case pqKemOneTimePrivateKeys = "e"      // Post-Quantum private keys
        case finalPQKemPrivateKey = "f"         // Final Post-Quantum private key
        case rotateKeysDate = "g"               // Date to rotate the keys
    }
    
    /// Unique identifier for the device.
    ///
    /// This UUID serves as the primary identifier for the device across the network.
    /// It should remain constant for the lifetime of the device and is used for
    /// routing messages and establishing device-specific secure channels.
    public let deviceId: UUID
    
    /// Data representing the private signing key of the device.
    ///
    /// This key is used for digital signatures to authenticate messages and verify
    /// the identity of the device. It should be kept secure and rotated periodically
    /// according to the `rotateKeysDate` schedule.
    public var signingPrivateKey: Data
    
    /// Data representing the private long-term key of the device.
    ///
    /// This key is used for establishing persistent secure channels and should be
    /// kept for extended periods. It provides the foundation for long-term
    /// cryptographic relationships between devices.
    public var longTermPrivateKey: Data
    
    /// Array of private one-time keys for the device.
    ///
    /// These keys provide forward secrecy by being used only once for ephemeral
    /// key exchange. They should be consumed and replaced regularly to maintain
    /// security. Each key is used for a single cryptographic operation.
    public var oneTimePrivateKeys: [CurvePrivateKey]
    
    /// Array of private Kyber one-time keys for the device.
    ///
    /// These post-quantum keys provide quantum-resistant forward secrecy. Like
    /// classical one-time keys, they should be consumed and replaced regularly.
    /// They are used in combination with classical keys for hybrid security.
    public var pqKemOneTimePrivateKeys: [PQKemPrivateKey]
    
    /// Final private Kyber key for the device.
    ///
    /// This is the last resort post-quantum key used when all one-time keys have
    /// been consumed. It should be replaced with new one-time keys as soon as
    /// possible to maintain optimal security.
    public var finalPQKemPrivateKey: PQKemPrivateKey
    
    /// Date to rotate the keys, if applicable.
    ///
    /// When this date is reached, the device should generate new cryptographic
    /// keys to maintain security. This is particularly important for long-term
    /// and signing keys that are used repeatedly.
    public var rotateKeysDate: Date?
    
    
    /// Initializes a new instance of `DeviceKeys` with all required cryptographic material.
    ///
    /// This initializer creates a complete set of device keys for secure communication.
    /// All cryptographic keys should be generated using cryptographically secure
    /// random number generators and stored securely.
    ///
    /// - Parameters:
    ///   - deviceId: Unique identifier for the device that remains constant throughout its lifetime.
    ///   - signingPrivateKey: Private key used for digital signatures and message authentication.
    ///   - longTermPrivateKey: Private key used for establishing persistent secure channels.
    ///   - oneTimePrivateKeys: Array of ephemeral private keys for forward secrecy.
    ///   - pqKemOneTimePrivateKeys: Array of post-quantum ephemeral private keys for quantum-resistant forward secrecy.
    ///   - finalPQKemPrivateKey: Fallback post-quantum private key used when one-time keys are exhausted.
    ///   - rotateKeysDate: Optional date when keys should be rotated for security maintenance.
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
    
    /// Updates the key rotation date for the device.
    ///
    /// This method allows scheduling when cryptographic keys should be rotated
    /// to maintain security. The rotation date is typically set based on
    /// security policies and key usage patterns.
    ///
    /// - Parameter date: The new date when keys should be rotated.
    public mutating func updateRotateKeysDate(_ date: Date) async {
        self.rotateKeysDate = date
    }
}
