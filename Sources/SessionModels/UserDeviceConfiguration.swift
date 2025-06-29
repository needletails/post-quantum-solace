//
//  UserDeviceConfiguration.swift
//  post-quantum-solace
//
//  Created by Cole M on 9/14/24.
//
//  Copyright (c) 2025 NeedleTails Organization.
//
//  This project is licensed under the AGPL-3.0 License.
//
//  See the LICENSE file for more information.
//
//  This file is part of the Post-Quantum Solace SDK, which provides
//  post-quantum cryptographic session management capabilities.
//
import Foundation
import DoubleRatchetKit

/// Errors that can occur during signing operations.
enum SigningErrors: Error {
    case invalidSignature          // Indicates that the signature is invalid.
    case missingSignedObject       // Indicates that a signed object is missing.
    case signingFailedOnVerification // Indicates that signing failed during verification.
}

/// A struct representing the configuration of a user device, including its identity,
/// signing information, and whether it is a master device.
public struct UserDeviceConfiguration: Codable, Sendable {
    
    /// Unique identifier for the device.
    public let deviceId: UUID
    
    /// The Curve25519 public key used for digital signatures and authentication in the PQXDH protocol.
    public var signingPublicKey: Data
    
    /// The Curve25519 public key used for long-term identity in the PQXDH protocol.
    public var longTermPublicKey: Data
    
    /// The final PQKEM public key used for post-quantum key exchange in the PQXDH protocol.
    public var finalPQKemPublicKey: PQKemPublicKey
    
    /// An optional device name to identify what device this actually is.
    public let deviceName: String?
    
    /// HMAC data for JWT authentication.
    public let hmacData: Data
    
    /// A flag indicating if this device is the master device.
    public let isMasterDevice: Bool
    
    /// Coding keys for encoding and decoding the struct.
    /// Single-letter keys are used for obfuscation and reduced payload size.
    enum CodingKeys: String, CodingKey, Codable, Sendable {
        case deviceId = "a"               // Key for the device identifier
        case signingPublicKey = "b"       // Key for the public signing key
        case longTermPublicKey = "c"      // Key for the public long-term key
        case finalPQKemPublicKey = "d"     // Key for the Kyber 1024 public key
        case deviceName = "e"              // Key for the device name
        case hmacData = "f"                // Key for the HMAC data
        case isMasterDevice = "g"          // Key for the master device flag
    }
    
    /// Initializes a new `UserDeviceConfiguration` instance.
    ///
    /// - Parameters:
    ///   - deviceId: The unique identifier for the device.
    ///   - signingPublicKey: The Curve25519 public key for digital signatures.
    ///   - longTermPublicKey: The Curve25519 public key for long-term identity.
    ///   - finalPQKemPublicKey: The final PQKEM public key for post-quantum key exchange.
    ///   - deviceName: An optional name for the device.
    ///   - hmacData: The HMAC data for JWT authentication.
    ///   - isMasterDevice: A flag indicating if this is the master device.
    public init(
        deviceId: UUID,
        signingPublicKey: Data,
        longTermPublicKey: Data,
        finalPQKemPublicKey: PQKemPublicKey,
        deviceName: String?,
        hmacData: Data,
        isMasterDevice: Bool
    ) {
        self.deviceId = deviceId
        self.signingPublicKey = signingPublicKey
        self.longTermPublicKey = longTermPublicKey
        self.finalPQKemPublicKey = finalPQKemPublicKey
        self.deviceName = deviceName
        self.hmacData = hmacData
        self.isMasterDevice = isMasterDevice
    }
    
    /// Updates the signing public key with new data.
    ///
    /// - Parameter data: The new Curve25519 public key data for digital signatures.
    public mutating func updateSigningPublicKey(_ data: Data) async {
        self.signingPublicKey = data
    }
    
    /// Updates the long-term public key with new data.
    ///
    /// - Parameter data: The new Curve25519 public key data for long-term identity.
    public mutating func updateLongTermPublicKey(_ data: Data) async {
        self.longTermPublicKey = data
    }
    
    /// Updates the final PQKEM public key with a new key.
    ///
    /// - Parameter key: The new PQKEM public key for post-quantum key exchange.
    public mutating func updateFinalPQKemPublicKey(_ key: PQKemPublicKey) async {
        self.finalPQKemPublicKey = key
    }
}

/// A struct representing a user session, including its identity, secret name, and device configuration.
public struct UserSession: Identifiable, Codable, Sendable, Hashable {
    
    /// The unique identifier for the user session.
    public let id: UUID
    
    /// The secret name associated with the user session.
    public let secretName: String
    
    /// The unique identifier for the device associated with the session.
    public let deviceId: UUID
    
    /// The configuration of the user device associated with the session.
    public let configuration: UserDeviceConfiguration
    
    /// Initializes a new `UserSession` instance.
    ///
    /// - Parameters:
    ///   - id: The unique identifier for the user session.
    ///   - secretName: The secret name associated with the user session.
    ///   - configuration: The configuration of the user device associated with the session.
    public init(
        id: UUID,
        secretName: String,
        configuration: UserDeviceConfiguration
    ) {
        self.id = id
        self.secretName = secretName
        self.deviceId = configuration.deviceId
        self.configuration = configuration
    }
    
    /// Compares two `UserSession` instances for equality.
    ///
    /// - Parameters:
    ///   - lhs: The left-hand side `UserSession` instance.
    ///   - rhs: The right-hand side `UserSession` instance.
    /// - Returns: A boolean indicating whether the two instances are equal.
    public static func == (lhs: UserSession, rhs: UserSession) -> Bool {
        return lhs.id == rhs.id
    }
    
    /// Computes a hash value for the `UserSession`.
    ///
    /// - Parameter hasher: The hasher to use for hashing the `UserSession`.
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
}

/// A struct representing one-time keys used for ephemeral key exchange in the Double Ratchet protocol.
/// These keys are used once and then discarded to provide forward secrecy.
public struct OneTimeKeys: Codable, Sendable {
    /// The Curve25519 public key for classical cryptography operations.
    public let curve: DoubleRatchetKit.CurvePublicKey?
    
    /// The Kyber public key for post-quantum cryptography operations.
    public let kyber: DoubleRatchetKit.PQKemPublicKey?
    
    /// Initializes a new `OneTimeKeys` instance.
    ///
    /// - Parameters:
    ///   - curve: The Curve25519 public key for classical cryptography. Optional.
    ///   - kyber: The Kyber public key for post-quantum cryptography. Optional.
    public init(
        curve: DoubleRatchetKit.CurvePublicKey? = nil,
        kyber: DoubleRatchetKit.PQKemPublicKey? = nil
    ) {
        self.curve = curve
        self.kyber = kyber
    }
}

/// A struct representing long-term keys used for persistent identity and authentication.
/// These keys remain valid for extended periods and are used for device identification.
public struct LongTermKeys: Codable, Sendable {
    /// The Curve25519 public key for classical cryptography operations.
    public let curve: DoubleRatchetKit.CurvePublicKey?
    
    /// The Curve25519 public key used for digital signatures and authentication.
    public let signing:  DoubleRatchetKit.CurvePublicKey?
    
    /// The Kyber public key for post-quantum cryptography operations.
    public let kyber: DoubleRatchetKit.PQKemPublicKey?
    
    /// Initializes a new `LongTermKeys` instance.
    ///
    /// - Parameters:
    ///   - curve: The Curve25519 public key for classical cryptography. Optional.
    ///   - signing: The Curve25519 public key used for digital signatures. Optional.
    ///   - kyber: The Kyber public key for post-quantum cryptography. Optional.
    public init(
        curve: DoubleRatchetKit.CurvePublicKey? = nil,
        signing: DoubleRatchetKit.CurvePublicKey? = nil,
        kyber: DoubleRatchetKit.PQKemPublicKey? = nil
    ) {
        self.curve = curve
        self.signing = signing
        self.kyber = kyber
    }
}

/// A struct representing rotated public keys that have been updated during a key rotation event.
/// Contains the new pre-shared key data and the signed device configuration after rotation.
public struct RotatedPublicKeys: Codable, Sendable {
    /// The pre-shared key data used for the key rotation.
    public let pskData: Data
    
    /// The signed device configuration after the key rotation has been completed.
    public let signedDevice: UserConfiguration.SignedDeviceConfiguration
    
    /// Initializes a new `RotatedPublicKeys` instance.
    ///
    /// - Parameters:
    ///   - pskData: The pre-shared key data used during the key rotation process.
    ///   - signedDevice: The signed device configuration after key rotation.
    public init(
        pskData: Data,
        signedDevice: UserConfiguration.SignedDeviceConfiguration
    ) {
        self.pskData = pskData
        self.signedDevice = signedDevice
    }
}
