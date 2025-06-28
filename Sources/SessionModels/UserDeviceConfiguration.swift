//
//  UserDeviceConfiguration.swift
//  post-quantum-solace
//
//  Created by Cole M on 9/14/24.
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
    
    /// Data representing the signing identity of the device.
    public var signingPublicKey: Data
    
    /// Public key associated with the device.
    public var longTermPublicKey: Data
    
    /// Public key associated with the device.
    public var finalPQKemPublicKey: PQKemPublicKey
    
    /// An optional device name to identify what device this actually is.
    public let deviceName: String?
    
    /// HMAC data for JWT authentication.
    public let hmacData: Data
    
    /// A flag indicating if this device is the master device.
    public let isMasterDevice: Bool
    
    /// Coding keys for encoding and decoding the struct.
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
    ///   - signingPublicKey: The signing identity data.
    ///   - longTermPublicKey: The public long-term key data.
    ///   - finalPQKemPublicKey: The PQKem public key data.
    ///   - deviceName: An optional name for the device.
    ///   - hmacData: The HMAC data for JWT authentication.
    ///   - isMasterDevice: A flag indicating if this is the master device.
    /// - Throws: An error if signing the configuration fails.
    public init(
        deviceId: UUID,
        signingPublicKey: Data,
        longTermPublicKey: Data,
        finalPQKemPublicKey: PQKemPublicKey,
        deviceName: String?,
        hmacData: Data,
        isMasterDevice: Bool
    ) throws {
        self.deviceId = deviceId
        self.signingPublicKey = signingPublicKey
        self.longTermPublicKey = longTermPublicKey
        self.finalPQKemPublicKey = finalPQKemPublicKey
        self.deviceName = deviceName
        self.hmacData = hmacData
        self.isMasterDevice = isMasterDevice
    }
    
    public mutating func updateSigningPublicKey(_ data: Data) async {
        self.signingPublicKey = data
    }
    
    public mutating func updateLongTermPublicKey(_ data: Data) async {
        self.longTermPublicKey = data
    }
    
    public mutating func updateFinalPQKemPublicKey(_ represetable: PQKemPublicKey) async {
        self.finalPQKemPublicKey = represetable
    }
}

/// A struct representing a user session, including its identity, secret name, and device configuration.
public struct UserSession: Identifiable, Codable, Sendable, Hashable {
    
    /// The unique identifier for the user session.
    public let id: UUID
    
    /// The secret name associated with the user session.
    public let secretName: String
    
    /// The unique identifier for the device associated with the session.
    public let identity: UUID
    
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
        self.identity = configuration.deviceId
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


public struct OneTimeKeys: Codable, Sendable {
    public let curve: DoubleRatchetKit.CurvePublicKey?
    public let kyber: DoubleRatchetKit.PQKemPublicKey?
    
    public init(
        curve: DoubleRatchetKit.CurvePublicKey? = nil,
        kyber: DoubleRatchetKit.PQKemPublicKey? = nil
    ) {
        self.curve = curve
        self.kyber = kyber
    }
}

public struct LongTermKeys: Codable, Sendable {
    public let curve: DoubleRatchetKit.CurvePublicKey?
    public let signing:  DoubleRatchetKit.CurvePublicKey?
    public let kyber: DoubleRatchetKit.PQKemPublicKey?
    
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

public struct RotatedPublicKeys: Codable, Sendable {
    public let pskData: Data
    public let signedDevice: UserConfiguration.SignedDeviceConfiguration
    
    public init(
        pskData: Data,
        signedDevice: UserConfiguration.SignedDeviceConfiguration
    ) {
        self.pskData = pskData
        self.signedDevice = signedDevice
    }
}
