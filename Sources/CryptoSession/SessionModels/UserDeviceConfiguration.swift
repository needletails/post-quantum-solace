//
//  UserDeviceConfiguration.swift
//  needletail-crypto
//
//  Created by Cole M on 9/14/24.
//
import Foundation
import BSON
import NeedleTailHelpers

/// Errors that can occur during signing operations.
enum SigningErrors: Error {
    case invalidSignature, missingSignedObject, signingFailedOnVerfication
}

/// A struct representing the configuration of a user device, including its identity, signing information, and whether it is a master device.
public struct UserDeviceConfiguration: Codable, Sendable {
    
    /// Unique identifier for the device.
    public let deviceIdentity: UUID
    /// Data representing the signing identity of the device.
    public let publicSigningKey: Data
    /// Public key associated with the device.
    public let publicKey: Data
    /// A flag indicating if this device is the master device.
    public let isMasterDevice: Bool

    /// Coding keys for encoding and decoding the struct.
    enum CodingKeys: String, CodingKey, Codable, Sendable {
        case deviceIdentity = "a"
        case publicSigningKey = "b"
        case publicKey = "c"
        case isMasterDevice = "d"
    }
    
    /// Initializes a new `UserDeviceConfiguration` instance.
    /// - Parameters:
    ///   - deviceIdentity: The unique identifier for the device.
    ///   - signingIdentity: The signing identity data.
    ///   - publicKey: The public key data.
    ///   - isMasterDevice: A flag indicating if this is the master device.
    /// - Throws: An error if signing the configuration fails.
   public init(
        deviceIdentity: UUID,
        publicSigningKey: Data,
        publicKey: Data,
        isMasterDevice: Bool
    ) throws {
        self.deviceIdentity = deviceIdentity
        self.publicSigningKey = publicSigningKey
        self.publicKey = publicKey
        self.isMasterDevice = isMasterDevice
    }
}

public struct UserSession: Codable, Sendable, Hashable {
    let id = UUID()
    public let secretName: String
    public let identity: UUID
    public let configuration: UserDeviceConfiguration
    public let deviceName: String
    
    public init(
        secretName: String,
        configuration: UserDeviceConfiguration,
        deviceName: String
    ) {
        self.secretName = secretName
        self.identity = configuration.deviceIdentity
        self.configuration = configuration
        self.deviceName = deviceName
    }
    
    public static func == (lhs: UserSession, rhs: UserSession) -> Bool {
        return lhs.id == rhs.id
    }
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
}
