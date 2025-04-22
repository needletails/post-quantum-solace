//
//  UserDeviceConfiguration.swift
//  needletail-crypto
//
//  Created by Cole M on 9/14/24.
//
import Foundation
import BSON

/// Errors that can occur during signing operations.
enum SigningErrors: Error {
    case invalidSignature, missingSignedObject, signingFailedOnVerfication
}

/// A struct representing the configuration of a user device, including its identity, signing information, and whether it is a master device.
public struct UserDeviceConfiguration: Codable, Sendable {
    
    /// Unique identifier for the device.
    public let deviceId: UUID
    /// Data representing the signing identity of the device.
    public let publicSigningKey: Data
    /// Public key associated with the device.
    public let publicKey: Data
    /// An optional Device Name to identify What device this actualy is.
    public let deviceName: String?
    /// A flag indicating if this device is the master device.
    public let isMasterDevice: Bool
    
    /// Coding keys for encoding and decoding the struct.
    enum CodingKeys: String, CodingKey, Codable, Sendable {
        case deviceId = "a"
        case publicSigningKey = "b"
        case publicKey = "c"
        case deviceName = "d"
        case isMasterDevice = "e"
    }
    
    /// Initializes a new `UserDeviceConfiguration` instance.
    /// - Parameters:
    ///   - deviceId: The unique identifier for the device.
    ///   - signingIdentity: The signing identity data.
    ///   - publicKey: The public key data.
    ///   - isMasterDevice: A flag indicating if this is the master device.
    /// - Throws: An error if signing the configuration fails.
    public init(
        deviceId: UUID,
        publicSigningKey: Data,
        publicKey: Data,
        deviceName: String?,
        isMasterDevice: Bool
    ) throws {
        self.deviceId = deviceId
        self.publicSigningKey = publicSigningKey
        self.publicKey = publicKey
        self.deviceName = deviceName
        self.isMasterDevice = isMasterDevice
    }
}

public struct UserSession: Identifiable, Codable, Sendable, Hashable {
    public let id: UUID
    public let secretName: String
    public let identity: UUID
    public let configuration: UserDeviceConfiguration
    
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
    
    public static func == (lhs: UserSession, rhs: UserSession) -> Bool {
        return lhs.id == rhs.id
    }
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
}
