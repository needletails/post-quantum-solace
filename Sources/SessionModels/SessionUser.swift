//
//  SessionUser.swift
//  needletail-crypto
//
//  Created by Cole M on 9/14/24.
//
import Foundation

/// A struct representing a session user, including their secret name, device identity,
/// and device keys.
public struct SessionUser: Codable & Sendable {
    
    /// Coding keys for encoding and decoding the struct.
    enum CodingKeys: String, CodingKey, Codable & Sendable {
        case secretName = "a"      // Key for the secret name
        case deviceId = "b"        // Key for the device identifier
        case deviceKeys = "c"      // Key for the device keys
        case metadata = "d"        // Key for the user-specific metadata
    }
    
    /// The name of the secret associated with the session user.
    public let secretName: String
    
    /// Unique identifier for the device associated with the session user.
    public let deviceId: UUID
    
    /// The device keys associated with the session user.
    public var deviceKeys: DeviceKeys
    
    /// The user-specific metadata associated with the session user.
    public var metadata: ContactMetadata
    
    /// Initializes a new instance of `SessionUser`.
    ///
    /// - Parameters:
    ///   - secretName: The name of the secret associated with the session user.
    ///   - deviceId: Unique identifier for the device associated with the session user.
    ///   - deviceKeys: The device keys associated with the session user.
    ///   - metadata: The user-specific metadata associated with the session user.
    public init(
        secretName: String,
        deviceId: UUID,
        deviceKeys: DeviceKeys,
        metadata: ContactMetadata
    ) {
        self.secretName = secretName
        self.deviceId = deviceId
        self.deviceKeys = deviceKeys
        self.metadata = metadata
    }
}
