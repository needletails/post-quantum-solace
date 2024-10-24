//
//  SessionUser.swift
//  needletail-crypto
//
//  Created by Cole M on 9/14/24.
//
import Foundation

/// A struct representing a session user, including their secret name, device identity, and device keys.
public struct SessionUser: Codable & Sendable {
    /// Coding keys for encoding and decoding the struct.
    enum CodingKeys: String, CodingKey, Codable & Sendable {
        case secretName = "a"
        case deviceIdentity = "b"
        case deviceKeys = "c"
        case metadata = "d"
    }
    /// The name of the secret associated with the session user.
    public let secretName: String
    /// Unique identifier for the device associated with the session user.
    public let deviceIdentity: UUID
    /// The device keys associated with the session user.
    public let deviceKeys: DeviceKeys
    /// The User Specific Metadata
    public let metadata: ContactMetadata
    
}
