//
//  SessionUser.swift
//  post-quantum-solace
//
//  Created by Cole M on 9/14/24.
//
import Foundation

/// A struct representing a session user in the post-quantum secure messaging system.
///
/// This struct encapsulates the essential information needed to identify and authenticate
/// a user within a secure session, including their secret name, device identity, cryptographic
/// keys, and contact metadata. It conforms to `Codable` and `Sendable` protocols for
/// serialization and thread safety.
///
/// ## Properties
/// - `secretName`: A privacy-preserving identifier for the user, used for secure communication
///   without exposing real identities.
/// - `deviceId`: A unique identifier for the specific device associated with the session user.
/// - `deviceKeys`: The cryptographic keys associated with the device, including signing keys,
///   long-term keys, and post-quantum keys for secure communication.
/// - `metadata`: Contact-specific metadata containing user profile information such as
///   nickname, status, and contact details.
///
/// ## Usage
/// This struct is typically used to represent the current user or other participants
/// in a secure messaging session. It provides the necessary information for establishing
/// secure communication channels and managing user identity across the system.
///
/// ## Security Considerations
/// - The `secretName` should be treated as sensitive information and not logged or exposed
///   in error messages.
/// - The `deviceKeys` contain private cryptographic material and should be handled with
///   appropriate security measures.
/// - The `metadata` may contain personal information and should be protected accordingly.
///
/// ## Conformance
/// - `Codable`: Allows the struct to be encoded and decoded for persistence and transmission.
/// - `Sendable`: Ensures thread safety when used across concurrent tasks.
public struct SessionUser: Codable & Sendable {
    
    /// Coding keys for encoding and decoding the struct.
    ///
    /// Single-letter keys are used for obfuscation and to reduce payload size during
    /// network transmission. This pattern is consistent across the codebase for
    /// security-sensitive data structures.
    enum CodingKeys: String, CodingKey, Codable & Sendable {
        case secretName = "a"      // Key for the secret name
        case deviceId = "b"        // Key for the device identifier
        case deviceKeys = "c"      // Key for the device keys
        case metadata = "d"        // Key for the user-specific metadata
    }
    
    /// The secret name associated with the session user.
    ///
    /// This is a privacy-preserving identifier used for secure communication without
    /// exposing real user identities. It should be treated as sensitive information.
    public let secretName: String
    
    /// Unique identifier for the device associated with the session user.
    ///
    /// This UUID uniquely identifies the specific device that the user is using
    /// for the session. Multiple devices can be associated with the same user.
    public let deviceId: UUID
    
    /// The device keys associated with the session user.
    ///
    /// Contains all cryptographic keys needed for secure communication, including:
    /// - Signing keys for message authentication
    /// - Long-term keys for identity verification
    /// - One-time keys for ephemeral key exchange
    /// - Post-quantum keys for future-proof security
    public var deviceKeys: DeviceKeys
    
    /// The contact metadata associated with the session user.
    ///
    /// Contains user profile information such as nickname, status, contact details,
    /// and other metadata that can be shared with other users in the system.
    public var metadata: ContactMetadata
    
    /// Initializes a new instance of `SessionUser`.
    ///
    /// Creates a session user with the specified secret name, device identifier,
    /// cryptographic keys, and contact metadata.
    ///
    /// - Parameters:
    ///   - secretName: The privacy-preserving identifier for the user. This should be
    ///     a unique, non-reversible identifier that doesn't expose real user identity.
    ///   - deviceId: The unique identifier for the device associated with this session.
    ///     This UUID should be consistent for the same device across sessions.
    ///   - deviceKeys: The cryptographic keys associated with the device. These keys
    ///     are essential for establishing secure communication channels.
    ///   - metadata: The contact metadata containing user profile information.
    ///     This can include nickname, status, and other shareable contact details.
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
