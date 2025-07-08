//
//  SessionTransport.swift
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
import BSON
import Crypto
import DoubleRatchetKit
import Foundation
import SessionModels

/// Metadata structure for signed ratchet messages that contains sensitive information
/// used to prepare messages for network transmission.
///
/// This metadata should be handled with care as it contains recipient information
/// and should not be sent over the wire. It is used internally to prepare and
/// route messages to the correct recipients.
///
/// ## Important Security Note
/// None of this metadata should be transmitted over the network. It is used
/// solely for internal message preparation and routing.
///
/// ## Properties
/// - `secretName`: The recipient's secret identifier for privacy-preserving communication
/// - `deviceId`: The unique identifier for the recipient's device
/// - `recipient`: The type of recipient (individual, group, etc.)
/// - `transportMetadata`: Optional additional metadata for transport layer processing
/// - `sharedMessageId`: A shared identifier for message correlation and tracking
public struct SignedRatchetMessageMetadata: Sendable {
    /// The recipient's secret name used for privacy-preserving identification.
    ///
    /// This identifier is used to route messages without exposing real user identities.
    /// It should be treated as sensitive information and not logged or exposed.
    public let secretName: String

    /// The unique identifier for the recipient's device.
    ///
    /// This UUID identifies the specific device that should receive the message.
    /// Multiple devices can be associated with the same user.
    public let deviceId: UUID

    /// The type of recipient for the message.
    ///
    /// Determines how the message should be processed and routed (e.g., individual user,
    /// group conversation, broadcast, etc.).
    public let recipient: MessageRecipient

    /// Optional metadata for transport layer processing.
    ///
    /// Contains additional information that may be needed by the transport layer
    /// for message delivery, but should not be included in the message payload.
    public let transportMetadata: Data?

    /// A shared identifier for message correlation and tracking.
    ///
    /// Used to group related messages and track message delivery across
    /// different devices and sessions.
    public let sharedMessageId: String

    public var synchronizationKeyIds: SynchronizationKeyIdentities?

    /// Initializes a new instance of `SignedRatchetMessageMetadata`.
    ///
    /// - Parameters:
    ///   - secretName: The recipient's secret identifier for privacy-preserving communication
    ///   - deviceId: The unique identifier for the recipient's device
    ///   - recipient: The type of recipient for the message
    ///   - transportMetadata: Optional additional metadata for transport layer processing
    ///   - sharedMessageId: A shared identifier for message correlation and tracking
    public init(
        secretName: String,
        deviceId: UUID,
        recipient: MessageRecipient,
        transportMetadata: Data?,
        sharedMessageId: String,
        synchronizationKeyIds: SynchronizationKeyIdentities?
    ) {
        self.secretName = secretName
        self.deviceId = deviceId
        self.recipient = recipient
        self.transportMetadata = transportMetadata
        self.sharedMessageId = sharedMessageId
        self.synchronizationKeyIds = synchronizationKeyIds
    }
}

/// A protocol defining the interface for secure session transport operations.
///
/// This protocol provides methods for sending encrypted messages, managing user configurations,
/// and handling cryptographic key operations in a post-quantum secure messaging system.
/// All operations are asynchronous and thread-safe, supporting concurrent execution.
///
/// ## Usage
/// Implement this protocol to provide transport layer functionality for the secure
/// messaging system. This typically involves network communication, database operations,
/// and cryptographic key management.
///
/// ```swift
/// class NetworkTransport: SessionTransport {
///     func sendMessage(_ message: SignedRatchetMessage, metadata: SignedRatchetMessageMetadata) async throws {
///         // Implement message sending logic
///     }
///
///     func findConfiguration(for secretName: String) async throws -> UserConfiguration {
///         // Implement configuration retrieval logic
///     }
///     // ... implement other required methods
/// }
/// ```
///
/// ## Thread Safety
/// All methods in this protocol are marked as `async` and should be implemented
/// with thread safety in mind. The protocol conforms to `Sendable` to support
/// concurrent execution contexts.
public protocol SessionTransport: Sendable {
    /// Sends a signed ratchet message to the network with associated metadata.
    ///
    /// This method is responsible for transmitting encrypted messages to the specified
    /// recipient. The message contains the encrypted payload, while the metadata
    /// provides routing and processing information.
    ///
    /// - Parameters:
    ///   - message: The signed ratchet message containing the encrypted payload
    ///   - metadata: Metadata containing recipient information and routing details
    /// - Throws: An error if the message could not be sent (e.g., network failure, invalid recipient)
    func sendMessage(_ message: SignedRatchetMessage,

                     metadata: SignedRatchetMessageMetadata) async throws

    /// Retrieves the user configuration for a given secret name from the network.
    ///
    /// This method fetches the complete user configuration including device information,
    /// cryptographic keys, and user preferences. The configuration is used to establish
    /// secure communication channels and verify user identities.
    ///
    /// - Parameter secretName: The secret name of the user whose configuration to retrieve
    /// - Returns: The complete user configuration containing device and key information
    /// - Throws: An error if the configuration could not be found or retrieved
    func findConfiguration(for secretName: String) async throws -> UserConfiguration

    /// Publishes a user configuration to the network for device synchronization.
    ///
    /// This method is called for master devices and when updating device bundles with
    /// new devices. It ensures that all devices associated with a user have access
    /// to the latest configuration information.
    ///
    /// - Parameters:
    ///   - configuration: The user configuration to be published to the network
    ///   - identity: The UUID of the recipient identity for the configuration
    /// - Throws: An error if the configuration could not be published
    func publishUserConfiguration(_ configuration: UserConfiguration, recipient identity: UUID) async throws

    /// Fetches one-time keys for a specific user and device.
    ///
    /// Retrieves the available one-time keys that can be used for establishing
    /// secure communication sessions. These keys are used in the Double Ratchet
    /// protocol for forward secrecy.
    ///
    /// - Parameters:
    ///   - secretName: The secret name of the user
    ///   - deviceId: The device identifier for which to fetch keys
    /// - Returns: A collection of one-time keys available for the specified device
    /// - Throws: An error if the keys could not be retrieved
    func fetchOneTimeKeys(for secretName: String, deviceId: String) async throws -> OneTimeKeys

    /// Fetches the identities of one-time keys for a specific user and device.
    ///
    /// Retrieves the UUIDs of available one-time keys without the actual key data.
    /// This is useful for key discovery and management operations.
    ///
    /// - Parameters:
    ///   - secretName: The secret name of the user
    ///   - deviceId: The device identifier for which to fetch key identities
    ///   - type: The type of keys to fetch (e.g., Curve25519, PQKEM)
    /// - Returns: An array of UUIDs representing the available one-time key identities
    /// - Throws: An error if the key identities could not be retrieved
    func fetchOneTimeKeyIdentities(for secretName: String, deviceId: String, type: KeysType) async throws -> [UUID]

    /// Updates the one-time keys for a specific user and device.
    ///
    /// Adds new Curve25519 one-time keys to the user's key bundle. These keys
    /// are used for establishing secure communication sessions and providing
    /// forward secrecy.
    ///
    /// - Parameters:
    ///   - secretName: The secret name of the user
    ///   - deviceId: The device identifier for which to update keys
    ///   - keys: An array of signed one-time public keys to add
    /// - Throws: An error if the keys could not be updated
    func updateOneTimeKeys(for secretName: String, deviceId: String, keys: [UserConfiguration.SignedOneTimePublicKey]) async throws

    /// Updates the post-quantum KEM one-time keys for a specific user and device.
    ///
    /// Adds new post-quantum KEM one-time keys to the user's key bundle. These keys
    /// provide quantum-resistant security for future-proof communication.
    ///
    /// - Parameters:
    ///   - secretName: The secret name of the user
    ///   - deviceId: The device identifier for which to update keys
    ///   - keys: An array of signed post-quantum KEM one-time keys to add
    /// - Throws: An error if the keys could not be updated
    func updateOneTimePQKemKeys(for secretName: String, deviceId: String, keys: [UserConfiguration.SignedPQKemOneTimeKey]) async throws

    /// Deletes multiple one-time keys in a batch operation.
    ///
    /// Removes multiple one-time keys of the specified type for a user. This is
    /// typically used when keys have been consumed or are no longer needed.
    ///
    /// - Parameters:
    ///   - secretName: The secret name of the user
    ///   - id: The identifier for the batch of keys to delete
    ///   - type: The type of keys to delete (e.g., Curve25519, PQKEM)
    /// - Throws: An error if the keys could not be deleted
    func batchDeleteOneTimeKeys(for secretName: String, with id: String, type: KeysType) async throws

    /// Deletes a specific one-time key.
    ///
    /// Removes a single one-time key of the specified type for a user. This is
    /// typically used when a key has been consumed or is no longer valid.
    ///
    /// - Parameters:
    ///   - secretName: The secret name of the user
    ///   - id: The identifier of the specific key to delete
    ///   - type: The type of key to delete (e.g., Curve25519, PQKEM)
    /// - Throws: An error if the key could not be deleted
    func deleteOneTimeKeys(for secretName: String, with id: String, type: KeysType) async throws

    /// Publishes rotated cryptographic keys to the network.
    ///
    /// Announces new rotated keys to other users in the system. Key rotation
    /// is a security practice that limits the impact of key compromise.
    ///
    /// - Parameters:
    ///   - secretName: The secret name of the user whose keys are being rotated
    ///   - deviceId: The device identifier for which keys are being rotated
    ///   - keys: The new rotated public keys to publish
    /// - Throws: An error if the keys could not be published
    func publishRotatedKeys(
        for secretName: String,
        deviceId: String,
        rotated keys: RotatedPublicKeys
    ) async throws

    /// Creates an upload packet for secure data transmission.
    ///
    /// Prepares a data packet for secure upload to the network. This method
    /// is used for transmitting large files or media content securely.
    ///
    /// - Parameters:
    ///   - secretName: The secret name of the user creating the upload packet
    ///   - deviceId: The device identifier creating the upload packet
    ///   - recipient: The intended recipient of the upload packet
    ///   - metadata: Additional metadata describing the upload packet contents
    /// - Throws: An error if the upload packet could not be created
    func createUploadPacket(
        secretName: String,
        deviceId: UUID,
        recipient: MessageRecipient,
        metadata: Document
    ) async throws
}
