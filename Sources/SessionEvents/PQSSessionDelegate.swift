//
//  PQSSessionDelegate.swift
//  post-quantum-solace
//
//  Created by Cole M on 4/19/25.
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

import struct BSON.BSONDecoder
import struct BSON.Document
import class DoubleRatchetKit.SessionIdentity
import Foundation
import SessionModels

/// A delegate protocol that provides hooks for integrating application-specific
/// logic with the lifecycle of a cryptographic messaging session.
///
/// Conforming to `PQSSessionDelegate` allows the implementer to manage transport-level
/// metadata, synchronize communication, handle delivery state changes, and manage contacts.
/// This protocol is `Sendable` to support concurrent contexts such as Swift concurrency (async/await).
///
/// ## Usage
///
/// Implement this protocol to customize how your application handles various session events:
///
/// ```swift
/// class MySessionDelegate: PQSSessionDelegate {
///     func synchronizeCommunication(recipient: MessageRecipient, sharedIdentifier: String) async throws {
///         // Handle communication synchronization
///     }
///
///     func handleBlockUnblock(recipient: MessageRecipient, blockData: Data?, metadata: Document, currentState: FriendshipMetadata.State) async throws {
///         // Handle contact blocking/unblocking
///     }
///     // ... implement other required methods
/// }
/// ```
///
/// ## Thread Safety
///
/// All delegate methods are called on background queues and should be implemented
/// with thread safety in mind. The protocol is marked as `Sendable` to support
/// concurrent execution contexts.
public protocol PQSSessionDelegate: Sendable {
    /// Called to synchronize communication state between two users.
    ///
    /// This method is invoked when the session needs to establish or refresh
    /// communication state with a recipient. Use this opportunity to:
    /// - Exchange session metadata
    /// - Update contact information
    /// - Establish shared context for future communications
    ///
    /// - Parameters:
    ///   - recipient: The message recipient to synchronize with.
    ///   - sharedIdentifier: A shared session identifier used to associate the context.
    ///     This identifier is consistent across all devices and sessions for the same
    ///     communication channel.
    ///
    /// - Throws: Any error that occurs during synchronization. Errors will be
    ///   propagated to the calling context and may affect session establishment.
    func synchronizeCommunication(
        recipient: MessageRecipient,
        sharedIdentifier: String
    ) async throws

    /// Called when friendshipstate changes. May block or unblock a contact
    ///
    /// This method is invoked whenever the blocking state of a contact changes.
    /// Use this to update your application's contact management system and
    /// handle any side effects of blocking/unblocking.
    ///
    /// - Parameters:
    ///   - recipient: The message recipient affected by the block/unblock action.
    ///   - blockData: Optional encrypted or identifying data related to the block action.
    ///     May contain additional context about why the contact was blocked/unblocked.
    ///   - metadata: Metadata describing the event, including timestamps and
    ///     any additional context about the block/unblock action.
    ///   - currentState: The current state of the friendship or contact relationship
    ///     after the block/unblock action has been applied.
    ///
    /// - Throws: Any error that occurs while processing the block/unblock event.
    func requestFriendshipStateChange(
        recipient: MessageRecipient,
        blockData: Data?,
        metadata: Document,
        currentState: FriendshipMetadata.State
    ) async throws

    /// Called when the delivery state of a message changes (e.g., delivered, read).
    ///
    /// This method is invoked whenever the delivery status of a message is updated.
    /// Use this to update your application's message delivery tracking and
    /// provide user feedback about message status.
    ///
    /// - Parameters:
    ///   - recipient: The intended recipient of the message whose delivery state changed.
    ///   - metadata: Transport metadata that describes the delivery state change.
    ///     Contains information such as delivery timestamps, read receipts,
    ///     and any additional delivery context.
    ///
    /// - Throws: Any error that occurs while processing the delivery state change.
    func deliveryStateChanged(
        recipient: MessageRecipient,
        metadata: Document
    ) async throws

    /// Called when a new contact is created and recognized in the messaging system.
    ///
    /// This method is invoked when the system detects and establishes a new contact.
    /// Use this to initialize contact records, fetch contact information,
    /// and set up any necessary contact management structures.
    ///
    /// - Parameter recipient: The new message recipient that has been created.
    ///
    /// - Throws: Any error that occurs while processing the new contact creation.
    func contactCreated(
        recipient: MessageRecipient
    ) async throws

    /// Requests metadata from the recipient's side, such as session or user status info.
    ///
    /// This method is called when the system needs to fetch additional information
    /// about a recipient. Use this to request user status, session information,
    /// or any other metadata that may be needed for proper message handling.
    ///
    /// - Parameter recipient: The message recipient to query for metadata.
    ///
    /// - Throws: Any error that occurs while requesting metadata from the recipient.
    func requestMetadata(
        recipient: MessageRecipient
    ) async throws

    /// Called when a previously sent message is edited.
    ///
    /// This method is invoked when a message that was previously sent has been
    /// modified. Use this to update your application's message history and
    /// handle any side effects of message editing.
    ///
    /// - Parameters:
    ///   - recipient: The recipient of the edited message.
    ///   - metadata: The updated message metadata containing the new message
    ///     content and any additional context about the edit.
    ///
    /// - Throws: Any error that occurs while processing the message edit.
    func editMessage(
        recipient: MessageRecipient,
        metadata: Document
    ) async throws

    /// Determines whether a given transport message should be persisted.
    ///
    /// This method is called for each incoming message to determine if it should
    /// be stored in the application's persistent storage. Use this to filter
    /// messages based on your application's requirements.
    ///
    /// - Parameter transportInfo: Transport-specific data about the message,
    ///   including routing information, message flags, and other transport metadata.
    ///
    /// - Returns: `true` if the message should be persisted, `false` otherwise.
    ///   Messages that return `false` will still be processed but won't be stored.
    func shouldPersist(
        transportInfo: Data?
    ) -> Bool

    /// Retrieves identifying information about the sender based on the provided transport context.
    ///
    /// This method is useful for resolving session identities or applying custom logic
    /// depending on message types, flags, or routing data. It enables the application
    /// to extract meaningful identifiers—such as the sender's secret name and device ID—
    /// from transport-level metadata.
    ///
    /// - Parameter transportInfo: Optional transport-layer data containing routing
    ///   or message identifiers that can be used to determine sender information.
    ///
    /// - Returns: A tuple containing the sender's `secretName` and `deviceId`, or `nil`
    ///   if the information cannot be resolved from the provided transport data.
    ///
    /// - Throws: Any error that occurs while extracting user information.
    func retrieveUserInfo(
        _ transportInfo: Data?
    ) async -> (secretName: String, deviceId: String)?

    /// Updates the metadata of a `CryptoMessage` after the Double Ratchet sender initialization,
    /// but before encryption is performed via `ratchetEncrypt()`.
    ///
    /// This is the final opportunity to modify the message metadata before it is encrypted.
    /// Use this method to attach or update any contextual information, such as timestamps,
    /// identifiers, or flags that should be included in the message's metadata prior to encryption.
    ///
    /// - Parameters:
    ///   - message: The original `CryptoMessage` to be customized.
    ///   - sharedMessageId: A globally shared identifier for correlating the message
    ///     across devices or sessions. This ID is consistent across all devices
    ///     participating in the conversation.
    ///
    /// - Returns: The updated `CryptoMessage`, ready for encryption.
    ///   The returned message should contain all necessary metadata for proper
    ///   message handling on the recipient side.
    ///
    /// - Throws: Any error that occurs while updating the message metadata.
    func updateCryptoMessageMetadata(
        _ message: CryptoMessage,
        sharedMessageId: String
    ) -> CryptoMessage

    /// Allows customization of an encrypted message's metadata before it is processed
    /// by the Double Ratchet encryption pipeline (PQXDH).
    ///
    /// This method is invoked **once per session identity** before the encryptable message
    /// is forwarded for ratcheting and transmission. It gives consumers an opportunity to
    /// inspect, modify, or redact metadata from the `CryptoMessage`, such as removing
    /// metadata or identifiers not intended for the final recipient.
    ///
    /// Use this delegate to ensure that any sensitive or context-specific information
    /// is excluded from the message payload prior to encryption and transport.
    ///
    /// - Parameters:
    ///   - message: The encrypted message that is about to be ratcheted and sent.
    ///   - transportInfo: Optional metadata related to transport routing or delivery context.
    ///   - identity: The session identity associated with this encryption context.
    ///   - recipient: The intended recipient of the message.
    ///
    /// - Returns: A modified `EncryptedMessage` ready for ratcheting and delivery.
    ///   The returned message should contain only the metadata that should be
    ///   transmitted to the recipient.
    ///
    /// - Throws: Any error that occurs while updating the encryptable message metadata.
    func updateEncryptableMessageMetadata(
        _ message: SessionModels.EncryptedMessage,
        transportInfo: Data?,
        identity: SessionIdentity,
        recipient: MessageRecipient
    ) async -> SessionModels.EncryptedMessage

    /// Determines whether communication synchronization should be finalized.
    ///
    /// This method is called during the communication synchronization process to
    /// determine if the synchronization can be completed. Use this to implement
    /// custom logic for when synchronization should finish based on your
    /// application's requirements.
    ///
    /// - Parameter transportInfo: Optional data relevant to the current transport session
    ///   that may influence the decision to finalize synchronization.
    ///
    /// - Returns: `true` if synchronization can be completed, `false` otherwise.
    ///   Returning `false` will prevent the synchronization from completing
    ///   and may trigger additional synchronization attempts.
    func shouldFinishCommunicationSynchronization(
        _ transportInfo: Data?
    ) -> Bool

    /// Processes a decrypted message that was not persisted but should be handled immediately.
    ///
    /// This method is called for messages that were determined not to be persisted
    /// (via `shouldPersist(_:)`) but still require immediate processing. Use this
    /// to handle system messages, control messages, or other non-persistent
    /// communications that need immediate attention.
    ///
    /// - Parameters:
    ///   - message: The decrypted message object that needs immediate processing.
    ///   - senderSecretName: The sender's authenticated secret name.
    ///   - senderDeviceId: The UUID of the sender's device.
    ///
    /// - Returns: `true` if the message was successfully processed, `false` otherwise.
    ///   Returning `false` may indicate that the message should be handled differently
    ///   or that processing failed.
    ///
    /// - Throws: Any error that occurs while processing the unpersisted message.
    func processUnpersistedMessage(
        _ message: CryptoMessage,
        senderSecretName: String,
        senderDeviceId: UUID
    ) async -> Bool
}
