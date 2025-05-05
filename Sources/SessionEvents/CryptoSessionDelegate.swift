//
//  CryptoSessionDelegate.swift
//  crypto-session
//
//  Created by Cole M on 4/19/25.
//

import Foundation
import SessionModels
import struct BSON.Document
import struct BSON.BSONDecoder
import class DoubleRatchetKit.SessionIdentity

/// A delegate protocol that provides hooks for integrating application-specific
/// logic with the lifecycle of a cryptographic messaging session.
///
/// Conforming to `CryptoSessionDelegate` allows the implementer to manage transport-level
/// metadata, synchronize communication, handle delivery state changes, and manage contacts.
/// This protocol is `Sendable` to support concurrent contexts such as Swift concurrency (async/await).
public protocol CryptoSessionDelegate: Sendable {
    
    /// Called to synchronize communication state between two users.
    ///
    /// - Parameters:
    ///   - recipient: The message recipient to synchronize with.
    ///   - sharedIdentifier: A shared session identifier used to associate the context.
    func communicationSynchonization(
        recipient: MessageRecipient,
        sharedIdentifier: String
    ) async throws

    /// Called when a contact is blocked or unblocked.
    ///
    /// - Parameters:
    ///   - recipient: The message recipient affected.
    ///   - data: Optional encrypted or identifying data related to the block action.
    ///   - metadata: Metadata describing the event.
    ///   - myState: The current state of the friendship or contact relationship.
    func blockUnblock(
        recipient: MessageRecipient,
        data: Data?,
        metadata: Document,
        myState: FriendshipMetadata.State
    ) async throws

    /// Called when the delivery state of a message changes (e.g., delivered, read).
    ///
    /// - Parameters:
    ///   - recipient: The intended recipient of the message.
    ///   - metadata: Transport metadata that describes the delivery state.
    func deliveryStateChanged(
        recipient: MessageRecipient,
        metadata: Document
    ) async throws

    /// Called when a new contact is created and recognized in the messaging system.
    ///
    /// - Parameter recipient: The new message recipient.
    func contactCreated(
        recipient: MessageRecipient
    ) async throws

    /// Requests metadata from the recipient's side, such as session or user status info.
    ///
    /// - Parameter recipient: The message recipient to query.
    func requestMetadata(
        recipient: MessageRecipient
    ) async throws

    /// Called when a previously sent message is edited.
    ///
    /// - Parameters:
    ///   - recipient: The recipient of the edited message.
    ///   - metadata: The updated message metadata.
    func editMessage(
        recipient: MessageRecipient,
        metadata: Document
    ) async throws

    /// Determines whether a given transport message should be persisted.
    ///
    /// - Parameter transportInfo: Transport-specific data about the message.
    /// - Returns: `true` if the message should be persisted, `false` otherwise.
    func shouldPersist(
        transportInfo: Data?
    ) -> Bool

    /// Retrieves identifying information about the sender based on the provided transport context.
    ///
    /// This method is useful for resolving session identities or applying custom logic depending on message types, flags, or routing data.
    /// It enables the application to extract meaningful identifiers—such as the sender's secret name and device ID—from transport-level metadata.
    ///
    /// - Parameter transportInfo: Optional transport-layer data containing routing or message identifiers.
    /// - Returns: A tuple containing the sender’s `secretName` and `deviceId`, or `nil` if the information cannot be resolved.
    func getUserInfo(
        _ transportInfo: Data?
    ) async throws -> (secretName: String, deviceId: String)?


    /// Updates the metadata of a `CryptoMessage` after the Double Ratchet sender initialization, but before encryption is performed via `ratchetEncrypt()`.
    ///
    /// This is the final opportunity to modify the message metadata before it is encrypted. Use this method to attach or update any contextual information,
    /// such as timestamps, identifiers, or flags that should be included in the message's metadata prior to encryption.
    ///
    /// - Parameters:
    ///   - message: The original `CryptoMessage` to be customized.
    ///   - sharedMessageId: A globally shared identifier for correlating the message across devices or sessions.
    /// - Returns: The updated `CryptoMessage`, ready for encryption.
    func updateCryptoMessageMetadata(
        _ message: CryptoMessage,
        sharedMessageId: String
    ) throws -> CryptoMessage


    /// Allows customization of an encrypted message's metadata before it is processed by the Double Ratchet encryption pipeline (PQXDH). It also runs before a job is created. It is the soonest point that a message metadata can be customized before encryption.
    ///
    /// This method is invoked **once per session identity** before the encryptable message is forwarded for ratcheting and transmission.
    /// It gives consumers an opportunity to inspect, modify, or redact metadata from the `CryptoMessage`, such as removing metadata
    /// or identifiers not intended for the final recipient.
    ///
    /// Use this delegate to ensure that any sensitive or context-specific information is excluded from the message payload prior to
    /// encryption and transport.
    ///
    /// - Parameters:
    ///   - message: The encrypted message that is about to be ratcheted and sent.
    ///   - transportInfo: Optional metadata related to transport routing or delivery context.
    ///   - identity: The session identity associated with this encryption context.
    ///   - recipient: The intended recipient of the message.
    /// - Returns: A modified `EncryptedMessage` ready for ratcheting and delivery.
    func updateEncryptableMessageMetadata(
        _ message: SessionModels.EncryptedMessage,
        transportInfo: Data?,
        identity: SessionIdentity,
        recipient: MessageRecipient
    ) async throws -> SessionModels.EncryptedMessage


    /// Determines whether communication synchronization should be finalized.
    ///
    /// - Parameter transportInfo: Optional data relevant to the current transport session.
    /// - Returns: `true` if synchronization can be completed, `false` otherwise.
    func shouldFinishCommunicationSynchronization(
        _ transportInfo: Data?
    ) -> Bool

    /// Processes a decrypted message that was not persisted but should be handled immediately.
    ///
    /// - Parameters:
    ///   - message: The decrypted message object.
    ///   - senderSecretName: The sender's authenticated secret name.
    ///   - senderDeviceId: The UUID of the sender's device.
    func processUnpersistedMessage(
        _ message: CryptoMessage,
        senderSecretName: String,
        senderDeviceId: UUID
    ) async throws -> Bool
}
