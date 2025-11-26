//
//  EventReceiver.swift
//  post-quantum-solace
//
//  Created by Cole M on 2024-09-18.
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

import SessionModels

/// A protocol that defines methods for receiving events related to messages and contacts.
///
/// This protocol provides a comprehensive interface for handling various events that occur
/// during the lifecycle of messages and contacts in the secure messaging system. It conforms
/// to `Sendable` to ensure thread safety in concurrent environments.
///
/// ## Event Categories
/// - **Message Events**: Creation, updates, and deletion of encrypted messages
/// - **Contact Events**: Contact lifecycle management and metadata changes
/// - **Communication Events**: Updates to communication channels and member management
///
/// ## Usage
/// Implement this protocol to receive real-time notifications about changes in the messaging
/// system. The protocol methods are called asynchronously and should handle events efficiently
/// to maintain system responsiveness.
///
/// ## Thread Safety
/// All methods in this protocol are marked as `async` and should be implemented to handle
/// concurrent access safely. The `Sendable` conformance ensures that implementations can be
/// safely used across different execution contexts.
public protocol EventReceiver: Sendable {
    /// Called when a new message is created in the system.
    ///
    /// This method is invoked when a new encrypted message has been successfully created
    /// and stored in the local database. Use this method to update UI components, trigger
    /// notifications, or perform any necessary side effects when new messages arrive.
    ///
    /// - Parameter message: The `EncryptedMessage` instance that was created. Contains
    ///   the encrypted message data and associated metadata.
    /// - Returns: An asynchronous operation that completes when the event has been processed.
    func createdMessage(_ message: EncryptedMessage) async

    /// Called when an existing message is updated in the system.
    ///
    /// This method is invoked when an existing encrypted message has been modified,
    /// such as when delivery status changes, message content is edited, or metadata
    /// is updated. Use this method to refresh UI components or update local state.
    ///
    /// - Parameter message: The `EncryptedMessage` instance that was updated. Contains
    ///   the updated message data and metadata.
    /// - Returns: An asynchronous operation that completes when the event has been processed.
    func updatedMessage(_ message: EncryptedMessage) async

    /// Called when a message is deleted from the system.
    ///
    /// This method is invoked when an encrypted message has been permanently removed
    /// from the local database. Use this method to clean up UI components, remove
    /// cached data, or perform any necessary cleanup operations.
    ///
    /// - Parameter message: The `EncryptedMessage` instance that was deleted. Contains
    ///   the message data that was removed (may be useful for cleanup operations).
    /// - Returns: An asynchronous operation that completes when the event has been processed.
    func deletedMessage(_ message: EncryptedMessage) async

    /// Called when a new contact is created in the system.
    ///
    /// This method is invoked when a new contact has been successfully added to the
    /// local contact database. Use this method to update contact lists, trigger
    /// notifications, or perform any necessary initialization for new contacts.
    ///
    /// - Parameter contact: The `Contact` instance that was created. Contains the
    ///   contact's identification information, configuration, and metadata.
    /// - Throws: An error if the operation fails, such as database errors or
    ///   validation failures.
    func createdContact(_ contact: Contact) async throws

    /// Call when a recipient(Contact, Channel) is removed from the system.
    ///
    /// This method is invoked when a recipient wants to be permanently removed from the
    /// local contact database. Use this method to clean up contact-related UI components,
    /// remove cached data, or perform any necessary cleanup operations.
    ///
    /// - Parameter MessageRecipient: The the recipeint indicating the message type.
    /// - Throws: An error if the operation fails, such as database errors or
    ///   cleanup failures.
    func removedCommunication(_ type: MessageRecipient) async throws

    /// Synchronizes a contact with the remote system, optionally requesting friendship.
    ///
    /// This method is invoked to synchronize contact information with other devices
    /// or users in the network. It can optionally initiate a friendship request as
    /// part of the synchronization process.
    ///
    /// - Parameters:
    ///   - contact: The `Contact` instance to synchronize. Contains the contact's
    ///     identification information and metadata to be synchronized.
    ///   - requestFriendship: A boolean indicating whether to request friendship
    ///     with the contact during synchronization. When `true`, a friendship
    ///     request will be sent to the contact.
    /// - Throws: An error if the operation fails, such as network errors,
    ///   authentication failures, or synchronization conflicts.
    func synchronize(contact: Contact, requestFriendship: Bool) async throws

    /// Transports contact metadata to other devices or users in the network.
    ///
    /// This method is invoked to share the current user's contact metadata with
    /// other participants in the system. This typically includes profile information,
    /// status updates, and other metadata that should be visible to contacts.
    ///
    /// - Throws: An error if the operation fails, such as network errors,
    ///   authentication failures, or transport layer issues.
    func transportContactMetadata() async throws

    /// Updates an existing contact in the system.
    ///
    /// This method is invoked when an existing contact's information has been
    /// modified, such as when contact metadata is updated or configuration
    /// settings are changed.
    ///
    /// - Parameter contact: The `Contact` instance to be updated. Contains the
    ///   updated contact information and metadata.
    /// - Throws: An error if the operation fails, such as database errors,
    ///   validation failures, or update conflicts.
    func updateContact(_ contact: Contact) async throws

    /// Called when the metadata for a contact has changed.
    ///
    /// This method is invoked when a contact's metadata has been updated, such as
    /// when their profile information, status, or other metadata fields change.
    /// Use this method to update UI components that display contact information
    /// or trigger notifications about contact updates.
    ///
    /// - Parameter for: The `Contact` instance whose metadata has changed. Contains
    ///   the updated contact information including the modified metadata.
    /// - Returns: An asynchronous operation that completes when the event has been processed.
    func contactMetadata(changed for: Contact) async

    /// Called when communication is updated in the system.
    ///
    /// This method is invoked when a communication channel or group has been
    /// modified, such as when members are added/removed, communication settings
    /// are changed, or the communication metadata is updated.
    ///
    /// - Parameters:
    ///   - model: The `BaseCommunication` model that was updated. Contains the
    ///     updated communication information and settings.
    ///   - members: A set of member identifiers associated with the communication.
    ///     This set represents the current members of the communication channel.
    /// - Returns: An asynchronous operation that completes when the event has been processed.
    func updatedCommunication(_ model: BaseCommunication, members: Set<String>) async
    
    /// Called when a channel's BaseCommunication Model is created
    ///
    /// This method is invoked when a Channel's BaseCommunication  Model has been created.
    ///
    /// - Parameters:
    ///   - model: The `BaseCommunication` model that was updated. Contains the
    ///     updated communication information and settings.
    /// - Returns: An asynchronous operation that completes when the event has been processed.
    func createdChannel(_ model: BaseCommunication) async
}
