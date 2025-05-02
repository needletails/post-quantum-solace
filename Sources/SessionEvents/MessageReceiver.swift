//
//  MessageNotifier.swift
//  needletail-crypto
//
//  Created by Cole M on 9/18/24.
//

import SessionModels

/// A protocol that defines methods for receiving events related to messages and contacts.
public protocol EventReceiver: Sendable {
    
    /// Called when a new message is created.
    /// - Parameter message: The `EncryptedMessage` instance that was created.
    /// - Returns: An asynchronous operation.
    func createdMessage(_ message: EncryptedMessage) async
    
    /// Called when an existing message is updated.
    /// - Parameter message: The `EncryptedMessage` instance that was updated.
    /// - Returns: An asynchronous operation.
    func updatedMessage(_ message: EncryptedMessage) async
    
    /// Called when a message is deleted.
    /// - Parameter message: The `EncryptedMessage` instance that was deleted.
    /// - Returns: An asynchronous operation.
    func deletedMessage(_ message: EncryptedMessage) async
    
    /// Called when a new contact is created.
    /// - Parameter contact: The `Contact` instance that was created.
    /// - Throws: An error if the operation fails.
    func createdContact(_ contact: Contact) async throws
    
    /// Called when a contact is removed.
    /// - Parameter secretName: The secret name of the contact that was removed.
    /// - Throws: An error if the operation fails.
    func removedContact(_ secretName: String) async throws
    
    /// Synchronizes a contact, optionally requesting friendship.
    /// - Parameters:
    ///   - contact: The `Contact` instance to synchronize.
    ///   - requestFriendship: A boolean indicating whether to request friendship.
    /// - Throws: An error if the operation fails.
    func synchronize(contact: Contact, requestFriendship: Bool) async throws
    
    /// Transports contact metadata.
    /// - Throws: An error if the operation fails.
    func transportContactMetadata() async throws
    
    /// Updates an existing contact.
    /// - Parameter contact: The `Contact` instance to be updated.
    /// - Throws: An error if the operation fails.
    func updateContact(_ contact: Contact) async throws
    
    /// Called when the metadata for a contact has changed.
    /// - Parameter for: The `Contact` instance whose metadata has changed.
    /// - Returns: An asynchronous operation.
    func contactMetadata(changed for: Contact) async
    
    /// Called when communication is updated.
    /// - Parameters:
    ///   - model: The `BaseCommunication` model that was updated.
    ///   - members: A set of member identifiers associated with the communication.
    /// - Returns: An asynchronous operation.
    func updatedCommunication(_ model: BaseCommunication, members: Set<String>) async
}
