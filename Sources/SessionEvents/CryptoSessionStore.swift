//
//  IdentityStore.swift
//  needletail-crypto
//
//  Created by Cole M on 9/14/24.
//
import Foundation
import DoubleRatchetKit
import Crypto
import SessionModels

// MARK: - Ordering Enum

/// An enumeration representing the order in which items can be sorted.
/// - `ascending`: Represents an ascending order.
/// - `descending`: Represents a descending order.
public enum Ordering: Sendable {
    case ascending, descending
}

// MARK: - WrappedPrivateMessage Struct

/// A struct that wraps a private message along with its associated shared communication ID.
/// This struct is used to manage encrypted messages in a secure manner.
public struct _WrappedPrivateMessage: Sendable {
    /// The unique identifier for the shared communication associated with the message.
    public let sharedCommunicationId: String
    
    /// The encrypted message.
    public let message: EncryptedMessage
    
    /// Initializes a new instance of `_WrappedPrivateMessage`.
    /// - Parameters:
    ///   - sharedCommunicationId: The unique identifier for the shared communication.
    ///   - message: The encrypted message to be wrapped.
    public init(sharedCommunicationId: String, message: EncryptedMessage) {
        self.sharedCommunicationId = sharedCommunicationId
        self.message = message
    }
}

// MARK: - CryptoSessionStore Protocol

/// A protocol that defines CRUD (Create, Read, Update, Delete) operations for managing device configurations in a database store.
public protocol CryptoSessionStore: Sendable {
    
    /// Creates a local device configuration with the provided data.
    /// - Parameter data: The configuration data to be stored.
    /// - Throws: An error if the operation fails, such as if the data is invalid or if there is a database error.
    func createLocalSessionContext(_ data: Data) async throws
    
    /// Retrieves the local device configuration.
    /// - Returns: The configuration data stored in the database.
    /// - Throws: An error if the operation fails, such as if the configuration does not exist or if there is a database error.
    func findLocalSessionContext() async throws -> Data
    
    /// Retrieves the local device salt.
    /// - Returns: The salt data associated with the local device.
    /// - Throws: An error if the operation fails, such as if the salt does not exist or if there is a database error.
    func findLocalDeviceSalt(keyData: Data) async throws -> Data
    
    /// Deletes the local device salt from the local database.
    /// - Throws: An error if the operation fails.
    func deleteLocalDeviceSalt() async throws
    
    /// Updates the local device configuration with the provided data.
    /// - Parameter data: The new configuration data to be stored.
    /// - Throws: An error if the operation fails, such as if the data is invalid or if there is a database error.
    func updateLocalSessionContext(_ data: Data) async throws
    
    /// Deletes the local device configuration.
    /// - Throws: An error if the operation fails, such as if the configuration does not exist or if there is a database error.
    func deleteLocalSessionContext() async throws
    
    /// Creates a new session identity in the database.
    /// - Parameter session: The `SessionIdentity` object to be created.
    /// - Throws: An error if the operation fails.
    func createSessionIdentity(_ session: SessionIdentity) async throws
    
    /// Fetches all session identities from the database.
    /// - Returns: An array of `SessionIdentity` objects.
    /// - Throws: An error if the operation fails.
    func fetchSessionIdentities() async throws -> [SessionIdentity]
    
    /// Updates an existing session identity in the database.
    /// - Parameter session: The `SessionIdentity` object to be updated.
    /// - Throws: An error if the operation fails.
    func updateSessionIdentity(_ session: SessionIdentity) async throws
    
    /// Removes a session identity from the database by its identifier.
    /// - Parameter id: The unique identifier of the session identity to be removed.
    /// - Throws: An error if the operation fails.
    func removeSessionIdentity(_ id: UUID) async throws
    
    /// Fetches all contacts from the database.
    /// - Returns: An array of `ContactModel` objects.
    /// - Throws: An error if the operation fails.
    func fetchContacts() async throws -> [ContactModel]
    
    /// Creates a new contact in the database.
    /// - Parameter contact: The `ContactModel` object to be created.
    /// - Throws: An error if the operation fails.
    func createContact(_ contact: ContactModel) async throws
    
    /// Updates an existing contact in the database.
    /// - Parameter contact: The `ContactModel` object to be updated.
    /// - Throws: An error if the operation fails.
    func updateContact(_ contact: ContactModel) async throws
    
    /// Removes a contact from the database by its identifier.
    /// - Parameter id: The unique identifier of the contact to be removed.
    /// - Throws: An error if the operation fails.
    func removeContact(_ id: UUID) async throws
    
    /// Fetches all communications from the database.
    /// - Returns: An array of `BaseCommunication` objects.
    /// - Throws: An error if the operation fails.
    func fetchCommunications() async throws -> [BaseCommunication]
    
    /// Creates a new communication in the database.
    /// - Parameter type: The `BaseCommunication` object to be created.
    /// - Throws: An error if the operation fails.
    func createCommunication(_ type: BaseCommunication) async throws
    
    /// Updates an existing communication in the database.
    /// - Parameter type: The `BaseCommunication` object to be updated.
    /// - Throws: An error if the operation fails.
    func updateCommunication(_ type: BaseCommunication) async throws
    
    /// Removes a communication from the database.
    /// - Parameter type: The `BaseCommunication` object to be removed.
    /// - Throws: An error if the operation fails.
    func removeCommunication(_ type: BaseCommunication) async throws
    
    /// Fetches messages associated with a specific shared communication identifier.
    /// - Parameter sharedCommunicationId: The unique identifier for the shared communication.
    /// - Returns: An array of `_WrappedPrivateMessage` objects.
    /// - Throws: An error if the operation fails.
    func fetchMessages(sharedCommunicationId: UUID) async throws -> [_WrappedPrivateMessage]
    
    /// Fetches a message by its unique identifier.
    /// - Parameter messageId: The unique identifier of the message to be fetched.
    /// - Returns: The corresponding `EncryptedMessage`.
    /// - Throws: An error if the operation fails.
    func fetchMessage(byId messageId: UUID) async throws -> EncryptedMessage
    
    /// Fetches a message by its shared message identifier.
    /// - Parameter sharedMessageId: The shared identifier of the message to be fetched.
    /// - Returns: The corresponding `EncryptedMessage`.
    /// - Throws: An error if the operation fails.
    func fetchMessage(by sharedMessageId: String) async throws -> EncryptedMessage
    
    /// Creates a new message in the database.
    /// - Parameters:
    ///   - message: The `EncryptedMessage` to be created.
    ///   - symmetricKey: The symmetric key used for encryption.
    /// - Throws: An error if the operation fails.
    func createMessage(_ message: EncryptedMessage, symmetricKey: SymmetricKey) async throws
    
    /// Updates an existing message in the database.
    /// - Parameters:
    ///   - message: The `EncryptedMessage` to be updated.
    ///   - symmetricKey: The symmetric key used for encryption.
    /// - Throws: An error if the operation fails.
    func updateMessage(_ message: EncryptedMessage, symmetricKey: SymmetricKey) async throws
    
    /// Removes a message from the database.
    /// - Parameter message: The `EncryptedMessage` to be removed.
    /// - Throws: An error if the operation fails.
    func removeMessage(_ message: EncryptedMessage) async throws
    
    /// Streams messages associated with a specific shared identifier.
    /// - Parameter sharedIdentifier: The unique identifier for the shared communication.
    /// - Returns: A tuple containing an `AsyncThrowingStream` of `EncryptedMessage` and its continuation.
    /// - Throws: An error if the operation fails.
    func streamMessages(sharedIdentifier: UUID) async throws -> (AsyncThrowingStream<EncryptedMessage, Error>, AsyncThrowingStream<EncryptedMessage, Error>.Continuation?)
    
    /// Retrieves the count of messages for a specific shared identifier.
    /// - Parameter sharedIdentifier: The unique identifier for the shared communication.
    /// - Returns: The count of messages as an `Int`.
    /// - Throws: An error if the operation fails.
    func messageCount(for sharedIdentifier: UUID) async throws -> Int
    
    /// Reads all jobs asynchronously.
    /// - Returns: An array of `JobModel` representing the jobs.
    /// - Throws: An error if the operation fails.
    func readJobs() async throws -> [JobModel]
    
    /// Creates a new job asynchronously.
    /// - Parameter job: The `JobModel` instance to be created.
    /// - Throws: An error if the operation fails.
    func createJob(_ job: JobModel) async throws
    
    /// Updates an existing job asynchronously.
    /// - Parameter job: The `JobModel` instance to be updated.
    /// - Throws: An error if the operation fails.
    func updateJob(_ job: JobModel) async throws
    
    /// Removes a job asynchronously.
    /// - Parameter job: The `JobModel` instance to be removed.
    /// - Throws: An error if the operation fails.
    func removeJob(_ job: JobModel) async throws
    
    /// Creates a media job asynchronously.
    /// - Parameter packet: The `DataPacket` instance representing the media job to be created.
    /// - Throws: An error if the operation fails.
    func createMediaJob(_ packet: DataPacket) async throws
    
    /// Finds all media jobs asynchronously.
    /// - Returns: An array of `DataPacket` representing all media jobs.
    /// - Throws: An error if the operation fails.
    func findAllMediaJobs() async throws -> [DataPacket]
    
    /// Finds media jobs for a specific recipient asynchronously.
    /// - Parameters:
    ///   - recipient: The recipient's identifier for whom to find media jobs.
    ///   - symmetricKey: The symmetric key used for decryption.
    /// - Returns: An array of `DataPacket` representing the media jobs for the recipient.
    /// - Throws: An error if the operation fails.
    func findMediaJobs(for recipient: String, symmetricKey: SymmetricKey) async throws -> [DataPacket]
    
    /// Finds a media job by its synchronization identifier asynchronously.
    /// - Parameters:
    ///   - synchronizationIdentifier: The identifier used for synchronization.
    ///   - symmetricKey: The symmetric key used for decryption.
    /// - Returns: An optional `DataPacket` representing the media job, or `nil` if not found.
    /// - Throws: An error if the operation fails.
    func findMediaJob(for synchronizationIdentifier: String, symmetricKey: SymmetricKey) async throws -> DataPacket?
    
    /// Finds a media job by its unique identifier asynchronously.
    /// - Parameter id: The unique identifier of the media job.
    /// - Returns: An optional `DataPacket` representing the media job, or `nil` if not found.
    /// - Throws: An error if the operation fails.
    func findMediaJob(_ id: UUID) async throws -> DataPacket?
    
    /// Deletes a media job by its unique identifier asynchronously.
    /// - Parameter id: The unique identifier of the media job to be deleted.
    /// - Throws: An error if the operation fails.
    func deleteMediaJob(_ id: UUID) async throws
}
