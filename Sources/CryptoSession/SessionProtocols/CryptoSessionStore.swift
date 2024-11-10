//
//  IdentityStore.swift
//  needletail-crypto
//
//  Created by Cole M on 9/14/24.
//
import Foundation
import NeedleTailCrypto
import DoubleRatchetKit
import Crypto

public enum Ordering: Sendable {
    case ascending, descending
}

/// A protocol that defines CRUD operations for managing device configurations in a database store.
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
    /// - Returns: The salt string associated with the local device.
    /// - Throws: An error if the operation fails, such as if the salt does not exist or if there is a database error.
    func findLocalDeviceSalt() async throws -> String
    
    /// Updates the local device configuration with the provided data.
    /// - Parameter data: The new configuration data to be stored.
    /// - Throws: An error if the operation fails, such as if the data is invalid or if there is a database error.
    func updateLocalSessionContext(_ data: Data) async throws
    
    /// Deletes the local device configuration.
    /// - Throws: An error if the operation fails, such as if the configuration does not exist or if there is a database error.
    func deleteLocalSessionContext() async throws
    
    
    func createSessionIdentity(_ session: SessionIdentity) async throws
    func fetchSessionIdentities() async throws -> [SessionIdentity]
    func updateSessionIdentity(_ session: SessionIdentity) async throws
    func removeSessionIdentity(_ id: UUID) async throws
    
    func fetchContacts() async throws -> [ContactModel]
    func createContact(_ contact: ContactModel) async throws
    func updateContact(_ contact: ContactModel) async throws
    func removeContact(_ id: UUID) async throws

    func fetchCommunications() async throws -> [BaseCommunication]
    func createCommunication(_ type: BaseCommunication) async throws
    func updateCommunication(_ type: BaseCommunication) async throws
    func removeCommunication(_ type: BaseCommunication) async throws
    
    func fetchMessage(byId messageId: UUID) async throws -> PrivateMessage
    func fetchMessage(by sharedMessageId: String) async throws -> PrivateMessage
    func createMessage(_ message: PrivateMessage, symmetricKey: SymmetricKey) async throws
    func updateMessage(_ message: PrivateMessage, symmetricKey: SymmetricKey) async throws
    func removeMessage(_ message: PrivateMessage) async throws
    func streamMessages(
        offSet: Int,
        limit: Int,
        sharedIdentifier: UUID,
        sequenceId: Int
    ) async throws -> (AsyncThrowingStream<[PrivateMessage], Error>, AsyncThrowingStream<[PrivateMessage], Error>.Continuation?)
    
    func readJobs() async throws -> [JobModel]
    func createJob(_ job: JobModel) async throws
    func updateJob(_ job: JobModel) async throws
    func removeJob(_ job: JobModel) async throws
    
    func createMediaJob(_ packet: DataPacket) async throws
    func findAllMediaJobs() async throws -> [DataPacket]
    func findMediaJob(_ id: UUID) async throws -> DataPacket?
    func deleteMediaJob(_ id: UUID) async throws
}
