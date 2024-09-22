//
//  SessionCache.swift
//  crypto-session
//
//  Created by Cole M on 9/15/24.
//
import Foundation
import BSON
import NeedleTailHelpers
import NeedleTailCrypto
import DoubleRatchetKit

/// A protocol defining the requirements for a cache synchronizer.
protocol SessionCacheSynchronizer {
    func synchronizeLocalConfiguration(_ data: Data)
}

/// An actor that manages session caching and synchronization.
actor SessionCache: CryptoSessionStore {
    
    // MARK: - Properties
    
    private let store: CryptoSessionStore
    private var sessionIdentities = [SessionIdentityModel]()
    private var messages = [MessageModel]()
    private var contacts = [ContactModel]()
    private var communicationTypes = [DoubleRatchetKit.CommunicationModel]()
    private var jobs = [JobModel]()
    
    private var localDeviceConfiguration: Data? {
        didSet {
            if let localDeviceConfiguration = localDeviceConfiguration {
                synchronizer?.synchronizeLocalConfiguration(localDeviceConfiguration)
            }
        }
    }
    
    private var localDeviceSalt: String?
    var synchronizer: SessionCacheSynchronizer?
    
    // MARK: - Initializer
    
    init(store: CryptoSessionStore) {
        self.store = store
    }
    
    // MARK: - Cache Management
    
    /// Refreshes the entire cache by fetching the latest configurations, salts, contacts, communication types, and messages.
    /// - Throws: An error if any fetching operation fails.
    func refreshCache() async throws {
        // Refresh local device configuration
        localDeviceConfiguration = try await findLocalDeviceConfiguration()
        // Refresh local device salt
        localDeviceSalt = try await findLocalDeviceSalt()
        // Refresh contacts
        contacts = try await store.fetchContacts()
        // Refresh communication types
        communicationTypes = try await store.fetchCommunications()
        // Refresh messages (if needed, implement logic to fetch messages based on your requirements)
        //        messages = try await store.fetchMessages() // Assuming a method exists in the store to fetch all messages
    }
    
    /// Clears the cache by setting all cached properties to nil or empty.
    func dumpCache() {
        localDeviceConfiguration = nil
        localDeviceSalt = nil
        sessionIdentities.removeAll()
        messages.removeAll()
        contacts.removeAll()
        communicationTypes.removeAll()
    }
    
    
    // MARK: - Local Device Configuration Methods
    
    /// Creates a local device configuration and caches it.
    /// - Parameter data: The configuration data to be cached.
    /// - Throws: An error if the creation fails.
    func createLocalDeviceConfiguration(_ data: Data) async throws {
        try await store.createLocalDeviceConfiguration(data)
        localDeviceConfiguration = data // Cache the data directly
    }
    
    /// Finds the local device configuration, either from cache or the store.
    /// - Returns: The cached or fetched configuration data.
    /// - Throws: An error if the configuration cannot be found.
    func findLocalDeviceConfiguration() async throws -> Data {
        if let cachedConfig = localDeviceConfiguration {
            return cachedConfig
        }
        localDeviceConfiguration = try await store.findLocalDeviceConfiguration()
        guard let config = localDeviceConfiguration else {
            throw CacheErrors.localDeviceConfigurationIsNil
        }
        return config
    }
    
    /// Updates the local device configuration and refreshes the cache.
    /// - Parameter data: The new configuration data.
    /// - Throws: An error if the update fails.
    func updateLocalDeviceConfiguration(_ data: Data) async throws {
        try await store.updateLocalDeviceConfiguration(data)
        localDeviceConfiguration = data // Cache the updated data directly
    }
    
    /// Deletes the local device configuration and clears the cache.
    /// - Throws: An error if the deletion fails.
    func deleteLocalDeviceConfiguration() async throws {
        try await store.deleteLocalDeviceConfiguration()
        localDeviceConfiguration = nil
    }
    
    // MARK: - Local Device Salt Methods
    
    /// Finds the local device salt, either from cache or the store.
    /// - Returns: The cached or fetched salt.
    /// - Throws: An error if the salt cannot be found.
    func findLocalDeviceSalt() async throws -> String {
        if let cachedSalt = localDeviceSalt {
            return cachedSalt
        }
        localDeviceSalt = try await store.findLocalDeviceSalt()
        guard let salt = localDeviceSalt else {
            throw CacheErrors.localDeviceSaltIsNil
        }
        return salt
    }
    
    // MARK: - Session Identity Methods
    
    /// Creates a new session identity and caches it.
    /// - Parameter session: The session identity to be created.
    /// - Throws: An error if the creation fails.
    func createSessionIdentity(_ session: SessionIdentityModel) async throws {
        try await store.createSessionIdentity(session)
        sessionIdentities.append(session)
    }
    
    /// Fetches all session identities from the store and updates the cache.
    /// - Returns: An array of session identities.
    /// - Throws: An error if fetching fails.
    func fetchSessionIdentities() async throws -> [SessionIdentityModel] {
        let identities = try await store.fetchSessionIdentities()
        sessionIdentities = identities // Update the cache
        return sessionIdentities
    }
    
    /// Updates an existing session identity.
    /// - Parameter session: The session identity to be updated.
    /// - Throws: An error if the update fails.
    func updateSessionIdentity(_ session: SessionIdentityModel) async throws {
        if let index = sessionIdentities.firstIndex(where: { $0.id == session.id }) {
            sessionIdentities[index] = session
            try await store.updateSessionIdentity(session)
        } else {
            throw CacheErrors.sessionIdentityNotFound
        }
    }
    
    /// Removes a session identity from the cache and store.
    /// - Parameter session: The session identity to be removed.
    /// - Throws: An error if the removal fails.
    func removeSessionIdentity(_ session: SessionIdentityModel) async throws {
        sessionIdentities.removeAll(where: { $0.id == session.id })
        try await store.removeSessionIdentity(session)
    }
    
    // MARK: - Message Methods
    
    /// Fetches a message by its ID.
    /// - Parameter messageId: The ID of the message to fetch.
    /// - Returns: The fetched message.
    /// - Throws: An error if fetching fails.
    func fetchMessage(byId messageId: UUID) async throws -> MessageModel {
        if let message = messages.first(where: { $0.id == messageId }) {
            return message
        }
        let message = try await store.fetchMessage(byId: messageId)
        messages.append(message) // Cache the fetched message
        return message
    }
    
    
    /// Fetches a message by its shared message ID.
    /// - Parameter sharedMessageId: The shared message ID of the message to fetch.
    /// - Returns: The fetched message.
    /// - Throws: An error if fetching fails.
    func fetchMessage(by sharedMessageId: String) async throws -> DoubleRatchetKit.MessageModel {
        if let message = messages.first(where: { $0.sharedMessageIdentity == sharedMessageId }) {
            return message
        }
        let message = try await store.fetchMessage(by: sharedMessageId)
        messages.append(message) // Cache the fetched message
        return message
    }
    
    /// Creates a new message and caches it.
    /// - Parameter message: The message to be created.
    /// - Throws: An error if the creation fails.
    func createMessage(_ message: MessageModel) async throws {
        try await store.createMessage(message)
        messages.append(message)
    }
    
    /// Updates an existing message.
    /// - Parameter message: The message to be updated.
    /// - Throws: An error if the update fails.
    func updateMessage(_ message: MessageModel) async throws {
        if let index = messages.firstIndex(where: { $0.id == message.id }) {
            messages[index] = message
            try await store.updateMessage(message)
        } else {
            throw CacheErrors.messageNotFound
        }
    }
    
    /// Removes a message from the cache and store.
    /// - Parameter message: The message to be removed.
    /// - Throws: An error if the removal fails.
    func removeMessage(_ message: MessageModel) async throws {
        messages.removeAll(where: { $0.id == message.id })
        try await store.removeMessage(message)
    }
    
    /// Lists messages based on various criteria.
    /// - Parameters:
    ///   - communication: The communication ID to filter messages.
    ///   - senderId: The ID of the sender.
    ///   - minimumOrder: The minimum order to filter messages.
    ///   - maximumOrder: The maximum order to filter messages.
    ///   - offsetBy: The number of messages to skip.
    ///   - limit: The maximum number of messages to return.
    /// - Returns: An array of messages matching the criteria.
    /// - Throws: An error if fetching fails.
    func listMessages(
        in communication: UUID,
        senderId: Int,
        minimumOrder: Int? = nil,
        maximumOrder: Int? = nil,
        offsetBy: Int = 0,
        limit: Int = 100
    ) async throws -> [MessageModel] {
        // Implement filtering logic based on parameters
        return messages // Placeholder, implement filtering logic
    }
    
    // MARK: - Job Methods
    
    /// Fetches all jobs from the cache or store.
    /// - Returns: An array of jobs.
    /// - Throws: An error if fetching fails.
    func readJobs() async throws -> [JobModel] {
        // If the jobs cache is empty, fetch from the store
        if jobs.isEmpty {
            jobs = try await store.readJobs() // Assuming the store has a method to fetch jobs
        }
        return jobs
    }
    
    /// Creates a new job and caches it.
    /// - Parameter job: The job to be created.
    /// - Throws: An error if the creation fails.
    func createJob(_ job: JobModel) async throws {
        try await store.createJob(job) // Persist the job in the store
        jobs.append(job) // Cache the new job
    }
    
    /// Updates an existing job in the cache and store.
    /// - Parameter job: The job to be updated.
    /// - Throws: An error if the update fails.
    func updateJob(_ job: JobModel) async throws {
        if let index = jobs.firstIndex(where: { $0.id == job.id }) {
            jobs[index] = job // Update the cached job
            try await store.updateJob(job) // Persist the updated job in the store
        } else {
            throw CacheErrors.jobNotFound // Handle the case where the job is not found in the cache
        }
    }
    
    /// Removes a job from the cache and store.
    /// - Parameter job: The job to be removed.
    /// - Throws: An error if the removal fails.
    func removeJob(_ job: JobModel) async throws {
        jobs.removeAll(where: { $0.id == job.id }) // Remove from cache
        try await store.removeJob(job) // Remove from the store
    }
    
    // MARK: - Error Handling
    
    enum CacheErrors: Error {
        case localDeviceConfigurationIsNil
        case localDeviceSaltIsNil
        case sessionIdentityNotFound
        case messageNotFound
        case contactNotFound
        case communicationTypeNotFound
        case jobNotFound
    }
}

extension SessionCache {
    // MARK: - Contact Methods
    
    /// Fetches all contacts from the cache or store.
    /// - Returns: An array of contacts.
    /// - Throws: An error if fetching fails.
    func fetchContacts() async throws -> [ContactModel] {
        if contacts.isEmpty {
            contacts = try await store.fetchContacts()
        }
        return contacts
    }
    
    /// Creates a new contact and caches it.
    /// - Parameter contact: The contact to be created.
    /// - Throws: An error if the creation fails.
    func createContact(_ contact: ContactModel) async throws {
        try await store.createContact(contact)
        contacts.append(contact) // Cache the new contact
    }
    
    /// Updates an existing contact in the cache and store.
    /// - Parameter contact: The contact to be updated.
    /// - Throws: An error if the update fails.
    func updateContact(_ contact: ContactModel) async throws {
        if let index = contacts.firstIndex(where: { $0.id == contact.id }) {
            contacts[index] = contact
            try await store.updateContact(contact)
        } else {
            throw CacheErrors.contactNotFound
        }
    }
    
    /// Removes a contact from the cache and store.
    /// - Parameter contact: The contact to be removed.
    /// - Throws: An error if the removal fails.
    func removeContact(_ contact: ContactModel) async throws {
        contacts.removeAll(where: { $0.id == contact.id })
        try await store.removeContact(contact)
    }
    
    // MARK: - Communication Type Methods
    
    /// Fetches all communication types from the cache or store.
    /// - Returns: An array of communication types.
    /// - Throws: An error if fetching fails.
    func fetchCommunications() async throws -> [DoubleRatchetKit.CommunicationModel] {
        if communicationTypes.isEmpty {
            communicationTypes = try await store.fetchCommunications()
        }
        return communicationTypes
    }
    
    /// Creates a new communication type and caches it.
    /// - Parameter type: The communication type to be created.
    /// - Throws: An error if the creation fails.
    func createCommunication(_ type: DoubleRatchetKit.CommunicationModel) async throws {
        try await store.createCommunication(type)
        communicationTypes.append(type) // Cache the new communication type
    }
    
    /// Updates an existing communication type in the cache and store.
    /// - Parameter type: The communication type to be updated.
    /// - Throws: An error if the update fails.
    func updateCommunication(_ type: DoubleRatchetKit.CommunicationModel) async throws {
        if let index = communicationTypes.firstIndex(where: { $0.id == type.id }) {
            communicationTypes[index] = type
            try await store.updateCommunication(type)
        } else {
            throw CacheErrors.communicationTypeNotFound
        }
    }
    
    /// Removes a communication type from the cache and store.
    /// - Parameter type: The communication type to be removed.
    /// - Throws: An error if the removal fails.
    func removeCommunication(_ type: DoubleRatchetKit.CommunicationModel) async throws {
        communicationTypes.removeAll(where: { $0.id == type.id })
        try await store.removeCommunication(type)
    }
}
