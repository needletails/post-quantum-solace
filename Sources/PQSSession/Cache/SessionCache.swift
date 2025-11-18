//
//  SessionCache.swift
//  post-quantum-solace
//
//  Created by Cole M on 2024-09-15.
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
import DoubleRatchetKit
import Foundation
import SessionEvents
import SessionModels
import Crypto

/// A protocol defining the requirements for a cache synchronizer.
protocol SessionCacheSynchronizer: Sendable {
    func synchronizeLocalConfiguration(_ data: Data) async throws
}

/// An actor that manages session caching and synchronization.
///
/// This actor provides a two-tier caching system with in-memory cache and persistent store.
/// It implements the `PQSSessionStore` protocol with consistent naming conventions and
/// additional cache management capabilities.
///
/// ## Key Features
/// - **Consistent API**: All methods follow standardized naming patterns without prepositions
/// - **Thread Safety**: Uses actor isolation for concurrent access
/// - **Cache Management**: Built-in cache clearing, refreshing, and statistics
/// - **Error Handling**: Comprehensive error types with detailed descriptions
/// - **Synchronization**: Optional external synchronization support
///
/// ## Naming Conventions
/// - **Fetch Methods**: `fetch{Entity}({parameter}: {type})`
/// - **Create Methods**: `create{Entity}(_ {entity}: {EntityType})`
/// - **Delete Methods**: `delete{Entity}({parameter}: {type})`
/// - **Count Methods**: `{entity}Count({parameter}: {type})`
/// - **No Prepositions**: Parameter labels are clear and direct
///
/// ## Usage Example
/// ```swift
/// let cache = SessionCache(store: someStore)
///
/// // Fetch with consistent naming
/// let message = try await cache.fetchMessage(id: messageId)
/// let contacts = try await cache.fetchContacts()
///
/// // Cache management
/// let stats = cache.getCacheStats()
/// await cache.clearCache()
/// try await cache.refreshCache()
/// ```
public actor SessionCache: PQSSessionStore {
    // MARK: - Properties

    private let store: any PQSSessionStore
    private var sessionIdentities = [SessionIdentity]()
    private var messages = [EncryptedMessage]()
    private var contacts = [ContactModel]()
    private var communicationTypes = [BaseCommunication]()
    private var jobs = [JobModel]()
    private var mediaJobs = [DataPacket]()
    private var localDeviceConfiguration: Data?
    private var localDeviceSalt: Data?
    var synchronizer: SessionCacheSynchronizer?

    // MARK: - Initializer

    public init(store: any PQSSessionStore) {
        self.store = store
    }

    // MARK: - Synchronizer Management

    func setSynchronizer(_ synchronizer: SessionCacheSynchronizer?) {
        self.synchronizer = synchronizer
    }

    func setLocalDeviceConfiguration(_ configuration: Data) async throws {
        do {
            try await synchronizer?.synchronizeLocalConfiguration(configuration)
            localDeviceConfiguration = configuration
        } catch {
            throw CacheErrors.synchronizationFailed
        }
    }

    // MARK: - Local Device Configuration Methods

    /// Creates a local device configuration and caches it.
    /// - Parameter data: The configuration data to be cached.
    /// - Throws: An error if the creation fails.
    public func createLocalSessionContext(_ data: Data) async throws {
        guard !data.isEmpty else {
            throw CacheErrors.invalidData
        }

        try await store.createLocalSessionContext(data)
        try await setLocalDeviceConfiguration(data)
    }

    /// Fetches the local device configuration, either from cache or the store.
    /// - Returns: The cached or fetched configuration data.
    /// - Throws: An error if the configuration cannot be found.
    public func fetchLocalSessionContext() async throws -> Data {
        if let localDeviceConfiguration {
            return localDeviceConfiguration
        } else {
            let data = try await store.fetchLocalSessionContext()
            try await setLocalDeviceConfiguration(data)
            return data
        }
    }

    /// Updates the local device configuration and refreshes the cache.
    /// - Parameter data: The new configuration data.
    /// - Throws: An error if the update fails.
    public func updateLocalSessionContext(_ data: Data) async throws {
        try await setLocalDeviceConfiguration(data)
        try await store.deleteLocalSessionContext()
        try await createLocalSessionContext(data)
    }

    /// Deletes the local device configuration and clears the cache.
    /// - Throws: An error if the deletion fails.
    public func deleteLocalSessionContext() async throws {
        try await store.deleteLocalSessionContext()
        localDeviceConfiguration = nil
    }

    // MARK: - Local Device Salt Methods

    /// Fetches the local device salt, either from cache or the store.
    /// - Returns: The cached or fetched salt.
    /// - Throws: An error if the salt cannot be found.
    public func fetchLocalDeviceSalt(keyData: Data) async throws -> Data {
        if let cachedSalt = localDeviceSalt {
            return cachedSalt
        } else {
            localDeviceSalt = try await store.fetchLocalDeviceSalt(keyData: keyData)
            guard let salt = localDeviceSalt else {
                throw CacheErrors.localDeviceSaltIsNil
            }
            return salt
        }
    }

    public func deleteLocalDeviceSalt() async throws {
        try await store.deleteLocalDeviceSalt()
        localDeviceSalt = nil
    }

    // MARK: - Session Identity Methods

    /// Creates a new session identity and caches it.
    /// - Parameter session: The session identity to be created.
    /// - Throws: An error if the creation fails.
    public func createSessionIdentity(_ session: SessionIdentity) async throws {
        sessionIdentities.append(session)
        try await store.createSessionIdentity(session)
    }

    /// Fetches all session identities from the store and updates the cache.
    /// - Returns: An array of session identities.
    /// - Throws: An error if fetching fails.
    public func fetchSessionIdentities() async throws -> [SessionIdentity] {
        if !sessionIdentities.isEmpty {
            return sessionIdentities
        } else {
            let identities = try await store.fetchSessionIdentities()
            sessionIdentities = identities // Update the cache
            return identities
        }
    }

    /// Updates an existing session identity.
    /// - Parameter session: The session identity to be updated.
    /// - Throws: An error if the update fails.
    public func updateSessionIdentity(_ session: SessionIdentity) async throws {
        if sessionIdentities.isEmpty {
            let identities = try await store.fetchSessionIdentities()
            sessionIdentities = identities // Update the cache
        }
        if let index = sessionIdentities.firstIndex(where: { $0.id == session.id }) {
            sessionIdentities[index] = session
            try await store.updateSessionIdentity(session)
        } else {
            throw CacheErrors.sessionIdentityNotFound
        }
    }

    /// Removes a session identity from the cache and store.
    /// - Parameter id: The session identity to be removed.
    /// - Throws: An error if the removal fails.
    public func deleteSessionIdentity(_ id: UUID) async throws {
        sessionIdentities.removeAll(where: { $0.id == id })
        try await store.deleteSessionIdentity(id)
    }

    // MARK: - Message Methods

    /// Fetches a message by its ID.
    /// - Parameter messageId: The ID of the message to fetch.
    /// - Returns: The fetched message.
    /// - Throws: An error if fetching fails.
    public func fetchMessage(id: UUID) async throws -> EncryptedMessage {
        if let message = messages.first(where: { $0.id == id }) {
            return message
        } else {
            do {
                let message = try await store.fetchMessage(id: id)
                messages.append(message) // Cache the fetched message
                return message
            } catch {
                throw CacheErrors.messageNotFound
            }
        }
    }

    /// Fetches a message by its shared message ID.
    /// - Parameter sharedMessageId: The shared message ID of the message to fetch.
    /// - Returns: The fetched message.
    /// - Throws: An error if fetching fails.
    public func fetchMessage(sharedId: String) async throws -> EncryptedMessage {
        if let message = messages.first(where: { $0.sharedId == sharedId }) {
            return message
        } else {
            do {
                let message = try await store.fetchMessage(sharedId: sharedId)
                messages.append(message) // Cache the fetched message
                return message
            } catch {
                throw CacheErrors.messageNotFound
            }
        }
    }

    /// Fetches a message using a custom predicate.
    /// - Parameter predicate: A closure that takes a message and returns an optional message if it matches the criteria.
    /// - Returns: The first message that matches the predicate, or nil if none found.
    @Sendable
    public func fetchMessage(matching predicate: @escaping @Sendable (EncryptedMessage) async -> EncryptedMessage?) async throws -> EncryptedMessage? {
        for message in messages {
            if let found = await predicate(message) {
                return found
            }
        }
        return nil
    }

    public func fetchMessages(sharedCommunicationId: UUID) async throws -> [MessageRecord] {
        try await store.fetchMessages(sharedCommunicationId: sharedCommunicationId)
    }

    /// Creates a new message and caches it.
    /// - Parameter message: The message to be created.
    /// - Throws: An error if the creation fails.
    public func createMessage(_ message: EncryptedMessage, symmetricKey: SymmetricKey) async throws {
        try await store.createMessage(message, symmetricKey: symmetricKey)
        messages.append(message)
    }

    /// Updates an existing message.
    /// - Parameter message: The message to be updated.
    /// - Throws: An error if the update fails.
    public func updateMessage(_ message: EncryptedMessage, symmetricKey: SymmetricKey) async throws {
        if let index = messages.firstIndex(where: { $0.id == message.id }) {
            messages[index] = message
        }
        try await store.updateMessage(message, symmetricKey: symmetricKey)
    }

    /// Removes a message from the cache and store.
    /// - Parameter message: The message to be removed.
    /// - Throws: An error if the removal fails.
    public func deleteMessage(_ message: EncryptedMessage) async throws {
        messages.removeAll(where: { $0.id == message.id })
        try await store.deleteMessage(message)
    }

    /// Inserts a message into the cache with proper ordering.
    /// - Parameter message: The message to be inserted.
    /// - Throws: An error if the insertion fails.
    public func insertMessage(_ message: EncryptedMessage) async throws {
        if !messages.contains(where: { $0.id == message.id }) {
            messages.append(message)
            messages.sort(by: { $0.sequenceNumber < $1.sequenceNumber })
        }
    }

    /// Fetches cached messages for a specific shared ID.
    /// - Parameter sharedId: The shared ID to filter messages by.
    /// - Returns: An array of cached messages.
    /// - Throws: An error if fetching fails.
    public func fetchCachedMessages(sharedId: String) async throws -> [EncryptedMessage] {
        messages.filter { $0.sharedId == sharedId }
    }

    /// Gets the count of messages for a specific communication.
    /// - Parameter communicationId: The communication ID to count messages for.
    /// - Returns: The number of messages.
    public func messageCount(communicationId: UUID) -> Int {
        messages.count(where: { $0.communicationId == communicationId })
    }

    /// Streams messages for a specific shared identifier.
    /// - Parameter sharedIdentifier: The shared identifier to stream messages for.
    /// - Returns: A tuple containing the stream and its continuation.
    /// - Throws: An error if streaming fails.
    public func streamMessages(sharedIdentifier: UUID) async throws -> (AsyncThrowingStream<EncryptedMessage, Error>, AsyncThrowingStream<EncryptedMessage, Error>.Continuation?) {
        try await store.streamMessages(sharedIdentifier: sharedIdentifier)
    }

    /// Gets the message count for a specific shared identifier.
    /// - Parameter sharedIdentifier: The shared identifier to count messages for.
    /// - Returns: The number of messages.
    /// - Throws: An error if counting fails.
    public func messageCount(sharedIdentifier: UUID) async throws -> Int {
        try await store.messageCount(sharedIdentifier: sharedIdentifier)
    }

    // MARK: - Contact Methods

    /// Fetches all contacts from the cache or store.
    /// - Returns: An array of contacts.
    /// - Throws: An error if fetching fails.
    public func fetchContacts() async throws -> [ContactModel] {
        if contacts.isEmpty {
            contacts = try await store.fetchContacts()
        }
        return contacts
    }

    /// Creates a new contact and caches it.
    /// - Parameter contact: The contact to be created.
    /// - Throws: An error if the creation fails.
    public func createContact(_ contact: ContactModel) async throws {
        try await store.createContact(contact)
        contacts.append(contact) // Cache the new contact
    }

    /// Updates an existing contact in the cache and store.
    /// - Parameter contact: The contact to be updated.
    /// - Throws: An error if the update fails.
    public func updateContact(_ contact: ContactModel) async throws {
        if let index = contacts.firstIndex(where: { $0.id == contact.id }) {
            contacts[index] = contact
            try await store.updateContact(contact)
        } else {
            throw CacheErrors.contactNotFound
        }
    }

    /// Removes a contact from the cache and store.
    /// - Parameter id: The contact ID to be removed.
    /// - Throws: An error if the removal fails.
    public func deleteContact(_ id: UUID) async throws {
        contacts.removeAll(where: { $0.id == id })
        try await store.deleteContact(id)
    }

    // MARK: - Communication Type Methods

    /// Fetches all communication types from the cache or store.
    /// - Returns: An array of communication types.
    /// - Throws: An error if fetching fails.
    public func fetchCommunications() async throws -> [BaseCommunication] {
        if communicationTypes.isEmpty {
            communicationTypes = try await store.fetchCommunications()
        }
        return communicationTypes
    }

    /// Creates a new communication type and caches it.
    /// - Parameter type: The communication type to be created.
    /// - Throws: An error if the creation fails.
    public func createCommunication(_ type: BaseCommunication) async throws {
        try await store.createCommunication(type)
        communicationTypes.append(type) // Cache the new communication type
    }

    /// Updates an existing communication type in the cache and store.
    /// - Parameter type: The communication type to be updated.
    /// - Throws: An error if the update fails.
    public func updateCommunication(_ type: BaseCommunication) async throws {
        if let index = communicationTypes.firstIndex(where: { $0.id == type.id }) {
            communicationTypes[index] = type
            try await store.updateCommunication(type)
        } else {
            throw CacheErrors.communicationTypeNotFound
        }
    }

    /// Removes a communication type from the cache and store.
    /// - Parameter communication: The communication type to be removed.
    /// - Throws: An error if the removal fails.
    public func deleteCommunication(_ communication: BaseCommunication) async throws {
        communicationTypes.removeAll(where: { $0.id == communication.id })
        try await store.deleteCommunication(communication)
    }

    // MARK: - Job Methods

    /// Fetches all jobs from the cache or store.
    /// - Returns: An array of jobs.
    /// - Throws: An error if fetching fails.
    public func fetchJobs() async throws -> [JobModel] {
        // If the jobs cache is empty, fetch from the store
        if jobs.isEmpty {
            jobs = try await store.fetchJobs()
        }
        return jobs
    }

    /// Creates a new job and caches it.
    /// - Parameter job: The job to be created.
    /// - Throws: An error if the creation fails.
    public func createJob(_ job: JobModel) async throws {
        try await store.createJob(job) // Persist the job in the store
        jobs.append(job) // Cache the new job
    }

    /// Updates an existing job in the cache and store.
    /// - Parameter job: The job to be updated.
    /// - Throws: An error if the update fails.
    public func updateJob(_ job: JobModel) async throws {
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
    public func deleteJob(_ job: JobModel) async throws {
        jobs.removeAll(where: { $0.id == job.id }) // Remove from cache
        try await store.deleteJob(job) // Remove from the store
    }

    // MARK: - Media Job Methods

    /// Creates a new media job and caches it.
    /// - Parameter packet: The `DataPacket` representing the media job to be created.
    /// - Throws: An error if the creation fails in the store.
    public func createMediaJob(_ packet: DataPacket) async throws {
        try await store.createMediaJob(packet) // Persist the media job in the store
        mediaJobs.append(packet) // Cache the new media job
    }

    /// Fetches all media jobs from the cache or store.
    /// - Returns: An array of `DataPacket` representing all media jobs.
    /// - Throws: An error if fetching fails from the store.
    public func fetchAllMediaJobs() async throws -> [DataPacket] {
        if mediaJobs.isEmpty {
            mediaJobs = try await store.fetchAllMediaJobs() // Fetch from the store if cache is empty
        }
        return mediaJobs // Return the cached media jobs
    }

    /// Finds a specific media job by its ID, either from the cache or the store.
    /// - Parameter id: The unique identifier of the media job to fetch.
    /// - Returns: An optional `DataPacket` representing the media job if found, or `nil` if not found.
    /// - Throws: An error if fetching fails from the store.
    public func fetchMediaJob(id: UUID) async throws -> DataPacket? {
        if let job = mediaJobs.first(where: { $0.id == id }) {
            return job // Return from cache if found
        }
        do {
            let job = try await store.fetchMediaJob(id: id) // Fetch from the store
            if let job {
                mediaJobs.append(job) // Cache the fetched job if found
            }
            return job // Return the fetched job or nil if not found
        } catch {
            throw CacheErrors.mediaJobNotFound
        }
    }

    public func fetchMediaJobs(recipient: String, symmetricKey: SymmetricKey) async throws -> [DataPacket] {
        try await store.fetchMediaJobs(recipient: recipient, symmetricKey: symmetricKey)
    }

    public func fetchMediaJob(synchronizationIdentifier: String, symmetricKey: SymmetricKey) async throws -> DataPacket? {
        try await store.fetchMediaJob(synchronizationIdentifier: synchronizationIdentifier, symmetricKey: symmetricKey)
    }

    /// Deletes a media job from both the cache and the store.
    /// - Parameter id: The unique identifier of the media job to be removed.
    /// - Throws: An error if the removal fails in the store.
    public func deleteMediaJob(_ id: UUID) async throws {
        mediaJobs.removeAll(where: { $0.id == id }) // Remove from cache
        try await store.deleteMediaJob(id) // Remove from the store
    }

    // MARK: - Cache Management

    /// Clears all cached data, including session identities, messages, contacts, communications, jobs, media jobs, and local device configuration/salt.
    /// Use this to reset the in-memory cache without affecting the persistent store.
    public func clearCache() async {
        sessionIdentities.removeAll()
        messages.removeAll()
        contacts.removeAll()
        communicationTypes.removeAll()
        jobs.removeAll()
        mediaJobs.removeAll()
        localDeviceConfiguration = nil
        localDeviceSalt = nil
    }

    /// Refreshes the cache by fetching fresh data from the persistent store for all major entities.
    /// - Throws: An error if any fetch operation from the store fails.
    /// Use this to synchronize the in-memory cache with the latest data from the store.
    public func refreshCache() async throws {
        sessionIdentities = try await store.fetchSessionIdentities()
        contacts = try await store.fetchContacts()
        communicationTypes = try await store.fetchCommunications()
        jobs = try await store.fetchJobs()
        mediaJobs = try await store.fetchAllMediaJobs()
    }

    /// Returns statistics about the current state of the cache.
    /// - Returns: A `CacheStats` struct containing counts for each cached entity and flags for local device configuration/salt.
    /// Use this to monitor cache usage and health.
    public func getCacheStats() -> CacheStats {
        CacheStats(
            sessionIdentityCount: sessionIdentities.count,
            messageCount: messages.count,
            contactCount: contacts.count,
            communicationCount: communicationTypes.count,
            jobCount: jobs.count,
            mediaJobCount: mediaJobs.count,
            hasLocalDeviceConfiguration: localDeviceConfiguration != nil,
            hasLocalDeviceSalt: localDeviceSalt != nil
        )
    }

    /// Checks if a given item is present in the cache.
    /// - Parameter item: The item to check (must be one of the supported types: EncryptedMessage, ContactModel, JobModel, DataPacket).
    /// - Returns: `true` if the item is cached, `false` otherwise.
    /// Use this to quickly determine if an entity is already cached.
    public func isCached(_ item: some Any) -> Bool {
        switch item {
        case let message as EncryptedMessage:
            messages.contains { $0.id == message.id }
        case let contact as ContactModel:
            contacts.contains { $0.id == contact.id }
        case let job as JobModel:
            jobs.contains { $0.id == job.id }
        case let mediaJob as DataPacket:
            mediaJobs.contains { $0.id == mediaJob.id }
        default:
            false
        }
    }

    // MARK: - Cache Statistics

    /// A struct containing statistics about the cache.
    /// Provides counts for each major cached entity and flags for local device configuration and salt.
    public struct CacheStats {
        /// The number of session identities in the cache.
        public let sessionIdentityCount: Int
        /// The number of messages in the cache.
        public let messageCount: Int
        /// The number of contacts in the cache.
        public let contactCount: Int
        /// The number of communication types in the cache.
        public let communicationCount: Int
        /// The number of jobs in the cache.
        public let jobCount: Int
        /// The number of media jobs in the cache.
        public let mediaJobCount: Int
        /// Whether a local device configuration is cached.
        public let hasLocalDeviceConfiguration: Bool
        /// Whether a local device salt is cached.
        public let hasLocalDeviceSalt: Bool

        public init(
            sessionIdentityCount: Int,
            messageCount: Int,
            contactCount: Int,
            communicationCount: Int,
            jobCount: Int,
            mediaJobCount: Int,
            hasLocalDeviceConfiguration: Bool,
            hasLocalDeviceSalt: Bool
        ) {
            self.sessionIdentityCount = sessionIdentityCount
            self.messageCount = messageCount
            self.contactCount = contactCount
            self.communicationCount = communicationCount
            self.jobCount = jobCount
            self.mediaJobCount = mediaJobCount
            self.hasLocalDeviceConfiguration = hasLocalDeviceConfiguration
            self.hasLocalDeviceSalt = hasLocalDeviceSalt
        }
    }

    // MARK: - Error Handling

    public enum CacheErrors: Error {
        case localDeviceConfigurationIsNil
        case localDeviceSaltIsNil
        case sessionIdentityNotFound
        case messageNotFound
        case contactNotFound
        case communicationTypeNotFound
        case jobNotFound
        case mediaJobNotFound
        case synchronizationFailed
        case invalidData

        public var description: String {
            switch self {
            case .localDeviceConfigurationIsNil:
                "Local device configuration is nil"
            case .localDeviceSaltIsNil:
                "Local device salt is nil"
            case .sessionIdentityNotFound:
                "Session identity not found in cache"
            case .messageNotFound:
                "Message not found in cache"
            case .contactNotFound:
                "Contact not found in cache"
            case .communicationTypeNotFound:
                "Communication type not found in cache"
            case .jobNotFound:
                "Job not found in cache"
            case .mediaJobNotFound:
                "Media job not found in cache"
            case .synchronizationFailed:
                "Failed to synchronize with external system"
            case .invalidData:
                "Invalid data provided"
            }
        }

        public var reason: String {
            switch self {
            case .localDeviceConfigurationIsNil:
                "The local device configuration was not properly initialized"
            case .localDeviceSaltIsNil:
                "The local device salt was not found in the store"
            case .sessionIdentityNotFound:
                "The requested session identity does not exist in the cache"
            case .messageNotFound:
                "The requested message does not exist in the cache"
            case .contactNotFound:
                "The requested contact does not exist in the cache"
            case .communicationTypeNotFound:
                "The requested communication type does not exist in the cache"
            case .jobNotFound:
                "The requested job does not exist in the cache"
            case .mediaJobNotFound:
                "The requested media job does not exist in the cache"
            case .synchronizationFailed:
                "The synchronization operation failed due to network or system issues"
            case .invalidData:
                "The provided data is invalid or corrupted"
            }
        }

        public var suggestion: String {
            switch self {
            case .localDeviceConfigurationIsNil:
                "Try creating a new local session context"
            case .localDeviceSaltIsNil:
                "Try regenerating the device salt"
            case .sessionIdentityNotFound, .messageNotFound, .contactNotFound, .communicationTypeNotFound, .jobNotFound, .mediaJobNotFound:
                "Try refreshing the cache or checking if the item exists in the store"
            case .synchronizationFailed:
                "Check your network connection and try again"
            case .invalidData:
                "Verify the data format and try again"
            }
        }
    }
}
